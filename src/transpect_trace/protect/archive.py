"""Durable, encrypted snapshots for a before-send decision.

The gate process must run under a different Windows account from the agent.
Only the gate account can unwrap the archive key with user-scoped DPAPI.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
RETENTION_DAYS = 7
_MAGIC = b"TTRACE-DLP-2\x00"
_KEY_FILE = "archive-key.dpapi"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes) -> tuple[_DataBlob, object]:
    buffer = ctypes.create_string_buffer(data)
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _dpapi(data: bytes, *, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise OSError("encrypted archive requires Windows DPAPI")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CryptProtectData.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob), wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(_DataBlob)]
    crypt.CryptProtectData.restype = wintypes.BOOL
    crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPVOID,
        ctypes.POINTER(_DataBlob), wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(_DataBlob)]
    crypt.CryptUnprotectData.restype = wintypes.BOOL
    source, keepalive = _blob(data)
    result = _DataBlob()
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    args = (ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result))
    if not operation(*args):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel.LocalFree.restype = wintypes.HLOCAL
        kernel.LocalFree(ctypes.cast(result.pbData, wintypes.HLOCAL))


@dataclass(frozen=True)
class ArchiveReceipt:
    record_id: str
    kind: str
    body_sha256: str
    body_bytes: int
    saved_at: str


class EncryptedRequestArchive:
    """Write ciphertext and flush it before returning a send authorization.

    A failed save raises; the caller must translate every exception into DENY.
    The directory must be private to the gate account and inaccessible to the
    lower-privilege Codex account. No raw request or file bytes enter metadata.
    """

    def __init__(self, directory: Path, *, retention_days: int = RETENTION_DAYS):
        if not 1 <= retention_days <= 365:
            raise ValueError("invalid retention")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.retention = timedelta(days=retention_days)
        self.key = self._load_key()

    def _load_key(self) -> bytes:
        path = self.directory / _KEY_FILE
        if path.exists():
            key = _dpapi(path.read_bytes(), decrypt=True)
        else:
            candidate = secrets.token_bytes(32)
            protected = _dpapi(candidate, decrypt=False)
            try:
                with path.open("xb") as stream:
                    stream.write(protected)
                    stream.flush()
                    os.fsync(stream.fileno())
                key = candidate
            except FileExistsError:
                key = _dpapi(path.read_bytes(), decrypt=True)
        if len(key) != 32:
            raise ValueError("invalid archive key")
        return key

    def save(self, kind: str, payload: bytes, *, now: datetime | None = None) -> ArchiveReceipt:
        if kind not in {"model_request", "attachment"}:
            raise ValueError("unsupported snapshot kind")
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_SNAPSHOT_BYTES:
            raise ValueError("invalid snapshot size")
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("snapshot time must be timezone-aware")
        record_id = uuid.uuid4().hex
        receipt = ArchiveReceipt(record_id, kind, hashlib.sha256(payload).hexdigest(),
                                 len(payload), now.isoformat())
        header = json.dumps(receipt.__dict__, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)
        # The digest and timestamp are sensitive metadata too: a plaintext
        # digest permits offline guesses of a short request or attachment.
        plaintext = len(header).to_bytes(2, "little") + header + payload
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, _MAGIC)
        frame = _MAGIC + nonce + ciphertext
        final = self.directory / f"{record_id}.enc"
        temporary = self.directory / f".{record_id}.tmp"
        try:
            with temporary.open("xb") as stream:
                stream.write(frame)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, final)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return receipt

    def _decode(self, record_id: str) -> tuple[ArchiveReceipt, bytes]:
        if len(record_id) != 32 or any(c not in "0123456789abcdef" for c in record_id):
            raise ValueError("invalid record id")
        path = self.directory / f"{record_id}.enc"
        if path.stat().st_size > MAX_SNAPSHOT_BYTES + 8192:
            raise ValueError("oversized archive record")
        frame = path.read_bytes()
        if not frame.startswith(_MAGIC) or len(frame) > MAX_SNAPSHOT_BYTES + 8192:
            raise ValueError("invalid archive record")
        start = len(_MAGIC)
        nonce = frame[start:start + 12]
        ciphertext = frame[start + 12:]
        if len(nonce) != 12 or len(ciphertext) < 18:
            raise ValueError("truncated archive record")
        plaintext = AESGCM(self.key).decrypt(nonce, ciphertext, _MAGIC)
        size = int.from_bytes(plaintext[:2], "little")
        if size > 4096:
            raise ValueError("invalid archive header")
        if len(plaintext) < 2 + size:
            raise ValueError("truncated archive record")
        header = plaintext[2:2 + size]
        receipt = ArchiveReceipt(**json.loads(header))
        if receipt.record_id != record_id:
            raise ValueError("archive record mismatch")
        payload = plaintext[2 + size:]
        if len(payload) != receipt.body_bytes or hashlib.sha256(payload).hexdigest() != receipt.body_sha256:
            raise ValueError("archive body mismatch")
        return receipt, payload

    def read(self, record_id: str) -> tuple[ArchiveReceipt, bytes]:
        receipt, payload = self._decode(record_id)
        saved_at = datetime.fromisoformat(receipt.saved_at)
        if saved_at.tzinfo is None or saved_at <= datetime.now(timezone.utc) - self.retention:
            raise ValueError("archive record expired")
        return receipt, payload

    def prune(self, *, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("prune time must be timezone-aware")
        removed = 0
        for path in self.directory.glob("*.enc"):
            # A file's mtime can be refreshed without changing its authenticated
            # creation time, so retention checks both timestamps.
            old_mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) <= now - self.retention
            if not old_mtime:
                receipt, _ = self._decode(path.stem)
                saved_at = datetime.fromisoformat(receipt.saved_at)
                if saved_at.tzinfo is None:
                    raise ValueError("archive record time missing timezone")
            if old_mtime or saved_at <= now - self.retention:
                path.unlink()
                removed += 1
        return removed
