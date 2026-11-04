"""Block sensitive user-submitted Codex CLI prompts before a turn begins.

This is a UserPromptSubmit command hook. Only the event's ``prompt`` string is
examined. It does not inspect attached files, the final model request, or
later agent/tool traffic. A hook that Codex skips or disables cannot enforce
this policy; the demo runner must verify that the hook actually ran.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
import uuid
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

from cli_prompt_detector import ContentDLPEngine


MAX_EVENT_BYTES = 1024 * 1024
ARCHIVE_PREFIX = b"TTRACE_CLI_PROMPT_DPAPI_V1\n"
ARCHIVE_DIR_ENV = "TTRACE_CLI_PROMPT_DEMO_DIR"


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _parse_prompt(raw: bytes) -> str:
    if not raw or len(raw) > MAX_EVENT_BYTES:
        raise ValueError("invalid event size")
    event = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    if not isinstance(event, dict) or event.get("hook_event_name") != "UserPromptSubmit":
        raise ValueError("invalid hook event")
    prompt = event.get("prompt")
    if not isinstance(prompt, str):
        raise ValueError("missing prompt text")
    return prompt


def _archive_root() -> Path:
    override = os.environ.get(ARCHIVE_DIR_ENV)
    if override:
        return Path(override)
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise OSError("LOCALAPPDATA is unavailable")
    return Path(local) / "TranspectTrace" / "cli-prompt-demo"


def _dpapi_encrypt(plaintext: bytes) -> bytes:
    """Windows user-scope DPAPI; no plaintext or key is written to disk."""
    if sys.platform != "win32":
        raise OSError("Windows DPAPI is required")

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    data = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    source = DataBlob(len(plaintext), ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte)))
    protected = DataBlob()
    crypt32 = ctypes.WinDLL("Crypt32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [ctypes.POINTER(DataBlob), wintypes.LPCWSTR,
                                        ctypes.POINTER(DataBlob), ctypes.c_void_p,
                                        ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(DataBlob)]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    # CRYPTPROTECT_UI_FORBIDDEN prevents a modal dialog inside the hook.
    if not crypt32.CryptProtectData(ctypes.byref(source), None, None, None,
                                    None, 0x1, ctypes.byref(protected)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(protected.pbData, protected.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(protected.pbData, ctypes.c_void_p))


def _store_prompt(root: Path, prompt_bytes: bytes) -> str:
    root.mkdir(parents=True, exist_ok=True)
    archive_id = uuid.uuid4().hex
    cipher = _dpapi_encrypt(prompt_bytes)
    destination = root / f"{archive_id}.dpapi"
    temporary = root / f".{archive_id}.tmp"
    try:
        with temporary.open("xb") as stream:
            stream.write(ARCHIVE_PREFIX)
            stream.write(cipher)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return archive_id


def _write_audit(root: Path, *, archive_id: str, prompt_bytes: bytes,
                 action: str, findings: list[object]) -> None:
    # Evidence strings can contain prompt fragments. Persist only rule metadata.
    rules = sorted({f"{finding.category}:{finding.layer}" for finding in findings})
    record = {
        "schema": "transpect.cli-prompt-audit/1.0",
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "archive_id": archive_id,
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "prompt_bytes": len(prompt_bytes),
        "action": action,
        "rules": rules,
    }
    with (root / "audit.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def inspect_event(raw: bytes) -> dict[str, str] | None:
    prompt = _parse_prompt(raw)
    prompt_bytes = prompt.encode("utf-8")
    root = _archive_root()
    # Capture and persist before returning an ALLOW decision.
    archive_id = _store_prompt(root, prompt_bytes)
    report = ContentDLPEngine().inspect(prompt, source="user_prompt")
    action = report.action if report.action in {"ALLOW", "REVIEW", "BLOCK"} else "BLOCK"
    _write_audit(root, archive_id=archive_id, prompt_bytes=prompt_bytes,
                 action=action, findings=report.findings)
    if action == "ALLOW":
        return None
    if action == "REVIEW":
        return {"decision": "block", "reason": "User prompt requires local content review"}
    return {"decision": "block", "reason": "Sensitive content detected in user prompt"}


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_EVENT_BYTES + 1)
        result = inspect_event(raw)
    except Exception:
        # The hook itself returns an explicit block if it executes but cannot
        # validate, encrypt, save, audit, or inspect the submitted text.
        result = {"decision": "block", "reason": "Local prompt inspection failed"}
    if result is not None:
        sys.stdout.buffer.write((json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
