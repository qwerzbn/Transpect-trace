from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterable

import zstandard

from .models import ContentRef, Manifest, TraceEvent


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class TraceBundle:
    """Crash-tolerant writer for a single trace bundle.

    Collectors write separate raw files. Normalized events are produced only
    after collection has stopped, which makes global ingest ordering stable.
    """

    DIRECTORIES = (
        "raw/client",
        "raw/gateway",
        "raw/otel",
        "raw/system",
        "raw/frida",
        "blobs/sha256",
        "normalized",
        "analytics",
        "quality",
        "logs",
        "input",
        "workspace",
    )

    def __init__(self, root: Path | str, *, initialize: bool = True) -> None:
        self.root = Path(root).resolve()
        self._locks: dict[Path, threading.Lock] = {}
        self.root.mkdir(parents=True, exist_ok=True)
        if initialize:
            for directory in self.DIRECTORIES:
                (self.root / directory).mkdir(parents=True, exist_ok=True)

    def _safe_path(self, relative: Path | str) -> Path:
        path = (self.root / relative).resolve()
        if path != self.root and self.root not in path.parents:
            raise ValueError(f"path escapes trace bundle: {relative}")
        return path

    def append_jsonl(self, relative: Path | str, value: Any) -> None:
        path = self._safe_path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        lock = self._locks.setdefault(path, threading.Lock())
        line = (canonical_json(value) + "\n").encode("utf-8")
        with lock, path.open("ab", buffering=0) as handle:
            handle.write(line)
            os.fsync(handle.fileno())

    def replace_jsonl(self, relative: Path | str, values: Iterable[Any]) -> None:
        payload = "".join(canonical_json(value) + "\n" for value in values).encode("utf-8")
        atomic_write(self._safe_path(relative), payload)

    def put_blob(
        self,
        data: bytes,
        *,
        media_type: str | None = None,
        encoding: str | None = None,
    ) -> ContentRef:
        digest = sha256_bytes(data)
        relative = Path("blobs") / "sha256" / digest[:2] / f"{digest}.zst"
        destination = self._safe_path(relative)
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            compressed = zstandard.ZstdCompressor(level=6).compress(data)
            try:
                atomic_write(destination, compressed)
            except OSError:
                if not destination.exists():
                    raise
        return ContentRef(
            bytes=len(data),
            sha256=f"sha256:{digest}",
            blob_ref=relative.as_posix(),
            media_type=media_type,
            encoding=encoding,
            payload_status="full",
        )

    def read_blob(self, reference: ContentRef | dict[str, Any]) -> bytes:
        ref = reference if isinstance(reference, ContentRef) else ContentRef.model_validate(reference)
        if not ref.blob_ref:
            raise ValueError("content has no blob_ref")
        compressed = self._safe_path(ref.blob_ref).read_bytes()
        data = zstandard.ZstdDecompressor().decompress(compressed)
        if ref.sha256 and f"sha256:{sha256_bytes(data)}" != ref.sha256:
            raise ValueError(f"blob digest mismatch: {ref.blob_ref}")
        if len(data) != ref.bytes:
            raise ValueError(f"blob length mismatch: {ref.blob_ref}")
        return data

    def write_manifest(self, manifest: Manifest) -> None:
        payload = json.dumps(manifest.model_dump(mode="json", by_alias=True), ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        atomic_write(self.root / "manifest.json", payload)

    def write_events(self, events: Iterable[TraceEvent]) -> None:
        self.replace_jsonl(
            "normalized/events.jsonl",
            (event.model_dump(mode="json", by_alias=True) for event in events),
        )

    def write_checksums(self) -> None:
        rows: list[str] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.name == "checksums.sha256":
                continue
            relative = path.relative_to(self.root).as_posix()
            rows.append(f"{sha256_bytes(path.read_bytes())}  {relative}")
        atomic_write(self.root / "checksums.sha256", ("\n".join(rows) + "\n").encode("utf-8"))
