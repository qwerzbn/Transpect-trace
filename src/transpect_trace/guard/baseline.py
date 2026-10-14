from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import subprocess

from . import BINARY_SHA256, VERSION


def inspect_binary(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        prefix = handle.read(4096)
        digest.update(prefix)
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    machine = None
    if prefix.startswith(b"MZ") and len(prefix) >= 64:
        offset = struct.unpack_from("<I", prefix, 60)[0]
        if offset + 6 <= len(prefix) and prefix[offset:offset + 4] == b"PE\0\0":
            machine = struct.unpack_from("<H", prefix, offset + 4)[0]
    sha = digest.hexdigest()
    found = "not_executed_baseline_mismatch"
    if machine == 0x8664 and sha == BINARY_SHA256:
        version = subprocess.run([str(path), "--version"], stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, timeout=15, check=False)
        found = version.stdout.strip()
    return {"path": str(path.resolve()), "version": found, "sha256": sha,
            "architecture": "windows-x64" if machine == 0x8664 else "unsupported",
            "supported": machine == 0x8664 and sha == BINARY_SHA256 and found == VERSION,
            "disk_mutation": False, "instrumentation": "runtime",
            "wss_streaming_coverage": "not_claimed"}
