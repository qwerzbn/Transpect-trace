from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import subprocess

from . import BINARY_SHA256, VERSION


def resolve_codex_binary(path: Path) -> Path:
    """Resolve an npm launcher shim to the real Codex PE.

    `npm install -g @openai/codex` puts a `codex.cmd`/`codex` Node shim on PATH,
    not the native executable. `shutil.which("codex")` returns that shim, which is
    not a PE and fails the baseline. Follow the documented npm package layout to
    the platform binary; return the input unchanged when it is already a PE.
    """
    path = Path(path)
    if path.suffix.lower() == ".exe" or not path.is_file():
        return path
    try:
        if path.read_bytes()[:2] == b"MZ":
            return path
    except OSError:
        return path
    # Shim on PATH -> <prefix>/node_modules/@openai/codex-win32-x64/**/bin/codex.exe
    for base in (path.parent, path.parent / "node_modules" / "@openai" / "codex"):
        root = base / "node_modules" / "@openai" / "codex-win32-x64"
        matches = sorted(root.glob("vendor/*/bin/codex.exe"))
        if matches:
            return matches[0]
    return path


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
