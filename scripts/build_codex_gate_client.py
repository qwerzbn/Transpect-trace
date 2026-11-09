"""Build the native Codex hook client that forwards events to the gate service."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT, enter_repository

SOURCE = ROOT / "native/protect/codex_gate_client.c"


def build(output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    executable = output / "codex_gate_client.exe"
    subprocess.run([
        sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2",
        "-municode", str(SOURCE), "-o", str(executable),
    ], check=True)
    manifest = {
        "schema": "transpect.codex-gate-client-build/1.0",
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
    }
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                                encoding="utf-8")
    return executable


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/codex-gate-client")
    args = parser.parse_args()
    enter_repository()
    print(build(args.output.resolve()))


if __name__ == "__main__":
    main()
