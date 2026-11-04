"""Build the isolated-VM desktop WFP utility without touching live filters."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT, enter_repository


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/desktop-wfp")
    args = parser.parse_args()
    enter_repository()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = ROOT / "native/behavior/wfp_desktop.c"
    executable = output / "wfp_desktop.exe"
    subprocess.run([
        sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2",
        str(source), "-lfwpuclnt", "-ladvapi32", "-lbcrypt", "-lrpcrt4",
        "-lws2_32", "-municode", "-o", str(executable),
    ], check=True)
    manifest = {
        "schema": "transpect.desktop-wfp-build/1.0",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "real_wfp_enforcement_verified": False,
    }
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(executable)


if __name__ == "__main__":
    main()
