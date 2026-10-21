"""Build the opt-in descendant connection gate (does not rebuild Guard)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT, enter_repository
from transpect_trace.behavior.native_egress import host_fingerprint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/egress")
    args = parser.parse_args()
    output = args.output.resolve()
    enter_repository()
    output.mkdir(parents=True, exist_ok=True)
    vendor = ROOT / "native/guard/third_party/minhook"
    expected = json.loads((vendor / "source-manifest.json").read_text())["sha256"]
    for name, digest in expected.items():
        if hashlib.sha256((vendor / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"Vendor checksum mismatch: minhook/{name}")
    sources = [ROOT / "native/egress/egress.c", *(vendor / "src" / name for name in ("buffer.c", "hook.c", "trampoline.c", "hde/hde64.c"))]
    destination = output / "ttrace-egress.dll"
    subprocess.run([sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2", "-shared", *map(str, sources), "-lws2_32", "-o", str(destination)], check=True)
    fixture = output / "egress-fixture.exe"
    subprocess.run([sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2", str(ROOT / "native/egress/fixture.c"), "-lws2_32", "-municode", "-o", str(fixture)], check=True)
    boundary = output / "egress-boundary-fixture.exe"
    subprocess.run([sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2", str(ROOT / "native/egress/boundary_fixture.c"), "-lws2_32", "-municode", "-o", str(boundary)], check=True)
    inputs = [*ROOT.glob("native/egress/*.[ch]"), *sources[1:], vendor / "source-manifest.json"]
    manifest = {"schema": "transpect.native.egress.build/1.0", "toolchain": "ziglang 0.13.0", "architecture": "x86_64", "artifacts_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (destination, fixture, boundary)}, "sources_sha256": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}}
    manifest["host_fingerprint"] = host_fingerprint()
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(destination)


if __name__ == "__main__":
    main()
