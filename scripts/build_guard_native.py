"""Build the standalone Windows x64 DLL using a portable Zig C toolchain."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from _build_support import ROOT, enter_repository


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/guard")
    args = parser.parse_args()
    args.output = args.output.resolve()
    enter_repository()
    args.output.mkdir(parents=True, exist_ok=True)
    root = Path("native/guard")
    for vendor in ("minhook", "jsmn"):
        folder = root / "third_party" / vendor
        manifest = json.loads((folder / "source-manifest.json").read_text())
        for name, expected in manifest["sha256"].items():
            if hashlib.sha256((folder / name).read_bytes()).hexdigest() != expected:
                raise SystemExit(f"Vendor checksum mismatch: {vendor}/{name}")
    sources = [root / "guard.c", *(root / "third_party/minhook/src" / n
               for n in ("buffer.c", "hook.c", "trampoline.c", "hde/hde64.c"))]
    destination = args.output / "ttrace-guard.dll"
    command = [sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2", "-shared",
               "-DJSMN_PARENT_LINKS", *map(str, sources), "-lbcrypt", "-o", str(destination)]
    subprocess.run(command, check=True)
    print(destination.resolve())
    for name,libraries in [("policy_fixture",["-ladvapi32"]),("etw",["-ladvapi32","-ltdh","-lole32"])]:
        destination=args.output/(name+".exe")
        subprocess.run([sys.executable,"-m","ziglang","cc","-target","x86_64-windows-gnu","-O2",
                        "-DJSMN_PARENT_LINKS",str(root/(name+".c")),*libraries,"-o",str(destination)],check=True)
        print(destination.resolve())
    artifacts={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
               for p in args.output.iterdir() if p.suffix in {".dll",".exe"}}
    (args.output/"build-manifest.json").write_text(json.dumps({
        "toolchain":"ziglang 0.13.0","artifacts_sha256":artifacts,
        "sources_sha256":{str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in root.glob("*.c")}},indent=2)+"\n",encoding="utf-8")


if __name__ == "__main__":
    main()
