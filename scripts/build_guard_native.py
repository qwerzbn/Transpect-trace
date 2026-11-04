"""Build the standalone Windows x64 DLL using a portable Zig C toolchain."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from _build_support import ROOT, enter_repository


def pin_defines(adapter_path: Path) -> list[str]:
    """Translate a validated adapter into compiler -D pin overrides.

    Refuses to build from an unvalidated candidate: a candidate adapter still has
    placeholder addresses and unconfirmed error-path layouts, so a DLL built from
    it would hook the wrong code. Re-pinning is adapter data + this rebuild once
    the adapter is promoted to validated by the dynamic Frida fixture.
    """
    adapter = json.loads(adapter_path.read_text(encoding="utf-8"))
    if adapter.get("schema") == "transpect.guard.desktop-adapter/1.0":
        from transpect_trace.guard.desktop import validate_desktop_adapter
        try:
            validate_desktop_adapter(adapter)
        except ValueError as error:
            raise SystemExit(f"Desktop adapter is not dynamically validated: {error}") from error
    if adapter.get("status") != "validated":
        raise SystemExit(f"Adapter {adapter_path} is not validated (status={adapter.get('status')!r}); "
                         f"promote it before building a DLL. "
                         f"Outstanding: {adapter.get('validation_required', ['see adapter'])}")
    hooks = {h["layer"]: h for h in adapter["hooks"]}
    http = hooks["http_encoded_body_preparation"]
    wss = hooks["wss_request_serialization"]
    drop = http.get("owned_headers_drop_rva")
    if not isinstance(drop, str) or not drop.startswith("0x"):
        raise SystemExit("Adapter is missing a validated owned_headers_drop_rva")
    def prefix_define(hook: dict, macro: str) -> str:
        value = hook.get("entry_prefix_hex")
        if (not isinstance(value, str) or len(value) < 16 or len(value) > 64
                or len(value) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in value)):
            raise SystemExit(f"Adapter has no validated {macro} entry prefix")
        return f"-D{macro}={{" + ",".join(f"0x{byte:02x}" for byte in bytes.fromhex(value)) + "}"
    return [f"-DHTTP_RVA={http['rva']}", f"-DWSS_RVA={wss['rva']}", f"-DDROP_HEADERS_RVA={drop}",
            prefix_define(http, "HTTP_ENTRY_PREFIX_BYTES"), prefix_define(wss, "WSS_ENTRY_PREFIX_BYTES"),
            f'-DTTRACE_EXPECTED_HASH="{adapter["binary_sha256"]}"']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/guard")
    parser.add_argument("--adapter", type=Path, default=None,
                        help="Validated adapter JSON to pin the DLL to; defaults to the compiled-in 0.162 pin.")
    args = parser.parse_args()
    args.output = args.output.resolve()
    enter_repository()
    args.output.mkdir(parents=True, exist_ok=True)
    root = Path("native/guard")
    pin = pin_defines(args.adapter.resolve()) if args.adapter else []
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
               "-DJSMN_PARENT_LINKS", *pin, *map(str, sources), "-lbcrypt", "-o", str(destination)]
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
        "adapter_sha256": hashlib.sha256(args.adapter.resolve().read_bytes()).hexdigest() if args.adapter else None,
        "target_binary_sha256": json.loads(args.adapter.resolve().read_text(encoding="utf-8"))["binary_sha256"] if args.adapter else None,
        "sources_sha256":{str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in root.glob("*.c")}},indent=2)+"\n",encoding="utf-8")


if __name__ == "__main__":
    main()
