"""Build a test-only 0.167 graceful Guard with controller-owned lease teardown.

This candidate fails open when its controller's mutex is released or abandoned.
It is not a production adapter and must only be used in isolated lab processes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT, enter_repository
from build_guard_graceful_current_lab import (
    BACKEND_SHA256, BACKEND_VERSION, DROP_HEADERS_PREFIX, DROP_HEADERS_RVA,
    HTTP_PREFIX, HTTP_RVA, WSS_PREFIX, WSS_RVA, _check_backend,
    _check_capture, _default_backend, _fail, _prefix_define,
)


SCHEMA = "transpect.guard.graceful-lease-current-lab-build/1.0"


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path)
    parser.add_argument("--http-evidence", type=Path,
                        default=ROOT / "runs/scratch/adapt-26.1103/current-capture-http-full-lab.json")
    parser.add_argument("--wss-evidence", type=Path,
                        default=ROOT / "runs/scratch/adapt-26.1103/current-capture-wss-full-lab.json")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "build/guard-graceful-lease-current-lab")
    args = parser.parse_args()
    enter_repository()
    backend = args.backend.resolve() if args.backend else _default_backend()
    output = args.output.resolve()
    if output in ((ROOT / "build/guard").resolve(),
                  (ROOT / "build/guard-graceful-current-lab").resolve(),
                  (ROOT / "build/guard-failstop-current-lab").resolve()):
        _fail("lease output must not overwrite an existing guard build")
    _check_backend(backend)
    captures = {
        "http": _check_capture(args.http_evidence.resolve(), "http"),
        "wss": _check_capture(args.wss_evidence.resolve(), "wss"),
    }
    from check_collection_portability import PEImage
    image = PEImage(backend)
    pins = {"http": (HTTP_RVA, HTTP_PREFIX), "wss": (WSS_RVA, WSS_PREFIX),
            "drop_headers": (DROP_HEADERS_RVA, DROP_HEADERS_PREFIX)}
    for name, (rva, prefix) in pins.items():
        if image.read(rva, len(prefix)) != prefix:
            _fail(f"{name} entry prefix differs from pinned lab candidate")

    source_root = ROOT / "native/guard"
    sources = [source_root / "guard.c", *(source_root / "third_party/minhook/src" / name
                for name in ("buffer.c", "hook.c", "trampoline.c", "hde/hde64.c"))]
    for vendor in ("minhook", "jsmn"):
        folder = source_root / "third_party" / vendor
        manifest = json.loads((folder / "source-manifest.json").read_text(encoding="utf-8"))
        for name, expected in manifest["sha256"].items():
            if _sha256(folder / name) != expected:
                _fail(f"vendor checksum mismatch: {vendor}/{name}")

    output.mkdir(parents=True, exist_ok=True)
    destination = output / "ttrace-guard-graceful-lease-current-lab.dll"
    defines = ["-DJSMN_PARENT_LINKS", "-DTTRACE_FAIL_STOP_DENY=0",
               "-DTTRACE_GRACEFUL_LEASE=1", "-DHTTP_EMPTY_ERROR_STRING=1",
               "-DHTTP_DENIED_TAG=3", "-DWSS_SUCCESS_TAG=0x20",
               "-DWSS_DENIED_TAG=0x0d", f"-DHTTP_RVA=0x{HTTP_RVA:x}",
               f"-DWSS_RVA=0x{WSS_RVA:x}", f"-DDROP_HEADERS_RVA=0x{DROP_HEADERS_RVA:x}",
               _prefix_define("HTTP_ENTRY_PREFIX_BYTES", HTTP_PREFIX),
               _prefix_define("WSS_ENTRY_PREFIX_BYTES", WSS_PREFIX),
               _prefix_define("DROP_HEADERS_PREFIX_BYTES", DROP_HEADERS_PREFIX),
               f'-DTTRACE_EXPECTED_HASH="{BACKEND_SHA256}"']
    command = [sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu",
               "-O2", "-shared", *defines, *map(str, sources), "-lbcrypt", "-o",
               str(destination)]
    subprocess.run(command, check=True, cwd=ROOT)
    manifest = {
        "schema": SCHEMA, "lab_only": True,
        "status": "unvalidated_test_only_graceful_lease_candidate",
        "deny_behavior": "return_rust_error_candidate",
        "controller_loss_behavior": "bypass_and_disable_hooks",
        "desktop_adapter_created": False,
        "backend": {"path": str(backend), "version": BACKEND_VERSION,
                    "sha256": BACKEND_SHA256},
        "pins": {name: {"rva": f"0x{rva:x}", "prefix_hex": prefix.hex()}
                 for name, (rva, prefix) in pins.items()},
        "abi": {"http_denied_tag": 3, "http_empty_string_words": [0, 1, 0],
                "wss_success_tag": 32, "wss_denied_tag": 13,
                "wss_owned_buffer_reused": True},
        "lease": {"mutex": "Local\\ttrace-guard-lease-<pid>-<creation_filetime>",
                  "disabled_event": "Local\\ttrace-guard-disabled-<pid>-<creation_filetime>",
                  "owner": "controller_main_thread", "dll_stays_mapped": True},
        "capture_evidence": captures,
        "artifact": {"path": str(destination), "sha256": _sha256(destination)},
        "sources_sha256": {str(path.relative_to(ROOT)): _sha256(path) for path in sources},
    }
    (output / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(destination)
    print("LAB ONLY: no desktop activation or production coverage is attested")


if __name__ == "__main__":
    main()
