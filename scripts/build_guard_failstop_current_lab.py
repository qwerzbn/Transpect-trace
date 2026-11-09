"""Build a lab-only 0.167 Native Guard that terminates on every denied model request.

The current HTTP/WSS capture points have isolated synthetic capture and full-body
archive/readback evidence. This build preflight does not itself validate denial;
the integrated DLL lab reports that result separately. It does not create or
promote a desktop adapter, inject the DLL, or validate live desktop coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT, enter_repository
from check_collection_portability import PEImage
from transpect_trace.protect.archive import EncryptedRequestArchive


BACKEND_SHA256 = "40ecc3d8b6899afd8f935a8cccb7d53ba41ffd7c199f679e186d30ddd0d0bf39"
BACKEND_VERSION = "codex-cli 0.167.0-alpha.3.2"
HTTP_RVA = 0x0AB2D670
WSS_RVA = 0x0400C4D0
HTTP_PREFIX = bytes.fromhex("5541574156415541545657534881ec28")
WSS_PREFIX = bytes.fromhex("5541574156415541545657534881ecd8")
EVIDENCE = {
    "http": ROOT / "runs/scratch/adapt-26.1103/current-capture-http-full-lab.json",
    "wss": ROOT / "runs/scratch/adapt-26.1103/current-capture-wss-full-lab.json",
}
PORTABILITY = ROOT / "runs/scratch/adapt-26.1103/portability.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _fail(message: str) -> None:
    raise SystemExit(f"Lab-only fail-stop build refused: {message}")


def _default_backend() -> Path:
    try:
        builds = json.loads(PORTABILITY.read_text(encoding="utf-8"))["builds"]
        matches = [Path(build["path"]) for build in builds.values()
                   if build.get("sha256", "").lower() == BACKEND_SHA256]
    except (OSError, ValueError, KeyError, TypeError) as error:
        _fail(f"cannot read current backend path from {PORTABILITY}: {error}")
    if len(matches) != 1:
        _fail("portability report must name exactly one current pinned backend")
    return matches[0]


def _check_backend(path: Path) -> None:
    if not path.is_file():
        _fail(f"backend missing: {path}")
    try:
        with PEImage(path) as image:
            if image.sha256().lower() != BACKEND_SHA256:
                _fail("backend SHA-256 differs from the pinned 0.167 build")
            if image.read(HTTP_RVA, len(HTTP_PREFIX)) != HTTP_PREFIX:
                _fail("HTTP candidate entry prefix differs from the pinned 0.167 build")
            if image.read(WSS_RVA, len(WSS_PREFIX)) != WSS_PREFIX:
                _fail("WSS candidate entry prefix differs from the pinned 0.167 build")
    except (OSError, ValueError, KeyError) as error:
        _fail(f"cannot inspect backend PE image: {error}")


def _check_capture(path: Path, transport: str) -> dict:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        _fail(f"cannot read {transport} capture evidence {path}: {error}")
    expected_kind = f"synthetic_{transport}_hit"
    exact_key = f"synthetic_{transport}_origin_exact"
    if (report.get("schema") != "transpect.desktop-current-capture-lab/1.0"
            or report.get("backend_sha256", "").lower() != BACKEND_SHA256
            or report.get("backend_version") != BACKEND_VERSION
            or report.get("synthetic_only") is not True
            or report.get("local_origin_only") is not True
            or report.get("codex_command_hooks_present") is not False
            or report.get("frida_enabled") is not True
            or report.get("trace_origin_exact") is not True
            or report.get(exact_key) is not True
            or report.get("full_body_collection_enabled") is not True
            or report.get("synthetic_collection_validated") is not True
            or report.get("collection_error") is not None
            or report.get("native_capture_validated") is not False
            or report.get("errors") != []):
        _fail(f"{transport} report lacks pinned synthetic collection evidence")
    if report.get("transport") != transport:
        _fail(f"{transport} report has the wrong transport")
    origin = report.get("origin")
    if not isinstance(origin, dict) or origin.get("requests") != 1 or origin.get("marker_in_body") is not True:
        _fail(f"{transport} report lacks one marked target origin request")
    expected_path = "responses" if transport == "http" else "websocket"
    if origin.get("paths") != [expected_path]:
        _fail(f"{transport} report has an unexpected target origin path")
    body_bytes = origin.get("body_bytes")
    body_hashes = origin.get("body_sha256")
    if (not isinstance(body_bytes, int) or body_bytes <= 0
            or not isinstance(body_hashes, list) or len(body_hashes) != 1
            or not isinstance(body_hashes[0], str) or len(body_hashes[0]) != 64):
        _fail(f"{transport} report lacks a single target body length and SHA-256")
    body_hash = body_hashes[0].lower()
    trace = [item["compact_json"] for item in report.get("trace_files", [])
             if isinstance(item, dict) and isinstance(item.get("compact_json"), dict)]
    if len(trace) != 1 or trace[0].get("bytes") != body_bytes or trace[0].get("sha256", "").lower() != body_hash:
        _fail(f"{transport} compact trace does not match the local origin")
    hits = [event for event in report.get("native_events", [])
            if isinstance(event, dict) and event.get("kind") == expected_kind]
    if not hits or any(hit.get("bytes") != body_bytes or hit.get("sha256", "").lower() != body_hash
                       or not isinstance(hit.get("marker_offset"), int)
                       or not 0 <= hit["marker_offset"] < body_bytes for hit in hits):
        _fail(f"{transport} Native candidate capture does not match trace and origin")
    collection = report.get("collection")
    if (not isinstance(collection, dict)
            or collection.get("observation_only") is not True
            or collection.get("readback_exact") is not True
            or collection.get("body_bytes") != body_bytes
            or collection.get("body_sha256", "").lower() != body_hash
            or not isinstance(collection.get("archive_record_id"), str)
            or not collection["archive_record_id"]
            or collection.get("recorded_decision_point") != "none"
            or collection.get("recorded_route_decision") != "not_enforceable"
            or collection.get("recorded_released_by_route") is not None):
        _fail(f"{transport} full-body archive/readback is not exact and observation-only")
    evidence_dir = path.parent / f"{path.stem}-evidence"
    archive_dir = evidence_dir / "archive"
    collection_file = evidence_dir / "collection.jsonl"
    record_id = collection["archive_record_id"]
    if (not isinstance(collection.get("archive_directory"), str)
            or not isinstance(collection.get("collection_file"), str)
            or Path(collection["archive_directory"]).resolve() != archive_dir.resolve()
            or Path(collection["collection_file"]).resolve() != collection_file.resolve()
            or not archive_dir.is_dir() or archive_dir.is_symlink()
            or not collection_file.is_file() or collection_file.is_symlink()
            or not (archive_dir / "archive-key.dpapi").is_file()
            or (archive_dir / "archive-key.dpapi").is_symlink()
            or not (archive_dir / f"{record_id}.enc").is_file()
            or (archive_dir / f"{record_id}.enc").is_symlink()):
        _fail(f"{transport} archive or collection evidence is missing or redirected")
    try:
        archive = EncryptedRequestArchive(archive_dir)
        receipt, archived_body = archive.read(record_id)
        archive_exact = (receipt.kind == "model_request"
                         and receipt.body_bytes == body_bytes
                         and receipt.body_sha256.lower() == body_hash
                         and len(archived_body) == body_bytes
                         and hashlib.sha256(archived_body).hexdigest() == body_hash)
    except Exception as error:
        _fail(f"{transport} DPAPI archive readback failed ({type(error).__name__})")
    if not archive_exact:
        _fail(f"{transport} decrypted archive body differs from trace and origin")
    try:
        if collection_file.stat().st_size > 1024 * 1024:
            _fail(f"{transport} collection evidence is unexpectedly large")
        records = [json.loads(line) for line in collection_file.read_text(encoding="utf-8").splitlines()
                   if line.strip()]
    except (OSError, ValueError) as error:
        _fail(f"{transport} collection evidence cannot be read ({type(error).__name__})")
    envelopes = [row for row in records if isinstance(row, dict)
                 and row.get("category") == "request_envelope"
                 and row.get("archive_record_id") == record_id]
    if (len(envelopes) != 1 or envelopes[0].get("schema") != "transpect.codex-collection/1.0"
            or envelopes[0].get("archive_kind") != "model_request"
            or envelopes[0].get("protocol") != transport
            or envelopes[0].get("route") != "native"
            or envelopes[0].get("gate_mode") != "observe"
            or envelopes[0].get("content_bytes") != body_bytes
            or envelopes[0].get("request_sha256", "").lower() != body_hash
            or envelopes[0].get("decision_point") != "none"
            or envelopes[0].get("route_decision") != "not_enforceable"
            or envelopes[0].get("released_by_route") is not None):
        _fail(f"{transport} collection envelope does not prove observation-only full-body capture")
    return {"report": str(path.resolve()), "report_sha256": _sha256(path),
            "target_body_bytes": body_bytes, "target_body_sha256": body_hash,
            "native_target_hits": len(hits), "full_body_readback_exact": True,
            "observation_only": True, "decrypted_archive_verified": True,
            "collection_envelope_verified": True}


def _prefix_define(name: str, prefix: bytes) -> str:
    return f"-D{name}={{" + ",".join(f"0x{byte:02x}" for byte in prefix) + "}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, help="Exact current codex.exe; defaults to the portability report path")
    parser.add_argument("--http-evidence", type=Path, default=EVIDENCE["http"])
    parser.add_argument("--wss-evidence", type=Path, default=EVIDENCE["wss"])
    parser.add_argument("--output", type=Path, default=ROOT / "build/guard-failstop-current-lab")
    args = parser.parse_args()
    enter_repository()
    backend = args.backend.resolve() if args.backend else _default_backend()
    output = args.output.resolve()
    if output == (ROOT / "build/guard").resolve():
        _fail("output must not overwrite the existing graceful-ABI guard build")
    _check_backend(backend)
    captures = {"http": _check_capture(args.http_evidence.resolve(), "http"),
                "wss": _check_capture(args.wss_evidence.resolve(), "wss")}

    source_root = ROOT / "native/guard"
    sources = [source_root / "guard.c", *(source_root / "third_party/minhook/src" / name
                for name in ("buffer.c", "hook.c", "trampoline.c", "hde/hde64.c"))]
    for vendor in ("minhook", "jsmn"):
        folder = source_root / "third_party" / vendor
        manifest = json.loads((folder / "source-manifest.json").read_text(encoding="utf-8"))
        for name, expected_hash in manifest["sha256"].items():
            if _sha256(folder / name) != expected_hash:
                _fail(f"vendor checksum mismatch: {vendor}/{name}")

    output.mkdir(parents=True, exist_ok=True)
    destination = output / "ttrace-guard-failstop-current-lab.dll"
    defines = ["-DJSMN_PARENT_LINKS", "-DTTRACE_FAIL_STOP_DENY=1",
               f"-DHTTP_RVA=0x{HTTP_RVA:x}", f"-DWSS_RVA=0x{WSS_RVA:x}",
               _prefix_define("HTTP_ENTRY_PREFIX_BYTES", HTTP_PREFIX),
               _prefix_define("WSS_ENTRY_PREFIX_BYTES", WSS_PREFIX),
               "-DWSS_SUCCESS_TAG=0x20", f'-DTTRACE_EXPECTED_HASH="{BACKEND_SHA256}"']
    command = [sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2",
               "-shared", *defines, *map(str, sources), "-lbcrypt", "-o", str(destination)]
    subprocess.run(command, check=True, cwd=ROOT)
    build_manifest = {
        "schema": "transpect.guard.failstop-current-lab-build/1.0",
        "lab_only": True,
        "status": "synthetic_collection_only_not_desktop_validated",
        "deny_behavior": "terminate_process_exit_76",
        "desktop_adapter_created": False,
        "backend": {"path": str(backend), "version": BACKEND_VERSION, "sha256": BACKEND_SHA256},
        "pins": {"http_rva": f"0x{HTTP_RVA:x}", "http_entry_prefix_hex": HTTP_PREFIX.hex(),
                 "wss_rva": f"0x{WSS_RVA:x}", "wss_entry_prefix_hex": WSS_PREFIX.hex(),
                 "wss_success_tag": "0x20"},
        "capture_evidence": captures,
        "artifact": {"path": str(destination), "sha256": _sha256(destination)},
        "sources_sha256": {str(path.relative_to(ROOT)): _sha256(path) for path in sources},
    }
    (output / "build-manifest.json").write_text(json.dumps(build_manifest, indent=2) + "\n", encoding="utf-8")
    print(destination)
    print("LAB ONLY: build preflight passed; check the integrated lab report for deny evidence; no live desktop validation")


if __name__ == "__main__":
    main()
