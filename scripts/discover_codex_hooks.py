"""Reproduce fixed-build candidate discovery; static hits are NOT capabilities.

This is the first step of re-pinning the Guard to a new Codex CLI build. It reads
a target codex.exe (resolving an npm launcher shim), locates the send-path
functions by the same version-stable string anchors and PE unwind ranges the
original pin used, and writes a *candidate* adapter. A candidate is never a
protection claim: the error-path memory layouts and the headers-drop thunk still
require a dynamic Frida fixture against the live
binary before the adapter may be marked validated and a DLL built from it.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct

from transpect_trace.guard import BINARY_SHA256, VERSION
from transpect_trace.guard.baseline import resolve_codex_binary

# Layer -> version-stable literal used to anchor the owning function. These phrases
# are compiler-embedded diagnostics that have survived across the pinned builds.
ANCHORS = {
    "request_construction": "responses_websocket.stream_request",
    "serialization": "failed to encode websocket request",
    "http_body_preparation": "Compressed request body with zstd",
    "http_trace_body": "<raw body:",
    "received_event_counterexample": "responses websocket timing",
}


def _sections(data: bytes) -> list[tuple[str, int, int, int, int]]:
    pe = struct.unpack_from("<I", data, 60)[0]
    opt = pe + 24
    count = struct.unpack_from("<H", data, pe + 6)[0]
    option_bytes = struct.unpack_from("<H", data, pe + 20)[0]
    sections = []
    for i in range(count):
        offset = opt + option_bytes + i * 40
        virtual_size, rva, raw_bytes, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        sections.append((data[offset:offset + 8].rstrip(b"\0").decode(), rva, virtual_size, raw_bytes, raw_offset))
    return sections


def discover(binary: Path) -> dict:
    data = binary.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    sections = _sections(data)
    text = next(s for s in sections if s[0] == ".text")
    ro = next(s for s in sections if s[0] == ".rdata")
    unwind = next(s for s in sections if s[0] == ".pdata")
    functions = list(struct.iter_unpack("<III", data[unwind[4]:unwind[4] + unwind[2] // 12 * 12]))
    starts = [x[0] for x in functions]

    anchors = []
    missing = []
    for layer, phrase in ANCHORS.items():
        position = data.find(phrase.encode())
        if position < 0:
            missing.append(layer)
        else:
            anchors.append((ro[1] + position - ro[4], layer, phrase))

    # One function per layer: the smallest distinct unwind range whose body makes a
    # RIP-relative LEA to the anchor string. Compiler format programs can point just
    # before the literal, so accept a small negative delta.
    by_layer: dict[str, dict] = {}
    pattern = re.compile(rb"[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....", re.DOTALL)
    for match in pattern.finditer(data, text[4], text[4] + text[3]):
        instruction = text[1] + match.start() - text[4]
        target = instruction + 7 + struct.unpack_from("<i", data, match.start() + 3)[0]
        for anchor, layer, phrase in anchors:
            if anchor - 32 <= target < anchor + len(phrase):
                index = bisect.bisect_right(starts, instruction) - 1
                if index < 0 or instruction >= functions[index][1]:
                    continue
                start, end = functions[index][:2]
                raw = text[4] + start - text[1]
                hit = {"layer": layer, "anchor": phrase, "xref_rva": hex(instruction),
                       "function_rva": hex(start), "function_end_rva": hex(end), "function_bytes": end - start,
                       "entry_prefix_hex": data[raw:raw + 16].hex(), "status": "static_candidate_only"}
                previous = by_layer.get(layer)
                if previous is None or hit["function_bytes"] < previous["function_bytes"]:
                    by_layer[layer] = hit
    return {"binary": str(binary.resolve()), "binary_sha256": sha,
            "matches_active_pin": sha == BINARY_SHA256, "active_pin_version": VERSION,
            "method": "RIP-relative LEA + PE unwind ranges",
            "candidates": list(by_layer.values()), "missing_anchors": missing,
            "pdb_required": False, "protection_verified": False,
            "low_layer": {"schannel": "requires_dynamic_validation", "winsock": "network_evidence_not_prompt"}}


def candidate_adapter(discovery: dict, version_label: str) -> dict:
    """Shape the static hits into the adapter schema, unvalidated."""
    http = next((c for c in discovery["candidates"] if c["layer"] == "http_body_preparation"), None)
    wss = next((c for c in discovery["candidates"] if c["layer"] == "serialization"), None)
    hooks = []
    if http:
        hooks.append({"layer": "http_encoded_body_preparation", "rva": http["function_rva"],
                      "entry_prefix_hex": http["entry_prefix_hex"], "scope": "EncodedJsonBody before compression",
                      "rejection": "existing Result error tag 3 with owned String",
                      "owned_headers_drop_rva": "needs_dynamic_validation"})
    if wss:
        hooks.append({"layer": "wss_request_serialization", "rva": wss["function_rva"],
                      "entry_prefix_hex": wss["entry_prefix_hex"], "scope": "response.create serialized JSON",
                      "rejection": "existing ApiError::Stream(String), tag 0x0d"})
    return {"schema": "transpect.guard.adapter/1.0", "version": version_label,
            "architecture": "windows-x64", "binary_sha256": discovery["binary_sha256"],
            "disk_mutation": False, "instrumentation": "runtime-native",
            "decision_deadline_ms": 2000, "payload_limit_bytes": 16777216, "hooks": hooks,
            "supported_actions": ["block_request", "block_session", "terminate_process"],
            "default_action": "block_request", "modes": ["exec", "tui_no_daemon"],
            "destination_extraction": "not_verified", "wss_streaming_coverage": "not_claimed",
            "uncovered": ["raw/multipart uploads", "other WSS message types", "full WSS streaming",
                          "daemon/app-server", "child process network egress", "whole-system bypass prevention"],
            "status": "candidate_unvalidated",
            "validation_required": ["owned_headers_drop_rva (no string anchor; locate via Frida fixture)",
                                    "HTTP Result::Err(String) field layout at tag 3",
                                    "WSS ApiError::Stream(String) layout at tag 0x0d, result tag 0x1c",
                                    "dynamic argument/return-layout confirmation via a Frida fixture"],
            "production_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, default=shutil.which("codex"))
    parser.add_argument("--output", type=Path, default=Path("runs/guard-discovery/candidates.json"))
    parser.add_argument("--emit-adapter", type=Path, default=None,
                        help="Also write a candidate adapter JSON for a re-pin.")
    parser.add_argument("--version-label", default=None,
                        help="Human adapter version label, e.g. 'codex-cli 0.163.0'.")
    args = parser.parse_args()
    binary = resolve_codex_binary(Path(args.codex))
    result = discover(binary)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if args.emit_adapter:
        label = args.version_label or f"codex sha256:{result['binary_sha256'][:12]}"
        adapter = candidate_adapter(result, label)
        args.emit_adapter.parent.mkdir(parents=True, exist_ok=True)
        args.emit_adapter.write_text(json.dumps(adapter, indent=2) + "\n")
        print(f"\ncandidate adapter -> {args.emit_adapter.resolve()} (status: {adapter['status']})")


if __name__ == "__main__":
    main()
