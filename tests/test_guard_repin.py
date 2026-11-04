"""Re-pin tooling: shim resolution, static discovery, and the build gate.

These cover the maintainability fix for the fragile fixed-version Codex pin:
re-pinning is adapter data plus a gated rebuild, not a C-source edit.
"""
import json
from pathlib import Path
import sys

import pytest

from transpect_trace.guard.baseline import resolve_codex_binary

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_guard_native import pin_defines  # noqa: E402
from discover_codex_hooks import candidate_adapter  # noqa: E402


def test_shim_passthrough_for_real_pe(tmp_path):
    exe = tmp_path / "codex.exe"
    exe.write_bytes(b"MZ" + b"\0" * 64)
    assert resolve_codex_binary(exe) == exe


def test_shim_resolves_npm_layout_to_platform_binary(tmp_path):
    shim = tmp_path / "codex.cmd"
    shim.write_text("@echo off\nnode codex.js %*\n")
    real = (tmp_path / "node_modules/@openai/codex-win32-x64/vendor"
            / "x86_64-pc-windows-msvc/bin/codex.exe")
    real.parent.mkdir(parents=True)
    real.write_bytes(b"MZ" + b"\0" * 64)
    assert resolve_codex_binary(shim) == real


def test_build_refuses_unvalidated_candidate_adapter(tmp_path):
    discovery = {"binary_sha256": "a" * 64,
                 "candidates": [
                     {"layer": "http_body_preparation", "function_rva": "0x1000", "entry_prefix_hex": "90" * 16},
                     {"layer": "serialization", "function_rva": "0x2000", "entry_prefix_hex": "91" * 16}]}
    adapter = candidate_adapter(discovery, "codex-cli test")
    assert adapter["status"] == "candidate_unvalidated"
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(adapter))
    with pytest.raises(SystemExit):
        pin_defines(path)


def test_build_pins_come_from_validated_adapter(tmp_path):
    adapter = {"status": "validated", "binary_sha256": "d" * 64,
               "hooks": [
                   {"layer": "http_encoded_body_preparation", "rva": "0xaaaa", "owned_headers_drop_rva": "0xbbbb",
                    "entry_prefix_hex": "554157415641554154565753"},
                   {"layer": "wss_request_serialization", "rva": "0xcccc",
                    "entry_prefix_hex": "555657534883ec68"}]}
    path = tmp_path / "validated.json"
    path.write_text(json.dumps(adapter))
    defines = pin_defines(path)
    assert "-DHTTP_RVA=0xaaaa" in defines
    assert "-DWSS_RVA=0xcccc" in defines
    assert "-DDROP_HEADERS_RVA=0xbbbb" in defines
    assert "-DHTTP_ENTRY_PREFIX_BYTES={0x55,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x53}" in defines
    assert "-DWSS_ENTRY_PREFIX_BYTES={0x55,0x56,0x57,0x53,0x48,0x83,0xec,0x68}" in defines
    assert '-DTTRACE_EXPECTED_HASH="' + "d" * 64 + '"' in defines


def test_validated_adapter_without_drop_rva_is_refused(tmp_path):
    adapter = {"status": "validated", "binary_sha256": "d" * 64,
               "hooks": [
                   {"layer": "http_encoded_body_preparation", "rva": "0xaaaa",
                    "owned_headers_drop_rva": "needs_dynamic_validation"},
                   {"layer": "wss_request_serialization", "rva": "0xcccc"}]}
    path = tmp_path / "partial.json"
    path.write_text(json.dumps(adapter))
    with pytest.raises(SystemExit):
        pin_defines(path)


def test_validated_adapter_without_entry_prefix_is_refused(tmp_path):
    adapter = {"status": "validated", "binary_sha256": "d" * 64,
               "hooks": [
                   {"layer": "http_encoded_body_preparation", "rva": "0xaaaa",
                    "owned_headers_drop_rva": "0xbbbb", "entry_prefix_hex": "55" * 12},
                   {"layer": "wss_request_serialization", "rva": "0xcccc"}]}
    path = tmp_path / "missing-prefix.json"
    path.write_text(json.dumps(adapter))
    with pytest.raises(SystemExit, match="entry prefix"):
        pin_defines(path)
