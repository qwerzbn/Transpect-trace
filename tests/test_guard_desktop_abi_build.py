"""A desktop DLL pin must carry the fixed build's observed native ABI."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_guard_native import pin_defines  # noqa: E402


def _validated_fixture() -> dict:
    return {
        "schema": "transpect.guard.desktop-adapter/1.0",
        "status": "validated", "binary_sha256": "a" * 64,
        "hooks": [
            {"layer": "http_encoded_body_preparation", "rva": "0xb117de0",
             "entry_prefix_hex": "5541574156415541545657534881ece8",
             "owned_headers_drop_rva": "0xa6320",
             "owned_headers_drop_entry_prefix_hex": "555657534883ec58"},
            {"layer": "wss_request_serialization", "rva": "0x41e3330",
             "entry_prefix_hex": "5541574156415541545657534881ecd8"},
        ],
    }


def test_actual_desktop_candidate_stays_unbuildable():
    candidate = ROOT / "deploy/guard/desktop-candidate-26.1029.7803.0.json"
    with pytest.raises(SystemExit, match="not dynamically validated"):
        pin_defines(candidate)


def test_desktop_build_requires_explicit_tags_and_header_destructor_prefix(tmp_path, monkeypatch):
    from transpect_trace.guard import desktop
    # Isolate compiler-flag generation; production still executes the real
    # desktop validation gate before reaching this branch.
    monkeypatch.setattr(desktop, "validate_desktop_adapter", lambda adapter: adapter)
    adapter = _validated_fixture()
    path = tmp_path / "validated-desktop-fixture.json"
    path.write_text(json.dumps(adapter), encoding="utf-8")
    with pytest.raises(SystemExit, match="result ABI proof"):
        pin_defines(path)
    adapter["native_abi"] = {"wss_success_tag": "0x1f", "wss_denied_tag": "0x0d",
                             "http_denied_tag": "0x03", "http_empty_error_string": True}
    path.write_text(json.dumps(adapter), encoding="utf-8")
    defines = pin_defines(path)
    for expected in ("-DWSS_SUCCESS_TAG=0x1f", "-DWSS_DENIED_TAG=0x0d",
                     "-DHTTP_DENIED_TAG=0x03", "-DHTTP_EMPTY_ERROR_STRING=1",
                     "-DDROP_HEADERS_PREFIX_BYTES={0x55,0x56,0x57,0x53,0x48,0x83,0xec,0x58}"):
        assert expected in defines
    adapter["hooks"][0].pop("owned_headers_drop_entry_prefix_hex")
    path.write_text(json.dumps(adapter), encoding="utf-8")
    with pytest.raises(SystemExit, match="DROP_HEADERS_PREFIX_BYTES"):
        pin_defines(path)
