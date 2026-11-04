"""Research trace stays synthetic, pinned, read-only, and unvalidated."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from probe_desktop_paths_vm import (  # noqa: E402
    agent_source, load_fixtures, prepare_fixtures, require_qemu_vm,
    run_trace, safe_event, verify_static_entries, verify_trace_targets,
    verify_wfp_tool,
)


def adapter():
    return {"status": "candidate_unvalidated", "package_full_name":
            "OpenAI.Codex_26.1029.7803.0_x64__2p2nqsd0c76g0",
            "desktop_image_sha256": "c" * 64, "binary_sha256": "a" * 64,
            "hooks": [
                {"layer": "http_encoded_body_preparation", "rva": "0x1000", "entry_prefix_hex": "90" * 16},
                {"layer": "wss_request_serialization", "rva": "0x2000", "entry_prefix_hex": "91" * 16},
            ]}


def test_synthetic_fixture_is_hash_bound_and_bounded(tmp_path):
    root = tmp_path / "fixtures"
    result = prepare_fixtures(root)
    manifest, prompt, attachment = load_fixtures(root / "fixtures.json")
    assert manifest == result
    assert result["prompt_marker"] in prompt.read_text(encoding="utf-8")
    assert result["upload_marker"] in attachment.read_text(encoding="utf-8")
    attachment.write_bytes(attachment.read_bytes() + b"modified")
    with pytest.raises(ValueError, match="hash"):
        load_fixtures(root / "fixtures.json")


def test_frida_source_only_hashes_matched_buffers_and_never_replaces_calls(tmp_path):
    marker = "FAKE_DESKTOP_PROMPT_" + "a" * 32
    source = agent_source("backend", adapter(), marker, tmp_path / "fixture.txt")
    assert "Checksum.compute('sha256', data)" in source
    assert "readVolatile" in source
    assert "Interceptor.attach" in source
    assert "Interceptor.replace" not in source
    assert "start_guarded_lease" not in source
    if shutil.which("node"):
        script = tmp_path / "research-agent.js"
        script.write_text(source, encoding="utf-8")
        check = subprocess.run(["node", "--check", str(script)], capture_output=True, text=True)
        assert check.returncode == 0, check.stderr


def test_event_sanitizer_discards_unexpected_plaintext_and_paths():
    value = safe_event({"kind": "marker_buffer", "hook": "ReadFile", "stage": "completed-read",
                        "sha256": "a" * 64, "bytes": 123, "payload_utf8": "secret",
                        "path": r"C:\private\secret.txt", "caller": {"module": "ChatGPT.exe", "rva": "0x10"},
                        "stack": [{"module": "ChatGPT.exe", "rva": "0x10"},
                                  {"module": "bad/path", "rva": "0x20"}]}, "desktop")
    encoded = json.dumps(value)
    assert "secret" not in encoded and "private" not in encoded
    assert value["sha256"] == "a" * 64 and len(value["stack"]) == 1
    assert safe_event({"kind": "unknown", "payload_utf8": "secret"}, "desktop") is None


def test_static_candidate_rva_and_prologue_must_still_match(monkeypatch, tmp_path):
    found = {"binary_sha256": "a" * 64, "candidates": [
        {"layer": "http_body_preparation", "function_rva": "0x1000", "entry_prefix_hex": "90" * 16},
        {"layer": "serialization", "function_rva": "0x2000", "entry_prefix_hex": "91" * 16},
    ]}
    monkeypatch.setattr("probe_desktop_paths_vm.discover", lambda _: found)
    verify_static_entries(adapter(), tmp_path / "codex.exe")
    found["candidates"][0]["entry_prefix_hex"] = "00" * 16
    with pytest.raises(ValueError, match="prologue"):
        verify_static_entries(adapter(), tmp_path / "codex.exe")


def test_trace_subject_requires_pinned_parent_mode_and_separate_controller(monkeypatch):
    package = adapter()["package_full_name"]
    images = {
        100: {"pid": 100, "creation_filetime": 10, "image_sha256": "c" * 64,
              "image_path": rf"C:\WindowsApps\{package}\app\ChatGPT.exe"},
        200: {"pid": 200, "creation_filetime": 20, "image_sha256": "a" * 64,
              "image_path": r"C:\bin\codex.exe"},
        300: {"pid": 300, "creation_filetime": 30, "image_sha256": "c" * 64,
              "image_path": rf"C:\WindowsApps\{package}\app\ChatGPT.exe"},
    }
    sid = "S-1-5-21-111-222-333-1001"
    rows = {100: {"UserSid": sid},
            200: {"UserSid": sid, "ParentProcessId": 100,
                  "CommandLine": r"C:\bin\codex.exe app-server"},
            300: {"UserSid": sid, "ParentProcessId": 100,
                  "CommandLine": "--type=utility --utility-sub-type=network.mojom.NetworkService"}}
    monkeypatch.setattr("probe_desktop_paths_vm.process_identity", lambda pid: images[pid])
    monkeypatch.setattr("probe_desktop_paths_vm._cim_process", lambda pid: rows[pid])
    monkeypatch.setattr("probe_desktop_paths_vm.current_user_sid", lambda: "S-1-5-21-111-222-333-1002")
    targets = verify_trace_targets(adapter(), 100, 200, 300, sid)
    assert set(targets) == {"desktop", "backend", "network"}
    rows[200]["ParentProcessId"] = 999
    with pytest.raises(ValueError, match="backend"):
        verify_trace_targets(adapter(), 100, 200, 300, sid)
    rows[200]["ParentProcessId"] = 100
    monkeypatch.setattr("probe_desktop_paths_vm.current_user_sid", lambda: sid)
    with pytest.raises(ValueError, match="separate"):
        verify_trace_targets(adapter(), 100, 200, 300, sid)


def test_trace_requires_explicit_vm_before_any_probe():
    with pytest.raises(ValueError, match="isolated-vm"):
        run_trace(SimpleNamespace(isolated_vm=False))


def test_wfp_status_utility_requires_matching_build_manifest(tmp_path):
    executable = tmp_path / "wfp_desktop.exe"
    executable.write_bytes(b"fixture WFP utility")
    source = ROOT / "native" / "behavior" / "wfp_desktop.c"
    manifest = {"schema": "transpect.desktop-wfp-build/1.0",
                "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    (tmp_path / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_wfp_tool(executable) == executable.resolve()
    executable.write_bytes(b"different utility")
    with pytest.raises(ValueError, match="pinned build"):
        verify_wfp_tool(executable)


@pytest.mark.skipif(os.name != "nt", reason="Windows QEMU probe")
def test_qemu_identity_refuses_physical_host(monkeypatch):
    monkeypatch.setattr("probe_desktop_paths_vm.subprocess.run", lambda *a, **kw:
                        SimpleNamespace(returncode=0, stdout=json.dumps({
                            "Manufacturer": "Dell Inc.", "Model": "Desktop"})))
    with pytest.raises(RuntimeError, match="QEMU"):
        require_qemu_vm()
    monkeypatch.setattr("probe_desktop_paths_vm.subprocess.run", lambda *a, **kw:
                        SimpleNamespace(returncode=0, stdout=json.dumps({
                            "Manufacturer": "QEMU", "Model": "Standard PC"})))
    assert require_qemu_vm()["confirmed"] is True
