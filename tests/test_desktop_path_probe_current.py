"""Current-client observation remains identity-pinned and metadata-only."""
from __future__ import annotations

import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import probe_desktop_paths_current as current  # noqa: E402


SID = "S-1-5-21-111-222-333-1001"


def adapter() -> dict:
    return {"status": "candidate_unvalidated", "production_ready": False,
            "coverage": {name: {"validated": False} for name in
                         ("model.http", "model.wss", "attachment.upload")},
            "desktop_image_sha256": "d" * 64, "binary_sha256": "b" * 64}


@pytest.mark.skipif(os.name != "nt", reason="Windows process paths")
def test_current_client_backend_requires_exact_user_parent_hash_cache_and_signer(
        monkeypatch, tmp_path):
    local = tmp_path / "Local"
    image = local / "OpenAI" / "Codex" / "bin" / "a159911ff70742e9" / "codex.exe"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"synthetic")
    package = {"Location": str(tmp_path / "WindowsApps" / "OpenAI.Codex_fixed")}
    desktop_image = Path(package["Location"]) / "app" / "ChatGPT.exe"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(current, "current_user_sid", lambda: SID)
    monkeypatch.setattr(current, "registered_package", lambda _: package)
    signed = []
    monkeypatch.setattr(current, "verify_backend_signer", lambda path: signed.append(path))
    images = {100: {"pid": 100, "creation_filetime": 10,
                    "image_path": str(desktop_image), "image_sha256": "d" * 64},
              200: {"pid": 200, "creation_filetime": 20,
                    "image_path": str(image), "image_sha256": "b" * 64}}
    rows = {100: {"UserSid": SID},
            200: {"UserSid": SID, "ParentProcessId": 100,
                  "CommandLine": f'"{image}" app-server'}}
    monkeypatch.setattr(current, "process_identity", lambda pid: images[pid])
    monkeypatch.setattr(current, "_cim_process", lambda pid: rows[pid])
    assert set(current.verify_current_targets(adapter(), package, 100, 200, SID)) == {
        "desktop", "backend"}
    assert signed == [image.resolve(strict=True)]
    rows[200]["ParentProcessId"] = 999
    with pytest.raises(ValueError, match="app-server"):
        current.verify_current_targets(adapter(), package, 100, 200, SID)
    rows[200]["ParentProcessId"] = 100
    images[200]["image_sha256"] = "x" * 64
    with pytest.raises(ValueError, match="app-server"):
        current.verify_current_targets(adapter(), package, 100, 200, SID)
    images[200]["image_sha256"] = "b" * 64
    images[200]["image_path"] = str(tmp_path / "other" / "codex.exe")
    with pytest.raises(FileNotFoundError):
        current.verify_current_targets(adapter(), package, 100, 200, SID)


@pytest.mark.skipif(os.name != "nt", reason="Windows account identity")
def test_current_user_sid_must_match(monkeypatch):
    monkeypatch.setattr(current, "current_user_sid", lambda: SID)
    current.require_current_user(SID)
    with pytest.raises(ValueError, match="current interactive user"):
        current.require_current_user("S-1-5-21-111-222-333-1002")


def test_live_observer_requires_explicit_flags_before_accessing_processes():
    with pytest.raises(ValueError, match="active-current-client"):
        current.run_trace(SimpleNamespace(active_current_client=False,
                                          observation_only=False))


def test_only_minimal_model_call_metadata_and_marker_matches_are_retained():
    entry = current._safe_model_event({"kind": "candidate_entry", "hook": "model.http",
                                       "caller": {"module": "codex.exe", "rva": "0x111"},
                                       "thread_id": 42, "raw_body": "PRIVATE"})
    assert set(entry) == {"kind", "role", "hook", "observed_unix_ns"}
    assert entry["kind"] == "candidate_entry"
    assert current._safe_model_event({"kind": "candidate_entry", "hook": "ReadFile"}) is None
    assert current._safe_model_event({"kind": "marker_buffer", "hook": "ReadFile",
                                      "sha256": "a" * 64}) is None
    failed = current._safe_model_event({"kind": "read_hypothesis_failed",
                                        "hook": "model.wss", "stage": "hypothesized-wss-serialized",
                                        "raw_body": "PRIVATE"})
    assert set(failed) == {"kind", "role", "hook", "stage", "observed_unix_ns"}
    event = current._safe_model_event({"kind": "marker_buffer", "hook": "model.http",
                                       "sha256": "a" * 64, "request_shape": "other-json",
                                       "raw_body": "PRIVATE"})
    assert event["kind"] == "marker_buffer"
    assert event["hook"] == "model.http"
    assert event["request_shape"] == "other-json"
    assert "raw_body" not in event
    rejected = current._safe_model_event({"kind": "marker_buffer", "hook": "model.wss",
                                          "request_shape": "PRIVATE", "raw_body": "PRIVATE"})
    assert "request_shape" not in rejected and "raw_body" not in rejected


def test_candidate_summary_keeps_counts_and_receive_time_without_request_attribution():
    rows = [{"kind": "candidate_entry", "hook": "model.http", "observed_unix_ns": 30},
            {"kind": "candidate_entry", "hook": "model.http", "observed_unix_ns": 10},
            {"kind": "candidate_entry", "hook": "model.wss", "observed_unix_ns": 20},
            {"kind": "marker_buffer", "hook": "model.http", "observed_unix_ns": 25},
            {"kind": "candidate_entry", "hook": "ReadFile", "observed_unix_ns": 40}]
    assert current.summarize_candidate_entries(rows) == {
        "model.http": {"count": 2, "first_observed_unix_ns": 10,
                       "last_observed_unix_ns": 30},
        "model.wss": {"count": 1, "first_observed_unix_ns": 20,
                      "last_observed_unix_ns": 20},
    }


def test_live_frida_source_omits_file_io_hooks():
    source = current.agent_source("backend", {
        "hooks": [
            {"layer": "http_encoded_body_preparation", "rva": "0x1234",
             "entry_prefix_hex": "5541574156415541"},
            {"layer": "wss_request_serialization", "rva": "0x5678",
             "entry_prefix_hex": "5541574156415541"},
        ]}, "FAKE_DESKTOP_PROMPT_" + "a" * 32, Path("synthetic.txt"), observe_io=False)
    assert '"observe_io":false' in source
    assert "if (CONFIG.observe_io) Process.attachModuleObserver" in source
