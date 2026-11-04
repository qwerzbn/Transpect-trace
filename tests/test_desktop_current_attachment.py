"""Metadata-only bounds for the current-desktop attachment research probe."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from probe_desktop_current_attachment import (  # noqa: E402
    MAX_OBSERVED_BUFFER, _collect, attachment_agent_source, network_identity_matches,
    require_opt_in, safe_attachment_event,
    summarize_events,
)


FIXTURE = b"Synthetic desktop upload fixture.\nFAKE_DESKTOP_UPLOAD_" + b"a" * 32 + b"\n"
FIXTURE_SHA = hashlib.sha256(FIXTURE).hexdigest()
MARKER_OFFSET = FIXTURE.index(b"FAKE_DESKTOP_UPLOAD_")


def safe(payload: object, role: str = "backend") -> dict | None:
    return safe_attachment_event(
        payload, role, fixture_size=len(FIXTURE),
        fixture_sha256=FIXTURE_SHA, marker_offset=MARKER_OFFSET,
    )


def test_only_exact_synthetic_buffer_can_be_labeled_exact_without_raw_data():
    payload = {
        "kind": "marker_buffer", "hook": "ReadFile", "stage": "completed-read",
        "bytes": len(FIXTURE), "marker_offset": MARKER_OFFSET,
        "sha256": FIXTURE_SHA, "payload_utf8": "PRIVATE PAYLOAD",
        "file_path": r"C:\private\real-document.docx", "thread_id": 77,
        "caller": {"module": "codex.exe", "rva": "0x1234"},
    }
    row = safe(payload)
    assert row is not None and row["exact_fixture_buffer"] is True
    assert row["caller"] == {"module": "codex.exe", "rva": "0x1234"}
    assert "PRIVATE" not in str(row) and "real-document" not in str(row)
    assert "sha256" not in row and "thread_id" not in row
    assert safe({**payload, "sha256": "b" * 64})["exact_fixture_buffer"] is False
    assert safe({**payload, "bytes": len(FIXTURE) + 1})["exact_fixture_buffer"] is False
    assert safe({**payload, "marker_offset": len(FIXTURE)}) is None
    assert safe({**payload, "bytes": MAX_OBSERVED_BUFFER + 1}) is None


def test_observation_agent_caps_in_process_buffer_scans(tmp_path):
    adapter = {"hooks": [
        {"layer": "http_encoded_body_preparation", "rva": "0x1234",
         "entry_prefix_hex": "55415741"},
        {"layer": "wss_request_serialization", "rva": "0x5678",
         "entry_prefix_hex": "55415741"},
    ]}
    fixture = tmp_path / "synthetic-attachment.txt"
    fixture.write_bytes(FIXTURE)
    source = attachment_agent_source(
        "backend", adapter, "FAKE_DESKTOP_UPLOAD_" + "a" * 32, fixture)
    assert f'"max_buffer":{MAX_OBSERVED_BUFFER}' in source
    assert '"max_buffer":16777216' not in source


def test_unattributed_model_calls_are_reduced_to_counters():
    row = safe({"kind": "candidate_entry", "hook": "model.http",
                "thread_id": 123, "caller": {"module": "codex.exe", "rva": "0x1234"},
                "payload_utf8": "SECRET"})
    assert row is not None and set(row) == {
        "kind", "role", "hook", "observed_unix_ns"}
    assert safe({"kind": "candidate_entry", "hook": "ReadFile"}) is None
    assert safe({"kind": "marker_buffer", "hook": "UnknownHook",
                 "bytes": len(FIXTURE), "marker_offset": MARKER_OFFSET}) is None


def test_all_stages_still_leave_coverage_unvalidated():
    rows = [{"kind": "probe_ready", "role": role} for role in ("desktop", "backend")]
    rows += [
        {"kind": "fixture_open", "role": "desktop", "hook": "CreateFileW"},
        {"kind": "marker_buffer", "role": "desktop", "hook": "ReadFile",
         "exact_fixture_buffer": True},
        {"kind": "marker_buffer", "role": "backend", "hook": "model.http",
         "exact_fixture_buffer": False},
    ]
    result = summarize_events(rows, [], {"desktop", "backend"})
    assert result["status"] == "synthetic_marker_seen_at_candidates"
    assert result["fixture_open_events"] == 1
    assert result["file_read_marker_events"] == 1
    assert result["model_marker_events"] == 1
    assert result["exact_fixture_buffer_events"] == 1
    assert summarize_events(rows, ["worker_failed"], {"desktop", "backend"})[
        "status"] == "unvalidated_probe_error"
    assert summarize_events(rows, [], {"desktop", "backend", "network"})[
        "status"] == "unvalidated_probe_error"


def test_fixed_model_entry_mismatch_marks_probe_error():
    class Receiver:
        def __init__(self):
            self.done = False

        def recv(self):
            if self.done:
                raise EOFError
            self.done = True
            return {"event": {"kind": "entry_mismatch", "role": "backend",
                              "hook": "model.http"}}

    rows, errors = [], []
    _collect(Receiver(), rows, errors, threading.Event(), {"backend"}, {})
    assert errors == ["fixed_model_entry_mismatch"]
    assert summarize_events(rows, errors, {"backend"})["status"] == "unvalidated_probe_error"


def test_network_service_must_match_pinned_package_parent_and_sid():
    image = "a" * 64
    path = r"C:\Program Files\WindowsApps\OpenAI.Codex_26\app\ChatGPT.exe"
    process = {"image_path": path, "image_sha256": image,
               "creation_filetime": 123}
    row = {"ParentProcessId": 456, "UserSid": "S-1-5-21-demo",
           "CommandLine": "ChatGPT.exe --type=utility --utility-sub-type=network.mojom.NetworkService"}
    kwargs = {"desktop_pid": 456, "desktop_image": image,
              "package_location": r"C:\Program Files\WindowsApps\OpenAI.Codex_26",
              "expected_sid": "S-1-5-21-demo"}
    assert network_identity_matches(process, row, **kwargs)
    assert not network_identity_matches(process, {**row, "ParentProcessId": 999}, **kwargs)
    assert not network_identity_matches({**process, "image_sha256": "b" * 64}, row, **kwargs)
    assert not network_identity_matches({**process, "image_path": r"C:\temp\ChatGPT.exe"}, row, **kwargs)


def test_explicit_current_synthetic_observation_opt_in():
    class Args:
        active_current_client = True
        observation_only = True
        synthetic_file_only = False
        seconds = 20

    with pytest.raises(ValueError, match="explicit"):
        require_opt_in(Args())
    Args.synthetic_file_only = True
    require_opt_in(Args())
