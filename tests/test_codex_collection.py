"""Collection rows share one schema across routes and never carry plaintext."""
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect import codex_hook_gate as gate  # noqa: E402
from transpect_trace.protect import collection  # noqa: E402
from transpect_trace.protect.archive import ArchiveReceipt, EncryptedRequestArchive  # noqa: E402
from transpect_trace.protect.content_dlp import DLPVerdict  # noqa: E402

from probe_codex_hook_coverage import FAKE_KEY, MARKER  # noqa: E402

needs_dpapi = pytest.mark.skipif(os.name != "nt",
                                 reason="the encrypted archive requires Windows DPAPI")
_RECEIPT = ArchiveReceipt("0" * 32, "model_request", "a" * 64, 42, "2026-11-06T00:00:00+00:00")
_EVENT = {"hook_event_name": "PreToolUse", "session_id": "s-1", "turn_id": "t-1",
          "tool_use_id": "call_0", "tool_name": "Bash", "model": "gpt-test",
          "tool_input": {"command": f"echo {MARKER}"}}


def _record(**overrides):
    fields = dict(route="hook", route_event="PreToolUse", protocol="hook",
                  category="tool_call_args", location="hook:PreToolUse/tool_input",
                  collection="content", receipt=_RECEIPT, content_hmac="b" * 64,
                  match_hmac=None, inspected=True, decision_point="before_execution",
                  verdict=DLPVerdict("ALLOW", "NO_FINDINGS"), actionable="ALLOW",
                  route_decision="allow", released_by_route=True,
                  correlation=collection.hook_correlation(_EVENT),
                  policy_version="codex-hook-gate/2", gate_mode="enforce", elapsed_ms=1.23456)
    return collection.build_record(**{**fields, **overrides})


def test_record_validates_and_round_trips():
    record = _record(findings=(("SENSITIVE_PATH", "SENSITIVE_PATH_READ", 0.9),),
                     extra={"image_items": 0, "incremental": False})
    assert record["schema"] == collection.SCHEMA
    assert record["archive_record_id"] == "0" * 32 and record["content_bytes"] == 42
    assert (record["session_id"], record["turn_id"], record["call_id"]) == ("s-1", "t-1", "call_0")
    assert record["thread_id"] is None and record["request_sha256"] is None
    assert record["matched_rule_ids"] == ["SENSITIVE_PATH_READ"]
    assert record["elapsed_ms"] == 1.235
    again = json.loads(json.dumps(record, sort_keys=True))
    collection.validate_record(again)
    assert again == record
    metadata = _record(route_event="PreModelRequest", category="request_metadata",
                       collection="metadata_only", receipt=None, content_hmac=None,
                       inspected=False, decision_point="none", verdict=None, actionable=None,
                       route_decision="not_enforceable", released_by_route=None)
    assert metadata["content_bytes"] == 0 and metadata["archive_kind"] is None
    envelope = _record(route="native", route_event="model.request", protocol="http",
                       category="request_envelope", location="/", receipt=None,
                       content_bytes=9000, correlation={"request_sha256": "c" * 64})
    assert envelope["content_bytes"] == 9000


@pytest.mark.parametrize("overrides", [
    {"category": "prompt"}, {"route": "etw"}, {"protocol": "http"},
    {"route_event": "SessionStart"}, {"decision_point": "later"},
    {"route_decision": "maybe"}, {"collection": "metadata_only"},
    {"content_hmac": "not-hex"}, {"correlation": {"prompt": "x"}},
    {"extra": {"note": "free text with spaces"}},
])
def test_record_rejects_unknown_category_or_route(overrides):
    with pytest.raises(ValueError):
        _record(**overrides)
    record = _record()
    record.pop("extra")
    with pytest.raises(ValueError):
        collection.validate_record(record)
    with pytest.raises(ValueError):
        collection.validate_record({**_record(), "prompt": MARKER})


@needs_dpapi
def test_records_never_contain_planted_plaintext(tmp_path):
    archive = EncryptedRequestArchive(tmp_path / "archive")
    text = f"deploy with {FAKE_KEY} for {MARKER}"
    item = collection.CollectedItem("user_prompt", "hook:UserPromptSubmit/prompt",
                                    text.encode("utf-8"), text,
                                    collection.normalize_match_text("user_prompt", text))
    receipt = archive.save(item.archive_kind, item.payload)
    record = _record(route_event="UserPromptSubmit", category="user_prompt",
                     location=item.location, receipt=receipt,
                     content_hmac=archive.keyed_digest(item.payload),
                     match_hmac=archive.keyed_digest(item.match_text.encode("utf-8")),
                     decision_point="before_upstream",
                     verdict=DLPVerdict("BLOCK", "SECRET", ("GITHUB_TOKEN",), ("SECRET",)),
                     actionable="BLOCK", route_decision="deny", released_by_route=False)
    path = tmp_path / "collection.jsonl"
    collection.CollectionWriter(path).write([record])
    written = path.read_bytes()
    for planted in (MARKER, FAKE_KEY, text):
        assert planted.encode("utf-8") not in written
        assert planted not in json.dumps(record)
    assert hashlib.sha256(item.payload).hexdigest() not in written.decode("utf-8")
    assert archive.read(record["archive_record_id"])[1] == item.payload


@needs_dpapi
def test_keyed_digest_stable_for_same_archive_and_differs_across_archives(tmp_path):
    first = EncryptedRequestArchive(tmp_path / "a")
    reopened = EncryptedRequestArchive(tmp_path / "a")
    other = EncryptedRequestArchive(tmp_path / "b")
    data = MARKER.encode("utf-8")
    digest = first.keyed_digest(data)
    assert len(digest) == 64 and digest == first.keyed_digest(data) == reopened.keyed_digest(data)
    assert digest != other.keyed_digest(data)
    assert digest != first.keyed_digest(data + b"!")
    assert digest != hashlib.sha256(data).hexdigest()


def test_strip_exec_output_header():
    # Shapes copied from origin captures (runs/scratch/native-03), values synthetic.
    exited = ("Chunk ID: 54f285\nWall time: 4.1597 seconds\nProcess exited with code 0\n"
              f"Original token count: 11\nOutput:\nmeeting notes {MARKER}\r\n")
    running = ("Chunk ID: 20e681\nWall time: 10.0077 seconds\n"
               "Process running with session ID 19881\nOriginal token count: 0\nOutput:\n")
    hook_side = f"meeting notes {MARKER}\r\n"
    assert collection.strip_exec_output_header(exited) == f"meeting notes {MARKER}\r\n"
    assert collection.strip_exec_output_header(running) == ""
    assert collection.strip_exec_output_header(hook_side) == hook_side
    quoted = f"log line\nChunk ID: 1\nOutput:\n{MARKER}"
    assert collection.strip_exec_output_header(quoted) == quoted
    assert (collection.normalize_match_text("tool_output", exited)
            == collection.normalize_match_text("tool_output", hook_side)
            == f"meeting notes {MARKER}")
    # Only tool output is unwrapped; NFC and line ends apply to every category.
    assert collection.normalize_match_text("user_prompt", exited).startswith("Chunk ID:")
    assert collection.normalize_match_text("user_prompt", " Café\r\nx ") == "Café\nx"


def test_data_url_payloads_and_hook_correlation():
    png = b"\x89PNG\r\n\x1a\nsynthetic"
    url = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
    value = {"content": [{"type": "input_text", "text": MARKER},
                         {"type": "input_image", "image_url": url}], "other": [url]}
    assert collection.data_url_payloads(value) == [png, png]
    assert collection.data_url_payloads(MARKER) == []
    # A malformed payload is reported, never raised: collection must not decide.
    assert collection.data_url_payloads("data:image/png;base64,***") == []
    (bad,) = collection.data_urls(["data:image/png;base64,***"])
    assert bad.data is None and bad.image and bad.base64
    (text,) = collection.data_urls("data:text/plain;charset=utf-8,a%20b")
    assert (text.media_type, text.base64, text.data) == ("text/plain", False, b"a b")
    assert collection.hook_correlation({"session_id": "s", "tool_use_id": 7}) == {
        "session_id": "s", "thread_id": None, "turn_id": None, "call_id": None,
        "tool_name": None, "model": None}


def test_writer_uses_locked_rotating_append(tmp_path, monkeypatch):
    path = tmp_path / "collection.jsonl"
    calls = []
    real = gate.append_audit_line
    monkeypatch.setattr(gate, "append_audit_line",
                        lambda target, line: (calls.append((target, line)), real(target, line)))
    writer = collection.CollectionWriter(path)
    writer.write(iter([_record(), _record()]))
    writer.write([])
    assert len(calls) == 1 and calls[0][0] == path
    assert path.with_name(path.name + ".lock").exists()
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    for row in rows:
        collection.validate_record(row)
    bad = {**_record(), "category": "prompt"}
    with pytest.raises(ValueError):
        writer.write([_record(), bad])
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2
    assert gate.audit_files(path) == [path]
