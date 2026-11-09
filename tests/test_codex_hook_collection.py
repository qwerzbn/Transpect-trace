"""Route H writes one `transpect.codex-collection/1.0` row per collected item."""
import base64
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect import codex_hook_gate as gate  # noqa: E402
from transpect_trace.protect import collection as col  # noqa: E402

import install_codex_hook_gate as installer  # noqa: E402
from probe_codex_hook_coverage import FAKE_KEY, MARKER  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "nt",
                                reason="the encrypted archive requires Windows DPAPI")

FIXTURES = ROOT / "tests" / "fixtures" / "codex_collection"
PNG = b"\x89PNG\r\n\x1a\n" + MARKER.encode("ascii")


def _config_path(tmp_path, mode="enforce", **fields):
    path = installer.write_gate_config(tmp_path / "gate", mode, None)
    if fields:
        value = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps({**value, **fields}), encoding="utf-8")
    return path


def _gate(tmp_path, mode="enforce", **fields):
    return gate.CodexHookGate(gate.GateConfig.load(_config_path(tmp_path, mode, **fields)))


def _event(name, **fields):
    base = {"hook_event_name": name, "session_id": "s-1", "turn_id": "t-1",
            "cwd": str(ROOT), "model": "gpt-test", "permission_mode": "default",
            "transcript_path": None}
    return {**base, **fields}


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        col.validate_record(row)
    return rows


def _rows_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_prompt_emits_user_prompt_record_linked_to_archive_and_ids(tmp_path):
    hook = _gate(tmp_path)
    prompt = f"deploy {MARKER} with {FAKE_KEY}\r\n"
    outcome = hook.decide(_event("UserPromptSubmit", prompt=prompt))
    assert outcome.allowed is False
    (record,) = outcome.collection
    assert record["category"] == "user_prompt" and record["route"] == "hook"
    assert record["decision_point"] == "before_upstream"
    assert record["route_decision"] == "deny" and record["released_by_route"] is False
    assert record["archive_record_id"] == outcome.audit["archive_record_id"]
    assert record["archive_kind"] == "model_request" and record["inspected"] is True
    assert (record["session_id"], record["turn_id"], record["model"]) == ("s-1", "t-1", "gpt-test")
    assert record["actionable_decision"] == outcome.audit["actionable_decision"] == "BLOCK"
    assert record["matched_rule_ids"] == outcome.audit["matched_rule_ids"]
    archive = hook._archive
    _, payload = archive.read(record["archive_record_id"])
    assert record["content_hmac"] == archive.keyed_digest(payload)
    assert record["match_hmac"] == archive.keyed_digest(
        col.normalize_match_text("user_prompt", prompt).encode("utf-8"))
    gate.run_event(_event("UserPromptSubmit", prompt=prompt), None, None, hook)
    text = hook.config.collection_file.read_text(encoding="utf-8")
    assert MARKER not in text and FAKE_KEY not in text
    assert hook.config.collection_file == hook.config.audit_file.parent / "collection.jsonl"


def test_pre_tool_use_record_is_before_execution_with_call_id(tmp_path):
    outcome = _gate(tmp_path).decide(
        _event("PreToolUse", tool_name="Bash", tool_use_id="call_7",
               tool_input={"command": "git status"}))
    assert outcome.allowed is True
    (record,) = outcome.collection
    assert record["category"] == "tool_call_args"
    assert record["decision_point"] == "before_execution"
    assert record["location"] == "hook:PreToolUse/tool_input"
    assert (record["call_id"], record["tool_name"]) == ("call_7", "Bash")
    assert record["match_hmac"] is None
    assert record["route_decision"] == "allow" and record["released_by_route"] is True


def test_post_tool_use_image_archived_as_attachment_uninspected(tmp_path):
    hook = _gate(tmp_path)
    url = "data:image/png;base64," + base64.b64encode(PNG).decode("ascii")
    outcome = hook.decide(_event(
        "PostToolUse", tool_name="view_image", tool_use_id="call_8", tool_input={},
        tool_response=[{"type": "text", "text": "meeting notes\r\n"},
                       {"type": "input_image", "image_url": url}]))
    text, image = outcome.collection
    assert text["category"] == "tool_output"
    assert text["decision_point"] == "after_execution_before_upstream"
    assert text["extra"] == {"image_items": 1}
    assert "IMAGE_UNINSPECTED" not in text["matched_rule_ids"]
    assert image["category"] == "tool_output_image" and image["inspected"] is False
    assert image["archive_kind"] == "attachment" and image["call_id"] == "call_8"
    assert image["matched_rule_ids"] == ["IMAGE_UNINSPECTED"] and image["dlp_decision"] is None
    assert image["content_bytes"] == len(PNG)
    assert image["match_hmac"] == image["content_hmac"] == hook._archive.keyed_digest(PNG)
    receipt, data = hook._archive.read(image["archive_record_id"])
    assert receipt.kind == "attachment" and data == PNG


def test_pre_model_request_emits_metadata_only_with_model(tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    rows = [{"type": "event_msg", "payload": {"type": "task_started", "turn_id": "t-1"}},
            {"type": "response_item", "payload": {
                "type": "message", "role": "user",
                "content": [{"type": "input_text", "text": MARKER},
                            {"type": "input_image", "image_url": "data:image/png;base64,AA=="}]}}]
    rollout.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    hook = _gate(tmp_path)
    outcome = hook.decide(_event("PreModelRequest", transcript_path=str(rollout)))
    metadata, attachment = outcome.collection
    for record in (metadata, attachment):
        assert record["collection"] == "metadata_only" and record["archive_record_id"] is None
        assert record["decision_point"] == "none"
        assert record["route_decision"] == "not_enforceable" and record["model"] == "gpt-test"
    assert metadata["category"] == "request_metadata"
    assert attachment["category"] == "user_attachment"
    assert attachment["extra"] == {"ungated_attachments": 1}
    assert hook._archive is None  # no archive work for an observed event


def test_collection_write_failure_denies_enforced_event(tmp_path):
    target = tmp_path / "occupied"
    target.mkdir()
    hook = _gate(tmp_path, collection_file=str(target))
    response = gate.run_event(_event("UserPromptSubmit", prompt="请总结公开文档。"), None,
                              None, hook)
    assert response["decision"] == "block" and "COLLECTION_UNAVAILABLE" in response["reason"]
    (audit,) = _rows_audit(hook.config.audit_file)
    assert audit["allowed"] is False and audit["reason"] == "COLLECTION_UNAVAILABLE"
    observed = gate.run_event(_event("PreModelRequest"), None, None, hook)
    assert observed == {}


def test_malformed_data_url_decides_the_same_with_collection(tmp_path):
    event = _event("PostToolUse", tool_name="Bash", tool_use_id="c", tool_input={},
                   tool_response="data:image/png;base64,iVBORw0KGgo=\nsecond line\n")
    off = _gate(tmp_path / "off", collection_file=None).decide(event)
    on = _gate(tmp_path / "on").decide(event)
    assert (on.allowed, on.reason) == (off.allowed, off.reason) == (
        True, "REQUIRED_CHECKS_COMPLETE")
    text, image = on.collection
    assert image["category"] == "tool_output_image" and image["matched_rule_ids"] == [
        "IMAGE_UNINSPECTED"]


def test_audit_failure_supersedes_released_rows(tmp_path):
    hook = _gate(tmp_path)
    hook.config.audit_file.mkdir(parents=True)  # a directory cannot be appended to
    response = gate.run_event(_event("UserPromptSubmit", prompt="请总结公开文档。"), None,
                              None, hook)
    assert response["decision"] == "block" and "AUDIT_UNAVAILABLE" in response["reason"]
    allowed, denied = _rows(hook.config.collection_file)
    assert allowed["route_decision"] == "allow"
    assert (denied["route_decision"], denied["released_by_route"]) == ("deny", False)
    assert denied["extra"] == {"superseded_reason": "AUDIT_UNAVAILABLE"}
    assert denied["archive_record_id"] == allowed["archive_record_id"]


def test_collection_file_null_disables(tmp_path):
    hook = _gate(tmp_path, collection_file=None)
    assert hook.config.collection_file is None
    event = _event("PostToolUse", tool_name="Bash", tool_use_id="c", tool_input={},
                   tool_response=["notes", "data:image/png;base64," + base64.b64encode(PNG).decode()])
    outcome = hook.decide(event)
    assert outcome.collection == () and outcome.allowed is True
    assert gate.run_event(event, None, None, hook) == {}
    assert not (hook.config.audit_file.parent / "collection.jsonl").exists()


def test_service_decide_raw_emits_same_records(tmp_path):
    from transpect_trace.protect import codex_gate_service as service
    config = _config_path(tmp_path)
    event = _event("PostToolUse", tool_name="Bash", tool_use_id="call_9",
                   tool_input={"command": "type notes.txt"},
                   tool_response=f"notes {MARKER}\n")
    raw = json.dumps(event).encode("utf-8")
    gate.run_event(event, None, str(config))
    service.decide_raw(raw, service._ConfigCache(config))
    first, second = _rows(gate.GateConfig.load(config).collection_file)
    volatile = {"collected_at", "elapsed_ms", "archive_record_id"}
    assert first["archive_record_id"] != second["archive_record_id"]
    assert ({k: v for k, v in first.items() if k not in volatile}
            == {k: v for k, v in second.items() if k not in volatile})


def test_prompt_match_hmac_equals_wire_prompt_match_hmac(tmp_path):
    wire = pytest.importorskip("transpect_trace.protect.wire_items")
    if not (FIXTURES / "http_turn1.json").exists() or not (FIXTURES / "hook_events.jsonl").exists():
        pytest.skip("WP1 collection fixtures are not present yet")
    events = [json.loads(line) for line in
              (FIXTURES / "hook_events.jsonl").read_text(encoding="utf-8").splitlines() if line]
    prompt = next(item for item in events if item["hook_event_name"] == "UserPromptSubmit")
    hook = _gate(tmp_path)
    (record,) = [row for row in hook.decide(prompt).collection if row["category"] == "user_prompt"]
    parsed = wire.parse_wire_request((FIXTURES / "http_turn1.json").read_bytes(), protocol="http")
    (item,) = [item for item in parsed.items if item.category == "user_prompt"]
    assert record["match_hmac"] == hook._archive.keyed_digest(
        col.normalize_match_text("user_prompt", item.match_text).encode("utf-8"))
    assert record["session_id"] == parsed.correlation.get("session_id")
