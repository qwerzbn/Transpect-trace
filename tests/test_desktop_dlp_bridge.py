import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import pytest

from transpect_trace.guard.policy import GuardRequest
from transpect_trace.protect.archive import EncryptedRequestArchive
from transpect_trace.protect.desktop_bridge import DesktopDLPBridge


def _request(body, *, protocol="http"):
    if protocol == "wss":
        body = {"type": "response.create", "response": body}
    return GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": "fixture-1",
        "guard_session_id": "123-456", "pid": 123, "tid": 1,
        "kind": "model.request", "protocol": protocol,
        "completeness": "complete", "payload_utf8": json.dumps(body),
    })


def _bridge(tmp_path):
    return DesktopDLPBridge({"pid": 123}, EncryptedRequestArchive(tmp_path / "archive"))


def test_model_gate_archives_before_allow_and_blocks_secret(tmp_path):
    bridge = _bridge(tmp_path)
    allowed, row = bridge.evaluate(_request({"model": "fixture", "input": "Hello"}))
    assert allowed.decision == "allow"
    assert bridge.archive.read(row["archive_record_id"])[1]
    denied, row = bridge.evaluate(_request({"model": "fixture", "input": "password=FakeSecret12345"}))
    assert denied.decision == "deny" and denied.action == "block_request"
    assert b"FakeSecret12345" in bridge.archive.read(row["archive_record_id"])[1]
    assert "FakeSecret12345" not in json.dumps(row)


def test_wss_and_inline_file_are_checked(tmp_path):
    bridge = _bridge(tmp_path)
    body = {"model": "fixture", "input": [{"type": "input_file", "filename": "sample.txt",
        "file_data": "data:text/plain;base64," + base64.b64encode(b"api_key=FakeSyntheticApiKey12345").decode()}]}
    denied, row = bridge.evaluate(_request(body, protocol="wss"))
    assert denied.decision == "deny"
    assert row["archive_record_id"]
    assert len(list(bridge.archive.directory.glob("*.enc"))) == 2


def test_file_reference_requires_approved_byte_snapshot(tmp_path):
    bridge = _bridge(tmp_path)
    body = {"model": "fixture", "input": [{"type": "input_file", "file_id": "file_fixture"}]}
    assert bridge.evaluate(_request(body))[0].decision == "deny"
    approval = bridge.evaluate_attachment("good.txt", b"A public project note.")
    assert approval.decision == "ALLOW"
    with pytest.raises(ValueError, match="matching approved upload"):
        bridge.bind_reference(approval.approval_id, "file_wrong_name", "renamed.txt",
                              approval.receipt.body_sha256)
    approval = bridge.evaluate_attachment("good.txt", b"A public project note.")
    bridge.bind_reference(approval.approval_id, "file_fixture", "good.txt",
                          approval.receipt.body_sha256)
    assert bridge.evaluate(_request(body))[0].decision == "allow"


def test_unverified_server_history_fails_closed(tmp_path):
    bridge = _bridge(tmp_path)
    body = {"model": "fixture", "input": "A safe new prompt", "previous_response_id": "resp_earlier"}
    decision, row = bridge.evaluate(_request(body))
    assert decision.decision == "deny"
    assert row["archive_record_id"]


@pytest.mark.parametrize("attachment", [
    {"type": "input_file", "file_url": "https://example.invalid/file.pdf"},
    {"type": "input_file", "file_path": "C:/secrets/private.pdf"},
    {"file_id": "untyped_file"},
    {"type": "input_image", "image_url": "data:image/png;base64,AAAA"},
])
def test_uninspectable_attachment_shapes_fail_closed(tmp_path, attachment):
    bridge = _bridge(tmp_path)
    body = {"model": "fixture", "input": [attachment]}
    assert bridge.evaluate(_request(body))[0].decision == "deny"


def test_storage_failure_denies_before_send(tmp_path):
    bridge = _bridge(tmp_path)
    def fail(*args, **kwargs):
        raise OSError("disk unavailable")
    bridge.archive.save = fail
    decision, row = bridge.evaluate(_request({"model": "fixture", "input": "Hello"}))
    assert decision.decision == "deny"
    assert decision.reason == "ARCHIVE_OR_INSPECTION_FAILED"
    assert row["archive_record_id"] is None


def test_native_outcome_is_retained_for_block_evidence(tmp_path):
    bridge = _bridge(tmp_path)
    event = GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": "event-1",
        "guard_session_id": "123-456", "pid": 123, "tid": 1,
        "kind": "native.outcome", "protocol": "control", "completeness": "complete",
        "payload_utf8": "", "outcome_for_request_id": "fixture-1",
        "outcome_action": "block_request", "outcome_captured_qpc": 999,
    })
    decision, row = bridge.evaluate(event)
    assert decision.decision == "allow"
    assert row["kind"] == "native.outcome"
    assert row["request_id"] == "fixture-1"
    assert row["action_execution"] == "native_error_constructed"


def test_duplicate_json_and_wss_outer_fields_cannot_hide_sensitive_data(tmp_path):
    bridge = _bridge(tmp_path)
    duplicate = _request({"model": "fixture", "input": "Hello"}).model_copy(update={
        "payload_utf8": '{"model":"fixture","input":"password=FakeSecret12345","input":"Hello"}',
    })
    assert bridge.evaluate(duplicate)[0].decision == "deny"
    outer = _request({"model": "fixture", "input": "Hello"}, protocol="wss").model_copy(update={
        "payload_utf8": json.dumps({"type": "response.create",
                                    "response": {"model": "fixture", "input": "Hello"},
                                    "extra": "password=FakeSecret12345"}),
    })
    assert bridge.evaluate(outer)[0].decision == "deny"


def test_nested_parent_key_supplies_sensitive_context(tmp_path):
    bridge = _bridge(tmp_path)
    body = {"model": "fixture", "input": "Hello", "metadata": {
        "password": {"value": "FakeSecret12345"}}}
    assert bridge.evaluate(_request(body))[0].decision == "deny"


@pytest.mark.parametrize("attachment", [
    {"type": "input_file", "filename": "good.txt", "file_data": "data:text/plain;base64,SGVsbG8=",
     "extra": "password=FakeSecret12345"},
    {"type": "input_file", "filename": "good.txt", "file_data": "data:text/plain;base64,SGVsbG8=",
     "data": "data:text/plain;base64,cGFzc3dvcmQ9RmFrZVNlY3JldDEyMzQ1"},
    {"type": "input_file", "filename": "good.txt", "file_data": "data:text/plain;base64,SGVsbG8=",
     "detail": "password=FakeSecret12345"},
])
def test_attachment_unknown_or_ambiguous_fields_fail_closed(tmp_path, attachment):
    bridge = _bridge(tmp_path)
    assert bridge.evaluate(_request({"model": "fixture", "input": [attachment]}))[0].decision == "deny"


def test_reference_filename_and_archive_integrity_are_checked(tmp_path):
    bridge = _bridge(tmp_path)
    approval = bridge.evaluate_attachment("good.txt", b"A public project note.")
    bridge.bind_reference(approval.approval_id, "file_fixture", "good.txt", approval.receipt.body_sha256)
    mismatch = {"model": "fixture", "input": [{"type": "input_file", "file_id": "file_fixture",
                                                "filename": "other.txt"}]}
    assert bridge.evaluate(_request(mismatch))[0].decision == "deny"
    second = bridge.evaluate_attachment("second.txt", b"Another public note.")
    with pytest.raises(ValueError, match="matching approved upload"):
        bridge.bind_reference(second.approval_id, "file_fixture", "second.txt", second.receipt.body_sha256)
    (bridge.archive.directory / f"{approval.receipt.record_id}.enc").unlink()
    original = {"model": "fixture", "input": [{"type": "input_file", "file_id": "file_fixture"}]}
    assert bridge.evaluate(_request(original))[0].decision == "deny"


def test_pending_upload_approval_expires_before_reference_binding(tmp_path):
    bridge = _bridge(tmp_path)
    approval = bridge.evaluate_attachment("good.txt", b"A public project note.")
    old = datetime.now(timezone.utc) - timedelta(minutes=6)
    bridge._pending[approval.approval_id] = replace(
        approval, receipt=replace(approval.receipt, saved_at=old.isoformat()))
    with pytest.raises(ValueError, match="matching approved upload"):
        bridge.bind_reference(approval.approval_id, "file_fixture", "good.txt",
                              approval.receipt.body_sha256)
    assert approval.approval_id not in bridge._pending


def test_pending_upload_approval_capacity_fails_closed(tmp_path, monkeypatch):
    from transpect_trace.protect import desktop_bridge
    monkeypatch.setattr(desktop_bridge, "MAX_PENDING_APPROVALS", 1)
    bridge = _bridge(tmp_path)
    first = bridge.evaluate_attachment("first.txt", b"A public project note.")
    with pytest.raises(ValueError, match="capacity"):
        bridge.evaluate_attachment("second.txt", b"Another public project note.")
    bridge.bind_reference(first.approval_id, "file_first", "first.txt", first.receipt.body_sha256)
    assert bridge.evaluate_attachment("second.txt", b"Another public project note.").decision == "ALLOW"


def test_untyped_data_url_and_empty_input_fail_closed(tmp_path):
    bridge = _bridge(tmp_path)
    assert bridge.evaluate(_request({"model": "fixture", "input": ["data:application/pdf;base64,SGVsbG8="]}))[0].decision == "deny"
    assert bridge.evaluate(_request({"model": "fixture", "input": ["prefix data:application/pdf;base64,SGVsbG8="]}))[0].decision == "deny"
    assert bridge.evaluate(_request({"model": "fixture", "input": ["data:;base64,SGVsbG8="]}))[0].decision == "deny"
    assert bridge.evaluate(_request({"model": "fixture", "input": None}))[0].decision == "deny"


def test_flat_wss_tool_parameter_schema_is_not_an_attachment(tmp_path):
    bridge = _bridge(tmp_path)
    body = {"type": "response.create", "model": "fixture", "input": "Hello",
            "tools": [{"type": "function", "name": "example",
                       "parameters": {"type": "object", "properties": {
                           "image_url": {"type": "string"},
                           "file_id": {"type": ["string", "null"]}}}}]}
    fixture = _request({"model": "fixture", "input": "Hello"}, protocol="wss")
    request = fixture.model_copy(update={"payload_utf8": json.dumps(body)})
    decision, row = bridge.evaluate(request)
    assert decision.decision == "allow"
    assert bridge.archive.read(row["archive_record_id"])[1] == request.payload_utf8.encode()

    body["tools"][0]["parameters"]["properties"]["file_id"] = "file_unchecked"
    assert bridge.evaluate(fixture.model_copy(update={"payload_utf8": json.dumps(body)}))[0].decision == "deny"
    body["tools"][0]["parameters"]["properties"]["file_id"] = {"type": "string"}
    body["tools"][0]["parameters"]["properties"]["image_url"]["default"] = "password=FakeSecret12345"
    assert bridge.evaluate(fixture.model_copy(update={"payload_utf8": json.dumps(body)}))[0].decision == "deny"


def test_fixed_wss_protocol_ids_and_start_time_do_not_become_content(tmp_path):
    bridge = _bridge(tmp_path)
    body = {
        "type": "response.create", "model": "fixture",
        "input": [{"type": "message", "role": "user",
                   "id": "msg_79d870c2-718d-471d-8baf-81e475ab4a67",
                   "content": [{"type": "input_text", "text": "Hello"}]}],
        "client_metadata": {"x-codex-ws-stream-request-start-ms": "1790000000005"},
    }
    template = _request({"model": "fixture", "input": "Hello"}, protocol="wss")
    request = template.model_copy(update={"payload_utf8": json.dumps(body)})
    allowed, audit = bridge.evaluate(request)
    assert allowed.decision == "allow"
    assert bridge.archive.read(audit["archive_record_id"])[1] == request.payload_utf8.encode()

    # A non-protocol value in either field remains visible to content policy.
    body["input"][0]["id"] = "password=FakeSecret12345"
    assert bridge.evaluate(template.model_copy(update={"payload_utf8": json.dumps(body)}))[0].decision == "deny"
    body["input"][0]["id"] = "msg_79d870c2-718d-471d-8baf-81e475ab4a67"
    body["client_metadata"]["x-codex-ws-stream-request-start-ms"] = "password=FakeSecret12345"
    assert bridge.evaluate(template.model_copy(update={"payload_utf8": json.dumps(body)}))[0].decision == "deny"


def test_fixed_wss_embedded_turn_timestamp_is_not_a_card(tmp_path):
    bridge = _bridge(tmp_path)
    body = {
        "type": "response.create", "model": "fixture", "input": "Hello",
        "client_metadata": {"x-codex-turn-metadata": json.dumps({
            "turn_started_at_unix_ms": 1790000000005,
            "task": "Public synthetic test",
        })},
    }
    template = _request({"model": "fixture", "input": "Hello"}, protocol="wss")
    request = template.model_copy(update={"payload_utf8": json.dumps(body)})
    allowed, audit = bridge.evaluate(request)
    assert allowed.decision == "allow"
    assert bridge.archive.read(audit["archive_record_id"])[1] == request.payload_utf8.encode()

    body["client_metadata"]["x-codex-turn-metadata"] = json.dumps({
        "turn_started_at_unix_ms": 1790000000005,
        "task": "password=FakeSecret12345",
    })
    assert bridge.evaluate(template.model_copy(update={"payload_utf8": json.dumps(body)}))[0].decision == "deny"


def test_fixed_flat_http_protocol_metadata_uses_same_scoring_view(tmp_path):
    bridge = _bridge(tmp_path)
    body = {"model": "fixture", "stream": True, "input": [{
        "type": "message", "role": "user",
        "id": "msg_79d870c2-718d-471d-8baf-81e475ab4a67",
        "content": [{"type": "input_text", "text": "Hello"}],
    }], "client_metadata": {"x-codex-turn-metadata": json.dumps({
        "turn_started_at_unix_ms": 1790000000005,
    })}}
    assert bridge.evaluate(_request(body))[0].decision == "allow"
    body["input"][0]["content"][0]["text"] = "password=FakeSecret12345"
    assert bridge.evaluate(_request(body))[0].decision == "deny"

    # Duplicate keys must not let JSON normalization discard an earlier secret.
    body["input"][0]["content"][0]["text"] = "Hello"
    body["client_metadata"]["x-codex-turn-metadata"] = (
        '{"turn_started_at_unix_ms":"password=FakeSecret12345",'
        '"turn_started_at_unix_ms":1790000000005}'
    )
    assert bridge.evaluate(_request(body))[0].decision == "deny"


def test_inline_file_data_url_header_cannot_hide_sensitive_bytes(tmp_path):
    bridge = _bridge(tmp_path)
    template = {"model": "fixture", "input": [{"type": "input_file", "filename": "safe.txt",
        "file_data": "data:text/plain;base64,SGVsbG8="}]}
    assert bridge.evaluate(_request(template))[0].decision == "allow"

    for header in ("data:text/plain;name=password=FakeSecret12345;base64,",
                   "data:text/password=FakeSecret12345;base64,"):
        template["input"][0]["file_data"] = header + "SGVsbG8="
        assert bridge.evaluate(_request(template))[0].decision == "deny"
