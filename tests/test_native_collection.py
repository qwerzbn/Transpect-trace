"""Route N collects each new request item once, decides per item and fails closed."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import sys
from pathlib import Path
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.guard.policy import GuardDecision, GuardRequest  # noqa: E402
from transpect_trace.protect import codex_hook_gate as gate  # noqa: E402
from transpect_trace.protect import native_collection as native  # noqa: E402
from transpect_trace.protect.collection import validate_record  # noqa: E402

import install_codex_hook_gate as installer  # noqa: E402
from probe_codex_hook_coverage import FAKE_KEY, MARKER  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "nt",
                                reason="the encrypted archive requires Windows DPAPI")

FIXTURES = ROOT / "tests" / "fixtures" / "codex_collection"


def _body(name):
    return (FIXTURES / f"{name}.json").read_text(encoding="utf-8")


def _request(payload, number=1, *, protocol="http", kind="model.request"):
    return GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": f"4242-{number}",
        "guard_session_id": "4242-133000000000000000", "pid": 4242, "tid": 7, "kind": kind,
        "protocol": "control" if kind != "model.request" else protocol,
        "completeness": "complete", "payload_utf8": payload if kind == "model.request" else ""})


def _engine(tmp_path, mode="enforce"):
    config = gate.GateConfig.load(installer.write_gate_config(tmp_path, mode, None))
    return native.NativeCollectionEngine(config, collection_file=tmp_path / "collection.jsonl")


def _shared_engine(tmp_path):
    config = gate.GateConfig.load(installer.write_gate_config(tmp_path, "enforce", None))
    return native.NativeCollectionEngine(
        config, collection_file=tmp_path / "shared-collection.jsonl",
        archive_full_body=True, shared_request_archive=True)


def _rows(tmp_path):
    rows = [json.loads(line) for line in
            (tmp_path / "collection.jsonl").read_text(encoding="utf-8").splitlines()]
    for row in rows:
        validate_record(row)
    return rows


def _with_agents_secret():
    body = json.loads(_body("http_turn1"))
    part = body["input"][2]["content"][0]
    part["text"] = part["text"].replace("Use short answers.", f"Deploy key {FAKE_KEY}.")
    return json.dumps(body)


def test_turn2_archives_only_new_items(tmp_path):
    engine = _engine(tmp_path)
    first = engine.collector.collect(_request(_body("http_turn1"), 1))
    second = engine.collector.collect(_request(_body("http_turn2"), 2))
    assert first.action == second.action == "ALLOW"
    assert first.envelope["extra"]["items_new"] == first.envelope["extra"]["items_total"] == 7
    assert ({"items_total": 9, "items_new": 2, "items_cached": 7}.items()
            <= second.envelope["extra"].items())
    assert sorted(r["category"] for r in second.records) == [
        "request_envelope", "tool_call_args", "tool_output"]
    output = next(r for r in second.records if r["category"] == "tool_output")
    assert output["extra"] == {"tool_executed_before_decision": True}
    assert (output["call_id"], output["tool_name"]) == ("call_0", "exec_command")
    assert output["session_id"] == "0a1b2c3d-0000-7000-8000-000000000001"
    assert output["first_request_id"] == output["request_id"] == "4242-2"
    assert output["decision_point"] == "before_upstream" and output["released_by_route"]
    archive = engine.gate._archive
    _, payload = archive.read(output["archive_record_id"])
    assert payload.startswith(b"Chunk ID: ")
    assert output["match_hmac"] == archive.keyed_digest(f"meeting notes {MARKER}".encode())
    assert len(_rows(tmp_path)) == len(first.records) + len(second.records) == 8 + 3


def test_shared_request_archive_inspects_items_with_one_durable_save(tmp_path, monkeypatch):
    engine = _shared_engine(tmp_path)
    archive = engine.gate._archive
    original_save = archive.save
    saves = []

    def save(kind, payload, **kwargs):
        saves.append((kind, len(payload)))
        return original_save(kind, payload, **kwargs)

    monkeypatch.setattr(archive, "save", save)
    body = _with_agents_secret()
    result = engine.collector.collect(_request(body))
    assert result.action == "BLOCK" and result.reason == "SENSITIVE_OR_AMBIGUOUS_CONTENT"
    assert saves == [("model_request", len(body.encode()))]
    record_id = result.envelope["archive_record_id"]
    item_rows = [row for row in result.records if row["category"] != "request_envelope"]
    assert item_rows and all(row["archive_record_id"] == record_id
                             and row["archive_kind"] == "model_request"
                             and row["extra"].get("shared_request_archive") is True
                             for row in item_rows)
    assert all(len(native.read_shared_request_item(archive, row)) == row["content_bytes"]
               for row in item_rows)
    blocked = next(row for row in item_rows if row["actionable_decision"] == "BLOCK")
    assert FAKE_KEY.encode() in native.read_shared_request_item(archive, blocked)
    with pytest.raises(ValueError, match="absent or differs"):
        native.read_shared_request_item(archive, {**blocked, "location": "/wrong"})


def test_shared_archive_parallel_requests_preserve_each_decision(tmp_path, monkeypatch):
    engine = _shared_engine(tmp_path)
    archive = engine.gate._archive
    original_save = archive.save
    simultaneous = threading.Barrier(2)

    def save(kind, payload, **kwargs):
        simultaneous.wait(timeout=5)
        return original_save(kind, payload, **kwargs)

    monkeypatch.setattr(archive, "save", save)
    bodies = (_body("http_turn1"), _body("http_turn2"))
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(engine.evaluate, _request(body, number))
                   for number, body in enumerate(bodies, 1)]
        decisions = [future.result(timeout=10) for future in futures]
    assert all(decision.decision == "allow" for decision, _ in decisions)
    rows = [json.loads(line) for line in
            (tmp_path / "shared-collection.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {row["request_id"] for row in rows} == {"4242-1", "4242-2"}
    assert all(row["route_decision"] == "allow" for row in rows)
    for row in rows:
        validate_record(row)
    for body, (_, envelope) in zip(bodies, decisions):
        receipt, recovered = archive.read(envelope["archive_record_id"])
        assert receipt.body_sha256 == hashlib.sha256(body.encode()).hexdigest()
        assert recovered == body.encode()


def test_shared_request_archive_recovers_attachment_and_duplicates(tmp_path, monkeypatch):
    engine = _shared_engine(tmp_path)
    archive = engine.gate._archive
    original_save = archive.save
    saves = []

    def save(kind, payload, **kwargs):
        saves.append(kind)
        return original_save(kind, payload, **kwargs)

    monkeypatch.setattr(archive, "save", save)
    attachment = b"synthetic attachment data"
    body = _turn1_with(part={"type": "input_file", "filename": "notes.txt",
                             "file_data": "data:text/plain;base64," +
                             base64.b64encode(attachment).decode()})
    first = engine.collector.collect(_request(body, 1))
    second = engine.collector.collect(_request(body, 2))
    assert first.action == second.action == "ALLOW"
    assert second.reason == "DUPLICATE_INVOCATION"
    assert saves == ["model_request", "model_request"]
    attachment_row = next(row for row in first.records if row["category"] == "user_attachment")
    assert native.read_shared_request_item(archive, attachment_row) == attachment
    assert second.envelope["archive_record_id"] != first.envelope["archive_record_id"]


def test_shared_request_archive_requires_full_body(tmp_path):
    config = gate.GateConfig.load(installer.write_gate_config(tmp_path, "enforce", None))
    with pytest.raises(ValueError, match="requires archive_full_body"):
        native.NativeCollectionEngine(config, shared_request_archive=True)


_CODEX_THREAD = "00000000-0000-7000-8000-000000000001"
_TURN_A = "00000000-0000-7000-8000-000000000002"
_TURN_B = "00000000-0000-7000-8000-000000000003"


def _history_engine(path):
    config = gate.GateConfig.load(installer.write_gate_config(path, "enforce", None))
    return native.NativeCollectionEngine(config, collection_file=path / "history.jsonl",
                                         archive_full_body=True, shared_request_archive=True,
                                         scrub_codex_denied_history=True)


def _history_request(messages, turn, seq, *, protocol="http", thread=_CODEX_THREAD,
                     wrap=False, incremental=False, **kwargs):
    body = {"model": "test", "client_metadata": {"thread_id": thread, "turn_id": turn},
            "input": [{"type": "message", "role": "user",
                       "content": [{"type": "input_text", "text": part} for part in parts]}
                      for parts in messages], **kwargs}
    if incremental:
        body["previous_response_id"] = "prev"
    if protocol == "wss":
        body = {"type": "response.create", **({"response": body} if wrap else body)}
    return _request(json.dumps(body, ensure_ascii=False, indent=2), seq, protocol=protocol)


@pytest.mark.parametrize(("protocol", "wrap"), [("http", False), ("wss", False), ("wss", True)])
def test_codex_history_scrubs_only_recorded_denial_with_new_safe_user_turn(tmp_path, protocol, wrap):
    engine = _history_engine(tmp_path)
    secret = "合成凭据 " + FAKE_KEY
    routes = {"protocol": protocol, "wrap": wrap}
    first = _history_request([[secret]], _TURN_A, 1, **routes)
    denied, _ = engine.evaluate(first)
    assert denied.decision == "deny" and denied.redacted_payload is None
    following = _history_request([[secret], ["请回答 OK"]], _TURN_B, 2, **routes)
    decision, audit = engine.evaluate(following)
    assert (decision.decision, decision.reason) == ("allow", "HISTORICAL_BLOCK_SCRUBBED")
    clean = decision.redacted_payload.encode()
    assert len(clean) == len(following.payload_utf8.encode())
    assert FAKE_KEY.encode() not in clean
    payload = json.loads(clean)
    message = (payload.get("response", payload))["input"][1]
    assert message["content"] == [{"type": "input_text", "text": "请回答 OK"}]
    assert audit["extra"]["forwarded_body_hmac"] == engine.gate._archive.keyed_digest(clean)
    assert audit["extra"]["history_replacement_count"] == 1
    _, archive_raw = engine.gate._archive.read(audit["archive_record_id"])
    assert archive_raw == following.payload_utf8.encode()
    retry, retry_audit = engine.evaluate(following)
    assert retry.redacted_payload == decision.redacted_payload
    assert retry.reason == decision.reason
    assert retry_audit["extra"]["forwarded_body_hmac"] == audit["extra"]["forwarded_body_hmac"]


def test_codex_recovery_requires_same_thread_distinct_turn_and_new_user_message(tmp_path):
    engine = _history_engine(tmp_path)
    def action(req):
        return engine.evaluate(req)[0].decision

    assert action(_history_request([[FAKE_KEY]], _TURN_A, 1)) == "deny"
    for seq, request in enumerate((
        _history_request([[FAKE_KEY]], _TURN_B, 2),
        _history_request([[FAKE_KEY], ["ok"]], _TURN_A, 3),
        _history_request([[FAKE_KEY, "ok"]], _TURN_B, 4),
        _history_request([[FAKE_KEY], [FAKE_KEY]], _TURN_B, 5),
        _history_request([[FAKE_KEY], ["ok"]], _TURN_B, 6, thread=_TURN_B),
        _history_request([[FAKE_KEY], ["ok"]], None, 7),
        _history_request([[FAKE_KEY], ["ok"]], _TURN_B, 8, incremental=True),
        _history_request([[FAKE_KEY], ["ok"]], _TURN_B, 9, other=FAKE_KEY),
    )):
        assert action(request) == "deny", seq

    fresh_engine = _history_engine(tmp_path / "restarted")
    after_restart = _history_request([[FAKE_KEY], ["ok"]], _TURN_B, 10)
    assert fresh_engine.evaluate(after_restart)[0].decision == "deny"


def test_wss_denied_delta_uses_unique_message_id_and_complete_user_message(tmp_path):
    msg = {"type": "message", "id": "msg_" + _TURN_A, "role": "user",
           "content": [{"type": "input_text", "text": FAKE_KEY}]}
    benign = {"type": "message", "id": "msg_" + _TURN_B, "role": "user",
              "content": [{"type": "input_text", "text": "Reply about tea."}]}
    system = {"type": "message", "role": "developer", "content": "Be concise."}
    request = lambda entries, turn, seq, **kw: _history_request(
        [], turn, seq, protocol="wss", input=entries, **kw)
    cases = [
        ([system, msg, benign], _TURN_B, {}, "allow"),
        ([system, msg, benign], _TURN_A, {}, "deny"),
        ([system, msg, benign], _TURN_B, {"thread": _TURN_B}, "deny"),
        ([system, msg, benign], _TURN_B, {"incremental": True}, "deny"),
        ([system, msg, benign, msg], _TURN_B, {}, "deny"),
        ([system, msg, msg, benign], _TURN_B, {}, "deny"),
        ([system, {**msg, "id": "msg_" + _CODEX_THREAD}, benign], _TURN_B, {}, "deny"),
        ([system, msg, benign, {**msg, "id": "msg_" + _CODEX_THREAD}], _TURN_B, {}, "deny"),
        ([system, {**msg, "content": msg["content"] + benign["content"]}, benign], _TURN_B, {}, "deny"),
        ([system, {**msg, "role": "assistant"}, benign], _TURN_B, {}, "deny"),
        ([system, benign, msg], _TURN_B, {}, "deny"),
    ]
    for index, (entries, turn_id, options, expected) in enumerate(cases):
        engine = _history_engine(tmp_path / str(index))
        assert engine.evaluate(request([msg], _TURN_A, 1, incremental=True))[0].decision == "deny"
        decision, _ = engine.evaluate(request(entries, turn_id, 2, **options))
        assert decision.decision == expected, index
        if expected == "allow":
            assert FAKE_KEY not in decision.redacted_payload
        else:
            assert decision.redacted_payload is None


def test_shared_archive_failure_and_partial_capture_stay_denied(tmp_path, monkeypatch):
    engine = _shared_engine(tmp_path)
    body = _body("http_turn1")
    archive = engine.gate._archive
    original_save = archive.save

    def fail_save(*_args, **_kwargs):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(archive, "save", fail_save)
    failed = engine.collector.collect(_request(body, 1))
    assert failed.action == "BLOCK" and failed.reason == "COLLECTION_FAILED_OSError"
    monkeypatch.setattr(archive, "save", original_save)
    partial = _request(body, 2).model_copy(update={"completeness": "partial"})
    result = engine.collector.collect(partial)
    assert result.action == "BLOCK" and result.reason == "INCOMPLETE_CONTENT"
    _, stored = archive.read(result.envelope["archive_record_id"])
    assert stored == body.encode()


def test_duplicate_invocation_reuses_decision_without_records(tmp_path):
    engine = _engine(tmp_path)
    first = engine.collector.collect(_request(_with_agents_secret(), 1))
    again = engine.collector.collect(_request(_with_agents_secret(), 2))
    assert first.action == again.action == "BLOCK"
    assert again.reason == "DUPLICATE_INVOCATION"
    (envelope,) = again.records
    assert envelope["category"] == "request_envelope"
    assert envelope["extra"] == {"duplicate_invocation": True}
    assert envelope["first_request_id"] == "4242-1" and envelope["request_id"] == "4242-2"
    assert envelope["route_decision"] == "deny"


def test_cached_blocked_item_still_blocks_later_request(tmp_path):
    engine = _engine(tmp_path)
    assert engine.collector.collect(_request(_with_agents_secret(), 1)).action == "BLOCK"
    body = json.loads(_with_agents_secret())
    body["input"].append({"type": "message", "role": "user",
                          "content": [{"type": "input_text", "text": "try again"}]})
    later = engine.collector.collect(_request(json.dumps(body), 2))
    assert later.action == "BLOCK"
    assert later.envelope["extra"]["items_new"] == 1
    assert {r["category"] for r in later.records} == {"user_prompt", "request_envelope"}
    assert all(r["route_decision"] == "deny" for r in later.records)


def test_agents_md_secret_blocks_request(tmp_path):
    engine = _engine(tmp_path)
    decision, row = engine.evaluate(_request(_with_agents_secret()))
    assert (decision.decision, decision.action) == ("deny", "block_request")
    assert row["decision"] == "deny" and row["action"] == "BLOCK"
    rows = _rows(tmp_path)
    (agents,) = [r for r in rows if r["category"] == "client_instructions"]
    assert agents["actionable_decision"] == "BLOCK" and agents["categories"] == ["SECRET"]
    assert all(r["actionable_decision"] == "ALLOW" for r in rows
               if r["category"] not in ("client_instructions", "request_envelope"))
    text = (tmp_path / "collection.jsonl").read_text(encoding="utf-8")
    assert FAKE_KEY not in text and "Deploy key" not in text and "read notes" not in text


def test_observe_mode_allows_but_records(tmp_path):
    engine = _engine(tmp_path, "enforce")
    observe = native.NativeCollectionEngine(engine.gate.config, mode="observe",
                                            collection_file=tmp_path / "collection.jsonl")
    decision, row = observe.evaluate(_request(_with_agents_secret()))
    assert decision.decision == "allow" and row["action"] == "BLOCK"
    rows = _rows(tmp_path)
    assert {r["gate_mode"] for r in rows} == {"observe"}
    assert all(r["route_decision"] == "observe_allow" and r["released_by_route"] for r in rows)
    with pytest.raises(ValueError):
        native.NativeCollectionEngine(engine.gate.config, mode="audit")


def test_parse_failure_fails_closed_with_unknown_record(tmp_path):
    engine = _engine(tmp_path)
    result = engine.collector.collect(_request("not json at all"))
    assert (result.action, result.reason) == ("BLOCK", "WIRE_PARSE_FAILED")
    (unknown,) = [r for r in result.records if r["category"] == "unknown"]
    assert unknown["inspected"] is False and "WIRE_PARSE_FAILED" in unknown["matched_rule_ids"]
    assert result.envelope["extra"]["format"] == "unparsed"
    # A delta message is itemized like a full body and flagged incremental.
    delta = engine.collector.collect(_request(_body("wss_incremental"), 2, protocol="wss"))
    assert delta.action == "ALLOW"
    assert [r["category"] for r in delta.records] == ["tool_output", "request_metadata",
                                                       "request_envelope"]
    assert delta.envelope["extra"]["incremental"] is True
    # A failure inside collection blocks too, without writing rows.
    engine.collector.writer.path = tmp_path
    failed = engine.collector.collect(_request(_body("http_turn1"), 3))
    assert failed.action == "BLOCK" and failed.reason.startswith("COLLECTION_FAILED_")
    engine.collector.writer.path = tmp_path / "collection.jsonl"
    retried = engine.collector.collect(_request(_body("http_turn1"), 4))
    assert retried.action == "ALLOW" and retried.envelope["extra"]["items_new"] == 7


@pytest.mark.parametrize("completeness", ["partial", "unknown"])
@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_incomplete_native_capture_never_releases_or_reuses_allow(
        tmp_path, completeness, mode):
    engine = _engine(tmp_path, mode)
    body = _body("http_turn1")
    complete = _request(body, 1)
    partial = _request(body, 2).model_copy(update={"completeness": completeness})

    # A previous allow for the same bytes cannot make a later partial capture safe.
    assert engine.collector.collect(complete).action == "ALLOW"
    decision, envelope = engine.evaluate(partial)
    assert (decision.decision, decision.action, decision.reason) == (
        "deny", "block_request", "INCOMPLETE_CONTENT")
    assert envelope["decision"] == "deny"
    assert envelope["extra"] == {"capture_completeness": completeness,
                                 "limitations": ["capture_incomplete"]}
    assert envelope["route_decision"] == "deny"
    assert envelope["released_by_route"] is False
    assert envelope["category"] == "request_envelope"
    assert envelope["archive_record_id"] is None

    # A partial observation must not poison the next complete capture's cache.
    fresh_root = tmp_path / "fresh"
    fresh_root.mkdir()
    fresh = _engine(fresh_root, mode)
    assert fresh.collector.collect(partial).action == "BLOCK"
    allowed = fresh.collector.collect(complete)
    assert (allowed.action, allowed.reason) == ("ALLOW", "REQUIRED_CHECKS_COMPLETE")
    assert allowed.envelope["extra"]["items_new"] == 7


def test_incomplete_capture_full_body_archive_preserves_observed_bytes(tmp_path):
    ordinary = _engine(tmp_path)
    engine = native.NativeCollectionEngine(
        ordinary.gate.config, collection_file=tmp_path / "full-collection.jsonl",
        archive_full_body=True)
    request = _request(_body("http_turn1")).model_copy(update={"completeness": "partial"})
    result = engine.collector.collect(request)
    assert (result.action, result.reason) == ("BLOCK", "INCOMPLETE_CONTENT")
    receipt, stored = engine.gate._archive.read(result.envelope["archive_record_id"])
    assert receipt.kind == "model_request"
    assert stored == request.payload_utf8.encode("utf-8")


@pytest.mark.parametrize("payload,action", [
    ("http_turn1", "ALLOW"),
    ("secret", "BLOCK"),
])
def test_capture_only_archives_full_body_without_enforcement_claims(tmp_path, payload, action):
    config = gate.GateConfig.load(installer.write_gate_config(tmp_path, "enforce", None))
    with pytest.raises(ValueError, match="archive_full_body"):
        native.NativeCollectionEngine(config, capture_only=True)
    engine = native.NativeCollectionEngine(
        config, collection_file=tmp_path / "observed-collection.jsonl",
        archive_full_body=True, capture_only=True)
    body = _body(payload) if payload != "secret" else _with_agents_secret()
    request = _request(body)

    result = engine.collector.collect(request)
    assert result.action == action
    assert all(row["route"] == "native" and row["decision_point"] == "none"
               and row["route_decision"] == "not_enforceable"
               and row["released_by_route"] is None and row["gate_mode"] == "observe"
               for row in result.records)
    assert result.envelope["collection"] == "content"
    assert result.envelope["request_sha256"] == hashlib.sha256(body.encode("utf-8")).hexdigest()
    receipt, stored = engine.gate._archive.read(result.envelope["archive_record_id"])
    assert receipt.kind == "model_request" and stored == body.encode("utf-8")
    rows = [json.loads(line) for line in
            (tmp_path / "observed-collection.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == len(result.records)
    for row in rows:
        validate_record(row)
    with pytest.raises(ValueError, match="capture_only cannot serve pipe"):
        engine.evaluate(request)


def test_capture_only_duplicate_and_partial_have_no_enforcement_claim(tmp_path, monkeypatch):
    config = gate.GateConfig.load(installer.write_gate_config(tmp_path, "enforce", None))
    engine = native.NativeCollectionEngine(config, archive_full_body=True, capture_only=True)
    monkeypatch.setattr(native, "_DECISION_BUDGET_SECONDS", 0.0)
    body = _body("http_turn1")
    first = engine.collector.collect(_request(body, 1))
    duplicate = engine.collector.collect(_request(body, 2))
    partial = engine.collector.collect(
        _request(body, 3).model_copy(update={"completeness": "partial"}))
    assert (first.action, duplicate.action, partial.action) == ("ALLOW", "ALLOW", "BLOCK")
    assert duplicate.reason == "DUPLICATE_INVOCATION"
    assert duplicate.envelope["archive_record_id"] is not None
    assert partial.reason == "INCOMPLETE_CONTENT"
    assert all(row["decision_point"] == "none"
               and row["route_decision"] == "not_enforceable"
               and row["released_by_route"] is None
               for result in (first, duplicate, partial) for row in result.records)


def _turn1_with(*items, part=None):
    body = json.loads(_body("http_turn1"))
    body["input"].extend(items)
    if part is not None:
        body["input"][-1]["content"].append(part)
    return json.dumps(body)


def test_inline_document_reasoning_and_extra_fields_are_inspected(tmp_path):
    engine = _engine(tmp_path)
    data = base64.b64encode(f"password = {FAKE_KEY}".encode()).decode()
    cases = {
        "user_attachment": _turn1_with(part={"type": "input_file", "filename": "creds.txt",
                                             "file_data": "data:text/plain;base64," + data}),
        "reasoning_opaque": _turn1_with({"type": "reasoning", "encrypted_content": None,
                                         "summary": [{"type": "summary_text",
                                                      "text": f"The key is {FAKE_KEY}"}]}),
        "request_metadata": _turn1_with({"type": "function_call_output", "call_id": "c9",
                                         "output": "ok", "status": f"{FAKE_KEY}-st"}),
        "unknown": _turn1_with({"type": "function_call_output", "call_id": "c9",
                                "output": "ok", "note": f"{FAKE_KEY}-st"}),
    }
    for number, (category, payload) in enumerate(cases.items(), 1):
        result = engine.collector.collect(_request(payload, number))
        assert result.action == "BLOCK", category
        (row,) = [r for r in result.records if r["actionable_decision"] == "BLOCK"
                  and r["category"] != "request_envelope"]
        assert row["category"] == category and row["inspected"] is True


def test_malformed_image_is_a_gap_not_a_parse_failure(tmp_path):
    engine = _engine(tmp_path)
    result = engine.collector.collect(_request(_turn1_with(part={
        "type": "input_image", "image_url": "data:image/png;base64,iVBORw0KGgo=\n"})))
    assert (result.action, result.reason) == ("ALLOW", "REQUIRED_CHECKS_COMPLETE")
    (image,) = [r for r in result.records if r["archive_kind"] == "attachment"]
    assert image["matched_rule_ids"] == ["IMAGE_UNINSPECTED"] and image["inspected"] is False


def test_delta_records_its_inline_image_as_a_gap(tmp_path):
    engine = _engine(tmp_path)
    body = json.loads(_body("wss_incremental"))
    url = "data:image/png;base64," + base64.b64encode(b"\x89PNG synthetic").decode()
    body["input"].append({"type": "message", "role": "user",
                          "content": [{"type": "input_image", "image_url": url}]})
    result = engine.collector.collect(_request(json.dumps(body), protocol="wss"))
    assert result.action == "ALLOW"
    (image,) = [r for r in result.records if r["archive_kind"] == "attachment"]
    assert image["category"] == "user_attachment"
    assert image["matched_rule_ids"] == ["IMAGE_UNINSPECTED"]


def _desktop_delta(*items):
    """A 0.166 desktop WSS delta: custom tool items with client bookkeeping."""
    body = json.loads(_body("wss_incremental"))
    body["input"] = list(items)
    return json.dumps(body)


_PASSTHROUGH = {"internal_chat_message_metadata_passthrough": {
    "create_time": 1793934410.5, "turn_id": "0a1b2c3d-0000-7000-8000-00000000000a"}}


def test_desktop_custom_tool_items_get_their_categories(tmp_path):
    engine = _engine(tmp_path)
    benign = engine.collector.collect(_request(_desktop_delta(
        {"type": "additional_tools", "id": "at_1", "role": "developer",
         "tools": [{"type": "namespace", "name": "synthetic", "description": "d", "tools": []}]},
        {"type": "custom_tool_call", "id": "ctc_1", "call_id": "call_9", "name": "shell",
         "input": "Get-Content build_log.txt", "status": "completed", **_PASSTHROUGH},
        {"type": "custom_tool_call_output", "id": "ctco_1", "call_id": "call_9",
         "output": [{"type": "input_text", "text": "ordinary build output"}], **_PASSTHROUGH},
    ), 1, protocol="wss"))
    assert benign.action == "ALLOW"
    rows = {r["category"]: r for r in benign.records}
    assert {"tool_definitions", "tool_call_args", "tool_output", "request_metadata"} <= set(rows)
    assert "unknown" not in rows
    assert rows["tool_output"]["call_id"] == "call_9" and rows["tool_output"]["tool_name"] == "shell"
    # The bookkeeping turn UUID no longer scores as a token.
    assert not any("ENTROPY" in rule for r in benign.records for rule in r["matched_rule_ids"])
    leaked = engine.collector.collect(_request(_desktop_delta(
        {"type": "custom_tool_call_output", "id": "ctco_2", "call_id": "call_9",
         "output": [{"type": "input_text", "text": f"{MARKER} build token {FAKE_KEY}"}],
         **_PASSTHROUGH}), 2, protocol="wss"))
    assert leaked.action == "BLOCK"
    (row,) = [r for r in leaked.records if r["actionable_decision"] == "BLOCK"
              and r["category"] != "request_envelope"]
    assert row["category"] == "tool_output"


def test_secret_in_desktop_bookkeeping_is_still_inspected(tmp_path):
    engine = _engine(tmp_path)
    meta = {"internal_chat_message_metadata_passthrough": {"turn_id": FAKE_KEY}}
    result = engine.collector.collect(_request(_desktop_delta(
        {"type": "custom_tool_call_output", "call_id": "c1", "output": "ok", **meta}),
        protocol="wss"))
    assert result.action == "BLOCK"
    (row,) = [r for r in result.records if r["actionable_decision"] == "BLOCK"
              and r["category"] != "request_envelope"]
    assert row["category"] == "request_metadata"


def test_lone_surrogate_body_blocks_with_a_record(tmp_path):
    engine = _engine(tmp_path)
    result = engine.collector.collect(_request('{"input": "\ud800"}'))
    assert result.action == "BLOCK" and result.records


def test_late_decision_is_recorded_as_the_pipe_will_enforce_it(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    monkeypatch.setattr(native, "_DECISION_BUDGET_SECONDS", 0.0)
    result = engine.collector.collect(_request(_body("http_turn1"), 1))
    assert (result.action, result.reason) == ("BLOCK", "DECISION_DEADLINE_EXCEEDED")
    assert all(r["route_decision"] == "deny" for r in result.records)
    assert result.envelope["extra"]["deadline_exceeded"] is True
    assert engine.collector.collect(_request(_body("http_turn1"), 2)).action == "BLOCK"


def test_pipe_deadline_supersedes_an_allow(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    monkeypatch.setattr(native, "DECISION_DEADLINE_SECONDS", 0.0)
    decision, row = engine.evaluate(_request(_body("http_turn1"), 1))
    assert (decision.decision, decision.redacted_payload, row["action"], row["reason"]) == (
        "deny", None, "BLOCK", "DECISION_DEADLINE_EXCEEDED")
    assert row["released_by_route"] is False
    rows = _rows(tmp_path)
    superseding = [r for r in rows if r["extra"].get("superseded_reason")]
    assert superseding and len(superseding) == len(rows) // 2
    assert all(not r["released_by_route"] for r in superseding)
    again = engine.collector.collect(_request(_body("http_turn1"), 2))
    assert (again.action, again.reason) == ("BLOCK", "DUPLICATE_INVOCATION")


def test_superseding_audit_error_cannot_release_a_late_decision(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    monkeypatch.setattr(native, "DECISION_DEADLINE_SECONDS", 0.0)

    def fail(*_):
        raise OSError("simulated write failure")

    monkeypatch.setattr(engine.collector, "supersede", fail)
    decision, row = engine.evaluate(_request(_body("http_turn1")))
    assert decision.decision == row["route_decision"] == "deny"
    assert decision.reason == "DECISION_DEADLINE_EXCEEDED"
    assert decision.redacted_payload is None


def test_engine_satisfies_pipe_server_contract(tmp_path):
    engine = _engine(tmp_path)
    assert engine.policy.version.startswith("native-collection/1:")
    control, row = engine.evaluate(_request("", kind="native.initialize"))
    assert isinstance(control, GuardDecision) and control.decision == "allow" and row is None
    decision, row = engine.evaluate(_request(_body("http_turn1")))
    assert isinstance(decision, GuardDecision)
    assert (decision.decision, decision.action, decision.reason) == (
        "allow", "none", "REQUIRED_CHECKS_COMPLETE")
    assert decision.policy_version == engine.policy.version and len(decision.policy_version) <= 127
    assert row["decision"] == "allow" and row["category"] == "request_envelope"
    json.dumps(row)
