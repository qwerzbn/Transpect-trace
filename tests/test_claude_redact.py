"""Redact 模式单元测试：BLOCK 条目被清洗、决策转 allow 且携带清洗正文。"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from transpect_trace.guard.policy import GuardRequest
from transpect_trace.protect.codex_hook_gate import GateConfig
from transpect_trace.protect.native_collection import NativeCollectionEngine

TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8iJ9J0k1L2m3N4o5P6q7R8"
TOKEN_B = "ghp_" + "z9Y8x7W6v5U4t3S2r1Q0p9O8n7M6l5K4j3I2"


def _body() -> str:
    return json.dumps({
        "model": "claude-haiku-5-5",
        "max_tokens": 1024,
        "stream": True,
        "system": "You are concise.",
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": f"请原样回复，内部部署令牌：{TOKEN}"}]},
        ],
    }, ensure_ascii=False)


def _engine(tmp_path: Path, redact: bool, *, scrub_denied_history: bool = False) -> NativeCollectionEngine:
    config = GateConfig(
        mode="enforce",
        archive_directory=tmp_path / "archive",
        audit_file=tmp_path / "audit.jsonl",
        registration_directory=None,
        collection_file=tmp_path / "collection.jsonl",
        redact_on_block=redact,
    )
    return NativeCollectionEngine(config, archive_full_body=True,
                                  shared_request_archive=True,
                                  allowed_formats=frozenset(("anthropic_messages",)),
                                  scrub_denied_history=scrub_denied_history)


def _request() -> GuardRequest:
    return GuardRequest(
        schema="transpect.guard.request/1.0",
        request_id="r-1", guard_session_id="s-1", pid=1, tid=0,
        kind="model.request", protocol="http", completeness="complete",
        payload_utf8=_body(),
    )


def test_redact_mode_allows_with_cleaned_payload(tmp_path):
    engine = _engine(tmp_path, redact=True)
    decision, row = engine.evaluate(_request())
    assert decision.decision == "allow"
    assert decision.redacted_payload is not None
    assert TOKEN not in decision.redacted_payload
    assert "已脱敏" in decision.redacted_payload
    # 清洗后的正文仍是合法 Messages 结构
    parsed = json.loads(decision.redacted_payload)
    assert parsed["messages"][0]["content"][0]["type"] == "text"


def test_enforce_mode_still_denies(tmp_path):
    engine = _engine(tmp_path, redact=False)
    decision, _row = engine.evaluate(_request())
    assert decision.decision == "deny"
    assert decision.redacted_payload is None


def test_claude_service_does_not_allow_blocked_turn_with_legacy_env(tmp_path, monkeypatch):
    from transpect_trace.guard.claude_service import _engine as claude_engine

    monkeypatch.setenv("TTRACE_CLAUDE_REDACT", "1")
    decision, _ = claude_engine(tmp_path).evaluate(_request())
    assert decision.decision == "deny"
    assert decision.redacted_payload is None


def test_benign_passes_unchanged(tmp_path):
    engine = _engine(tmp_path, redact=True)
    request = _request()
    request = request.model_copy(update={
        "payload_utf8": json.dumps({
            "model": "claude-haiku-5-5", "max_tokens": 1024, "stream": True,
            "system": "You are concise.",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "你好"}]}],
        }, ensure_ascii=False)})
    decision, _row = engine.evaluate(request)
    assert decision.decision == "allow"
    assert decision.redacted_payload is None


def test_cached_blocked_item_is_redacted_in_followup(tmp_path):
    engine = _engine(tmp_path, redact=True)
    first = _request()
    first_decision, _ = engine.evaluate(first)
    assert first_decision.decision == "allow"
    body = json.loads(first.payload_utf8)
    body["messages"][0]["content"].append(
        {"type": "text", "text": f"internal token: {TOKEN_B}"})
    second = first.model_copy(update={"request_id": "r-2",
                                      "payload_utf8": json.dumps(body, ensure_ascii=False)})
    decision, _ = engine.evaluate(second)
    assert decision.decision == "allow"
    assert decision.redacted_payload is not None
    assert TOKEN not in decision.redacted_payload
    assert TOKEN_B not in decision.redacted_payload
    assert len(decision.redacted_payload.encode()) == len(second.payload_utf8.encode())


def test_blocked_turn_is_denied_but_later_benign_turn_recovers(tmp_path):
    engine = _engine(tmp_path, redact=False, scrub_denied_history=True)
    first = _request()
    denied, _ = engine.evaluate(first)
    assert denied.decision == "deny"
    assert denied.redacted_payload is None

    body = json.loads(first.payload_utf8)
    body["messages"].append({"role": "assistant", "content": "Request failed."})
    body["messages"].append({"role": "user", "content": [
        {"type": "text", "text": "现在只回答 OK"}]})
    second = first.model_copy(update={"request_id": "r-2",
                                      "payload_utf8": json.dumps(body, ensure_ascii=False)})
    continued, row = engine.evaluate(second)
    assert continued.decision == "allow"
    assert continued.reason == "HISTORICAL_BLOCK_SCRUBBED"
    assert row["extra"]["history_scrubbed"] is True
    assert continued.redacted_payload is not None
    assert TOKEN not in continued.redacted_payload
    assert len(continued.redacted_payload.encode()) == len(second.payload_utf8.encode())
    assert json.loads(continued.redacted_payload)["messages"][-1]["content"][0]["text"] == "现在只回答 OK"


def test_blocked_turn_retry_and_fresh_secret_stay_denied(tmp_path):
    engine = _engine(tmp_path, redact=False, scrub_denied_history=True)
    first = _request()
    assert engine.evaluate(first)[0].decision == "deny"
    same_turn = first.model_copy(update={"request_id": "r-2"})
    assert engine.evaluate(same_turn)[0].decision == "deny"
    body = json.loads(first.payload_utf8)
    body["messages"].append({"role": "user", "content": [
        {"type": "text", "text": "新的令牌：" + TOKEN_B}]})
    new_secret = first.model_copy(update={"request_id": "r-3",
        "payload_utf8": json.dumps(body, ensure_ascii=False)})
    assert engine.evaluate(new_secret)[0].decision == "deny"
    repeated = json.loads(first.payload_utf8)
    repeated["messages"].append({"role": "user", "content": [
        {"type": "text", "text": "再次发送 " + TOKEN},
        {"type": "text", "text": "现在回答 OK"}]})
    repeated_request = first.model_copy(update={"request_id": "r-4",
        "payload_utf8": json.dumps(repeated, ensure_ascii=False)})
    assert engine.evaluate(repeated_request)[0].decision == "deny"
    repeated["messages"][1]["content"].append(
        {"type": "text", "text": "最终只回答 OK"})
    after_repeat = first.model_copy(update={"request_id": "r-5",
        "payload_utf8": json.dumps(repeated, ensure_ascii=False)})
    continued, _ = engine.evaluate(after_repeat)
    assert continued.decision == "allow"
    assert TOKEN not in continued.redacted_payload


def test_blocked_tool_result_does_not_poison_later_question(tmp_path):
    engine = _engine(tmp_path, redact=False, scrub_denied_history=True)
    body = {
        "model": "claude-sonnet-4-5", "max_tokens": 512, "stream": True,
        "messages": [
            {"role": "user", "content": "read secret.txt"},
            {"role": "assistant", "content": [{"type": "tool_use",
                "id": "toolu_123", "name": "Read", "input": {"file_path": "secret.txt"}}]},
            {"role": "user", "content": [{"type": "tool_result",
                "tool_use_id": "toolu_123", "content": [
                    {"type": "text", "text": "internal token: " + TOKEN}]}]},
        ],
    }
    first = _request().model_copy(update={"payload_utf8": json.dumps(body, ensure_ascii=False)})
    denied, _ = engine.evaluate(first)
    assert denied.decision == "deny"
    assert denied.redacted_payload is None
    body["messages"][2]["content"].append({"type": "text", "text": "现在回答 OK"})
    second = first.model_copy(update={"request_id": "r-2",
                                      "payload_utf8": json.dumps(body, ensure_ascii=False)})
    continued, row = engine.evaluate(second)
    assert continued.decision == "allow"
    assert row["extra"]["history_scrubbed"] is True
    assert TOKEN not in continued.redacted_payload
    assert len(continued.redacted_payload.encode()) == len(second.payload_utf8.encode())


def test_blocked_base64_tool_result_allows_later_safe_question(tmp_path):
    engine = _engine(tmp_path, redact=False, scrub_denied_history=True)
    encoded = base64.b64encode(("internal token: " + TOKEN).encode()).decode()
    body = {
        "model": "claude-sonnet-4-5", "max_tokens": 512, "stream": True,
        "messages": [
            {"role": "user", "content": "read encoded.txt"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_123",
                "name": "Bash", "input": {"command": "cat encoded.txt"}}]},
            {"role": "user", "content": [{"type": "tool_result",
                "tool_use_id": "toolu_123", "content": encoded}]},
        ],
    }
    first = _request().model_copy(update={"payload_utf8": json.dumps(body, ensure_ascii=False)})
    denied, _ = engine.evaluate(first)
    assert denied.decision == "deny"
    assert denied.redacted_payload is None

    body["messages"][2]["content"].append({"type": "text", "text": "现在回答 OK"})
    second = first.model_copy(update={"request_id": "r-2",
                                      "payload_utf8": json.dumps(body, ensure_ascii=False)})
    continued, row = engine.evaluate(second)
    assert continued.decision == "allow"
    assert row["extra"]["history_scrubbed"] is True
    assert encoded not in continued.redacted_payload
    assert TOKEN not in continued.redacted_payload


@pytest.mark.parametrize("indent,ascii_escaped", [(None, False), (2, False), (4, True)])
def test_redaction_preserves_exact_json_bytes(tmp_path, indent, ascii_escaped):
    engine = _engine(tmp_path, redact=True)
    original = _request()
    raw = json.dumps(json.loads(original.payload_utf8), indent=indent,
                     ensure_ascii=ascii_escaped)
    request = original.model_copy(update={"payload_utf8": raw})
    decision, _ = engine.evaluate(request)
    assert decision.decision == "allow"
    assert decision.redacted_payload is not None
    assert TOKEN not in decision.redacted_payload
    assert len(decision.redacted_payload.encode()) == len(raw.encode())
    parsed = json.loads(decision.redacted_payload)
    assert parsed["messages"][0]["content"][0]["type"] == "text"


def test_tool_result_and_reviewed_path_are_cleaned_together(tmp_path):
    engine = _engine(tmp_path, redact=True)
    body = {
        "model": "claude-sonnet-4-5", "max_tokens": 512, "stream": True,
        "messages": [
            {"role": "user", "content": "read secret.txt"},
            {"role": "assistant", "content": [{"type": "tool_use",
                "id": "toolu_123", "name": "Read", "input": {"file_path": "secret.txt"}}]},
            {"role": "user", "content": [{"type": "tool_result",
                "tool_use_id": "toolu_123", "content": [
                    {"type": "text", "text": "internal token: " + TOKEN}]}]},
        ],
    }
    raw = json.dumps(body, ensure_ascii=False, indent=2)
    request = _request().model_copy(update={"payload_utf8": raw})
    decision, _ = engine.evaluate(request)
    assert decision.decision == "allow"
    assert decision.redacted_payload is not None
    assert TOKEN not in decision.redacted_payload
    parsed = json.loads(decision.redacted_payload)
    assert parsed["messages"][1]["content"][0]["input"]["file_path"] != "secret.txt"
    assert len(decision.redacted_payload.encode()) == len(raw.encode())


def test_shadowed_duplicate_json_key_is_denied(tmp_path):
    engine = _engine(tmp_path, redact=True)
    raw = _body().replace('"text": "请原样回复，内部部署令牌：' + TOKEN + '"',
                          '"text": "内部部署令牌：' + TOKEN + '", "text": "你好"')
    assert raw != _body() and raw.count('"text":') == 2
    request = _request().model_copy(update={"payload_utf8": raw})
    decision, _ = engine.evaluate(request)
    assert decision.decision == "deny"
    assert decision.redacted_payload is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
