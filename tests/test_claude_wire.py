"""Anthropic Messages content is itemized before the native policy decision."""
import base64
from dataclasses import replace
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect import wire_items  # noqa: E402
from transpect_trace.protect.native_collection import NativeRequestCollector  # noqa: E402


def _body(**changes):
    body = {
        "model": "claude-sonnet-4-5", "max_tokens": 512, "stream": True,
        "system": [{"type": "text", "text": "Protect customer data.",
                    "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": "Summarize this ticket."},
            {"role": "assistant", "content": [
                {"type": "text", "text": "I will read the ticket."},
                {"type": "tool_use", "id": "toolu_123", "name": "read_ticket",
                 "input": {"ticket_id": "INC-7"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_123",
                 "content": [{"type": "text", "text": "The customer email is alice@example.com"}]}]},
        ],
        "tools": [{"name": "read_ticket", "description": "Fetch a support ticket",
                   "input_schema": {"type": "object", "properties": {
                       "ticket_id": {"type": "string"}}}}],
    }
    body.update(changes)
    return body


def _parse(body):
    return wire_items.parse_wire_request(json.dumps(body).encode(), protocol="http")


def test_messages_system_tools_and_tool_result_are_separate_inspection_items():
    request = _parse(_body())
    assert request.format == "anthropic_messages"
    assert request.correlation["model"] == "claude-sonnet-4-5"
    by_category = {}
    for item in request.items:
        by_category.setdefault(item.category, []).append(item)
    assert [item.location for item in by_category["system_developer_prompt"]] == [
        "/system/0"]
    assert by_category["user_prompt"][0].payload == b"Summarize this ticket."
    assert by_category["model_output_history"][0].payload == b"I will read the ticket."
    (call,) = by_category["tool_call_args"]
    assert (call.call_id, call.tool_name) == ("toolu_123", "read_ticket")
    assert call.inspect_text == "tool_name=read_ticket\nticket_id\nINC-7"
    (output,) = by_category["tool_output"]
    assert (output.call_id, output.tool_name) == ("toolu_123", "read_ticket")
    assert output.inspect_text == "The customer email is alice@example.com"
    assert by_category["tool_definitions"][0].location == "/tools/0"
    assert any("cache_control" in item.inspect_text
               for item in by_category["request_metadata"])
    assert all("Authorization" not in item.inspect_text for item in request.items)


def test_inline_pdf_and_image_bytes_are_itemized_without_base64_text():
    pdf = b"%PDF-1.4\nsynthetic document bytes"
    png = b"\x89PNG\r\n\x1a\nsynthetic pixels"
    body = _body(messages=[{"role": "user", "content": [
        {"type": "document", "source": {"type": "base64",
         "media_type": "application/pdf", "data": base64.b64encode(pdf).decode()},
         "title": "ticket.pdf"},
        {"type": "image", "source": {"type": "base64",
         "media_type": "image/png", "data": base64.b64encode(png).decode()}},
    ]}])
    request = _parse(body)
    attachments = [item for item in request.items if item.archive_kind == "attachment"]
    assert [(item.category, item.location, item.payload) for item in attachments] == [
        ("user_attachment", "/messages/0/content/0", pdf),
        ("user_attachment", "/messages/0/content/1", png)]
    assert attachments[0].file_name == "document.pdf" and attachments[0].inspectable
    assert not attachments[1].inspectable
    assert attachments[1].findings == (("INSPECTION_ERROR",
                                        "CLAUDE_ATTACHMENT_UNINSPECTABLE", 1.0),)
    assert all("base64" not in item.inspect_text for item in request.items)
    assert any(item.inspect_text == "title\nticket.pdf" for item in request.items)


def test_tool_result_image_keeps_tool_provenance_and_blocks():
    png = b"\x89PNG\r\n\x1a\nsynthetic pixels"
    body = _body(messages=[
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_img",
            "name": "capture_screen", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result",
            "tool_use_id": "toolu_img", "content": [{"type": "image", "source": {
                "type": "base64", "media_type": "image/png",
                "data": base64.b64encode(png).decode()}}]}]},
    ])
    image = next(item for item in _parse(body).items if item.category == "tool_output_image")
    assert (image.call_id, image.tool_name, image.payload) == (
        "toolu_img", "capture_screen", png)
    assert image.findings[0][0] == "INSPECTION_ERROR"


@pytest.mark.parametrize("block", [
    {"type": "image", "source": {"type": "url", "url": "https://example.invalid/x.png"}},
    {"type": "document", "source": {"type": "file", "file_id": "file_123"}},
    {"type": "document", "source": {"type": "base64",
     "media_type": "application/pdf", "data": "%%%"}},
    {"type": "future_content_block", "value": "unmodeled"},
    {"type": "redacted_thinking", "data": "opaque"},
    {"type": "text", "text": "data:application/pdf;base64,JVBERi0xLjQ="},
    {"type": "text", "text": "safe", "extra": {
        "type": "base64", "data": "JVBERi0xLjQ="}},
    {"type": "text", "text": "\ud800"},
])
def test_unavailable_or_unknown_content_fails_closed(block):
    raw = json.dumps(_body(messages=[{"role": "user", "content": [block]}])).encode()
    with pytest.raises((ValueError, UnicodeError)):
        wire_items.parse_wire_request(raw, protocol="http")
    wire, items, failed = NativeRequestCollector._items(raw, "http")
    assert wire is None and failed
    assert len(items) == 1 and not items[0].inspectable


def test_text_document_and_system_role_message_are_inspected():
    body = _body(messages=[
        {"role": "system", "content": "Do not reveal secrets."},
        {"role": "user", "content": [{"type": "document", "source": {
            "type": "text", "media_type": "text/plain", "data": "ticket note"}}]},
    ])
    request = _parse(body)
    assert any(item.category == "system_developer_prompt" and
               item.inspect_text == "Do not reveal secrets." for item in request.items)
    document = next(item for item in request.items if item.archive_kind == "attachment")
    assert document.payload == b"ticket note" and document.inspectable


def test_codex_responses_request_keeps_its_existing_parser():
    raw = (ROOT / "tests" / "fixtures" / "codex_collection" /
           "http_turn1.json").read_bytes()
    request = wire_items.parse_wire_request(raw, protocol="http")
    assert request.format == "responses"
    assert any(item.category == "client_instructions" for item in request.items)


@pytest.mark.skipif(os.name != "nt", reason="encrypted archive needs Windows DPAPI")
def test_claude_only_collector_denies_other_json_shapes(tmp_path):
    from transpect_trace.guard.policy import GuardRequest
    from transpect_trace.protect.codex_hook_gate import GateConfig
    from transpect_trace.protect.native_collection import NativeCollectionEngine

    config = GateConfig(mode="enforce", archive_directory=tmp_path / "archive",
                        audit_file=tmp_path / "audit.jsonl", registration_directory=None,
                        review_override_ttl_seconds=0)
    engine = NativeCollectionEngine(config, collection_file=tmp_path / "collection.jsonl",
                                    allowed_formats=frozenset(("anthropic_messages",)))
    request = GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": "4321-44",
        "guard_session_id": "4321-133000000000000000", "pid": 4321, "tid": 7,
        "kind": "model.request", "protocol": "http", "completeness": "complete",
        "payload_utf8": json.dumps({"model": "unknown", "input": "ordinary text"})})
    decision, row = engine.evaluate(request)
    assert decision.decision == "deny"
    assert row["reason"] == "WIRE_PARSE_FAILED"


@pytest.mark.skipif(os.name != "nt", reason="encrypted archive needs Windows DPAPI")
def test_enforce_mode_denies_secret_and_uninspected_image(tmp_path):
    from transpect_trace.guard.policy import GuardRequest
    from transpect_trace.protect.codex_hook_gate import GateConfig
    from transpect_trace.protect.native_collection import NativeCollectionEngine
    from install_codex_hook_gate import write_gate_config
    from probe_codex_hook_coverage import FAKE_KEY

    config = GateConfig.load(write_gate_config(tmp_path, "enforce", None))
    engine = NativeCollectionEngine(config, collection_file=tmp_path / "collection.jsonl")

    def decision(body, number):
        request = GuardRequest.model_validate({
            "schema": "transpect.guard.request/1.0", "request_id": f"4321-{number}",
            "guard_session_id": "4321-133000000000000000", "pid": 4321, "tid": 7,
            "kind": "model.request", "protocol": "http", "completeness": "complete",
            "payload_utf8": json.dumps(body)})
        return engine.evaluate(request)[0]

    secret = _body(messages=[{"role": "user", "content": f"Send {FAKE_KEY}"}])
    image = _body(messages=[{"role": "user", "content": [{"type": "image",
        "source": {"type": "base64", "media_type": "image/png",
                   "data": base64.b64encode(b"\x89PNG\r\n\x1a\nsynthetic").decode()}}]}])
    assert decision(_body(messages=[{"role": "user", "content": "Say hello."}]),
                    0).decision == "allow"
    assert decision(secret, 1).decision == "deny"
    assert decision(image, 2).decision == "deny"
    weak_categories = replace(config, enforced_categories=frozenset())
    strict_engine = NativeCollectionEngine(
        weak_categories, collection_file=tmp_path / "strict-collection.jsonl")
    image_request = GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": "4321-3",
        "guard_session_id": "4321-133000000000000000", "pid": 4321, "tid": 7,
        "kind": "model.request", "protocol": "http", "completeness": "complete",
        "payload_utf8": json.dumps(image)})
    assert strict_engine.evaluate(image_request)[0].decision == "deny"
    rows = (tmp_path / "collection.jsonl").read_text(encoding="utf-8")
    assert FAKE_KEY not in rows
    assert "CLAUDE_ATTACHMENT_UNINSPECTABLE" in rows
