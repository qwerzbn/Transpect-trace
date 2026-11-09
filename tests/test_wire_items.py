"""One wire parser splits a 0.166-shaped model request into categorized items."""
import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect import wire_items as wire  # noqa: E402
from transpect_trace.protect.collection import ATTACHMENT_UNDECODABLE, IMAGE_GAP  # noqa: E402
from transpect_trace.protect.codex_hook_gate import CodexHookGate, GateConfig  # noqa: E402
from transpect_trace.protect.content_dlp import ContentDLPEngine  # noqa: E402

from probe_codex_hook_coverage import FAKE_KEY, MARKER, _png_with_marker  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "codex_collection"


def _parse(name, protocol="http"):
    return wire.parse_wire_request((FIXTURES / f"{name}.json").read_bytes(), protocol=protocol)


def _by(request, category):
    return [item for item in request.items if item.category == category]


def test_agents_md_block_is_client_instructions_not_prompt():
    request = _parse("http_turn1")
    (agents,) = _by(request, "client_instructions")
    (prompt,) = _by(request, "user_prompt")
    assert agents.location == "/input/2/content/0/text"
    assert agents.inspect_text.startswith("# AGENTS.md instructions for ")
    assert prompt.payload == b"read notes.txt" and prompt.match_text == "read notes.txt"
    assert wire.classify_user_text("  # AGENTS.md instructions for C:\\x\n") == "client_instructions"
    assert wire.classify_user_text("read notes.txt") == "user_prompt"


def test_environment_context_is_separate_category():
    request = _parse("http_turn1")
    (context,) = _by(request, "environment_context")
    assert context.location == "/input/2/content/1/text"
    assert "<environment_context>" in context.inspect_text
    assert request.format == "responses" and not request.incremental
    assert request.correlation == {
        "session_id": "0a1b2c3d-0000-7000-8000-000000000001",
        "thread_id": "0a1b2c3d-0000-7000-8000-000000000001",
        "turn_id": "0a1b2c3d-0000-7000-8000-000000000002", "model": "gpt-synthetic"}


def test_developer_messages_are_system_developer_prompt():
    request = _parse("http_turn2")
    assert [item.location for item in _by(request, "system_developer_prompt")] == [
        "/input/0/content/0/text", "/input/1/content/0/text"]
    (call,) = _by(request, "tool_call_args")
    (output,) = _by(request, "tool_output")
    assert (call.call_id, call.tool_name, call.match_text) == ("call_0", "exec_command", None)
    assert call.inspect_text == "tool_name=exec_command\ncmd\nGet-Content notes.txt"
    # The exec header stays in the archived bytes but not in the cross-route text.
    assert output.payload.startswith(b"Chunk ID: ")
    assert output.match_text == f"meeting notes {MARKER}"
    # Inspected as the hook sees it: the client header is not command output.
    assert output.inspect_text.startswith(f"meeting notes {MARKER}")
    assert (output.call_id, output.tool_name) == ("call_0", "exec_command")
    assert len(_by(request, "tool_definitions")) == len(_by(request, "request_metadata")) == 1


def test_tool_output_image_and_user_attachment_decode_data_urls():
    png = _png_with_marker()
    image, fields = _by(_parse("http_image_output"), "tool_output_image")
    assert image.payload == png and image.archive_kind == "attachment"
    assert not image.inspectable and image.call_id == "call_0"
    assert image.findings == (IMAGE_GAP,)
    # The part's other fields are inspected as text, without the pixels.
    assert fields.location == image.location + "#fields" and fields.inspectable
    assert b"base64" not in fields.payload and fields.call_id == "call_0"
    attached = _by(_parse("http_user_attachment"), "user_attachment")
    assert [item.archive_kind for item in attached] == ["model_request", "model_request",
                                                        "attachment", "model_request"]
    assert attached[2].payload == png
    assert [item.inspect_text for item in attached[:2]] == [
        '<image name=[Image #1] path="marker.png">', "</image>"]
    (prompt,) = _by(_parse("http_user_attachment"), "user_prompt")
    assert prompt.payload == b"describe the image"
    # A payload that is not base64 is an uninspected image, not a failed parse.
    body = json.loads((FIXTURES / "http_image_output.json").read_bytes())
    bad = "data:image/png;base64,iVBORw0KGgo=\n"
    body["input"][-1]["output"][0]["image_url"] = bad
    image = _by(wire.parse_wire_request(json.dumps(body).encode(), protocol="http"),
                "tool_output_image")[0]
    assert image.payload == bad.encode() and image.findings == (IMAGE_GAP,)


def _turn1_with(*items, part=None):
    body = json.loads((FIXTURES / "http_turn1.json").read_bytes())
    body["input"].extend(items)
    if part is not None:
        body["input"][-1]["content"].append(part)
    return wire.parse_wire_request(json.dumps(body).encode(), protocol="http")


def test_inline_document_is_inspected_as_a_file_with_its_fields():
    data = base64.b64encode(b"password = " + FAKE_KEY.encode()).decode()
    request = _turn1_with(part={"type": "input_file", "filename": "creds.txt",
                                "file_data": "data:text/plain;charset=utf-8;base64," + data})
    document, fields = _by(request, "user_attachment")
    assert document.file_name == "creds.txt" and document.inspectable
    assert document.payload == b"password = " + FAKE_KEY.encode()
    assert "creds.txt" in fields.inspect_text and data not in fields.inspect_text
    assert ContentDLPEngine().inspect_file_bytes(document.file_name,
                                                 document.payload).decision == "BLOCK"
    broken = _turn1_with(part={"type": "input_file", "file_data": "data:text/plain;base64,%%"})
    assert _by(broken, "user_attachment")[0].findings == (ATTACHMENT_UNDECODABLE,)


def test_reasoning_summary_and_unmodeled_fields_are_inspected():
    request = _turn1_with(
        {"type": "reasoning", "id": "rs_1", "encrypted_content": "gAAAA" + "x" * 64,
         "summary": [{"type": "summary_text", "text": f"The key is {FAKE_KEY}"}]},
        {"type": "function_call", "name": "shell", "call_id": "c9", "arguments": "{}",
         "namespace": f"{FAKE_KEY}-ns"})
    (reasoning,) = _by(request, "reasoning_opaque")
    assert reasoning.inspectable and FAKE_KEY in reasoning.inspect_text
    assert "gAAAA" not in reasoning.inspect_text and "rs_1" not in reasoning.inspect_text
    (residual,) = _by(request, "unknown")
    assert residual.location.endswith("#residual") and FAKE_KEY in residual.inspect_text
    assert "arguments" not in residual.inspect_text
    # Codex's own item shapes leave no residual.
    assert not _by(_parse("http_turn2"), "unknown")


def test_metadata_view_masks_protocol_ids(tmp_path):
    request = _parse("http_turn1")
    (metadata,) = _by(request, "request_metadata")
    assert b"0a1b2c3d-0000-7000-8000-000000000001" in metadata.payload
    assert "0a1b2c3d-0000" not in metadata.inspect_text
    assert "https://example.invalid/synthetic.git" in metadata.inspect_text
    assert all("msg_" not in item.inspect_text for item in request.items)
    engine = ContentDLPEngine()
    gate = CodexHookGate(GateConfig(mode="enforce", archive_directory=tmp_path,
                                    audit_file=tmp_path / "audit.jsonl",
                                    registration_directory=None))
    for item in request.items:
        verdict = engine.inspect_text(item.inspect_text)
        assert "ENTROPY_TOKEN" not in verdict.rule_ids, item.category
        assert gate.actionable(verdict) == "ALLOW"


def test_wss_response_create_parsed_and_incremental_flagged():
    full = _parse("wss_response_create", "wss")
    http = _parse("http_turn1")
    assert full.format == "wss_response_create" and not full.incremental
    assert ({(i.category, i.payload) for i in full.items if i.category != "request_metadata"}
            == {(i.category, i.payload) for i in http.items if i.category != "request_metadata"})
    (metadata,) = _by(full, "request_metadata")
    assert "<protocol-start-ms>" in metadata.inspect_text
    delta = _parse("wss_incremental", "wss")
    assert delta.incremental and "incremental_request_history_not_present" in delta.limitations
    assert wire.parse_wire_request(b'{"hello": "world"}', protocol="http").format == "unknown"
    with pytest.raises(ValueError):
        wire.parse_wire_request(b"not json", protocol="http")


def test_item_identity_ignores_message_ids():
    body = json.loads((FIXTURES / "http_turn1.json").read_bytes())
    first = wire.parse_wire_request(json.dumps(body).encode(), protocol="http")
    for item in body["input"]:
        if "id" in item:
            item["id"] = "msg_ffffffff-ffff-7fff-bfff-ffffffffffff"
    second = wire.parse_wire_request(json.dumps(body).encode(), protocol="http")
    content = [i for i in first.items if i.category != "request_metadata"]
    assert ({wire.item_identity(i) for i in content}
            <= {wire.item_identity(i) for i in second.items})
    turn2 = _parse("http_turn2")
    shared = {wire.item_identity(i) for i in first.items} & {wire.item_identity(i)
                                                             for i in turn2.items}
    assert len(shared) == len(first.items)


def test_exec_header_only_stripped_from_exec_tool_inspection():
    header = ("Chunk ID: 76f5a9\nWall time: 10.0124 seconds\n"
              "Process running with session ID 1\nOriginal token count: 8\nOutput:\n")

    def body(name):
        return json.dumps({"model": "m", "input": [
            {"type": "function_call", "call_id": "c", "name": name, "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c", "output": header + MARKER}]}).encode()

    def output(name):
        (item,) = _by(wire.parse_wire_request(body(name), protocol="http"), "tool_output")
        return item

    exec_out, other = output("exec_command"), output("mcp_tool")
    assert exec_out.payload == (header + MARKER).encode() and exec_out.inspect_text == MARKER
    assert other.inspect_text == header + MARKER  # only the client's own header is dropped
    engine = ContentDLPEngine()
    assert engine.inspect_text(exec_out.inspect_text).decision != "BLOCK"
