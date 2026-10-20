import base64
import gzip
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
from typer.testing import CliRunner

from transpect_trace.guard.policy import GuardPolicy
from transpect_trace.observe.cli import app
from transpect_trace.observe.models import CaptureEvent
from transpect_trace.observe.pipeline import Pipeline, report
from transpect_trace.observe.semantics import GROUPS, extract_request


def sample():
    return {"model": "fixture", "instructions": "FAKE_SYSTEM 中文上下文",
        "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "FAKE_PROMPT 请分析"}]},
            {"role": "assistant", "content": "FAKE_HISTORY"},
            {"type": "function_call", "call_id": "FAKE_CALL_ID", "name": "FAKE_TOOL_NAME",
             "arguments": json.dumps({"cmd": "FAKE_COMMAND", "nested": {"value": "FAKE_ARGUMENT"}})},
            {"type": "function_call_output", "call_id": "FAKE_CALL_ID", "output": "FAKE_RESULT"}],
        "tools": [{"type": "function", "name": "FAKE_DEFINITION",
                   "parameters": {"properties": {"tool_calls": {"type": "string"}}}}]}


def extract(value, **kwargs):
    return extract_request(json.dumps(value, ensure_ascii=False).encode(),
        observation_id="obs", capture_source="fixture", completeness="complete", **kwargs)


def test_responses_exact_values_locations_and_private_exports():
    r = extract(sample())
    assert r.status == "extracted" and r.format == "responses"
    assert [p.value for p in r.prompt] == ["FAKE_PROMPT 请分析"]
    assert [p.value for p in r.context] == ["FAKE_HISTORY", "FAKE_SYSTEM 中文上下文"]
    assert r.prompt[0].location == "/input/0/content/0/text"
    assert r.tool_calls[0].value == {"cmd": "FAKE_COMMAND", "nested": {"value": "FAKE_ARGUMENT"}}
    assert r.tool_calls[0].tool_name == "FAKE_TOOL_NAME"
    assert r.tool_results[0].value == "FAKE_RESULT"
    assert len(r.tool_definitions) == len(r.tool_calls) == len(r.tool_links) == 1
    assert r.tool_links[0].call_location == "/input/2"
    assert r.tool_links[0].result_location == "/input/3/output"
    assert not r.tool_links[0].proves_execution and not r.can_enforce
    assert "FAKE_" not in r.model_dump_json() and "FAKE_" not in repr(r)
    assert "FAKE_RESULT" in json.dumps(r.synthetic_export())
    jsonschema.validate(r.model_dump(), json.loads(Path("schemas/request-semantics-v1.schema.json").read_text()))


def test_chat_messages_preserve_history_roles_and_explicit_call_links():
    r = extract({"model": "fixture", "messages": [
        {"role": "system", "content": "policy"},
        {"role": "developer", "content": "developer"},
        {"role": "user", "content": "earlier user"},
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "call1", "type": "function", "function": {"name": "read", "arguments": '{"path":"fixture"}'}}]},
        {"role": "tool", "tool_call_id": "call1", "content": "file result"},
        {"role": "user", "content": "latest user"}]})
    assert r.format == "chat_completions" and r.status == "extracted"
    assert [x.value for x in r.prompt] == ["earlier user", "latest user"]
    assert [x.role for x in r.context] == ["system", "developer"]
    assert r.tool_calls[0].value == {"path": "fixture"}
    assert len(r.tool_links) == 1


@pytest.mark.parametrize("nested", [False, True])
def test_supported_wss_request_variants(nested):
    payload = sample()
    payload = {"type": "response.create", "response": payload} if nested else dict(payload, type="response.create")
    r = extract(payload, protocol="wss")
    assert r.format == "wss_response_create" and len(r.tool_results) == 1
    assert r.prompt[0].location.startswith("/response/" if nested else "/input/")


@pytest.mark.parametrize("variant", ["missing", "duplicate_call", "duplicate_result"])
def test_call_link_requires_unique_explicit_id(variant):
    data = sample()
    if variant == "missing":
        del data["input"][3]["call_id"]
    elif variant == "duplicate_call":
        data["input"].append(data["input"][2])
    else:
        data["input"].append(data["input"][3])
    r = extract(data)
    assert not r.tool_links and "tool_result_call_unresolved" in r.limitations


def test_definitions_never_become_tool_calls():
    r = extract({"model": "fixture", "input": "hello", "tools": sample()["tools"]})
    assert len(r.tool_definitions) == 1 and not r.tool_calls and not r.tool_results


def test_attachment_and_unknown_part_are_not_text():
    r = extract({"model": "fixture", "input": [{"role": "user", "content": [
        {"type": "input_image", "image_url": "data:image/png;base64,FAKE_IMAGE"},
        {"type": "future_type", "payload": "FAKE_UNKNOWN"}]}]})
    assert r.status == "partial" and len(r.attachments) == len(r.unknown) == 1
    assert not r.attachments[0].inspected and not r.prompt
    assert "FAKE_" not in r.model_dump_json()


@pytest.mark.parametrize("payload", [
    {"action": "next", "messages": [{"author": {"role": "user"}, "content": {"parts": ["private"]}}]},
    {"model": "m", "input": "one", "messages": []},
    {"type": "response.function_call_arguments.delta", "delta": '{"cmd":'},
])
def test_unknown_web_or_stream_delta_is_unsupported(payload):
    r = extract(payload)
    assert r.status == "unsupported"
    assert all(not getattr(r, g) for g in GROUPS)


@pytest.mark.parametrize("raw", [b'{"model":"a","model":"b","input":"x"}',
                                b'{"model":"a","input":NaN}', b'{"model":',
                                b'{"model":"a","input":"\xff"}'])
def test_invalid_json_has_no_partially_exported_content(raw):
    r = extract_request(raw, observation_id="obs", capture_source="fixture", completeness="complete")
    assert r.status == "failed" and not r.prompt


def test_unparseable_arguments_and_legacy_result_not_guessed():
    r = extract({"model": "fixture", "messages": [
        {"role": "assistant", "function_call": {"name": "read", "arguments": "not json"}},
        {"role": "function", "name": "read", "content": "result"}]})
    assert r.status == "partial" and not r.tool_links
    assert not r.tool_calls[0].inspected and r.tool_calls[0].value == "not json"
    assert r.tool_results[0].value == "result"


def test_boundary_and_encoding_are_independent():
    raw = json.dumps(sample()).encode()
    compressed = gzip.compress(raw)
    r = extract_request(compressed, observation_id="obs", capture_source="fixture",
                        content_encoding="gzip", completeness="unknown")
    assert r.status == "partial" and r.completeness == "unknown"
    assert r.encoding_state == "decoded" and r.decoded_body_sha256 == hashlib.sha256(raw).hexdigest()
    assert r.raw_body_sha256 == hashlib.sha256(compressed).hexdigest()
    assert extract_request(compressed[:-4], observation_id="obs", capture_source="fixture",
                           content_encoding="gzip").status == "failed"


def event(data, sequence, **kw):
    return CaptureEvent(provider="fixture", capture_point="tls", pid=12, tid=1,
        creation_filetime=100, connection_id="one", direction="send",
        sequence=sequence, captured_qpc=20, qpc_frequency=10,
        application="unknown", data_b64=base64.b64encode(data).decode(), **kw)


def test_http_fragments_to_live_pipeline_metadata_and_memory_sink(tmp_path):
    raw = gzip.compress(json.dumps(sample()).encode())
    wire = (b"POST /v1/responses HTTP/1.1\r\nHost: fixture.invalid\r\n"
            b"Authorization: Bearer FAKE_HEADER\r\nCookie: FAKE_COOKIE\r\n"
            b"Content-Encoding: gzip\r\nContent-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw)
    observed = []
    p = Pipeline(tmp_path, GuardPolicy(), semantic_sink=observed.append)
    p.consume(event(wire[:130], 1))
    assert not observed
    p.consume(event(wire[130:], 2))
    p.finish()
    assert len(observed) == 1 and observed[0].tool_results[0].value == "FAKE_RESULT"
    assert observed[0].status == "extracted"
    result = report(tmp_path)["request_semantics"]
    assert result["counts"] == {"prompt": 1, "context": 2, "tool_calls": 1, "tool_results": 1}
    for path in tmp_path.glob("*.jsonl"):
        assert "FAKE_" not in path.read_text(), path.name


def test_lost_fragment_never_creates_complete_semantics(tmp_path):
    p = Pipeline(tmp_path, GuardPolicy())
    p.consume(event(b'POST /responses HTTP/1.1\r\n', 1))
    p.consume(event(b'{}', 3, lost_events=1))
    p.finish()
    assert not report(tmp_path)["request_semantics"]["available"]
    assert p.gaps


def test_offline_cli_is_redacted_and_never_certifies_capture(tmp_path):
    source = tmp_path / "body.json"
    source.write_text(json.dumps(sample()), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["extract", "--body-file", str(source)])
    assert result.exit_code == 0 and "FAKE_" not in result.stdout
    meta = json.loads(result.stdout)
    assert meta["completeness"] == "unknown" and meta["status"] == "partial"
    target = tmp_path / "explicit-fake-content.json"
    args = ["extract", "--body-file", str(source), "--output", str(target), "--synthetic-content"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0 and "FAKE_" not in result.stdout
    assert json.loads(target.read_text(encoding="utf-8"))["tool_results"][0]["value"] == "FAKE_RESULT"
    assert runner.invoke(app, args).exit_code != 0  # existing file never overwritten


def test_legacy_report_has_no_reconstructed_plaintext(tmp_path):
    assert report(tmp_path)["request_semantics"] == {
        "available": False, "results": [], "counts": {"prompt": 0, "context": 0, "tool_calls": 0, "tool_results": 0},
        "plaintext_exported": False}


def test_structured_tool_result_attachment_remains_uninspected():
    value = sample()
    value["input"][3]["output"] = [
        {"type": "input_text", "text": "FAKE_RESULT"},
        {"type": "input_image", "image_url": "data:image/png;base64,FAKE_IMAGE"}]
    r = extract(value)
    assert r.status == "partial"
    assert not r.tool_results[0].inspected and len(r.attachments) == 1
    assert r.attachments[0].location == "/input/3/output/1"
    assert "FAKE_" not in r.model_dump_json()


@pytest.mark.parametrize("arguments", ["null", "42", "true"])
def test_scalar_tool_arguments_are_not_certified(arguments):
    value = sample()
    value["input"][2]["arguments"] = arguments
    r = extract(value)
    assert r.status == "partial" and not r.tool_calls[0].inspected


def test_utf16_and_excessive_structure_rejected():
    raw = json.dumps(sample()).encode("utf-16")
    assert extract_request(raw, observation_id="obs", capture_source="fixture").status == "failed"
    r = extract({"model": "fixture", "input": [{"role": "user", "content": "x"}] * 4097})
    assert r.status == "failed" and not r.prompt


def test_unified_identity_mismatch_rejects_values():
    from types import SimpleNamespace
    from transpect_trace.observe.semantics import from_unified
    raw = json.dumps(sample()).encode()
    unified = SimpleNamespace(observation_id="obs", capture_source="fixture",
        completeness="complete", capture_point="request", application_protocol="http",
        raw_payload_sha256=hashlib.sha256(raw).hexdigest(), raw_payload_bytes=len(raw),
        decoded_payload_sha256="0" * 64)
    r = from_unified(unified, raw)
    assert r.status == "failed" and not r.prompt
    assert "unified_body_identity_mismatch" in r.limitations


def test_http2_streams_do_not_mix_semantics(tmp_path):
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    client = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
    client.initiate_connection()
    for stream in (1, 3):
        client.send_headers(stream, [(":method", "POST"), (":scheme", "https"),
            (":authority", "fixture.invalid"), (":path", "/v1/responses")])
    for stream in (3, 1):
        value = sample()
        value["input"][0]["content"][0]["text"] = f"stream-{stream}"
        client.send_data(stream, json.dumps(value).encode(), end_stream=True)
    seen = []
    p = Pipeline(tmp_path, GuardPolicy(), semantic_sink=seen.append)
    wire = client.data_to_send()
    for seq, start in enumerate(range(0, len(wire), 11), 1):
        p.consume(event(wire[start:start+11], seq))
    p.finish()
    assert not p.gaps
    assert [r.prompt[0].value for r in seen] == ["stream-3", "stream-1"]
    assert all(r.status == "extracted" and len(r.tool_links) == 1 for r in seen)


def test_wss_fragmented_request_to_semantics(tmp_path):
    import struct
    def frame(data, opcode=1, fin=True):
        mask = b"mask"
        size = bytes([len(data) | 128]) if len(data) < 126 else b"\xfe" + struct.pack("!H", len(data))
        return bytes([opcode | (128 if fin else 0)]) + size + mask + bytes(x ^ mask[i % 4] for i, x in enumerate(data))
    seen = []
    p = Pipeline(tmp_path, GuardPolicy(), semantic_sink=seen.append)
    p.consume(event(b"GET /responses HTTP/1.1\r\nHost: fixture.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", 1))
    response = event(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", 1)
    p.consume(response.model_copy(update={"direction": "recv"}))
    raw = json.dumps(dict(sample(), type="response.create")).encode()
    p.consume(event(frame(raw[:60], fin=False), 2))
    assert not seen
    p.consume(event(frame(b"p", opcode=9) + frame(raw[60:], opcode=0), 3))
    p.finish()
    assert not p.gaps and len(seen) == 1
    assert seen[0].status == "extracted" and seen[0].tool_results[0].value == "FAKE_RESULT"
