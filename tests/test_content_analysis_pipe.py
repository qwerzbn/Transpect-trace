import hashlib
import json
import struct

import pytest

from transpect_trace.protect.content_analysis import (
    ContentAnalysisEngine,
    ContentAnalysisRequest,
)
from transpect_trace.protect.content_analysis.protocol import (
    MAX_HEADER_BYTES,
    MAX_REPLY_BYTES,
    ContentAnalysisProtocolError,
    decode_request,
    encode_reply,
    request_body_size,
    split_frame,
)


def metadata(body: bytes) -> dict:
    request = ContentAnalysisRequest.from_sdk(
        request_token="never-persist-this-token",
        connector="BULK_DATA_ENTRY",
        reason="CLIPBOARD_PASTE",
        destination_url="https://chatgpt.com/?secret=query",
        body=body,
        user_action_id="never-persist-this-action",
        tags=["dlp"],
    )
    return request.model_dump(mode="json")


def test_decode_request_rehydrates_only_exact_transient_snapshot():
    body = "普通粘贴内容".encode()
    header = json.dumps(metadata(body)).encode()
    request = decode_request(header, body)
    assert request.body == body
    assert request.body_sha256 == hashlib.sha256(body).hexdigest()
    assert request.destination_host == "chatgpt.com"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value | {"body_bytes": value["body_bytes"] + 1},
        lambda value: value | {"body_sha256": "0" * 64},
        lambda value: value | {"body": "secret"},
        lambda value: value | {"request_token": "secret"},
        lambda value: value | {"unexpected": True},
    ],
)
def test_decode_request_rejects_length_hash_transient_and_unknown_fields(mutator):
    body = b"clean"
    header = json.dumps(mutator(metadata(body))).encode()
    with pytest.raises(ContentAnalysisProtocolError):
        decode_request(header, body)


def test_decode_request_rejects_duplicate_fields_and_bounds():
    body = b"clean"
    value = metadata(body)
    duplicate = (
        '{"schema_version":"transpect.chrome.content.request/1.0",'
        '"schema_version":"transpect.chrome.content.request/1.0"}'
    ).encode()
    with pytest.raises(ContentAnalysisProtocolError, match="duplicate"):
        decode_request(duplicate, body)
    with pytest.raises(ContentAnalysisProtocolError, match="duplicate"):
        request_body_size(b'{"body_bytes":5,"body_bytes":6}')
    with pytest.raises(ContentAnalysisProtocolError):
        decode_request(b"x" * (MAX_HEADER_BYTES + 1), body)


def test_decode_request_does_not_coerce_wire_types():
    body = b"clean"
    value = metadata(body)
    value["body_bytes"] = str(value["body_bytes"])
    with pytest.raises(ContentAnalysisProtocolError):
        decode_request(json.dumps(value).encode(), body)


def test_reply_is_bounded_and_contains_no_inspected_content_or_sdk_token():
    body = b"password=FakeSecret12345"
    request = decode_request(json.dumps(metadata(body)).encode(), body)
    verdict, _ = ContentAnalysisEngine().evaluate(request)
    frame = encode_reply(verdict)
    payload = split_frame(frame, maximum=MAX_REPLY_BYTES)
    value = json.loads(payload)
    assert value["schema_version"] == "transpect.chrome.content.reply/1.0"
    assert value["decision"] == "BLOCK"
    assert "CONFIG_CREDENTIAL" in value["rule_ids"]
    assert body not in frame
    assert b"never-persist-this-token" not in frame


def test_split_frame_rejects_truncation_and_trailing_bytes():
    with pytest.raises(ContentAnalysisProtocolError):
        split_frame(b"\x01", maximum=10)
    with pytest.raises(ContentAnalysisProtocolError):
        split_frame(struct.pack("<I", 2) + b"x", maximum=10)
    with pytest.raises(ContentAnalysisProtocolError):
        split_frame(struct.pack("<I", 1) + b"xy", maximum=10)
