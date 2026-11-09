"""Native frames carrying a zstd HTTP body are recovered exactly or rejected."""
from __future__ import annotations

import json

import pytest
import zstandard

import transpect_trace.guard.pipe as pipe_module
from transpect_trace.guard.pipe import _decode_compressed_model_frame
from test_desktop_thread_scope import _serve_frames, _server

HEADER = ('{"schema":"transpect.guard.request/1.0","request_id":"%s",'
          '"guard_session_id":"1234-42","pid":1234,"tid":7,"kind":"model.request",'
          '"protocol":"%s","destination":null,"completeness":"complete",'
          '"captured_qpc":1,"qpc_frequency":1,"outcome_for_request_id":"",'
          '"outcome_action":"none","outcome_captured_qpc":0,"payload_utf8":')


def native_quote(data: bytes) -> bytes:
    """Byte-for-byte port of guard.c quote(): only '"', '\' and < 0x20 escaped."""
    out = bytearray(b'"')
    for byte in data:
        if byte in (0x22, 0x5C):
            out += b"\\" + bytes([byte])
        elif byte < 32:
            out += b"\\u00%02x" % byte
        else:
            out.append(byte)
    return bytes(out + b'"')


def native_frame(payload: bytes, *, request_id: str = "1234-4",
                 protocol: str = "http") -> bytes:
    return (HEADER % (request_id, protocol)).encode() + native_quote(payload) + b"}"


BODY = json.dumps({"model": "m", "input": [{"role": "user", "content": [
    {"type": "input_text", "text": "杭州出差三天，西湖附近 \"quoted\" \\ \u0001"}]}],
    "client_metadata": {"thread_id": "01a1bad5-5b05-7773-8d95-e5c0d04a6a0a"}},
    ensure_ascii=False).encode()


def test_quote_port_matches_valid_utf8_json_path():
    frame = native_frame(BODY)
    assert json.loads(frame)["payload_utf8"].encode() == BODY


def test_zstd_body_is_recovered_byte_exact():
    compressed = zstandard.ZstdCompressor().compress(BODY)
    frame = native_frame(compressed)
    with pytest.raises(UnicodeDecodeError):
        frame.decode("utf-8")  # the live failure: not UTF-8 JSON
    recovered = _decode_compressed_model_frame(frame)
    assert recovered["payload_utf8"].encode() == BODY
    assert recovered["_decoded"] == {"content_encoding": "zstd",
                                     "compressed_bytes": len(compressed),
                                     "decoded_bytes": len(BODY)}


def test_recovered_zstd_request_reaches_the_engine_and_is_visible(tmp_path):
    server, calls = _server(tmp_path, target=None)
    frame = native_frame(zstandard.ZstdCompressor().compress(BODY), request_id="1234-9")
    writes = _serve_frames(server, [frame])
    assert calls == ["1234-9"]  # inspected, not silently allowed
    assert len(writes) == 1 and json.loads(writes[0][4:])["decision"] == "deny"
    snapshot = server.validation_snapshot()
    assert snapshot["count"] == 0
    assert snapshot["decoded_compressed"] == [{
        "request_id": "1234-9", "content_encoding": "zstd",
        "compressed_bytes": len(zstandard.ZstdCompressor().compress(BODY)),
        "decoded_bytes": len(BODY)}]


@pytest.mark.parametrize("payload, protocol", [
    (b"\x1f\x8b\x08\x00" + bytes(range(128, 256)), "http"),             # not zstd
    (zstandard.ZstdCompressor().compress(b"\xff\xfe not utf-8"), "http"),
    (zstandard.ZstdCompressor().compress(BODY), "wss"),                 # HTTP only
    (zstandard.ZstdCompressor().compress(BODY)[:-6], "http"),            # truncated
])
def test_unrecoverable_binary_frames_stay_rejected(tmp_path, payload, protocol):
    server, calls = _server(tmp_path, target=None)
    writes = _serve_frames(server, [native_frame(payload, protocol=protocol)])
    assert writes == [] and calls == []  # no reply: the Native caller blocks
    assert server.validation_snapshot()["count"] == 1


def test_decoded_size_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(pipe_module, "MAX_DECODED_BODY_BYTES", 1024)
    bomb = zstandard.ZstdCompressor().compress(b"{" + b" " * 4096 + b"}")
    assert _decode_compressed_model_frame(native_frame(bomb)) is None
