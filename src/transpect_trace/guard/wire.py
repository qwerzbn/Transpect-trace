"""u32 little-endian byte length + UTF-8 JSON; no Python-specific serialization."""
import json
import struct

MAX_FRAME_BYTES = 100 * 1024 * 1024


def encode_frame(value: dict) -> bytes:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise ValueError("invalid frame length")
    return struct.pack("<I", len(payload)) + payload


def decode_frame(frame: bytes) -> dict:
    if len(frame) < 4:
        raise ValueError("missing frame header")
    size = struct.unpack_from("<I", frame)[0]
    if not size or size > MAX_FRAME_BYTES or len(frame) != size + 4:
        raise ValueError("invalid frame length")
    result = json.loads(frame[4:].decode("utf-8"))
    if not isinstance(result, dict):
        raise ValueError("frame requires a JSON object")
    return result
