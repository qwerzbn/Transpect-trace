"""Bounded wire protocol between the native browser agent and local policy.

The request body is carried as a separate transient byte sequence.  It is
never embedded in JSON, which keeps accidental logging and exception output
from persisting inspected content.
"""
from __future__ import annotations

import json
import struct
from typing import Any

from .models import (
    MAX_CONTENT_BYTES,
    ContentAnalysisRequest,
    ContentAnalysisVerdict,
)


MAX_HEADER_BYTES = 64 * 1024
MAX_REPLY_BYTES = 64 * 1024
REPLY_SCHEMA = "transpect.chrome.content.reply/1.0"


class ContentAnalysisProtocolError(ValueError):
    """A peer supplied an invalid or unsafe content-analysis frame."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContentAnalysisProtocolError("duplicate JSON field")
        result[key] = value
    return result


def decode_request(header: bytes, body: bytes) -> ContentAnalysisRequest:
    """Validate one metadata header and its exact transient body snapshot."""
    if not 0 < len(header) <= MAX_HEADER_BYTES:
        raise ContentAnalysisProtocolError("invalid request header length")
    if len(body) > MAX_CONTENT_BYTES:
        raise ContentAnalysisProtocolError("content limit exceeded")
    try:
        value = json.loads(header, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContentAnalysisProtocolError("invalid request JSON") from error
    if not isinstance(value, dict):
        raise ContentAnalysisProtocolError("request header must be an object")
    # Raw identifiers and content are forbidden in the metadata envelope even
    # though the in-memory Pydantic type has transient fields for SDK adapters.
    if {"body", "request_token", "user_action_id"}.intersection(value):
        raise ContentAnalysisProtocolError("transient field present in header")
    try:
        request = ContentAnalysisRequest.model_validate(
            value | {"body": body}, strict=True
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ContentAnalysisProtocolError("request snapshot validation failed") from error
    if request.body_bytes != len(body):
        raise ContentAnalysisProtocolError("request body length mismatch")
    return request


def request_body_size(header: bytes) -> int:
    """Read the bounded body length without accepting a weaker JSON dialect.

    The pipe server needs this value before it can read the trailing bytes.  It
    therefore uses the same duplicate-field and object checks as the final
    request decoder instead of performing a permissive preliminary parse.
    """
    if not 0 < len(header) <= MAX_HEADER_BYTES:
        raise ContentAnalysisProtocolError("invalid request header length")
    try:
        value = json.loads(header, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContentAnalysisProtocolError("invalid request JSON") from error
    if not isinstance(value, dict):
        raise ContentAnalysisProtocolError("request header must be an object")
    body_bytes = value.get("body_bytes")
    if type(body_bytes) is not int or not 0 <= body_bytes <= MAX_CONTENT_BYTES:
        raise ContentAnalysisProtocolError("invalid body length")
    return body_bytes


def encode_reply(verdict: ContentAnalysisVerdict) -> bytes:
    """Return a length-prefixed, privacy-safe decision frame."""
    rule_ids = sorted({finding.rule_id for finding in verdict.findings})
    value = {
        "schema_version": REPLY_SCHEMA,
        "attempt_id": verdict.attempt_id,
        "decision": verdict.decision,
        "action": verdict.action,
        "reason": verdict.reason,
        "policy_version": verdict.policy_version,
        "rule_ids": rule_ids,
    }
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    if not 0 < len(payload) <= MAX_REPLY_BYTES:
        raise ContentAnalysisProtocolError("invalid reply length")
    return struct.pack("<I", len(payload)) + payload


def split_frame(frame: bytes, *, maximum: int) -> bytes:
    """Test/helper parser for a single length-prefixed JSON frame."""
    if len(frame) < 4:
        raise ContentAnalysisProtocolError("truncated length prefix")
    size = struct.unpack("<I", frame[:4])[0]
    if not 0 < size <= maximum or len(frame) != size + 4:
        raise ContentAnalysisProtocolError("invalid frame length")
    return frame[4:]
