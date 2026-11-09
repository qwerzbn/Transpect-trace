"""One record shape for content collected by either Codex route.

Route H (the client's own hooks) and Route N (the native request hook) see
different parts of a model request. Both write `transpect.codex-collection/1.0`
rows so an evaluator can compare them item by item. A row never holds content:
plaintext goes only to the encrypted archive, and a row carries the archive
record id, a length and keyed digests (`EncryptedRequestArchive.keyed_digest`).
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Iterable
import unicodedata
from urllib.parse import unquote_to_bytes

from .archive import ArchiveReceipt
from .content_dlp import DLPVerdict

SCHEMA = "transpect.codex-collection/1.0"
CATEGORIES = frozenset((
    "user_prompt", "user_attachment", "client_instructions", "environment_context",
    "system_developer_prompt", "tool_call_args", "tool_output", "tool_output_image",
    "model_output_history", "reasoning_opaque", "tool_definitions", "request_metadata",
    "request_envelope", "unknown"))
ROUTES = frozenset(("hook", "native"))
ROUTE_EVENTS = frozenset(("UserPromptSubmit", "PreToolUse", "PostToolUse",
                          "PreModelRequest", "model.request"))
PROTOCOLS = {"hook": frozenset(("hook",)), "native": frozenset(("http", "wss"))}
COLLECTIONS = frozenset(("content", "metadata_only"))
ARCHIVE_KINDS = frozenset(("model_request", "attachment"))
DECISION_POINTS = frozenset(("before_upstream", "before_execution",
                             "after_execution_before_upstream", "none"))
ROUTE_DECISIONS = frozenset(("allow", "deny", "observe_allow", "not_enforceable"))
DECISIONS = frozenset(("ALLOW", "REVIEW", "BLOCK"))
CORRELATION_FIELDS = ("session_id", "thread_id", "turn_id", "call_id", "tool_name", "model",
                      "guard_session_id", "request_id", "request_sha256", "first_request_id")
RECORD_FIELDS = frozenset((
    "schema", "collected_at", "route", "route_event", "protocol", "category", "location",
    "collection", "archive_record_id", "archive_kind", "content_bytes", "content_hmac",
    "match_hmac", "inspected", "decision_point", "dlp_decision", "actionable_decision",
    "matched_rule_ids", "categories", "route_decision", "released_by_route",
    "policy_version", "gate_mode", "elapsed_ms", "extra", *CORRELATION_FIELDS))

# Any RFC 2397 data URL: media type, optional parameters, optional ;base64.
_DATA_URL = re.compile(r"^data:([\w.+/-]*)((?:;[\w.+-]+=[^;,]*)*)(;base64)?,", re.I)
# Non-engine evidence for content the engine cannot read.
IMAGE_GAP = ("INSPECTION_GAP", "IMAGE_UNINSPECTED", 0.60)
ATTACHMENT_UNDECODABLE = ("INSPECTION_ERROR", "ATTACHMENT_UNDECODABLE", 1.0)
# Codex `exec_command` wraps output as "Chunk ID: ..\nWall time: ..\nProcess ..\n
# Original token count: ..\nOutput:\n<output>"; the hook sees only <output>.
_EXEC_HEADER = re.compile(r"\A(?:(?:Chunk ID|Wall time|Process|Original token count"
                          r"|Total output lines|Exit code)\b[^\n]*\n)+Output:\n")
_HEX = re.compile(r"[0-9a-f]+")
_TOKEN = re.compile(r"[A-Za-z0-9_.:/-]{0,128}")
_MAX_ID = 256


@dataclass(frozen=True)
class CollectedItem:
    """One content item in memory. Carries plaintext; never serialize it."""
    category: str
    location: str
    payload: bytes
    inspect_text: str
    match_text: str | None
    archive_kind: str = "model_request"
    inspectable: bool = True
    call_id: str | None = None
    tool_name: str | None = None
    role: str | None = None
    file_name: str | None = None     # set: inspect `payload` as this file, not as text
    findings: tuple[tuple[str, str, float], ...] = ()   # known before inspection


@dataclass(frozen=True)
class DataURL:
    media_type: str
    base64: bool
    data: bytes | None               # None: the payload is not the encoding it claims
    url: str

    @property
    def image(self) -> bool:
        return self.media_type.startswith("image/")


def strip_exec_output_header(text: str) -> str:
    """Drop the exec_command result header, leaving what the command printed.

    The header uses LF line ends; text that does not start with it is returned
    unchanged, so a hook-side output passes through as is."""
    match = _EXEC_HEADER.match(text)
    return text[match.end():] if match else text


def normalize_match_text(category: str, text: str) -> str:
    """The text both routes should agree on for one item of `category`."""
    text = unicodedata.normalize("NFC", text).replace("\r\n", "\n")
    if category == "tool_output":
        text = strip_exec_output_header(text)
    return text.strip()


def parse_data_url(value: str) -> DataURL | None:
    """One data URL, decoded; never raises on a malformed payload."""
    match = _DATA_URL.match(value)
    if match is None:
        return None
    payload = value[match.end():]
    if match.group(3):
        try:
            data = base64.b64decode(payload, validate=True)
        except (ValueError, binascii.Error):
            data = None
    else:
        data = unquote_to_bytes(payload)
    return DataURL(match.group(1).casefold() or "text/plain", bool(match.group(3)), data, value)


def data_urls(value: object, *, depth: int = 0) -> list[DataURL]:
    """Every data URL in a JSON value, in document order."""
    if depth > 64:
        raise ValueError("value nesting exceeds limit")
    if isinstance(value, str):
        url = parse_data_url(value)
        return [url] if url else []
    items = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    return [url for item in items for url in data_urls(item, depth=depth + 1)]


def data_url_payloads(value: object) -> list[bytes]:
    """Decoded bytes of every decodable base64 data URL in a JSON value."""
    return [url.data for url in data_urls(value) if url.base64 and url.data]


def supersede(records: Iterable[dict], reason: str) -> list[dict]:
    """Copies of the released rows a later failure turned into a denial, marked
    with why; an evaluator takes a deny row for an item over its allow row."""
    return [{**record, "route_decision": "deny", "released_by_route": False,
             "extra": {**record["extra"], "superseded_reason": reason}}
            for record in records if record["released_by_route"]]


def _ident(value: object) -> str | None:
    return value[:_MAX_ID] if isinstance(value, str) and value else None


def hook_correlation(event: dict) -> dict:
    """Join keys a hook event carries; `tool_use_id` is the wire `call_id`."""
    return {"session_id": _ident(event.get("session_id")), "thread_id": None,
            "turn_id": _ident(event.get("turn_id")), "call_id": _ident(event.get("tool_use_id")),
            "tool_name": _ident(event.get("tool_name")), "model": _ident(event.get("model"))}


def build_record(*, route: str, route_event: str, protocol: str, category: str,
                 location: str, collection: str, receipt: ArchiveReceipt | None,
                 content_hmac: str | None, match_hmac: str | None, inspected: bool,
                 decision_point: str, verdict: DLPVerdict | None, actionable: str | None,
                 route_decision: str, released_by_route: bool | None, correlation: dict,
                 policy_version: str, gate_mode: str, elapsed_ms: float,
                 extra: dict | None = None,
                 findings: tuple[tuple[str, str, float], ...] = (),
                 content_bytes: int | None = None) -> dict:
    """Assemble and validate one row. `findings` are non-engine evidence (tool
    policy, image gaps) merged into the rule ids as the audit row does;
    `content_bytes` overrides the receipt length, e.g. for a request envelope."""
    unknown = set(correlation) - set(CORRELATION_FIELDS)
    if unknown:
        raise ValueError(f"unknown correlation fields: {sorted(unknown)}")
    rule_ids = set(verdict.rule_ids if verdict else ()) | {item[1] for item in findings}
    categories = set(verdict.categories if verdict else ()) | {item[0] for item in findings}
    record = {
        "schema": SCHEMA,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "route": route, "route_event": route_event, "protocol": protocol,
        "category": category, "location": location, "collection": collection,
        "archive_record_id": receipt.record_id if receipt else None,
        "archive_kind": receipt.kind if receipt else None,
        "content_bytes": (content_bytes if content_bytes is not None
                          else receipt.body_bytes if receipt else 0),
        "content_hmac": content_hmac, "match_hmac": match_hmac, "inspected": inspected,
        "decision_point": decision_point,
        "dlp_decision": verdict.decision if verdict else None,
        "actionable_decision": actionable,
        "matched_rule_ids": sorted(rule_ids), "categories": sorted(categories),
        "route_decision": route_decision, "released_by_route": released_by_route,
        **{key: correlation.get(key) for key in CORRELATION_FIELDS},
        "policy_version": policy_version, "gate_mode": gate_mode,
        "elapsed_ms": round(elapsed_ms, 3), "extra": dict(extra or {}),
    }
    validate_record(record)
    return record


def _check(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(f"invalid collection record: {message}")


def _is_hex(value: object, size: int) -> bool:
    return isinstance(value, str) and len(value) == size and _HEX.fullmatch(value) is not None


def _is_token(value: object) -> bool:
    if isinstance(value, list):
        return len(value) <= 64 and all(_is_token(item) for item in value)
    if isinstance(value, str):
        return _TOKEN.fullmatch(value) is not None
    return value is None or isinstance(value, (bool, int, float))


def validate_record(record: dict) -> None:
    """Raise ValueError unless `record` is a well-formed row without free text."""
    _check(isinstance(record, dict), "not an object")
    _check(set(record) == RECORD_FIELDS,
           f"fields differ: {sorted(set(record) ^ RECORD_FIELDS)}")
    _check(record["schema"] == SCHEMA, "schema")
    _check(record["route"] in ROUTES, "route")
    _check(record["protocol"] in PROTOCOLS[record["route"]], "protocol")
    _check(record["route_event"] in ROUTE_EVENTS, "route_event")
    _check(record["category"] in CATEGORIES, "category")
    _check(isinstance(record["location"], str) and 0 < len(record["location"]) <= 512,
           "location")
    _check(record["collection"] in COLLECTIONS, "collection")
    _check(record["decision_point"] in DECISION_POINTS, "decision_point")
    _check(record["route_decision"] in ROUTE_DECISIONS, "route_decision")
    record_id, kind = record["archive_record_id"], record["archive_kind"]
    _check((record_id is None and kind is None)
           or (_is_hex(record_id, 32) and kind in ARCHIVE_KINDS), "archive receipt")
    _check(record["collection"] == "content" or record_id is None,
           "metadata_only row references archived content")
    size = record["content_bytes"]
    _check(isinstance(size, int) and not isinstance(size, bool) and size >= 0, "content_bytes")
    for key in ("content_hmac", "match_hmac", "request_sha256"):
        _check(record[key] is None or _is_hex(record[key], 64), key)
    _check(isinstance(record["inspected"], bool), "inspected")
    _check(record["released_by_route"] is None or isinstance(record["released_by_route"], bool),
           "released_by_route")
    for key in ("dlp_decision", "actionable_decision"):
        _check(record[key] is None or record[key] in DECISIONS, key)
    for key in ("matched_rule_ids", "categories"):
        _check(isinstance(record[key], list) and all(isinstance(item, str) and _is_token(item)
                                                     for item in record[key]), key)
    for key in CORRELATION_FIELDS:
        value = record[key]
        _check(value is None or (isinstance(value, str) and 0 < len(value) <= _MAX_ID), key)
    for key in ("policy_version", "gate_mode"):
        _check(isinstance(record[key], str) and len(record[key]) <= _MAX_ID, key)
    elapsed = record["elapsed_ms"]
    _check(isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool) and elapsed >= 0,
           "elapsed_ms")
    _check(isinstance(record["collected_at"], str), "collected_at")
    extra = record["extra"]
    _check(isinstance(extra, dict) and all(isinstance(key, str) and _TOKEN.fullmatch(key)
                                           and _is_token(value) for key, value in extra.items()),
           "extra holds only counts, flags and identifiers")


class CollectionWriter:
    """Append validated rows with the gate's locked, fsynced, rotating writer."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def write(self, records: Iterable[dict]) -> None:
        rows = list(records)
        for record in rows:
            validate_record(record)
        if not rows:
            return
        # Imported here: codex_hook_gate imports this module.
        from .codex_hook_gate import append_audit_line
        # One call writes every row under one lock, so a batch lands together.
        append_audit_line(self.path, "\n".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True) for record in rows))
