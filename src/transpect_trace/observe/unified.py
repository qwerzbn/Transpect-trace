"""Unified in-memory semantics with metadata-only default serialization."""
from __future__ import annotations

import hashlib
import json
import zlib
from typing import Literal
from uuid import uuid4
from pydantic import Field
from .models import BODY_LIMIT, Record
from .protocol import CoverageGap, decode_body
from .classification import TrafficClassification, classify


class ContentField(Record):
    kind: Literal["message", "context", "tool_call", "tool_result", "attachment_reference", "attachment_inline", "tool_definition", "unknown"]
    location: str
    role: Literal["system", "developer", "user", "assistant", "tool", "function", "unknown"] = "unknown"
    bytes: int
    sha256: str
    inspected: bool = True
    # Never serialized or included in repr, even in model_dump_json().
    value: object = Field(default=None, exclude=True, repr=False)


class UnifiedLLMRequest(Record):
    schema_version: Literal["transpect.llm.request/1.0"] = "transpect.llm.request/1.0"
    request_id: str = Field(default_factory=lambda: uuid4().hex)
    observation_id: str
    capture_source: str
    application: str
    channel: Literal["cli", "ide", "api", "web", "unknown"]
    pid: int
    creation_filetime: int
    image_sha256: str | None
    connection_id: str
    stream_id: int | None
    transport_protocol: Literal["tls", "unknown"]
    application_protocol: str
    destination: str | None
    destination_evidence: str
    completeness: Literal["complete", "partial", "unknown"]
    encoding_state: Literal["identity", "decoded", "compressed", "encrypted", "unsupported", "unknown"]
    parsing_state: Literal["parsed", "failed", "unsupported", "unknown"]
    raw_payload_sha256: str
    raw_payload_bytes: int
    decoded_payload_sha256: str | None
    decoded_payload_bytes: int | None
    classification: TrafficClassification
    fields: list[ContentField]
    limitations: list[str]
    capture_point: str
    send_evidence: str
    can_enforce: Literal[False] = False


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def extract_fields(value):
    """Only visit runtime content; JSON schemas/metadata are not tool calls."""
    fields = []

    def add(kind, location, item, role="unknown", inspected=True):
        if len(fields) >= 4096:
            raise CoverageGap("semantic_field_limit")
        raw = canonical(item)
        fields.append(ContentField(kind=kind, location=location, role=role if isinstance(role,str) and role in {
            "system", "developer", "user", "assistant", "tool", "function"} else "unknown",
            bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), inspected=inspected, value=item))

    def walk(item, path, role="unknown", depth=0):
        if not isinstance(role,str):role='unknown'
        if depth > 64:
            raise CoverageGap("semantic_depth_limit")
        if isinstance(item, str):
            add("context" if role in {"system", "developer"} else "tool_result" if role in {"tool", "function"} else "message", path, item, role)
        elif isinstance(item, list):
            for i, child in enumerate(item):
                walk(child, f"{path}/{i}", role, depth+1)
        elif isinstance(item, dict):
            typ = item.get("type")
            r = item.get("role", role)
            if not isinstance(typ,str):typ=None
            if typ in {"input_file", "input_image", "input_audio", "image_url", "file"}:
                # References, URLs and base64 all remain uninspected attachments.
                inline = any((isinstance(v, str) and (v.startswith("data:") or k in {"file_data", "data", "image_base64"})) or
                             (isinstance(v,dict) and isinstance(v.get('url'),str) and v['url'].startswith('data:')) for k,v in item.items())
                add("attachment_inline" if inline else "attachment_reference", path, item, inspected=False)
            elif typ in {"function_call", "function_call_output"}:
                add("tool_call" if typ == "function_call" else "tool_result", path, item)
            else:
                if "content" in item:
                    walk(item["content"], path+"/content", r, depth+1)
                if "text" in item:
                    walk(item["text"], path+"/text", r, depth+1)
                if "tool_calls" in item:
                    for i, call in enumerate(item["tool_calls"] if isinstance(item["tool_calls"], list) else []):
                        add("tool_call", f"{path}/tool_calls/{i}", call, r)
                if not any(k in item for k in ("content", "text", "tool_calls")):
                    add("unknown", path, item, r, inspected=False)

    if isinstance(value, dict):
        base = value.get("response", value) if value.get("type") == "response.create" else value
        if not isinstance(base, dict):
            return fields
        prefix = "/response" if base is not value else ""
        for key in ("input", "messages"):
            if key in base:
                walk(base[key], prefix+"/"+key, "user" if isinstance(base[key], str) else "unknown")
        if "instructions" in base:
            add("context", prefix+"/instructions", base["instructions"], "system")
        if "tools" in base:
            add("tool_definition", prefix+"/tools", base["tools"])
    return fields


def normalize(event, body, observation):
    raw = body.data
    limits = list(body.limitations)
    if event.truncated: limits.append("capture_truncated")
    if event.lost_events: limits.append("capture_events_lost")
    if event.connection_identity != "stable": limits.append("connection_identity_unknown")
    encoding = body.headers.get("content-encoding", "").strip().lower()
    state = "identity" if encoding in {"", "identity"} else "decoded"
    decoded = None; value = None; fields = []; parsing = "unknown"
    if len(raw) > BODY_LIMIT:
        limits.append("body_limit"); state = "unknown"
    else:
        try:
            decoded = decode_body(raw, encoding)
        except (CoverageGap, ValueError, zlib.error):
            state = "compressed" if encoding in {"gzip", "deflate", "zstd"} else "unsupported"
            limits.append("content_decoding_unavailable")
    if decoded is not None:
        try:
            value = json.loads(decoded.decode("utf-8"))
            fields = extract_fields(value)
            parsing = "parsed"
        except (ValueError, UnicodeError, RecursionError):
            parsing = "failed"; limits.append("payload_parsing_failed")
    if any(not f.inspected for f in fields): limits.append("semantic_content_not_inspected")
    # JSON parsing and attachment semantics do not prove/disprove wire boundaries.
    wire_complete = not body.limitations and not event.truncated and not event.lost_events and event.connection_identity == "stable"
    complete = "complete" if wire_complete else "partial" if event.truncated else "unknown"
    classification = classify(observation.observation_id, value, body.headers, event.application,
        complete=wire_complete, decoded=decoded is not None, empty=decoded==b'')
    return UnifiedLLMRequest(observation_id=observation.observation_id, capture_source=event.provider,
        application=event.application, channel={"codex-cli":"cli", "vscode-codex":"ide", "python-api":"api", "chrome-web":"web"}.get(event.application,"unknown"),
        pid=event.pid, creation_filetime=event.creation_filetime, image_sha256=event.image_sha256,
        connection_id=event.connection_id, stream_id=body.stream_id,
        transport_protocol="tls" if event.capture_point == "tls" else "unknown", application_protocol=body.protocol,
        destination=observation.destination, destination_evidence=observation.destination_evidence,
        completeness=complete, encoding_state=state, parsing_state=parsing,
        raw_payload_sha256=hashlib.sha256(raw).hexdigest(), raw_payload_bytes=len(raw),
        decoded_payload_sha256=hashlib.sha256(decoded).hexdigest() if decoded is not None else None,
        decoded_payload_bytes=len(decoded) if decoded is not None else None,
        classification=classification, fields=fields, limitations=sorted(set(limits)),
        capture_point=event.capture_point, send_evidence=observation.send_evidence)
