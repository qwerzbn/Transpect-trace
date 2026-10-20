"""Request-side semantics, independent of capture backend and policy decisions.

Default serialization contains positions, lengths and hashes, never content.
User-role messages are prompt candidates, not proof of human authorship.
"""
from __future__ import annotations

import hashlib
import json
import zlib
from typing import Literal

from pydantic import Field

from .models import BODY_LIMIT, Record
from .protocol import CoverageGap, decode_body

VERSION = "request-semantics/1"
GROUPS = ("prompt", "context", "tool_calls", "tool_results", "attachments", "tool_definitions", "unknown")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encoded(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


class SemanticPart(Record):
    location: str
    role: Literal["system", "developer", "user", "assistant", "tool", "function", "unknown"] = "unknown"
    representation: Literal["text", "json", "json_string", "opaque", "attachment"]
    bytes: int
    sha256: str
    inspected: bool
    call_id_sha256: str | None = None
    tool_name_sha256: str | None = None
    # No raw arguments, names or identifiers in repr/default exports.
    value: object = Field(default=None, exclude=True, repr=False)
    call_id: str | None = Field(default=None, exclude=True, repr=False)
    tool_name: str | None = Field(default=None, exclude=True, repr=False)


class ToolLink(Record):
    call_location: str
    result_location: str
    basis: Literal["unique_call_id_within_request"] = "unique_call_id_within_request"
    proves_execution: Literal[False] = False


class RequestSemantics(Record):
    schema_version: Literal["transpect.observe.request-semantics/1.0"] = "transpect.observe.request-semantics/1.0"
    extractor_version: str = VERSION
    observation_id: str
    capture_source: str
    capture_point: str
    protocol: str
    completeness: Literal["complete", "partial", "unknown"]
    encoding_state: Literal["identity", "decoded", "unsupported", "unknown"] = "unknown"
    format: Literal["responses", "chat_completions", "wss_response_create", "unknown"] = "unknown"
    status: Literal["extracted", "partial", "unsupported", "failed"] = "unsupported"
    raw_body_sha256: str
    decoded_body_sha256: str | None = None
    prompt: list[SemanticPart] = Field(default_factory=list)
    context: list[SemanticPart] = Field(default_factory=list)
    tool_calls: list[SemanticPart] = Field(default_factory=list)
    tool_results: list[SemanticPart] = Field(default_factory=list)
    attachments: list[SemanticPart] = Field(default_factory=list)
    tool_definitions: list[SemanticPart] = Field(default_factory=list)
    unknown: list[SemanticPart] = Field(default_factory=list)
    tool_links: list[ToolLink] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    can_enforce: Literal[False] = False

    def synthetic_export(self):
        """Explicit fake-data laboratory export, never used by default auditing."""
        result = self.model_dump()
        result["synthetic_content_export"] = True
        for group in GROUPS:
            for row, part in zip(result[group], getattr(self, group)):
                row.update(value=part.value, call_id=part.call_id, tool_name=part.tool_name)
        return result


def _json(raw):
    def reject(_):
        raise ValueError("non-finite JSON number")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    value = json.loads(raw, parse_constant=reject, object_pairs_hook=unique)
    # Bounds apply before walking semantic fields or serializing subtrees.
    todo = [(value, 0)]
    count = 0
    while todo:
        item, depth = todo.pop()
        count += 1
        if count > 100_000 or depth > 64:
            raise CoverageGap("semantic_structure_limit")
        if isinstance(item, dict):
            todo.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            todo.extend((v, depth + 1) for v in item)
    return value


def extract_request(raw: bytes, *, observation_id: str, capture_source: str,
                    completeness="unknown", content_encoding="identity",
                    capture_point="unknown", protocol="unknown") -> RequestSemantics:
    result = RequestSemantics(observation_id=observation_id, capture_source=capture_source,
        capture_point=capture_point, protocol=protocol, completeness=completeness,
        raw_body_sha256=digest(raw),
        limitations=["user_role_is_not_proof_of_human_input",
                     "context_only_includes_content_present_in_this_request",
                     "request_tool_records_do_not_prove_actual_execution"])
    if completeness != "complete":
        result.limitations.append("request_boundary_not_complete")
    try:
        if len(raw) > BODY_LIMIT:
            raise CoverageGap("body_limit")
        decoded = decode_body(raw, content_encoding)
        result.encoding_state = "identity" if content_encoding.strip().lower() in {"", "identity"} else "decoded"
        result.decoded_body_sha256 = digest(decoded)
        value = _json(decoded.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request object required")
        if "input" in value and "messages" in value:
            result.limitations.append("ambiguous_request_structure")
            return result
        base, prefix = value, ""
        if value.get("type") == "response.create":
            base = value.get("response", value)
            if not isinstance(base, dict) or not any(k in base for k in ("input", "instructions")):
                result.limitations.append("unknown_request_structure")
                return result
            prefix = "/response" if base is not value else ""
            result.format = "wss_response_create"
        elif isinstance(value.get("model"), str) and "input" in value:
            result.format = "responses"
        elif isinstance(value.get("model"), str) and isinstance(value.get("messages"), list):
            result.format = "chat_completions"
        else:
            result.limitations.append("unknown_request_structure")
            return result

        count = 0

        def add(group, path, data, role="unknown", representation=None, call_id=None, name=None, inspected=True):
            nonlocal count
            count += 1
            if count > 4096:
                raise CoverageGap("semantic_field_limit")
            role = role if isinstance(role, str) and role in {"system", "developer", "user", "assistant", "tool", "function"} else "unknown"
            call_id = call_id if isinstance(call_id, str) and call_id else None
            name = name if isinstance(name, str) and name else None
            payload = encoded(data)
            part = SemanticPart(location=path, role=role,
                representation=representation or ("text" if isinstance(data, str) else "json"),
                bytes=len(payload), sha256=digest(payload), inspected=inspected,
                call_id_sha256=digest(call_id.encode()) if call_id else None,
                tool_name_sha256=digest(name.encode()) if name else None,
                value=data, call_id=call_id, tool_name=name)
            getattr(result, group).append(part)
            return part

        def unknown(path, data):
            add("unknown", path, data, representation="opaque", inspected=False)
            result.limitations.append("unknown_semantic_content")

        def content(data, path, role):
            group = "prompt" if role == "user" else "context" if role in ("system", "developer", "assistant") else "unknown"
            if isinstance(data, str):
                add(group, path, data, role, inspected=group != "unknown")
                if group == "unknown":
                    result.limitations.append("unknown_message_role")
            elif isinstance(data, list):
                for i, part in enumerate(data):
                    location = f"{path}/{i}"
                    if isinstance(part, str):
                        content(part, location, role)
                    elif isinstance(part, dict) and part.get("type") in ("text", "input_text", "output_text") and isinstance(part.get("text"), str):
                        content(part["text"], location + "/text", role)
                    elif isinstance(part, dict) and part.get("type") in ("input_file", "file", "input_image", "image_url", "input_audio"):
                        add("attachments", location, part, role, representation="attachment", inspected=False)
                        result.limitations.append("attachment_content_not_inspected")
                    else:
                        unknown(location, part)
            else:
                unknown(path, data)

        def call(item, path):
            function = item.get("function") if isinstance(item.get("function"), dict) else item
            if item.get("type") not in (None, "function", "function_call"):
                unknown(path, item)
                return
            arguments = function.get("arguments")
            representation = "json"
            inspected = True
            if isinstance(arguments, str):
                representation = "json_string"
                try:
                    if len(arguments.encode()) > 1024 * 1024:
                        raise ValueError("arguments limit")
                    arguments = _json(arguments)
                except (ValueError, RecursionError):
                    # Keep original in memory, but do not pretend opaque syntax was understood.
                    arguments = function["arguments"]
                    representation, inspected = "opaque", False
                    result.limitations.append("tool_arguments_not_parsed")
                if inspected and not isinstance(arguments, (dict, list)):
                    inspected = False
                    result.limitations.append("tool_arguments_not_parsed")
            elif not isinstance(arguments, (dict, list)):
                inspected = False
                result.limitations.append("tool_arguments_not_parsed")
            add("tool_calls", path, arguments, "assistant", representation=representation,
                call_id=item.get("call_id") or item.get("id"), name=function.get("name"), inspected=inspected)

        def output(data, path, role="tool", call_id=None, name=None):
            # Preserve structured tool output. Only inspect top-level content
            # parts; arbitrary nested tool JSON is not a new protocol message.
            inspected = True
            parts = enumerate(data) if isinstance(data, list) else [(None, data)]
            for index, part in parts:
                location = path if index is None else f"{path}/{index}"
                if isinstance(part, dict) and part.get("type") in (
                    "input_file", "file", "input_image", "image_url", "input_audio"):
                    add("attachments", location, part, role, representation="attachment", inspected=False)
                    result.limitations.append("attachment_content_not_inspected")
                    inspected = False
            add("tool_results", path, data, role, call_id=call_id, name=name, inspected=inspected)

        input_key = "messages" if result.format == "chat_completions" else "input"
        if input_key in base:
            items = base[input_key]
            if isinstance(items, str) and input_key == "input":
                content(items, prefix + "/input", "user")
            elif isinstance(items, list):
                for i, item in enumerate(items):
                    path = f"{prefix}/{input_key}/{i}"
                    if not isinstance(item, dict):
                        unknown(path, item)
                        continue
                    typ, role = item.get("type"), item.get("role")
                    if typ == "function_call":
                        call(item, path)
                    elif typ == "function_call_output":
                        if "output" not in item:
                            unknown(path, item)
                        else:
                            output(item["output"], path + "/output", call_id=item.get("call_id"))
                    elif typ not in (None, "message"):
                        unknown(path, item)
                    elif role in ("tool", "function"):
                        if "content" in item:
                            output(item["content"], path + "/content", role,
                                call_id=item.get("tool_call_id"), name=item.get("name"))
                        else:
                            unknown(path, item)
                    else:
                        if "content" in item and item["content"] is not None:
                            content(item["content"], path + "/content", role)
                        calls = item.get("tool_calls", [])
                        if isinstance(calls, list):
                            for n, tool in enumerate(calls):
                                if isinstance(tool, dict):
                                    call(tool, f"{path}/tool_calls/{n}")
                                else:
                                    unknown(f"{path}/tool_calls/{n}", tool)
                        else:
                            unknown(path + "/tool_calls", calls)
                        if "function_call" in item:
                            if isinstance(item["function_call"], dict):
                                call(item["function_call"], path + "/function_call")
                            else:
                                unknown(path + "/function_call", item["function_call"])
                        if not any(k in item for k in ("content", "tool_calls", "function_call")):
                            unknown(path, item)
            else:
                unknown(prefix + "/" + input_key, items)
        if "instructions" in base:
            content(base["instructions"], prefix + "/instructions", "system")
        if "tools" in base:
            add("tool_definitions", prefix + "/tools", base["tools"])
        if "functions" in base:
            add("tool_definitions", prefix + "/functions", base["functions"])

        # Explicit identifiers only. Never match results to calls by name/order/time.
        for output in result.tool_results:
            matches = [c for c in result.tool_calls if output.call_id and c.call_id == output.call_id]
            outputs = [r for r in result.tool_results if output.call_id and r.call_id == output.call_id]
            if len(matches) == len(outputs) == 1:
                result.tool_links.append(ToolLink(call_location=matches[0].location, result_location=output.location))
            else:
                result.limitations.append("tool_result_call_unresolved")
        if not any(getattr(result, g) for g in ("prompt", "context", "tool_calls", "tool_results")):
            result.limitations.append("no_supported_runtime_content")
        incomplete = (completeness != "complete" or result.unknown or result.attachments
                      or any(not p.inspected for p in result.tool_calls)
                      or "no_supported_runtime_content" in result.limitations)
        result.status = "partial" if incomplete else "extracted"
    except (ValueError, TypeError, UnicodeError, RecursionError, zlib.error):
        # Clear partial values after failure; exceptions must not export payloads.
        for group in GROUPS:
            getattr(result, group).clear()
        result.tool_links.clear()
        result.status = "failed"
        result.limitations.append("semantic_decode_or_parse_failed")
    result.limitations = sorted(set(result.limitations))
    return result


def from_unified(unified, raw, content_encoding="identity"):
    """Keep the existing v1 record unchanged and link an additive result to it."""
    result = extract_request(raw, observation_id=unified.observation_id,
        capture_source=unified.capture_source, completeness=unified.completeness,
        content_encoding=content_encoding, capture_point=unified.capture_point,
        protocol=unified.application_protocol)
    if (result.raw_body_sha256 != unified.raw_payload_sha256 or len(raw) != unified.raw_payload_bytes
            or (unified.decoded_payload_sha256 is not None
                and result.decoded_body_sha256 != unified.decoded_payload_sha256)):
        for group in GROUPS:
            getattr(result, group).clear()
        result.tool_links.clear()
        result.status = "failed"
        result.limitations.append("unified_body_identity_mismatch")
    return result
