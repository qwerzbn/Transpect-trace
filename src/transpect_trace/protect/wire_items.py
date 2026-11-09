"""Split one serialized Codex model request into categorized content items.

Route N sees the complete request body; the evaluator sees the bytes the origin
received. Both go through `parse_wire_request`, so a category means the same
thing on either side. It wraps `observe.semantics.extract_request` and only
re-labels what that walker finds: user-role text is the AGENTS.md block, the
environment context, an attachment wrapper or the prompt; developer text is the
system prompt; assistant text is echoed history; data-URL parts become archived
attachment bytes. Message ids never reach an item, and request metadata is
inspected through `desktop_bridge._protocol_metadata_view` with the verified
Codex protocol ids masked, so those ids stop scoring as high-entropy tokens.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import mimetypes
import re

from transpect_trace.observe.semantics import encoded, extract_request
from .codex_hook_gate import leaves
from .collection import (ATTACHMENT_UNDECODABLE, IMAGE_GAP, CollectedItem, DataURL,
                         data_urls, normalize_match_text, parse_data_url,
                         strip_exec_output_header)
from .desktop_bridge import _protocol_metadata_view

_ITEMIZED = frozenset(("input", "instructions", "tools", "functions"))
_TEXT_CATEGORIES = frozenset(("user_prompt", "user_attachment", "client_instructions",
                              "environment_context", "system_developer_prompt",
                              "model_output_history", "tool_output"))
_TEXT_PARTS = frozenset(("text", "input_text", "output_text"))
# Tools whose result the client prefixes with its own "Chunk ID/.../Output:" header.
# The hook inspects the output without it, and the header's "token count" made the
# context rule promote any high-entropy first line to a BLOCK.
_EXEC_TOOLS = frozenset(("exec_command", "write_stdin"))
_ATTACHMENT_PARTS = frozenset(("input_file", "file", "input_image", "image_url", "input_audio"))
# Codex-generated ids in client_metadata and x-codex-turn-metadata (0.166):
# UUIDs, the window id adds ":<n>". Only these keys are masked.
_ID_KEYS = frozenset(("session_id", "thread_id", "turn_id", "root_turn_id", "prompt_cache_key",
                      "x-codex-window-id", "x-codex-installation-id", "installation_id",
                      "window_id", "context_window_id"))
_PROTOCOL_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                          r"(?::\d{1,6})?", re.I)
_TURN_METADATA = "x-codex-turn-metadata"
_MAX_ID = 256
# Keys of an input item the semantic walker itemizes. Any other field of the
# item is inspected as a residual `unknown` item, so no field leaves unseen.
_MODELED_KEYS = {"function_call": frozenset(("type", "id", "call_id", "name", "arguments")),
                 "function_call_output": frozenset(("type", "id", "call_id", "output")),
                 "message": frozenset(("type", "id", "role", "content"))}
_OPAQUE_KEYS = frozenset(("id", "encrypted_content"))
# Desktop (0.166 WSS) item types the semantic walker leaves as `unknown`.
_CUSTOM_CALL, _CUSTOM_OUTPUT, _EXTRA_TOOLS = ("custom_tool_call", "custom_tool_call_output",
                                              "additional_tools")
# Client bookkeeping the desktop adds to input items. Still inspected, but as
# metadata with its protocol ids masked: their turn UUIDs scored as tokens.
_ITEM_METADATA_KEYS = frozenset(("internal_chat_message_metadata_passthrough", "phase",
                                 "status", "annotations", "logprobs"))


@dataclass
class WireRequest:
    format: str                      # responses | wss_response_create | unknown
    items: list[CollectedItem]
    correlation: dict
    incremental: bool                # previous_response_id: a delta, not the full context
    limitations: list[str]
    body_sha256: str


def classify_user_text(text: str) -> str:
    """Category of one user-role text part; the client injects the first three."""
    head = text.lstrip()
    if head.startswith("# AGENTS.md instructions for "):
        return "client_instructions"
    if head.startswith("<environment_context>"):
        return "environment_context"
    if head.startswith("<image name=") or head.rstrip() == "</image>":
        return "user_attachment"
    return "user_prompt"


def item_identity(item: CollectedItem) -> bytes:
    """Dedupe key across requests: what the item is and carries, never where it sits."""
    digest = hashlib.sha256()
    for part in (item.category, item.archive_kind, item.call_id or "", item.tool_name or ""):
        data = part.encode("utf-8")
        digest.update(len(data).to_bytes(4, "little") + data)
    digest.update(item.payload)
    return digest.digest()


def _ident(value: object) -> str | None:
    return value[:_MAX_ID] if isinstance(value, str) and value else None


def wire_correlation(body: dict) -> dict:
    """Join keys from client_metadata; `prompt_cache_key` is the session/thread id."""
    meta = body.get("client_metadata")
    meta = meta if isinstance(meta, dict) else {}
    cache_key = _ident(body.get("prompt_cache_key"))
    return {"session_id": _ident(meta.get("session_id")) or cache_key,
            "thread_id": _ident(meta.get("thread_id")) or cache_key,
            "turn_id": _ident(meta.get("turn_id")), "model": _ident(body.get("model"))}


def _mask_ids(value: dict) -> dict:
    return {key: "<protocol-id>" if key in _ID_KEYS and isinstance(item, str)
            and _PROTOCOL_ID.fullmatch(item) else item for key, item in value.items()}


def metadata_view(body: dict) -> dict:
    """The DLP view of the non-content fields: protocol ids and timestamps masked."""
    view = _mask_ids(_protocol_metadata_view(body))
    meta = view.get("client_metadata")
    if isinstance(meta, dict):
        meta = _mask_ids(meta)
        turn = meta.get(_TURN_METADATA)
        if isinstance(turn, str):
            try:
                parsed = json.loads(turn)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                meta[_TURN_METADATA] = _mask_ids(parsed)
        view["client_metadata"] = meta
    return view


def _metadata(body: dict, base: dict) -> dict:
    rest = {key: value for key, value in base.items() if key not in _ITEMIZED}
    if base is not body:
        rest = {**{key: value for key, value in body.items() if key != "response"},
                "response": rest}
    return rest


def _text_item(category: str, location: str, text: str, role: str | None,
               inspect: str | None = None, **ids) -> CollectedItem:
    return CollectedItem(category, location, text.encode("utf-8"),
                         text if inspect is None else inspect,
                         normalize_match_text(category, text), role=role, **ids)


def _without_data_urls(value: object) -> object:
    if isinstance(value, str):
        return None if parse_data_url(value) else value
    if isinstance(value, dict):
        return {key: _without_data_urls(item) for key, item in value.items()}
    return [_without_data_urls(item) for item in value] if isinstance(value, list) else value


def data_url_item(category: str, location: str, url: DataURL, file_name: object = None,
                  role: str | None = None, **ids) -> CollectedItem:
    """Inline bytes: a document is inspected as a file, an image is a recorded
    gap, and a payload that does not decode is uninspectable."""
    common = {"archive_kind": "attachment", "role": role, **ids}
    if not url.data:
        return CollectedItem(category, location, url.url.encode("utf-8"), "", None,
                             inspectable=False, findings=(
                                 IMAGE_GAP if url.image else ATTACHMENT_UNDECODABLE,), **common)
    if url.image:
        return CollectedItem(category, location, url.data, "", None, inspectable=False,
                             findings=(IMAGE_GAP,), **common)
    name = file_name if isinstance(file_name, str) and file_name else (
        "attachment" + (mimetypes.guess_extension(url.media_type) or ""))
    return CollectedItem(category, location, url.data, "", None, file_name=name, **common)


def _attachment_items(category: str, part, **ids) -> list[CollectedItem]:
    urls = data_urls(part.value)
    if not urls:
        # A file id or remote URL: the reference itself is what goes upstream.
        return [CollectedItem(category, part.location, encoded(part.value),
                              "\n".join(leaves(part.value)), None, role=part.role, **ids)]
    name = part.value.get("filename") if isinstance(part.value, dict) else None
    items = [data_url_item(category, part.location if len(urls) == 1
                           else f"{part.location}#{index}", url, name, part.role, **ids)
             for index, url in enumerate(urls)]
    # The part's other fields (file name, detail) also go upstream.
    fields = _without_data_urls(part.value)
    items.append(CollectedItem(category, f"{part.location}#fields", encoded(fields),
                               "\n".join(leaves(fields)), None, role=part.role, **ids))
    return items


def _tool_output_text(value: object) -> str:
    if isinstance(value, str):
        return value
    texts = []
    for part in value if isinstance(value, list) else [value]:
        if isinstance(part, dict) and part.get("type") in _TEXT_PARTS and isinstance(
                part.get("text"), str):
            texts.append(part["text"])
        elif not (isinstance(part, dict) and part.get("type") in _ATTACHMENT_PARTS):
            texts.extend(leaves(part))
    return "\n".join(texts)


def _masked_leaves(value: object) -> list[str]:
    """Leaves of client bookkeeping with protocol ids replaced; content never comes here."""
    return [_PROTOCOL_ID.sub("<protocol-id>", leaf) for leaf in leaves(value)]


def _split_metadata(value: dict) -> tuple[dict, dict]:
    """(content fields, client bookkeeping fields) of one input item, ids dropped."""
    content = {key: item for key, item in value.items()
               if key not in _ITEM_METADATA_KEYS and key != "id"}
    return content, {key: item for key, item in value.items() if key in _ITEM_METADATA_KEYS}


def _desktop_items(part, names: dict) -> list[CollectedItem] | None:
    """Items for the desktop's custom tool call/output and extra tool definitions."""
    value = part.value
    kind = value.get("type") if isinstance(value, dict) else None
    if kind not in (_CUSTOM_CALL, _CUSTOM_OUTPUT, _EXTRA_TOOLS):
        return None
    content, meta = _split_metadata(value)
    call_id = value.get("call_id") if isinstance(value.get("call_id"), str) else None
    tool_name = value.get("name") if isinstance(value.get("name"), str) else names.get(call_id)
    payload = encoded(part.value)
    if kind == _EXTRA_TOOLS:
        items = [CollectedItem("tool_definitions", part.location, payload,
                               "\n".join(leaves(content)), None, role=part.role)]
    elif kind == _CUSTOM_CALL:
        args = {key: item for key, item in content.items() if key not in ("type", "call_id")}
        items = [CollectedItem("tool_call_args", part.location, payload,
                               f"tool_name={tool_name}\n" + "\n".join(leaves(args)), None,
                               call_id=call_id, tool_name=tool_name, role=part.role)]
    else:
        output = content.get("output")
        text = _tool_output_text(output)
        inspect = strip_exec_output_header(text) if tool_name in _EXEC_TOOLS else text
        rest = {key: item for key, item in content.items()
                if key not in ("type", "call_id", "output")}
        if rest:  # fields beside the output still go upstream
            inspect = "\n".join((inspect, *leaves(rest)))
        items = [CollectedItem("tool_output", part.location, text.encode("utf-8") or payload,
                               inspect, normalize_match_text("tool_output", text), role=part.role,
                               call_id=call_id, tool_name=tool_name)]
        items += [data_url_item("tool_output_image", f"{part.location}#{index}", url,
                                call_id=call_id, tool_name=tool_name)
                  for index, url in enumerate(data_urls(output))]
    if meta:
        items.append(CollectedItem("request_metadata", f"{part.location}#metadata",
                                   encoded(meta), "\n".join(_masked_leaves(meta)), None,
                                   role=part.role))
    return items


def _unknown_item(part) -> CollectedItem:
    value = part.value
    reasoning = isinstance(value, dict) and value.get("type") == "reasoning"
    if isinstance(value, dict):
        # Only the encrypted blob is opaque; a reasoning summary is plaintext.
        value = {key: item for key, item in value.items()
                 if key not in (_OPAQUE_KEYS if reasoning else ("id",))}
    return CollectedItem("reasoning_opaque" if reasoning else "unknown", part.location,
                         encoded(part.value), "\n".join(leaves(value)), None, role=part.role)


def _residual_items(base: dict, prefix: str) -> list[CollectedItem]:
    """Fields of itemized input items that no item carries, as `unknown` items."""
    items = []
    entries = base.get("input")
    for index, entry in enumerate(entries if isinstance(entries, list) else ()):
        modeled = _MODELED_KEYS.get(entry.get("type") or "message") if isinstance(
            entry, dict) else None
        if modeled is None or entry.get("role") in ("tool", "function"):
            continue  # taken whole as `unknown`, or a chat-format tool message
        rest = {key: value for key, value in entry.items() if key not in modeled}
        content = entry.get("content") if "content" in modeled else None
        for number, part in enumerate(content if isinstance(content, list) else ()):
            if isinstance(part, dict) and part.get("type") in _TEXT_PARTS:
                extra = {key: value for key, value in part.items() if key not in ("type", "text")}
                if extra:
                    rest[f"content/{number}"] = extra
        if rest:
            meta = {key: value for key, value in rest.items() if key in _ITEM_METADATA_KEYS or (
                key.startswith("content/") and isinstance(value, dict)
                and set(value) <= _ITEM_METADATA_KEYS)}
            other = {key: value for key, value in rest.items() if key not in meta}
            location = f"{prefix}/input/{index}#residual"
            if meta:
                items.append(CollectedItem("request_metadata", f"{location}/metadata",
                                           encoded(meta), "\n".join(_masked_leaves(meta)),
                                           None, role=entry.get("role")))
            if other:
                items.append(CollectedItem("unknown", location, encoded(other),
                                           "\n".join(leaves(other)), None,
                                           role=entry.get("role")))
    return items


def parse_wire_request(raw: bytes, *, protocol: str) -> WireRequest:
    """Items of one complete HTTP body or WSS `response.create` message.

    Raises ValueError when the body cannot be parsed; a JSON body of another
    shape returns format `unknown` with no items."""
    sha = hashlib.sha256(raw).hexdigest()
    semantics = extract_request(raw, observation_id=sha, capture_source="native",
                                completeness="complete", protocol=protocol)
    if semantics.status == "failed":
        raise ValueError("wire request could not be parsed")
    body = json.loads(raw)
    limitations = list(semantics.limitations)
    if semantics.format not in ("responses", "wss_response_create") or not isinstance(body, dict):
        return WireRequest("unknown", [], {}, False, limitations, sha)
    base = body.get("response", body) if semantics.format == "wss_response_create" else body
    base = base if isinstance(base, dict) else body
    names = {part.call_id: part.tool_name for part in semantics.tool_calls if part.call_id}
    for entry in base.get("input") if isinstance(base.get("input"), list) else ():
        if (isinstance(entry, dict) and entry.get("type") == _CUSTOM_CALL
                and isinstance(entry.get("call_id"), str) and isinstance(entry.get("name"), str)):
            names[entry["call_id"]] = entry["name"]
    items: list[CollectedItem] = []
    for part in semantics.prompt:
        items.append(_text_item(classify_user_text(part.value), part.location, part.value,
                                part.role))
    for part in semantics.context:
        category = ("model_output_history" if part.role == "assistant"
                    else "system_developer_prompt")
        items.append(_text_item(category, part.location, part.value, part.role))
    for part in semantics.tool_calls:
        value = part.value
        text = f"tool_name={part.tool_name}\n" + "\n".join(leaves(value))
        items.append(CollectedItem("tool_call_args", part.location,
                                   value.encode("utf-8") if isinstance(value, str)
                                   else encoded(value), text, None, call_id=part.call_id,
                                   tool_name=part.tool_name, role=part.role))
    for part in semantics.tool_results:
        text = _tool_output_text(part.value)
        tool_name = part.tool_name or names.get(part.call_id)
        if text or not isinstance(part.value, list):
            inspect = strip_exec_output_header(text) if tool_name in _EXEC_TOOLS else None
            items.append(_text_item("tool_output", part.location, text, part.role, inspect,
                                    call_id=part.call_id, tool_name=tool_name))
    for part in semantics.attachments:
        if part.role in ("tool", "function"):
            # Tool images sit inside a result part; take that result's call id.
            owner = next((result for result in semantics.tool_results
                          if part.location.startswith(result.location + "/")), None)
            call_id = owner.call_id if owner else None
            items.extend(_attachment_items("tool_output_image", part, call_id=call_id,
                                           tool_name=names.get(call_id)))
        else:
            items.extend(_attachment_items("user_attachment", part))
    for part in semantics.tool_definitions:
        items.append(CollectedItem("tool_definitions", part.location,
                                   json.dumps(part.value, ensure_ascii=False, sort_keys=True,
                                              separators=(",", ":")).encode("utf-8"),
                                   "\n".join(leaves(part.value)), None))
    for part in semantics.unknown:
        items.extend(_desktop_items(part, names) or [_unknown_item(part)])
    items.extend(_residual_items(base, "/response" if base is not body else ""))
    metadata = _metadata(body, base)
    if metadata:
        view = metadata_view(body)
        view_base = view.get("response", view) if base is not body else view
        items.append(CollectedItem(
            "request_metadata", "/",
            json.dumps(metadata, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode("utf-8"),
            "\n".join(leaves(_metadata(view, view_base if isinstance(view_base, dict)
                                       else view))), None))
    # The archive refuses an empty payload; an empty part carries nothing anyway.
    items = [item for item in items if item.payload]
    incremental = isinstance(base.get("previous_response_id"), str)
    if incremental:
        limitations.append("incremental_request_history_not_present")
    return WireRequest(semantics.format, items, wire_correlation(base), incremental,
                       sorted(set(limitations)), sha)
