"""Itemize Anthropic Messages request bodies before a Claude native gate decides.

Only the JSON body enters this module. Authentication headers are not collected.
Unknown content blocks and referenced attachments fail closed rather than being
silently treated as inspectable text. The original body remains in the encrypted
request archive managed by ``NativeRequestCollector``.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json

from .codex_hook_gate import leaves
from .collection import CollectedItem, data_urls, normalize_match_text
from .wire_items import WireRequest


_MAX_ATTACHMENT_BYTES = 16 * 1024 * 1024
_IMAGE_TYPES = frozenset(("image/jpeg", "image/png", "image/gif", "image/webp"))
_ROLES = frozenset(("user", "assistant", "system", "developer"))
_UNINSPECTABLE_ATTACHMENT = ("INSPECTION_ERROR", "CLAUDE_ATTACHMENT_UNINSPECTABLE", 1.0)


def _encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _has_unmodeled_base64(value: object) -> bool:
    if isinstance(value, dict):
        return (value.get("type") == "base64" and isinstance(value.get("data"), str)
                or any(_has_unmodeled_base64(item) for item in value.values()))
    return (any(_has_unmodeled_base64(item) for item in value)
            if isinstance(value, list) else False)


def _text(category: str, location: str, value: str, role: str,
          *, call_id: str | None = None, tool_name: str | None = None) -> CollectedItem:
    if data_urls(value):
        raise ValueError("inline attachment disguised as Claude text")
    return CollectedItem(category, location, value.encode("utf-8"), value,
                         normalize_match_text(category, value), role=role,
                         call_id=call_id, tool_name=tool_name)


_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n\t ")


def _maybe_base64_decoded(items: list[CollectedItem], location: str, value: str,
                          role: str, *, call_id: str | None = None,
                          tool_name: str | None = None) -> None:
    """Append a decoded copy when tool output is one self-encoded base64 blob.

    Covers the CodeX "base64 编码后回传" scenario for tool results: a single
    line of base64 whose decoded bytes are readable text is checked as an
    additional tool_output item. Heuristics (padding or non-alphanumeric
    alphabet, minimum length, valid UTF-8 text) keep ordinary prose from
    being treated as encoded payloads.
    """
    if len(value) > (_MAX_ATTACHMENT_BYTES * 4 // 3 + 1024):
        return
    compact = "".join(value.split())
    if len(compact) < 40 or len(compact) % 4:
        return
    if any(char not in _B64_ALPHABET for char in compact):
        return
    if not compact.endswith("=") and "+" not in compact and "/" not in compact:
        return
    try:
        payload = base64.b64decode(compact.encode("ascii"), validate=True)
    except (ValueError, binascii.Error):
        return
    if len(payload) < 12:
        return
    try:
        decoded_text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return
    if not decoded_text or not decoded_text.strip():
        return
    printable = sum(1 for char in decoded_text if char.isprintable() or char in "\r\n\t")
    if printable * 10 < len(decoded_text) * 9:
        return
    items.append(CollectedItem("tool_output", location + "#base64-decoded",
                               payload, decoded_text,
                               normalize_match_text("tool_output", decoded_text),
                               role=role, call_id=call_id, tool_name=tool_name))


def _json_item(category: str, location: str, value: object, role: str | None = None,
               *, call_id: str | None = None,
               tool_name: str | None = None) -> CollectedItem:
    if data_urls(value) or _has_unmodeled_base64(value):
        raise ValueError("unmodeled inline attachment in Claude JSON field")
    return CollectedItem(category, location, _encoded(value), "\n".join(leaves(value)),
                         None, role=role, call_id=call_id, tool_name=tool_name)


def _extras(items: list[CollectedItem], location: str, value: dict,
            covered: tuple[str, ...], role: str | None = None) -> None:
    rest = {key: item for key, item in value.items() if key not in covered}
    if rest:
        items.append(_json_item("request_metadata", location + "#metadata", rest, role))


def _attachment(items: list[CollectedItem], block: dict, location: str, role: str,
                *, tool_result: bool, call_id: str | None,
                tool_name: str | None) -> None:
    kind, source = block.get("type"), block.get("source")
    if not isinstance(source, dict):
        raise ValueError("Claude attachment source is absent")
    source_type = source.get("type")
    media_type = source.get("media_type")
    if set(source) - {"type", "media_type", "data"}:
        raise ValueError("unsupported Claude attachment source fields")
    category = ("tool_output_image" if tool_result and kind == "image" else
                "tool_output" if tool_result else "user_attachment")
    if source_type == "base64":
        data = source.get("data")
        if not isinstance(data, str) or len(data) > (_MAX_ATTACHMENT_BYTES * 4 // 3 + 8):
            raise ValueError("Claude attachment base64 is absent or oversized")
        try:
            payload = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("Claude attachment base64 is malformed") from error
        if not payload or len(payload) > _MAX_ATTACHMENT_BYTES:
            raise ValueError("Claude attachment is empty or oversized")
        if kind == "image":
            if media_type not in _IMAGE_TYPES:
                raise ValueError("unsupported Claude image media type")
            items.append(CollectedItem(category, location, payload, "", None,
                                       archive_kind="attachment", inspectable=False,
                                       findings=(_UNINSPECTABLE_ATTACHMENT,), role=role,
                                       call_id=call_id, tool_name=tool_name))
        elif kind == "document" and media_type == "application/pdf":
            items.append(CollectedItem(category, location, payload, "", None,
                                       archive_kind="attachment", role=role,
                                       file_name="document.pdf", call_id=call_id,
                                       tool_name=tool_name))
        else:
            raise ValueError("unsupported Claude document media type")
    elif kind == "document" and source_type == "text":
        data = source.get("data")
        if not isinstance(data, str):
            raise ValueError("Claude text document is malformed")
        items.append(CollectedItem(category, location, data.encode("utf-8"), data,
                                   normalize_match_text(category, data),
                                   archive_kind="attachment", role=role,
                                   call_id=call_id, tool_name=tool_name))
    else:
        # URL, file-id and future source types have no bytes available to this gate.
        raise ValueError("Claude attachment is a reference or unsupported source")
    _extras(items, location, block, ("type", "source"), role)


def _content(items: list[CollectedItem], content: object, location: str, role: str,
             names: dict[str, str], *, tool_result: bool = False,
             call_id: str | None = None) -> None:
    category = ("tool_output" if tool_result else "user_prompt" if role == "user"
                else "model_output_history" if role == "assistant"
                else "system_developer_prompt")
    if isinstance(content, str):
        if content:
            items.append(_text(category, location, content, role, call_id=call_id,
                               tool_name=names.get(call_id)))
            if tool_result:
                _maybe_base64_decoded(items, location, content, role,
                                      call_id=call_id, tool_name=names.get(call_id))
        return
    if not isinstance(content, list):
        raise ValueError("Claude message content is not text or blocks")
    for index, block in enumerate(content):
        path = f"{location}/{index}"
        if not isinstance(block, dict) or not isinstance(block.get("type"), str):
            raise ValueError("Claude content block has no type")
        kind = block["type"]
        if kind == "text":
            value = block.get("text")
            if not isinstance(value, str):
                raise ValueError("Claude text block is malformed")
            if value:
                items.append(_text(category, path, value, role, call_id=call_id,
                                   tool_name=names.get(call_id)))
                if tool_result:
                    _maybe_base64_decoded(items, path, value, role,
                                          call_id=call_id, tool_name=names.get(call_id))
            _extras(items, path, block, ("type", "text"), role)
        elif kind in ("image", "document"):
            _attachment(items, block, path, role, tool_result=tool_result,
                        call_id=call_id, tool_name=names.get(call_id))
        elif kind == "tool_result" and not tool_result:
            tool_id = block.get("tool_use_id")
            if not isinstance(tool_id, str) or not tool_id:
                raise ValueError("Claude tool result has no tool_use_id")
            _content(items, block.get("content"), path + "/content", role, names,
                     tool_result=True, call_id=tool_id)
            _extras(items, path, block, ("type", "tool_use_id", "content"), role)
        elif kind in ("tool_use", "server_tool_use") and not tool_result:
            tool_name = block.get("name")
            tool_input = block.get("input")
            if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
                raise ValueError("Claude tool use is malformed")
            tool_id = block.get("id") if isinstance(block.get("id"), str) else None
            arguments = _json_item("tool_call_args", path + "/input", tool_input,
                                   role, call_id=tool_id, tool_name=tool_name)
            items.append(CollectedItem(arguments.category, arguments.location,
                                       arguments.payload,
                                       f"tool_name={tool_name}\n{arguments.inspect_text}",
                                       arguments.match_text, role=role,
                                       call_id=tool_id, tool_name=tool_name))
            _extras(items, path, block, ("type", "id", "name", "input"), role)
        elif kind == "thinking" and not tool_result:
            thought = block.get("thinking")
            if not isinstance(thought, str):
                raise ValueError("Claude thinking block is malformed")
            if thought:
                items.append(_text("model_output_history", path, thought, role))
            # Signature is an opaque server token, not content supplied by the user.
            _extras(items, path, block, ("type", "thinking", "signature"), role)
        else:
            # Includes redacted_thinking and blocks whose structure this fixed
            # version's parser has not validated. The collector denies parse fails.
            raise ValueError(f"unsupported Claude content block: {kind}")


def parse_claude_messages(body: dict, raw: bytes) -> WireRequest:
    """Parse one Anthropic Messages JSON body; reject unknown content shapes."""
    if (not isinstance(body.get("model"), str) or not isinstance(body.get("messages"), list)
            or not body["messages"]):
        raise ValueError("not an Anthropic Messages request")
    items: list[CollectedItem] = []
    names: dict[str, str] = {}
    for message in body["messages"]:
        if isinstance(message, dict) and isinstance(message.get("content"), list):
            for block in message["content"]:
                if (isinstance(block, dict) and block.get("type") in ("tool_use", "server_tool_use")
                        and isinstance(block.get("id"), str)
                        and isinstance(block.get("name"), str)):
                    names[block["id"]] = block["name"]
    system = body.get("system")
    if system is not None:
        if isinstance(system, str):
            if system:
                items.append(_text("system_developer_prompt", "/system", system, "system"))
        elif isinstance(system, list):
            for index, block in enumerate(system):
                if (not isinstance(block, dict) or block.get("type") != "text"
                        or not isinstance(block.get("text"), str)):
                    raise ValueError("unsupported Claude system block")
                if block["text"]:
                    items.append(_text("system_developer_prompt", f"/system/{index}",
                                       block["text"], "system"))
                _extras(items, f"/system/{index}", block, ("type", "text"), "system")
        else:
            raise ValueError("Claude system prompt is malformed")
    for index, message in enumerate(body["messages"]):
        if not isinstance(message, dict) or message.get("role") not in _ROLES:
            raise ValueError("Claude message role is unsupported")
        role = message["role"]
        path = f"/messages/{index}"
        _content(items, message.get("content"), path + "/content", role, names)
        _extras(items, path, message, ("role", "content"), role)
    tools = body.get("tools")
    if tools is not None:
        if not isinstance(tools, list):
            raise ValueError("Claude tools field is malformed")
        for index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                raise ValueError("Claude tool definition is malformed")
            items.append(_json_item("tool_definitions", f"/tools/{index}", tool))
    rest = {key: value for key, value in body.items()
            if key not in ("system", "messages", "tools")}
    if rest:
        items.append(_json_item("request_metadata", "/", rest))
    return WireRequest("anthropic_messages", [item for item in items if item.payload],
                       {"session_id": None, "thread_id": None, "turn_id": None,
                        "model": body["model"][:256]}, False, [],
                       hashlib.sha256(raw).hexdigest())
