"""In-place redaction of parsed request bodies at item JSON locations.

A BLOCK-classified item's location (e.g. "/messages/3/content/0") selects the
exact JSON node to replace. Block-shaped nodes become a plain text block;
string-shaped nodes become a placeholder string. Any unresolvable location
aborts the redaction (caller falls back to a deny) so a partial cleaning can
never leave sensitive bytes on the wire.
"""
from __future__ import annotations

import copy
import json

_REDACT_TEXT = "<已脱敏:{rules}>"


def placeholder(rules: tuple[str, ...]) -> str:
    shown = ",".join(rules[:3]) if rules else "SENSITIVE"
    return _REDACT_TEXT.format(rules=shown)


def placeholder_fit(rules: tuple[str, ...], target_bytes: int) -> str:
    """Length-preserving placeholder: exactly ``target_bytes`` UTF-8 bytes.

    A body whose redacted items keep their exact byte length keeps the wire
    byte-identical in size, so no Content-Length rewrite or TLS write-count
    desync follows. Too-short targets degrade to a fixed marker."""
    base = placeholder(rules)
    encoded = base.encode("utf-8")
    if len(encoded) > target_bytes:
        # 极短原文：退化标记（长度保持优先于可读性）
        fallback = "<脱敏>"
        while len(fallback.encode("utf-8")) > target_bytes:
            fallback = fallback[:-1]
        return fallback + "*" * (target_bytes - len(fallback.encode("utf-8")))
    return base + "*" * (target_bytes - len(encoded))


def _node_text_length(node) -> int:
    if isinstance(node, dict):
        text = node.get("text")
        if isinstance(text, str):
            return len(text.encode("utf-8"))
    if isinstance(node, str):
        return len(node.encode("utf-8"))
    return 0


def _lookup(node, parts: list[str]):
    cursor = node
    for part in parts:
        if isinstance(cursor, dict):
            if part not in cursor:
                raise KeyError(part)
            cursor = cursor[part]
        elif isinstance(cursor, list):
            index = int(part)
            if index >= len(cursor):
                raise KeyError(part)
            cursor = cursor[index]
        else:
            raise KeyError(part)
    return cursor


def redact_body(body: dict, targets: list[tuple[str, tuple[str, ...]]]) -> dict:
    """Return a deep copy of ``body`` with every target replaced.

    Raises KeyError/ValueError when a location cannot be resolved; the caller
    must treat that as "cannot prove clean" and keep the deny decision.
    """
    cleaned = copy.deepcopy(body)
    for location, rules in targets:
        parts = [part for part in location.split("/") if part]
        if not parts:
            raise KeyError(location)
        node = _lookup(cleaned, parts)
        last = int(parts[-1]) if isinstance(_lookup(cleaned, parts[:-1]), list) else parts[-1]
        parent = _lookup(cleaned, parts[:-1]) if len(parts) > 1 else cleaned
        original_bytes = _node_text_length(node)
        fitted = placeholder_fit(rules, original_bytes)
        if isinstance(node, dict):
            parent[last] = {"type": "text", "text": fitted}
        elif isinstance(node, str):
            parent[last] = fitted
        else:
            raise ValueError(f"unredactable node at {location}: {type(node).__name__}")
    return cleaned


def redact_raw_json(raw: bytes, targets: list[tuple[str, tuple[str, ...]]], *,
                    strings_only: bool = False) -> bytes:
    """Replace selected JSON strings without changing any wire byte offsets.

    The scanner records the original token spans. A target that is not a text
    string (or a text block with a string ``text`` field) cannot be safely
    rewritten at this layer and must be denied by the caller.
    """
    spans: dict[tuple[str, ...], tuple[int, int]] = {}
    size = len(raw)

    def space(pos: int) -> int:
        while pos < size and raw[pos] in b" \t\r\n":
            pos += 1
        return pos

    def string(pos: int) -> int:
        if pos >= size or raw[pos] != 34:
            raise ValueError("expected JSON string")
        pos += 1
        while pos < size:
            if raw[pos] == 92:
                pos += 2
            elif raw[pos] == 34:
                return pos + 1
            else:
                pos += 1
        raise ValueError("unterminated JSON string")

    def scan(pos: int, path: tuple[str, ...]) -> int:
        pos = space(pos)
        if pos >= size:
            raise ValueError("truncated JSON")
        first = raw[pos]
        if first == 34:
            end = string(pos)
            spans[path] = (pos, end)
            return end
        if first == 123:
            pos = space(pos + 1)
            if pos < size and raw[pos] == 125:
                return pos + 1
            while True:
                end = string(pos)
                key = json.loads(raw[pos:end])
                pos = space(end)
                if pos >= size or raw[pos] != 58:
                    raise ValueError("expected JSON colon")
                pos = scan(pos + 1, path + (key,))
                pos = space(pos)
                if pos < size and raw[pos] == 125:
                    return pos + 1
                if pos >= size or raw[pos] != 44:
                    raise ValueError("expected JSON comma")
                pos = space(pos + 1)
        if first == 91:
            pos = space(pos + 1)
            if pos < size and raw[pos] == 93:
                return pos + 1
            index = 0
            while True:
                pos = scan(pos, path + (str(index),))
                index += 1
                pos = space(pos)
                if pos < size and raw[pos] == 93:
                    return pos + 1
                if pos >= size or raw[pos] != 44:
                    raise ValueError("expected JSON comma")
                pos = space(pos + 1)
        end = pos
        while end < size and raw[end] not in b",}] \t\r\n":
            end += 1
        if end == pos:
            raise ValueError("invalid JSON value")
        return end

    def text_paths(node, path: tuple[str, ...]) -> list[tuple[str, ...]]:
        if isinstance(node, str):
            return [path]
        if (isinstance(node, dict) and node.get("type") == "text"
                and isinstance(node.get("text"), str)):
            return [path + ("text",)]
        if isinstance(node, dict):
            paths = [child_path for key, child in node.items()
                     if isinstance(child, (str, dict, list))
                     for child_path in text_paths(child, path + (key,))]
            if paths:
                return paths
        if isinstance(node, list):
            paths = [child_path for index, child in enumerate(node)
                     if isinstance(child, (str, dict, list))
                     for child_path in text_paths(child, path + (str(index),))]
            if paths:
                return paths
        raise ValueError(f"unredactable node at {path}")

    parsed = json.loads(raw)
    if space(scan(0, ())) != size:
        raise ValueError("trailing JSON")
    changes: list[tuple[int, int, bytes]] = []
    for location, rules in targets:
        parts = [part for part in location.split("/") if part]
        if not parts:
            raise ValueError("root cannot be redacted")
        node = _lookup(parsed, parts)
        if strings_only and not isinstance(node, str):
            raise ValueError("history target is not a single text field")
        for text_path in text_paths(node, tuple(parts)):
            start, end = spans[text_path]
            width = end - start - 2
            fitted = placeholder_fit(rules, width)
            replacement = json.dumps(fitted, ensure_ascii=False)[1:-1].encode("utf-8")
            if len(replacement) != width:
                raise ValueError("redaction changed JSON token length")
            changes.append((start + 1, end - 1, replacement))
    changes.sort()
    if any(left[1] > right[0] for left, right in zip(changes, changes[1:])):
        raise ValueError("overlapping redaction targets")
    result = bytearray(raw)
    for start, end, replacement in changes:
        result[start:end] = replacement
    if len(result) != len(raw):
        raise ValueError("redaction changed wire length")
    json.loads(result)
    return bytes(result)
