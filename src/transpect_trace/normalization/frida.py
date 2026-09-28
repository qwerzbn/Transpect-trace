from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Iterable


def _target(raw: dict[str, Any]) -> str | None:
    for key in ("path", "target"):
        value = raw.get(key)
        if value is not None:
            return str(value)
    address = raw.get("address")
    if address is not None:
        return json.dumps(address, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return None


def _map_kind(raw_kind: str, function: str) -> tuple[str, str]:
    if raw_kind == "frida.runtime.loaded":
        return "system.frida.loaded", "load"
    if raw_kind == "frida.runtime.unloaded":
        return "system.frida.unloaded", "unload"
    if raw_kind == "frida.runtime.detached":
        return "system.frida.detached", "detach"
    if raw_kind == "frida.hook.error":
        return "system.frida.hook_error", "instrument"
    if raw_kind == "frida.hook.unavailable":
        return "system.frida.hook_unavailable", "instrument"
    if raw_kind == "frida.file.open":
        return "system.frida.file.opened", function or "open"
    if raw_kind == "frida.io.read":
        if function.startswith("recv"):
            return "system.frida.network.received", function
        return "system.frida.file.read", function or "read"
    if raw_kind == "frida.io.write":
        if function.startswith("send"):
            return "system.frida.network.sent", function
        return "system.frida.file.write", function or "write"
    if raw_kind == "frida.network.connect":
        return "system.frida.network.connect", "connect"
    if raw_kind == "frida.process.exec":
        return "system.frida.process.exec", "execute"
    if raw_kind == "frida.process.exiting":
        return "system.frida.process.exiting", "exit"
    if raw_kind == "frida.fd.close":
        return "system.frida.fd.close", "close"
    if raw_kind == "frida.io.suppressed":
        return "system.frida.suppressed", "count"
    return "system.frida.unknown", function or raw_kind or "unknown"


def iter_frida_rows(frida_dir: Path) -> Iterable[dict[str, Any]]:
    """Read per-process Gadget JSONL files into one deterministic stream."""

    records: list[dict[str, Any]] = []
    for path in sorted(frida_dir.glob("events.*.jsonl")):
        if not path.is_file():
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as error:
                records.append(
                    {
                        "wall": "1970-01-01T00:00:00.000000Z",
                        "process_seq": line_number,
                        "pid": None,
                        "tid": None,
                        "fd": None,
                        "kind": "system.frida.hook_error",
                        "operation": "parse",
                        "target": path.name,
                        "content_bytes": None,
                        "content_truncated": False,
                        "attributes": {
                            "parse_error": error.msg,
                            "source_file": path.name,
                            "source_line": line_number,
                            "raw_line": line[:4096],
                        },
                    }
                )
                continue
            if not isinstance(raw, dict):
                continue
            function = str(raw.get("function") or "")
            kind, operation = _map_kind(str(raw.get("kind") or ""), function)
            encoded = raw.get("payload_base64")
            content: bytes | None = None
            decode_error: str | None = None
            if isinstance(encoded, str):
                try:
                    content = base64.b64decode(encoded, validate=True)
                    result = raw.get("result")
                    if function.startswith(("send", "write", "pwrite")) and isinstance(result, int) and result >= 0:
                        content = content[:result]
                except (ValueError, TypeError) as error:
                    decode_error = str(error)
            excluded = {
                "schema", "run_id", "collector_seq", "captured_at", "kind", "pid", "tid", "fd",
                "path", "target", "address", "payload_base64", "captured_bytes", "truncated",
            }
            attributes = {key: value for key, value in raw.items() if key not in excluded}
            attributes.update(
                {
                    "raw_kind": raw.get("kind"),
                    "process_seq": raw.get("collector_seq"),
                    "source_file": path.name,
                    "source_line": line_number,
                    "captured_bytes": raw.get("captured_bytes", 0),
                    "content_truncated": bool(raw.get("truncated", False)),
                }
            )
            if decode_error:
                attributes["payload_decode_error"] = decode_error
            records.append(
                {
                    "wall": str(raw.get("captured_at") or "1970-01-01T00:00:00.000000Z"),
                    "process_seq": int(raw.get("collector_seq") or line_number),
                    "pid": raw.get("pid"),
                    "tid": raw.get("tid"),
                    "fd": raw.get("fd"),
                    "kind": kind,
                    "operation": operation,
                    "target": _target(raw),
                    "content_bytes": content,
                    "content_truncated": bool(raw.get("truncated", False)),
                    "attributes": attributes,
                }
            )
    records.sort(key=lambda row: (row["wall"], row.get("pid") or -1, row["process_seq"]))
    yield from records
