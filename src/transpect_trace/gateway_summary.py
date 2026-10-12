"""Summarize what a standalone Gateway recorded: who called, with which model, and what was asked."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from transpect_trace.core.storage import TraceBundle


def _last_user_text(body: dict[str, Any]) -> str:
    for item in reversed(body.get("input") or body.get("messages") or []):
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content")
        if isinstance(content, str):
            return content
        for part in content or []:
            if isinstance(part, dict) and part.get("type") in {"input_text", "text"}:
                return str(part.get("text", ""))
    return ""


def _answer_text(raw: bytes) -> str:
    parts: list[str] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.startswith("data:"):
            continue
        try:
            data = json.loads(line[5:])
        except ValueError:
            continue
        if data.get("type") == "response.output_text.delta":
            parts.append(str(data.get("delta", "")))
    return "".join(parts)


def summarize(run_dir: Path) -> list[dict[str, Any]]:
    bundle = TraceBundle(run_dir, initialize=False)
    rows = [
        json.loads(line)
        for line in (run_dir / "raw" / "gateway" / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    endings = {
        row["request_id"]: row
        for row in rows
        if row.get("kind") in {"model.response.completed", "model.request.failed", "model.request.blocked"}
    }
    summary: list[dict[str, Any]] = []
    for row in rows:
        if row.get("kind") != "model.request":
            continue
        ending = endings.get(row["request_id"], {})
        entry: dict[str, Any] = {
            "time": row.get("captured_at"),
            "method": row.get("method"),
            "path": row.get("path"),
            "user_agent": (row.get("headers") or {}).get("user-agent"),
            "bytes": (row.get("content") or {}).get("bytes"),
            "status": ending.get("status") or ending.get("reason") or ending.get("kind"),
        }
        if row.get("method") == "POST" and row.get("content"):
            try:
                body = json.loads(bundle.read_blob(row["content"]))
            except ValueError:
                body = {}
            entry["model"] = body.get("model")
            entry["tools"] = len(body.get("tools") or [])
            entry["user_text"] = _last_user_text(body)[-300:]
            if ending.get("content"):
                entry["answer"] = _answer_text(bundle.read_blob(ending["content"]))[:300]
        summary.append(entry)
    return summary
