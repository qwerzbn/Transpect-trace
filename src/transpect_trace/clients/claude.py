from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from transpect_trace.core.interfaces import ClientAdapter


class ClaudeAdapter(ClientAdapter):
    """Command and stream-json interpretation for Claude Code."""

    def __init__(self, executable: str = "claude", model: str | None = None) -> None:
        self.executable = executable
        self.model = model

    def command(self, *, workspace: Path, prompt: str) -> list[str]:
        command = [
            self.executable,
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--verbose",
            "--dangerously-skip-permissions",
        ]
        if self.model and self.model != "default":
            command.extend(["--model", self.model])
        return command

    def parse_event(self, raw: dict[str, Any]) -> Iterable[dict[str, Any]]:
        event_type = str(raw.get("type") or "unknown")
        session_id = raw.get("session_id")
        if event_type == "system":
            yield {"event_type": event_type, "kind": "session", "session_id": session_id, "raw": raw}
            return
        if event_type == "assistant":
            message = raw.get("message") if isinstance(raw.get("message"), dict) else {}
            content = message.get("content") if isinstance(message.get("content"), list) else []
            emitted = False
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    emitted = True
                    yield {
                        "event_type": event_type,
                        "kind": "tool_start",
                        "session_id": session_id,
                        "tool_call_id": block.get("id"),
                        "tool_name": block.get("name"),
                        "tool_input": block.get("input"),
                        "raw": raw,
                    }
                elif block.get("type") == "text":
                    emitted = True
                    yield {
                        "event_type": event_type,
                        "kind": "message",
                        "session_id": session_id,
                        "text": block.get("text"),
                        "raw": raw,
                    }
            if not emitted:
                yield {"event_type": event_type, "kind": "unknown", "session_id": session_id, "raw": raw}
            return
        if event_type == "user":
            message = raw.get("message") if isinstance(raw.get("message"), dict) else {}
            content = message.get("content") if isinstance(message.get("content"), list) else []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    yield {
                        "event_type": event_type,
                        "kind": "tool_result",
                        "session_id": session_id,
                        "tool_call_id": block.get("tool_use_id"),
                        "tool_result": block.get("content"),
                        "is_error": block.get("is_error", False),
                        "raw": raw,
                    }
            return
        if event_type == "result":
            yield {
                "event_type": event_type,
                "kind": "result",
                "session_id": session_id,
                "text": raw.get("result"),
                "is_error": raw.get("is_error", False),
                "raw": raw,
            }
            return
        yield {"event_type": event_type, "kind": "unknown", "session_id": session_id, "raw": raw}

