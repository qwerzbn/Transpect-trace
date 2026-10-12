from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from transpect_trace.core.interfaces import ClientAdapter


class CodexAdapter(ClientAdapter):
    """Command and event interpretation for ``codex exec --json``."""

    def __init__(self, executable: str = "codex") -> None:
        self.executable = executable

    def command(self, *, workspace: Path, prompt: str, paper_mode: bool = False) -> list[str]:
        arguments = [self.executable, "exec"]
        if paper_mode:
            arguments.append("--dangerously-bypass-approvals-and-sandbox")
        arguments.extend(
            [
                "--ephemeral",
                "--json",
                "--skip-git-repo-check",
                "--cd",
                str(workspace),
                prompt,
            ]
        )
        return arguments

    def parse_event(self, raw: dict[str, Any]) -> Iterable[dict[str, Any]]:
        event_type = str(raw.get("type") or "unknown")
        item = raw.get("item") if isinstance(raw.get("item"), dict) else {}
        item_type = str(item.get("type") or "")
        result: dict[str, Any] = {
            "event_type": event_type,
            "item_type": item_type,
            "session_id": raw.get("thread_id") or raw.get("session_id"),
            "turn_id": raw.get("turn_id"),
            "tool_call_id": item.get("id") if item_type in {"command_execution", "mcp_tool_call", "collab_agent_tool_call"} else None,
            "raw": raw,
        }
        if item_type == "command_execution":
            result["command"] = item.get("command")
            result["exit_code"] = item.get("exit_code")
            result["status"] = item.get("status")
        elif item_type in {"agent_message", "reasoning"}:
            result["text"] = item.get("text")
        yield result
