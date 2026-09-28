from __future__ import annotations

from pathlib import Path

from transpect_trace.clients.claude import ClaudeAdapter


def test_claude_adapter_extracts_tool_and_result() -> None:
    adapter = ClaudeAdapter(model="default")
    rows = list(adapter.parse_event({
        "type": "assistant",
        "session_id": "session-1",
        "message": {"content": [
            {"type": "text", "text": "checking"},
            {"type": "tool_use", "id": "tool-1", "name": "Read", "input": {"file_path": "public.txt"}},
        ]},
    }))
    assert [row["kind"] for row in rows] == ["message", "tool_start"]
    assert rows[1]["tool_call_id"] == "tool-1"
    assert "--model" not in adapter.command(workspace=Path("/workspace"), prompt="test")

    result = list(adapter.parse_event({
        "type": "user",
        "session_id": "session-1",
        "message": {"content": [{"type": "tool_result", "tool_use_id": "tool-1", "content": "ok"}]},
    }))
    assert result[0]["kind"] == "tool_result"
    assert result[0]["tool_call_id"] == "tool-1"

