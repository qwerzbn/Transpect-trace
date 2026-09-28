from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from transpect_trace.core.models import utc_now


TYPE_MAP = {
    "string": "string",
    "integer": "integer",
    "number": "number",
    "boolean": "boolean",
    "array": "array",
    "object": "object",
}


def _input_schema(definition: dict[str, Any]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []
    for parameter in definition.get("parameters", []):
        parameter_type = TYPE_MAP.get(str(parameter.get("type")), "string")
        schema: dict[str, Any] = {
            "type": parameter_type,
            "description": str(parameter.get("description") or ""),
        }
        if parameter_type == "array":
            schema["items"] = {}
        elif parameter_type == "object":
            schema["additionalProperties"] = True
        name = str(parameter["name"])
        properties[name] = schema
        if parameter.get("required"):
            required.append(name)
    return {"type": "object", "properties": properties, "required": required}


class InjecAgentMCP:
    def __init__(self, case_file: Path, log_file: Path) -> None:
        self.case_file = case_file
        self.log_file = log_file
        self.bundle = json.loads(case_file.read_text(encoding="utf-8"))
        self.case = self.bundle["official_case"]
        self.definitions = self.bundle["tools"]
        self.responses = self.bundle["official_attacker_simulated_responses"]
        self.sequence = 0

    def record(self, kind: str, **fields: Any) -> None:
        self.sequence += 1
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "schema": "transpect.raw.injecagent-mcp/1.0",
            "collector_seq": self.sequence,
            "captured_at": utc_now(),
            "monotonic_ns": time.monotonic_ns(),
            "kind": kind,
            "case_number": self.bundle["source"]["case_number"],
            **fields,
        }
        with self.log_file.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    def tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "description": str(definition.get("summary") or name),
                "inputSchema": _input_schema(definition),
            }
            for name, definition in self.definitions.items()
        ]

    def _attacker_response(self, name: str, arguments: dict[str, Any]) -> tuple[str, str, bool]:
        candidates = [
            f"({name},{arguments!r})",
            f"({name},{json.dumps(arguments, ensure_ascii=False, separators=(',', ':'))})",
            f"({name},{json.dumps(arguments, ensure_ascii=False)})",
        ]
        if not arguments:
            candidates.insert(0, f"({name},{{}})")
        for key in candidates:
            if key in self.responses:
                return str(self.responses[key]), key, False
        empty_key = f"({name},{{}})"
        key = empty_key if empty_key in self.responses else next(iter(self.responses))
        return str(self.responses[key]), key, True

    def call_tool(self, name: str, arguments: dict[str, Any], rpc_id: Any) -> dict[str, Any]:
        invocation_id = str(uuid4())
        user_tool = str(self.case["User Tool"])
        attacker_tools = [str(value) for value in self.case["Attacker Tools"]]
        role = "unknown"
        matched_response_key: str | None = None
        fallback = False
        if name == user_tool:
            role = "user_tool"
            response = str(self.case["Tool Response"])
        elif name == attacker_tools[0]:
            role = "sensitive_source"
            response, matched_response_key, fallback = self._attacker_response(name, arguments)
        elif len(attacker_tools) > 1 and name == attacker_tools[1]:
            role = "exfiltration_sink"
            response = json.dumps(
                {"success": True, "simulated": True, "network_action_performed": False},
                separators=(",", ":"),
            )
        else:
            self.record(
                "adapter.tool.failed",
                rpc_id=rpc_id,
                invocation_id=invocation_id,
                tool_name=name,
                arguments=arguments,
                reason="tool_not_available_for_case",
            )
            return {
                "content": [{"type": "text", "text": f"Unknown benchmark tool: {name}"}],
                "isError": True,
            }
        self.record(
            "adapter.tool.called",
            rpc_id=rpc_id,
            invocation_id=invocation_id,
            tool_name=name,
            tool_role=role,
            arguments=arguments,
        )
        self.record(
            "adapter.tool.completed",
            rpc_id=rpc_id,
            invocation_id=invocation_id,
            tool_name=name,
            tool_role=role,
            response=response,
            official_response_cache_key=matched_response_key,
            response_cache_fallback=fallback,
        )
        return {"content": [{"type": "text", "text": response}], "isError": False}

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        request_id = message.get("id")
        if request_id is None:
            return None
        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion") or "2024-11-05"
            result = {
                "protocolVersion": requested,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "transpect-injecagent-adapter", "version": "0.1.0"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.tools()}
        elif method == "tools/call":
            params = message.get("params") or {}
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            result = self.call_tool(str(params.get("name") or ""), arguments, request_id)
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> int:
    case_file = Path(os.environ.get("TTRACE_INJECAGENT_CASE_FILE", "/evidence/input/injecagent-case.json"))
    log_file = Path(os.environ.get("TTRACE_MCP_LOG_FILE", "/evidence/raw/client/mcp-events.jsonl"))
    server = InjecAgentMCP(case_file, log_file)
    server.record(
        "adapter.mcp.started",
        case_file=str(case_file),
        tools=[tool["name"] for tool in server.tools()],
        official_source=server.bundle["source"],
    )
    for line in sys.stdin:
        try:
            message = json.loads(line)
            response = server.handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as error:  # keep the stdio server alive and make failures auditable
            server.record("adapter.mcp.error", error_type=type(error).__name__, detail=str(error)[:2000])
            request_id = message.get("id") if isinstance(locals().get("message"), dict) else None
            if request_id is not None:
                sys.stdout.write(json.dumps({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": str(error)},
                }, separators=(",", ":")) + "\n")
                sys.stdout.flush()
    server.record("adapter.mcp.stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

