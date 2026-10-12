"""Local receipt sink and explicit Codex child-agent adapter for trace demos.

The child is a real independent Codex invocation, NOT a claimed native
spawn_agent event. No email, external account, or upload service is used.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from transpect_trace.clients.codex import CodexAdapter
from transpect_trace.clients.codex_entrypoint import _write_codex_config
from transpect_trace.core.models import utc_now
from transpect_trace.core.storage import atomic_write
from transpect_trace.system.frida import gadget_environment


class DemoMCP:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.sequence = 0

    def record(self, kind: str, **fields: Any) -> None:
        self.sequence += 1
        row = dict(collector_seq=self.sequence, captured_at=utc_now(),
                   monotonic_ns=time.monotonic_ns(), kind=kind, pid=os.getpid(), **fields)
        path = self.root / "raw/client/demo-events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def tools(self) -> list[dict[str, Any]]:
        return [
            {"name": "delegate_budget", "description": "Delegate a budget analysis prompt to a real independent Codex child agent. The child can read the shared workspace. Returns its final answer. This is an explicit subprocess adapter, not native Codex delegation.",
             "inputSchema": {"type": "object", "properties": {"prompt": {"type": "string"}}, "required": ["prompt"], "additionalProperties": False}},
            {"name": "submit_report", "description": "Submit project_id and report text to a LOCAL DEMO RECEIPT SINK. Records exactly the supplied arguments and returns a receipt. Does not send email or contact an external service.",
             "inputSchema": {"type": "object", "properties": {"project_id": {"type": "string"}, "report": {"type": "string"}}, "required": ["project_id", "report"], "additionalProperties": False}},
        ]

    def child(self, prompt: str, invocation: str) -> str:
        child_id = "child-" + uuid4().hex[:12]
        home = Path("/tmp") / ("ttrace-" + child_id)
        _write_codex_config(home, base_url=os.environ["TTRACE_MODEL_BASE_URL"].rstrip("/") + "/agents/" + child_id,
                            otel_endpoint=os.environ.get("TTRACE_OTEL_ENDPOINT", "http://otel:4318"))
        env = gadget_environment(dict(os.environ))
        env["CODEX_HOME"] = str(home)
        env["TRANSPECT_PROXY_TOKEN"] = "transpect-internal-proxy"
        workspace = Path(os.environ.get("TTRACE_WORKSPACE", "/workspace"))
        command = CodexAdapter().command(workspace=workspace, prompt=prompt)
        command[2:2] = ["--model", os.environ["TTRACE_MODEL"]]
        # Inherited strace follows this child; a second trace would contend
        # for ptrace ownership. Timestamp each event as it arrives.
        process = subprocess.Popen(command, cwd=workspace, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.record("agent.started", agent_id=child_id, parent_agent_id="main", child_pid=process.pid,
                    invocation_id=invocation, prompt=prompt, implementation="explicit_codex_subprocess")
        timed_out = threading.Event()
        def expire() -> None:
            timed_out.set()
            process.kill()
        timer = threading.Timer(480, expire)
        timer.daemon = True
        timer.start()
        stderr_parts: list[str] = []
        def drain() -> None:
            assert process.stderr is not None
            stderr_parts.append(process.stderr.read())
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        answer = []
        assert process.stdout is not None
        with (self.root / f"raw/client/{child_id}.jsonl").open("w", encoding="utf-8") as log:
            for sequence, line in enumerate(process.stdout, 1):
                try:
                    event = json.loads(line)
                except ValueError:
                    event = {"type": "unparsed", "text": line}
                log.write(json.dumps(dict(collector_seq=sequence, captured_at=utc_now(), monotonic_ns=time.monotonic_ns(),
                                          kind="client.codex_event", event=event, pid=process.pid), ensure_ascii=False) + "\n")
                log.flush()
                item = event.get("item") or {}
                if item.get("type") == "agent_message":
                    answer.append(item.get("text", ""))
        process.wait()
        timer.cancel()
        reader.join(timeout=5)
        atomic_write(self.root / f"raw/client/{child_id}.stderr.log", "".join(stderr_parts).encode())
        self.record("agent.completed", agent_id=child_id, parent_agent_id="main", child_pid=process.pid,
                    invocation_id=invocation, return_code=process.returncode, timed_out=timed_out.is_set(),
                    response="\n".join(answer), event_file=f"raw/client/{child_id}.jsonl")
        if process.returncode or timed_out.is_set():
            raise RuntimeError(f"Child {child_id} failed (exit={process.returncode}, timeout={timed_out.is_set()}); see child evidence")
        return "\n".join(answer)

    def call(self, name: str, arguments: dict[str, Any], rpc_id: Any) -> dict[str, Any]:
        invocation = str(uuid4())
        self.record("tool.received", tool_name=name, arguments=arguments, rpc_id=rpc_id, invocation_id=invocation, agent_id="main")
        try:
            if name == "delegate_budget":
                if not isinstance(arguments.get("prompt"), str):
                    raise ValueError("prompt must be a string")
                result: Any = self.child(arguments["prompt"], invocation)
            elif name == "submit_report":
                if not all(isinstance(arguments.get(k), str) for k in ("project_id", "report")):
                    raise ValueError("project_id and report must be strings")
                result = {"receipt_id": invocation, "received": True, "local_simulated_sink": True, "external_delivery": False}
                self.record("sink.received", tool_name=name, arguments=arguments, invocation_id=invocation, receipt=result)
            else:
                raise ValueError("Unknown demo tool")
            self.record("tool.completed", tool_name=name, invocation_id=invocation, response=result)
            return {"content": [{"type": "text", "text": result if isinstance(result, str) else json.dumps(result)}], "isError": False}
        except Exception as error:
            self.record("tool.failed", tool_name=name, invocation_id=invocation, error=str(error))
            return {"content": [{"type": "text", "text": str(error)}], "isError": True}

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if "id" not in message:
            return None
        method, params = message.get("method"), message.get("params") or {}
        if method == "initialize":
            result = {"protocolVersion": params.get("protocolVersion", "2024-11-05"), "capabilities": {"tools": {}},
                      "serverInfo": {"name": "transpect-trace-demo", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": self.tools()}
        elif method == "tools/call":
            result = self.call(params.get("name", ""), params.get("arguments") or {}, message["id"])
        elif method == "ping":
            result = {}
        else:
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Unknown method"}}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def main() -> None:
    server = DemoMCP(Path(os.environ.get("TTRACE_RUN_DIR", "/evidence")))
    for line in sys.stdin:
        message: dict[str, Any] = {}
        try:
            message = json.loads(line)
            response = server.handle(message)
        except Exception as error:
            server.record("protocol.error", detail=str(error))
            response = {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32603, "message": str(error)}}
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
