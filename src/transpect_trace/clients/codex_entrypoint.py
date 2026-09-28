from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from transpect_trace.clients.codex import CodexAdapter
from transpect_trace.core.models import utc_now
from transpect_trace.core.storage import TraceBundle, atomic_write
from transpect_trace.system.frida import gadget_environment


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _codex_metadata(executable: str) -> dict[str, Any]:
    path = Path(shutil.which(executable) or executable)
    version = subprocess.run([executable, "--version"], capture_output=True, text=True, check=False)
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return {
        "captured_at": utc_now(),
        "executable": str(path),
        "version": (version.stdout or version.stderr).strip(),
        "sha256": f"sha256:{digest}" if digest else None,
    }


def _write_codex_config(home: Path, *, base_url: str, otel_endpoint: str, enable_injecagent: bool = False) -> None:
    home.mkdir(parents=True, exist_ok=True)
    content = f"""model_provider = "deepseek"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[model_providers.deepseek]
name = "DeepSeek"
base_url = {_toml_string(base_url)}
env_key = "TRANSPECT_PROXY_TOKEN"
wire_api = "responses"
requires_openai_auth = false

[shell_environment_policy]
exclude = ["TRANSPECT_PROXY_TOKEN", "DEEPSEEK_API_KEY", "TRANSPECT_MODEL_API_KEY", "TTRACE_PROMPT_FILE"]

[otel]
environment = "transpect-trace"
log_user_prompt = true
exporter = {{ otlp-http = {{ endpoint = {_toml_string(otel_endpoint.rstrip('/') + '/v1/logs')}, protocol = "json" }} }}
trace_exporter = {{ otlp-http = {{ endpoint = {_toml_string(otel_endpoint.rstrip('/') + '/v1/traces')}, protocol = "json" }} }}
"""
    if enable_injecagent:
        content += """

[mcp_servers.injecagent]
command = "python3"
args = ["-m", "transpect_trace.clients.injecagent_mcp"]
startup_timeout_sec = 20
tool_timeout_sec = 60
"""
    atomic_write(home / "config.toml", content.encode("utf-8"))


def _strace_command(command: list[str], output_prefix: Path) -> list[str]:
    return [
        "strace",
        "-ff",
        "-ttt",
        "-yy",
        "-s",
        "4096",
        "-e",
        "trace=%process,%file,%network,read,write,close,dup,dup2,pipe,pipe2",
        "-o",
        str(output_prefix),
        *command,
    ]


def main() -> int:
    run_dir = Path(os.environ.get("TTRACE_RUN_DIR", "/evidence")).resolve()
    run_id = os.environ.get("TTRACE_RUN_ID", "")
    prompt_file = Path(os.environ.get("TTRACE_PROMPT_FILE", "/evidence/input/prompt.txt"))
    workspace = Path(os.environ.get("TTRACE_WORKSPACE", "/workspace"))
    base_url = os.environ.get("TTRACE_MODEL_BASE_URL", "http://gateway:9000")
    otel_endpoint = os.environ.get("TTRACE_OTEL_ENDPOINT", "http://otel:4318")
    model = os.environ.get("TTRACE_MODEL", "deepseek-flash")
    if not run_id:
        raise SystemExit("TTRACE_RUN_ID is required")
    if not prompt_file.is_file():
        raise SystemExit(f"prompt file does not exist: {prompt_file}")

    bundle = TraceBundle(run_dir, initialize=False)
    prompt = prompt_file.read_text(encoding="utf-8")
    bundle.append_jsonl(
        "raw/client/events.jsonl",
        {
            "schema": "transpect.raw.client/1.0",
            "run_id": run_id,
            "collector_seq": 1,
            "captured_at": utc_now(),
            "monotonic_ns": time.monotonic_ns(),
            "kind": "client.user_message",
            "prompt": prompt,
        },
    )

    executable = shutil.which("codex") or "/usr/local/bin/codex"
    metadata = _codex_metadata(executable)
    atomic_write(
        run_dir / "raw/client/metadata.json",
        (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    codex_home = Path("/tmp/transpect-codex-home")
    _write_codex_config(
        codex_home,
        base_url=base_url,
        otel_endpoint=otel_endpoint,
        enable_injecagent=bool(os.environ.get("TTRACE_INJECAGENT_CASE_FILE")),
    )

    adapter = CodexAdapter(executable)
    command = adapter.command(
        workspace=workspace,
        prompt=prompt,
        paper_mode=os.environ.get("TTRACE_CODEX_PAPER_MODE") == "1",
    )
    command[command.index("--cd") : command.index("--cd") + 2] = ["--cd", str(workspace)]
    command[2:2] = ["--model", model]
    traced = _strace_command(command, run_dir / "raw/system/strace")
    env = gadget_environment(dict(os.environ), log_dir=run_dir / "raw/frida")
    env["CODEX_HOME"] = str(codex_home)
    env["HOME"] = os.environ.get("TTRACE_AGENT_HOME", "/home/agent")
    env["TRANSPECT_PROXY_TOKEN"] = "transpect-internal-proxy"
    for secret_name in ("DEEPSEEK_API_KEY", "TRANSPECT_MODEL_API_KEY"):
        env.pop(secret_name, None)

    process = subprocess.Popen(
        traced,
        cwd=workspace,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    sequence = 1
    assert process.stdout is not None
    for line in process.stdout:
        text = line.rstrip("\r\n")
        try:
            event = json.loads(text)
        except json.JSONDecodeError:
            event = {"type": "unparsed", "text": text}
        sequence += 1
        bundle.append_jsonl(
            "raw/client/events.jsonl",
            {
                "schema": "transpect.raw.client/1.0",
                "run_id": run_id,
                "collector_seq": sequence,
                "captured_at": utc_now(),
                "monotonic_ns": time.monotonic_ns(),
                "kind": "client.codex_event",
                "pid": process.pid,
                "event": event,
            },
        )
        print(text, flush=True)

    assert process.stderr is not None
    stderr = process.stderr.read()
    return_code = process.wait()
    atomic_write(run_dir / "raw/client/stderr.log", stderr.encode("utf-8", errors="replace"))
    sequence += 1
    bundle.append_jsonl(
        "raw/client/events.jsonl",
        {
            "schema": "transpect.raw.client/1.0",
            "run_id": run_id,
            "collector_seq": sequence,
            "captured_at": utc_now(),
            "monotonic_ns": time.monotonic_ns(),
            "kind": "client.process_exited",
            "return_code": return_code,
        },
    )
    return return_code


if __name__ == "__main__":
    sys.exit(main())
