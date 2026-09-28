from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from transpect_trace.clients.claude import ClaudeAdapter
from transpect_trace.core.models import utc_now
from transpect_trace.core.storage import TraceBundle, atomic_write
from transpect_trace.system.frida import gadget_environment


def main() -> int:
    run_dir = Path(os.environ.get("TTRACE_RUN_DIR", "/evidence")).resolve()
    run_id = os.environ.get("TTRACE_RUN_ID", "")
    prompt_file = Path(os.environ.get("TTRACE_PROMPT_FILE", "/evidence/input/prompt.txt"))
    workspace = Path(os.environ.get("TTRACE_WORKSPACE", "/workspace"))
    model = os.environ.get("TTRACE_MODEL", "default")
    if not run_id or not prompt_file.is_file():
        raise SystemExit("TTRACE_RUN_ID and a valid TTRACE_PROMPT_FILE are required")
    bundle = TraceBundle(run_dir, initialize=False)
    prompt = prompt_file.read_text(encoding="utf-8")
    bundle.append_jsonl("raw/client/events.jsonl", {
        "schema": "transpect.raw.client/1.0", "run_id": run_id, "collector_seq": 1,
        "captured_at": utc_now(), "monotonic_ns": time.monotonic_ns(),
        "kind": "client.user_message", "prompt": prompt,
    })
    executable = shutil.which("claude") or "/usr/local/bin/claude"
    version = subprocess.run([executable, "--version"], capture_output=True, text=True, check=False)
    executable_path = Path(executable).resolve()
    digest = hashlib.sha256(executable_path.read_bytes()).hexdigest() if executable_path.is_file() else None
    atomic_write(run_dir / "raw/client/metadata.json", (json.dumps({
        "captured_at": utc_now(), "executable": str(executable_path),
        "version": (version.stdout or version.stderr).strip(), "sha256": f"sha256:{digest}" if digest else None,
    }, ensure_ascii=False, indent=2) + "\n").encode())

    adapter = ClaudeAdapter(executable, model=model)
    command = adapter.command(workspace=workspace, prompt=prompt)
    traced = [
        "strace", "-ff", "-ttt", "-yy", "-s", "4096", "-e",
        "trace=%process,%file,%network,read,write,close,dup,dup2,pipe,pipe2",
        "-o", str(run_dir / "raw/system/strace"), *command,
    ]
    env = gadget_environment(dict(os.environ), log_dir=run_dir / "raw/frida")
    env.update({
        "HOME": "/home/agent",
        "ANTHROPIC_BASE_URL": os.environ.get("TTRACE_MODEL_BASE_URL", "http://gateway:9000"),
        "ANTHROPIC_API_KEY": "transpect-internal-proxy",
        "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
        "OTEL_LOGS_EXPORTER": "otlp",
        "OTEL_TRACES_EXPORTER": "otlp",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
        "OTEL_EXPORTER_OTLP_ENDPOINT": os.environ.get("TTRACE_OTEL_ENDPOINT", "http://otel:4318"),
        "OTEL_LOG_USER_PROMPTS": "1",
        "OTEL_LOG_ASSISTANT_RESPONSES": "1",
        "OTEL_LOG_TOOL_DETAILS": "1",
        "OTEL_LOG_RAW_API_BODIES": "1",
    })
    process = subprocess.Popen(
        traced, cwd=workspace, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
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
        bundle.append_jsonl("raw/client/events.jsonl", {
            "schema": "transpect.raw.client/1.0", "run_id": run_id, "collector_seq": sequence,
            "captured_at": utc_now(), "monotonic_ns": time.monotonic_ns(),
            "kind": "client.claude_event", "pid": process.pid, "event": event,
        })
        print(text, flush=True)
    assert process.stderr is not None
    stderr = process.stderr.read()
    return_code = process.wait()
    atomic_write(run_dir / "raw/client/stderr.log", stderr.encode("utf-8", errors="replace"))
    bundle.append_jsonl("raw/client/events.jsonl", {
        "schema": "transpect.raw.client/1.0", "run_id": run_id, "collector_seq": sequence + 1,
        "captured_at": utc_now(), "monotonic_ns": time.monotonic_ns(),
        "kind": "client.process_exited", "return_code": return_code,
    })
    return return_code


if __name__ == "__main__":
    sys.exit(main())
