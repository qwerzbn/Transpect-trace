"""Live coverage probe: what reaches the model origin with the gate installed.

Runs the pinned `codex exec` backend in a private CODEX_HOME against a local,
non-forwarding Responses origin that scripts the model's turns (it asks for a
tool call, then answers). The origin records every request body, so each case
is judged by *what actually arrived upstream*, not by the client's console:

| case                    | script                                  | expectation                          |
| ----------------------- | --------------------------------------- | ------------------------------------ |
| benign                  | read a harmless file                    | prompt + output reach the origin     |
| secret_prompt           | prompt carries a fake key               | zero requests                        |
| secret_file_output      | `Get-Content` a file holding a fake key | marker never reaches the origin      |
| sensitive_path_call     | `Get-Content .env`                      | call denied, file content never sent |
| image_tool_output       | `view_image` of a PNG carrying a marker | sent (pixels are not inspected) and  |
|                         |                                         | recorded as IMAGE_UNINSPECTED        |
| untrusted_hooks         | benign, without trust bypass            | hooks skipped; health check flags it |

Only synthetic markers and fake keys are used. Requires the pinned backend.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import threading
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import install_codex_hook_gate as installer  # noqa: E402
import check_codex_gate_health as health  # noqa: E402

SCHEMA = "transpect.codex-hook-coverage-live/1.0"
PINNED_BACKEND_SHA256 = "925c7d0665ffa49b0dcf748e034a805a04da984164ac92301432073b47789b99"
MARKER = "TTRACE_SYNTHETIC_MARKER_5521"
FAKE_KEY = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
USAGE = {"input_tokens": 1, "input_tokens_details": None, "output_tokens": 1,
         "output_tokens_details": None, "total_tokens": 2}


class _Origin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.steps: list = []
        self.bodies: list[bytes] = []
        self.lock = threading.Lock()


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.server.lock:
            self.server.bodies.append(body)
        request = json.loads(body)
        done = sum(item.get("type") == "function_call_output" for item in request.get("input", []))
        steps = self.server.steps
        if done < len(steps):
            # A step is `[name, arguments]`, or a callable that derives them from
            # the request (e.g. a session id printed by an earlier tool result).
            step = steps[done]
            name, arguments = step(request) if callable(step) else step
            item = {"type": "function_call", "id": f"fc{done}", "call_id": f"call_{done}",
                    "name": name, "arguments": json.dumps(arguments)}
        else:
            item = {"type": "message", "role": "assistant", "id": "m",
                    "content": [{"type": "output_text", "text": "DONE"}]}
        events = [{"type": "response.created", "response": {"id": "r"}},
                  {"type": "response.output_item.done", "item": item},
                  {"type": "response.completed", "response": {"id": "r", "usage": USAGE}}]
        data = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


@contextmanager
def origin():
    server = _Origin()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _png_with_marker() -> bytes:
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * 8 for _ in range(8))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0))
            + chunk(b"tEXt", b"Comment\x00" + MARKER.encode()) + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


CASES = (
    ("benign", "read notes.txt", [["exec_command", {"cmd": "Get-Content notes.txt"}]], True),
    ("secret_prompt", f"deploy with {FAKE_KEY}", [], True),
    ("secret_file_output", "read the build log", [["exec_command", {"cmd": "Get-Content build_log.txt"}]], True),
    ("sensitive_path_call", "read the env", [["exec_command", {"cmd": "Get-Content .env"}]], True),
    ("image_tool_output", "look at the image", [["view_image", {"path": "marker.png"}]], True),
    ("untrusted_hooks", "read notes.txt", [["exec_command", {"cmd": "Get-Content notes.txt"}]], False),
)


def run_case(backend: Path, home: Path, work: Path, server: _Origin, prompt: str, steps,
             bypass_trust: bool, timeout: int) -> dict:
    server.steps = steps
    server.bodies.clear()
    command = [str(backend), "exec", "--skip-git-repo-check"]
    if bypass_trust:
        command.append("--dangerously-bypass-hook-trust")
    command.append(prompt)
    began = time.perf_counter()
    completed = subprocess.run(command, cwd=work, env={**os.environ, "CODEX_HOME": str(home)},
                               capture_output=True, text=True, encoding="utf-8", errors="replace",
                               stdin=subprocess.DEVNULL, timeout=timeout)
    output = completed.stdout + "\n" + completed.stderr
    bodies = list(server.bodies)
    upstream = b"\n".join(bodies)
    return {
        "requests": len(bodies),
        "marker_reached_origin": MARKER.encode() in upstream,
        "fake_key_reached_origin": FAKE_KEY.encode() in upstream,
        "image_reached_origin": b"data:image/png" in upstream,
        "client_hook_lines": sorted({line.strip() for line in output.splitlines()
                                     if line.startswith("hook: ") and line.strip().count(" ") >= 2}),
        "exit_code": completed.returncode,
        "elapsed_ms": round((time.perf_counter() - began) * 1000),
    }


def judge(case: str, observed: dict) -> bool:
    if case == "benign":
        return observed["requests"] >= 2 and observed["marker_reached_origin"]
    if case == "secret_prompt":
        return observed["requests"] == 0 and not observed["fake_key_reached_origin"]
    if case == "secret_file_output":
        # The call itself is harmless; only its output carries the key, so the
        # tool must have run and PostToolUse must be what withheld it.
        return (observed["requests"] >= 2 and not observed["marker_reached_origin"]
                and not observed["fake_key_reached_origin"]
                and "hook: PostToolUse Blocked" in observed["client_hook_lines"])
    if case == "sensitive_path_call":
        return (observed["requests"] >= 2 and not observed["marker_reached_origin"]
                and "hook: PreToolUse Blocked" in observed["client_hook_lines"])
    if case == "image_tool_output":
        return observed["image_reached_origin"]
    if case == "untrusted_hooks":
        return observed["requests"] >= 2 and not any("hook:" in line for line in
                                                     observed["client_hook_lines"])
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--client", choices=("python", "native"), default="native")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    backend = args.backend.resolve(strict=True)
    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    if digest != PINNED_BACKEND_SHA256:
        raise SystemExit(f"backend is not the pinned build: {digest}")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    home, work, gate_dir = out / "codex-home", out / "work", out / "gate"
    home.mkdir()
    work.mkdir()
    (work / "notes.txt").write_text(f"meeting notes {MARKER}\n", encoding="utf-8")
    (work / "build_log.txt").write_text(f"{MARKER} token {FAKE_KEY}\n", encoding="utf-8")
    (work / ".env").write_text(f"{MARKER}=1\n", encoding="utf-8")
    (work / "marker.png").write_bytes(_png_with_marker())

    config = installer.write_gate_config(gate_dir, "enforce", None, codex_home=home)
    client = None
    if args.client == "native":
        client = (ROOT / "build" / "codex-gate-client" / "codex_gate_client.exe").resolve(strict=True)
    command = installer.build_command(Path(sys.executable).resolve(strict=True),
                                      (ROOT / "scripts" / "codex_hook_gate.py").resolve(strict=True),
                                      config, client)
    installer.install_user_layer(home, command, dry_run=False)
    installer.write_manifest(gate_dir, command,
                             installer.gate_source_files() + ([client] if client else []))
    service = None
    if client is not None:
        service = subprocess.Popen([sys.executable, "-m", "transpect_trace.protect.codex_gate_service",
                                    str(config)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   cwd=ROOT / "src")
        service.stdout.readline()  # status line once the pipe is listening

    results = []
    try:
        with origin() as server:
            (home / "config.toml").write_text(
                'model = "gpt-5.1-codex"\nmodel_provider = "lab"\napproval_policy = "never"\n'
                'sandbox_mode = "danger-full-access"\n[model_providers.lab]\nname = "lab"\n'
                f'base_url = "http://127.0.0.1:{server.server_address[1]}/v1"\n'
                'wire_api = "responses"\nrequires_openai_auth = false\nrequest_max_retries = 0\n'
                'stream_max_retries = 0\nsupports_websockets = false\n', encoding="utf-8")
            for case, prompt, steps, bypass in CASES:
                observed = run_case(backend, home, work, server, prompt, steps, bypass, args.timeout)
                results.append({"case": case, "verified": judge(case, observed), **observed})
                print(json.dumps(results[-1], ensure_ascii=False), flush=True)
    finally:
        if service is not None:
            service.terminate()
            service.wait(10)

    report_health = {}
    for check in (health.check_coverage(home, health.GateConfig.load(config),
                                        health.check_install(home, None)[1], None),):
        report_health = check
    audit_rows = [json.loads(line) for line in (gate_dir / "audit.jsonl").read_text(
        encoding="utf-8").splitlines()]
    image_rows = [row for row in audit_rows if row["hook_event_name"] == "PostToolUse"
                  and "IMAGE_UNINSPECTED" in row["matched_rule_ids"]]
    gaps = report_health.get("gaps", [])
    # Exactly the untrusted turn must be flagged, and nothing else.
    untrusted_flagged = (len(gaps) == 1 and "PROMPT_NOT_GATED" in gaps[0]["problems"])
    report = {
        "schema": SCHEMA, "backend_sha256": digest, "client": args.client,
        "scope": "codex exec in a private CODEX_HOME against a scripted local origin; "
                 "not the desktop UI",
        "cases": results,
        "image_output_recorded_as_uninspected": bool(image_rows),
        "health_check_flags_untrusted_turn": untrusted_flagged,
        "health_coverage": {k: report_health.get(k) for k in
                            ("status", "turns", "prompt_turns", "tool_turns", "ungated_turns")},
        "all_verified": all(r["verified"] for r in results) and bool(image_rows) and untrusted_flagged,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("image_output_recorded_as_uninspected",
                                             "health_check_flags_untrusted_turn",
                                             "health_coverage", "all_verified")}, indent=2))
    return 0 if report["all_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
