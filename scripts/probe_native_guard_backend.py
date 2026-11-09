"""Second route: the native send-point guard on the pinned desktop backend.

Compares two ways of gating the same pinned `codex.exe` (codex-cli
0.166.0-alpha.6, the backend the desktop app ships):

* `hook`   -- the client's own command hooks (UserPromptSubmit / PreToolUse /
              PostToolUse), the current mainline;
* `native` -- `native/guard/guard.c` built with the desktop candidate pins and
              injected into the process. It hooks the HTTP body preparation and
              the WSS `response.create` serialization, sends the *complete*
              serialized model request to a local policy service, and on deny
              makes the send function return an error instead of sending.

Both run `codex exec` in a private CODEX_HOME against the scripted,
non-forwarding local origin of `probe_codex_hook_coverage.py`, and every case is
judged by the bytes the origin actually received. Only synthetic markers and
fake keys are used. Requires the pinned backend.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import install_codex_hook_gate as installer  # noqa: E402
from probe_codex_hook_coverage import (  # noqa: E402
    FAKE_KEY, MARKER, PINNED_BACKEND_SHA256, _png_with_marker, origin,
)
from transpect_trace.guard.native import inject, wait_ready  # noqa: E402
from transpect_trace.guard.pipe import PipeServer  # noqa: E402
from transpect_trace.guard.policy import GuardDecision  # noqa: E402
from transpect_trace.protect.codex_hook_gate import (  # noqa: E402
    CodexHookGate, GateConfig, leaves,
)

SCHEMA = "transpect.native-guard-backend-probe/1.0"
ADAPTER = ROOT / "deploy" / "guard" / "desktop-candidate-26.1029.7803.0.json"
# Fixed-build ABI facts from the earlier Frida research on this exact binary
# (docs/development/desktop-path-current.md): HeaderMap destructor and result tags.
DROP_RVA, DROP_PREFIX = "0xa6320", "555657534883ec58"


def _bytes_define(macro: str, hex_text: str) -> str:
    return f"-D{macro}={{" + ",".join(f"0x{b:02x}" for b in bytes.fromhex(hex_text)) + "}"


def build_dll(output: Path) -> Path:
    """Compile guard.c pinned to the desktop backend. Experimental: the adapter
    is still `candidate_unvalidated`, which is what this probe is testing."""
    adapter = json.loads(ADAPTER.read_text(encoding="utf-8"))
    hooks = {h["layer"]: h for h in adapter["hooks"]}
    http, wss = hooks["http_encoded_body_preparation"], hooks["wss_request_serialization"]
    root = ROOT / "native" / "guard"
    sources = [root / "guard.c", *(root / "third_party/minhook/src" / n
               for n in ("buffer.c", "hook.c", "trampoline.c", "hde/hde64.c"))]
    output.mkdir(parents=True, exist_ok=True)
    dll = output / "ttrace-guard-desktop-candidate.dll"
    defines = [f"-DHTTP_RVA={http['rva']}", f"-DWSS_RVA={wss['rva']}", f"-DDROP_HEADERS_RVA={DROP_RVA}",
               _bytes_define("HTTP_ENTRY_PREFIX_BYTES", http["entry_prefix_hex"]),
               _bytes_define("WSS_ENTRY_PREFIX_BYTES", wss["entry_prefix_hex"]),
               _bytes_define("DROP_HEADERS_PREFIX_BYTES", DROP_PREFIX),
               f'-DTTRACE_EXPECTED_HASH="{adapter["binary_sha256"]}"',
               "-DWSS_SUCCESS_TAG=0x1f", "-DWSS_DENIED_TAG=0x0d",
               "-DHTTP_DENIED_TAG=0x03", "-DHTTP_EMPTY_ERROR_STRING=1"]
    subprocess.run([sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2",
                    "-shared", "-DJSMN_PARENT_LINKS", *defines, *map(str, sources), "-lbcrypt",
                    "-o", str(dll)], check=True)
    return dll


class NativeDLPEngine:
    """Policy service for the native guard: the same DLP engine and enforcement
    policy as the hook gate, applied to the complete serialized model request."""

    def __init__(self, config: GateConfig):
        self.gate = CodexHookGate(config)
        self.policy = SimpleNamespace(version="native-guard-dlp/1")
        self.decisions: list[dict] = []

    def evaluate(self, request):
        if request.kind != "model.request":
            return GuardDecision(request_id=request.request_id, decision="allow", action="none",
                                 reason="CONTROL", policy_version=self.policy.version), None
        raw = request.payload_utf8.encode("utf-8")
        row = {"request_id": request.request_id, "protocol": request.protocol,
               "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        began = time.perf_counter()
        try:
            body = json.loads(raw)
            images: list = []
            text = "\n".join(leaves(body, images=images))
            archive, engine = self.gate._prepare()
            row["record_id"] = archive.save("model_request", raw).record_id
            verdict = engine.inspect_text(text)
            action = self.gate.actionable(verdict)
            row.update(action=action, rules=list(verdict.rule_ids), images=len(images),
                       input_items=[item.get("type") for item in body.get("input", [])
                                    if isinstance(item, dict)])
        except Exception as error:  # fail closed
            action = "BLOCK"
            row.update(action=action, error=type(error).__name__)
        row["elapsed_ms"] = round((time.perf_counter() - began) * 1000, 1)
        row["marker_seen"] = MARKER.encode() in raw
        row["fake_key_seen"] = FAKE_KEY.encode() in raw
        self.decisions.append(row)
        if action == "ALLOW":
            return GuardDecision(request_id=request.request_id, decision="allow", action="none",
                                 reason="REQUIRED_CHECKS_COMPLETE",
                                 policy_version=self.policy.version), {**row, "decision": "allow"}
        return GuardDecision(request_id=request.request_id, decision="deny", action="block_request",
                             reason="SENSITIVE_OR_AMBIGUOUS_CONTENT",
                             policy_version=self.policy.version), {**row, "decision": "deny"}


def _creation_filetime(pid: int) -> int:
    k = c.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = w.HANDLE
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    handle = k.OpenProcess(0x1000, False, pid)
    if not handle:
        raise c.WinError(c.get_last_error())
    times = [w.FILETIME() for _ in range(4)]
    try:
        if not k.GetProcessTimes(w.HANDLE(handle), *(c.byref(t) for t in times)):
            raise c.WinError(c.get_last_error())
    finally:
        k.CloseHandle(w.HANDLE(handle))
    return times[0].dwLowDateTime + (times[0].dwHighDateTime << 32)


CASES = (
    # name, prompt, scripted tool steps, extra files
    ("benign", "read notes.txt", [["exec_command", {"cmd": "Get-Content notes.txt"}]]),
    ("secret_prompt", f"deploy with {FAKE_KEY}", []),
    ("secret_file_output", "read the build log", [["exec_command", {"cmd": "Get-Content build_log.txt"}]]),
    ("sensitive_path_call", "read the env", [["exec_command", {"cmd": "Get-Content .env"}]]),
    ("image_tool_output", "look at the image", [["view_image", {"path": "marker.png"}]]),
    ("agents_md_secret", "summarize the project", []),
)


def prepare_work(work: Path, case: str) -> None:
    work.mkdir(parents=True)
    (work / "notes.txt").write_text(f"meeting notes {MARKER}\n", encoding="utf-8")
    (work / "build_log.txt").write_text(f"{MARKER} token {FAKE_KEY}\n", encoding="utf-8")
    (work / ".env").write_text(f"{MARKER}=1\n", encoding="utf-8")
    (work / "marker.png").write_bytes(_png_with_marker())
    if case == "agents_md_secret":
        # Client-injected project instructions: no hook event carries them.
        (work / "AGENTS.md").write_text(f"# Project\nDeploy key {FAKE_KEY} ({MARKER}).\n",
                                        encoding="utf-8")


def write_config(home: Path, port: int) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(
        'model = "gpt-5.1-codex"\nmodel_provider = "lab"\napproval_policy = "never"\n'
        'sandbox_mode = "danger-full-access"\n[model_providers.lab]\nname = "lab"\n'
        f'base_url = "http://127.0.0.1:{port}/v1"\n'
        'wire_api = "responses"\nrequires_openai_auth = false\nrequest_max_retries = 0\n'
        'stream_max_retries = 0\nsupports_websockets = false\n', encoding="utf-8")


def observed(server, output: str, began: float, code: int, base: Path | None = None) -> dict:
    bodies = list(server.bodies)
    if base is not None:  # synthetic-only requests, kept for inspection
        for index, body in enumerate(bodies):
            (base / f"origin-{index}.json").write_bytes(body)
    upstream = b"\n".join(bodies)
    return {
        "requests": len(bodies),
        "origin_body_sha256": [hashlib.sha256(b).hexdigest() for b in bodies],
        "marker_reached_origin": MARKER.encode() in upstream,
        "fake_key_reached_origin": FAKE_KEY.encode() in upstream,
        "image_reached_origin": b"data:image/png" in upstream,
        "client_hook_lines": sorted({line.strip() for line in output.splitlines()
                                     if line.startswith("hook: ") and line.strip().count(" ") >= 2}),
        "client_error_lines": [line.strip()[:160] for line in output.splitlines()
                               if "error" in line.lower() or "denied" in line.lower()][:5],
        "exit_code": code,
        "elapsed_ms": round((time.perf_counter() - began) * 1000),
    }


def run_hook(backend: Path, out: Path, server, case, timeout: int, *,
             exec_args: tuple[str, ...] = (), setup=None, scratch: Path | None = None) -> dict:
    """`exec_args` go before the prompt; `setup(work)` adds case files;
    `scratch` holds codex-home and work instead of the output directory."""
    name, prompt, steps = case
    base = out / "hook" / name
    home, work = (scratch or base) / "codex-home", (scratch or base) / "work"
    prepare_work(work, name)
    if setup is not None:
        setup(work)
    write_config(home, server.server_address[1])
    config = installer.write_gate_config(base / "gate", "enforce", None, codex_home=home)
    command = installer.build_command(Path(sys.executable).resolve(strict=True),
                                      (ROOT / "scripts" / "codex_hook_gate.py").resolve(strict=True),
                                      config)
    installer.install_user_layer(home, command, dry_run=False)
    server.steps = steps
    server.bodies.clear()
    began = time.perf_counter()
    done = subprocess.run([str(backend), "exec", "--skip-git-repo-check",
                           "--dangerously-bypass-hook-trust", *exec_args, prompt],
                          cwd=work, env={**os.environ, "CODEX_HOME": str(home)},
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          stdin=subprocess.DEVNULL, timeout=timeout)
    return observed(server, done.stdout + "\n" + done.stderr, began, done.returncode, base)


def run_native(backend: Path, dll: Path, out: Path, server, case, timeout: int, *,
               engine=None, exec_args: tuple[str, ...] = (), setup=None,
               scratch: Path | None = None) -> dict:
    """`engine(config)` builds the policy service (default `NativeDLPEngine`);
    `exec_args` go before `-`; `setup(work)` adds case files; `scratch` holds
    codex-home and work instead of the output directory."""
    name, prompt, steps = case
    base = out / "native" / name
    home, work = (scratch or base) / "codex-home", (scratch or base) / "work"
    prepare_work(work, name)
    if setup is not None:
        setup(work)
    write_config(home, server.server_address[1])
    config = GateConfig.load(installer.write_gate_config(base / "gate", "enforce", None,
                                                         codex_home=home))
    server.steps = steps
    server.bodies.clear()
    began = time.perf_counter()
    # `exec -` reads the prompt from stdin, so nothing is sent before the hooks
    # attest readiness: the prompt is written only after injection.
    client = subprocess.Popen([str(backend), "exec", "--skip-git-repo-check", *exec_args,
                               "-"],
                              cwd=work, env={**os.environ, "CODEX_HOME": str(home)},
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    output_chunks: list[bytes] = []
    reader = threading.Thread(target=lambda: output_chunks.append(client.stdout.read()), daemon=True)
    reader.start()
    engine = (engine or NativeDLPEngine)(config)
    pipe = PipeServer(client.pid, engine, base / "native-audit.jsonl")
    status = {"injected": False, "ready": False}
    try:
        pipe.start()
        identity = {"pid": client.pid, "creation_filetime": _creation_filetime(client.pid),
                    "baseline": {"path": str(backend)}}
        identity["guard_session_id"] = f"{client.pid}-{identity['creation_filetime']}"
        deadline = time.monotonic() + 10
        while True:  # a just-started process may not list its loader module yet
            try:
                inject(client.pid, dll, identity, identity_resolver=lambda _pid: dict(identity))
                break
            except RuntimeError as error:
                if "loader module" not in str(error) or time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        status["injected"] = True
        status["ready"] = wait_ready(identity)
        if not status["ready"]:
            client.kill()
            raise RuntimeError("native hooks did not attest readiness")
        client.stdin.write(prompt.encode("utf-8"))
        client.stdin.close()
        client.wait(timeout)
    finally:
        if client.poll() is None:
            client.kill()
            client.wait(10)
        reader.join(10)
        pipe.close()
    output = b"".join(output_chunks).decode("utf-8", errors="replace")
    result = observed(server, output, began, client.returncode, base)
    origin_hashes = set(result["origin_body_sha256"])
    decisions = getattr(engine, "decisions", [])  # a collection engine logs records instead
    allowed = [d for d in decisions if d.get("action") == "ALLOW"]
    result.update(native=status, pipe_errors=list(pipe.errors), decisions=[
        {k: d.get(k) for k in ("protocol", "bytes", "action", "rules", "input_items",
                                 "marker_seen", "fake_key_seen", "elapsed_ms", "error")}
        for d in decisions],
        # Capture fidelity: every allowed request the hook saw must be byte-identical
        # to one the origin received.
        allowed_bytes_equal_origin=all(d["sha256"] in origin_hashes for d in allowed) if allowed else None)
    return result


def judge(route: str, case: str, r: dict) -> str:
    leaked_key = r["fake_key_reached_origin"]
    leaked_marker = r["marker_reached_origin"]
    if case == "benign":
        return "ALLOWED" if r["requests"] >= 2 and leaked_marker else "BROKEN"
    if case in ("secret_prompt", "secret_file_output", "agents_md_secret"):
        return "LEAKED" if leaked_key else "STOPPED"
    if case == "sensitive_path_call":
        return "LEAKED" if leaked_marker else "STOPPED"
    if case == "image_tool_output":
        return "SENT_UNINSPECTED" if r["image_reached_origin"] else "STOPPED"
    return "?"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--routes", default="hook,native")
    parser.add_argument("--cases", default=",".join(c[0] for c in CASES))
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    backend = args.backend.resolve(strict=True)
    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    if digest != PINNED_BACKEND_SHA256:
        raise SystemExit(f"backend is not the pinned build: {digest}")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    routes = args.routes.split(",")
    wanted = set(args.cases.split(","))
    dll = build_dll(out / "build") if "native" in routes else None
    results = []
    with origin() as server:
        for case in CASES:
            if case[0] not in wanted:
                continue
            for route in routes:
                try:
                    r = (run_hook(backend, out, server, case, args.timeout) if route == "hook"
                         else run_native(backend, dll, out, server, case, args.timeout))
                    r["outcome"] = judge(route, case[0], r)
                except Exception as error:
                    r = {"outcome": "PROBE_ERROR", "error": f"{type(error).__name__}: {error}"}
                results.append({"case": case[0], "route": route, **r})
                print(json.dumps({k: results[-1].get(k) for k in
                                  ("case", "route", "outcome", "requests", "exit_code",
                                   "client_hook_lines", "client_error_lines", "decisions",
                                   "allowed_bytes_equal_origin", "pipe_errors", "error")},
                                 ensure_ascii=False), flush=True)
    report = {"schema": SCHEMA, "backend_sha256": digest,
              "scope": "codex exec in a private CODEX_HOME against a scripted local origin; "
                       "not the desktop UI", "results": results}
    (out / "summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
