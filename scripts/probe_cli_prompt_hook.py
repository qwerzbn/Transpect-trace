"""Exercise the fixed Codex CLI prompt hook against a local non-forwarding sink.

The probe copies its hook into a temporary CODEX_HOME, sends synthetic prompts
through the real CLI, and records only metadata. No OpenAI credentials are read.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading


ROOT = Path(__file__).resolve().parents[1]
VERSION = "codex-cli 0.163.0"
CODEX_SHA256 = "2692C8C7BB2CF8B0AEFE638741FC90236F4B824C59578CE84994F9DE58200993"
SENSITIVE = "aws_access_key_id=AKIAABCDEFGHIJKLMNOP"
BENIGN = "请用一句话介绍公开的 Python 语言。"
EVENT_TYPE = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")


def default_codex() -> Path:
    roaming = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    return (roaming / "npm" / "node_modules" / "@openai" / "codex"
            / "node_modules" / "@openai" / "codex-win32-x64" / "vendor"
            / "x86_64-pc-windows-msvc" / "bin" / "codex.exe")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest().upper()


def isolated_env(home: Path, archive: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("CODEX_", "OPENAI_", "AZURE_OPENAI_"))}
    env["CODEX_HOME"] = str(home)
    env["TTRACE_CLI_PROMPT_DEMO_DIR"] = str(archive)
    return env


class LocalReceiver(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _ReceiverHandler)
        self.requests = 0
        self.body_bytes = 0
        self.lock = threading.Lock()

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return {"requests": self.requests, "body_bytes": self.body_bytes}


class _ReceiverHandler(BaseHTTPRequestHandler):
    def _reply(self) -> None:
        self.connection.settimeout(3)
        received = 0
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0:
                length = 0
            while received < min(length, 16 * 1024 * 1024):
                chunk = self.rfile.read(min(65536, length - received))
                if not chunk:
                    break
                received += len(chunk)
        except (OSError, ValueError):
            pass
        with self.server.lock:
            self.server.requests += 1
            self.server.body_bytes += received
        self.send_response(503)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self._reply()

    def do_POST(self) -> None:
        self._reply()

    def log_message(self, _format: str, *args: object) -> None:
        pass


@contextmanager
def receiver():
    server = LocalReceiver()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def configure(home: Path, hook_dir: Path, port: int) -> dict[str, str]:
    home.mkdir()
    hook_dir.mkdir()
    for name in ("cli_prompt_dlp_hook.py", "cli_prompt_detector.py"):
        shutil.copy2(ROOT / "scripts" / name, hook_dir / name)
    command = subprocess.list2cmdline([sys.executable, str(hook_dir / "cli_prompt_dlp_hook.py")])
    hooks = {"hooks": {"UserPromptSubmit": [{"hooks": [
        {"type": "command", "command": command, "timeout": 10}
    ]}]}}
    (home / "hooks.json").write_text(json.dumps(hooks, ensure_ascii=False), encoding="utf-8")
    (home / "config.toml").write_text(
        'model = "gpt-5.1-codex"\n'
        'model_provider = "ttrace_local_probe"\n'
        '[model_providers.ttrace_local_probe]\n'
        'name = "Local non-forwarding probe"\n'
        f'base_url = "http://127.0.0.1:{port}/v1"\n'
        'wire_api = "responses"\n'
        'requires_openai_auth = false\n'
        'request_max_retries = 0\n'
        'stream_max_retries = 0\n'
        'supports_websockets = false\n', encoding="utf-8")
    return {name: sha256(hook_dir / name)
            for name in ("cli_prompt_dlp_hook.py", "cli_prompt_detector.py")}


def event_summary(output: bytes) -> dict[str, object]:
    types: set[str] = set()
    item_types: set[str] = set()
    usage: dict[str, int] = {}
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except (UnicodeError, ValueError):
            continue
        if isinstance(value, dict):
            kind = value.get("type")
            if isinstance(kind, str) and EVENT_TYPE.fullmatch(kind):
                types.add(kind)
            item = value.get("item")
            if isinstance(item, dict) and isinstance(item.get("type"), str):
                item_type = item["type"]
                if EVENT_TYPE.fullmatch(item_type):
                    item_types.add(item_type)
            counters = value.get("usage")
            if isinstance(counters, dict):
                for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
                    number = counters.get(key)
                    if type(number) is int and number >= 0:
                        usage[key] = number
    return {"event_types": sorted(types), "item_types": sorted(item_types),
            "token_usage": usage}


def audit_summary(path: Path, prompt: str) -> dict[str, object]:
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    records = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and record.get("prompt_sha256") == digest:
                records.append(record)
    return {"matching_records": len(records),
            "actions": sorted({str(r.get("action")) for r in records}),
            "encrypted_snapshots": sum((path.parent / f"{r.get('archive_id')}.dpapi").is_file()
                                       for r in records)}


def run_case(codex: Path, root: Path, name: str, prompt: str) -> dict[str, object]:
    case_root = root / name
    case_root.mkdir()
    home = case_root / "home"
    hook_dir = case_root / "hook"
    archive = case_root / "archive"
    workspace = case_root / "empty-workspace"
    workspace.mkdir()
    with receiver() as sink:
        hook_hashes = configure(home, hook_dir, sink.server_port)
        command = [str(codex), "--dangerously-bypass-hook-trust", "exec",
                   "--ephemeral", "--skip-git-repo-check", "--json", "-C",
                   str(workspace), "-"]
        try:
            result = subprocess.run(command, input=prompt.encode("utf-8"),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=isolated_env(home, archive), cwd=workspace,
                                    timeout=45, check=False)
            exit_code = result.returncode
            events = event_summary(result.stdout)
            timed_out = False
        except subprocess.TimeoutExpired as error:
            exit_code = None
            events = event_summary(error.stdout or b"")
            timed_out = True
        received = sink.snapshot()
    audit = audit_summary(archive / "audit.jsonl", prompt)
    return {"case": name, "cli_exit_code": exit_code, "cli_timed_out": timed_out,
            "hook_audit": audit, "receiver": received, **events,
            "hook_files_sha256": hook_hashes,
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "prompt_bytes": len(prompt.encode("utf-8"))}


def probe(codex: Path) -> dict[str, object]:
    codex = codex.resolve(strict=True)
    binary_hash = sha256(codex)
    if binary_hash != CODEX_SHA256:
        raise ValueError(f"Codex CLI binary hash mismatch: {binary_hash}")
    with tempfile.TemporaryDirectory(prefix="ttrace-cli-prompt-") as directory:
        root = Path(directory)
        version_home = root / "version-home"
        version_home.mkdir()
        version = subprocess.run([str(codex), "--version"], capture_output=True,
                                 text=True, timeout=10, check=True,
                                 env=isolated_env(version_home, root / "version-archive")).stdout.strip()
        if version != VERSION:
            raise ValueError(f"Codex CLI version mismatch: {version}")
        sensitive = run_case(codex, root, "sensitive", SENSITIVE)
        benign = run_case(codex, root, "benign", BENIGN)
    block = (sensitive["hook_audit"]["actions"] == ["BLOCK"]
             and sensitive["hook_audit"]["matching_records"] == 1
             and sensitive["hook_audit"]["encrypted_snapshots"] == 1
             and sensitive["cli_exit_code"] == 0
             and "turn.completed" in sensitive["event_types"]
             and sensitive["receiver"] == {"requests": 0, "body_bytes": 0})
    allow = (benign["hook_audit"]["actions"] == ["ALLOW"]
             and benign["hook_audit"]["matching_records"] == 1
             and benign["hook_audit"]["encrypted_snapshots"] == 1
             and benign["receiver"]["body_bytes"] > 0)
    return {"schema": "transpect.cli-prompt-probe/1.0",
            "cli_version": version, "cli_sha256": binary_hash,
            "cases": [sensitive, benign],
            "sensitive_block_verified": block,
            "benign_reached_local_sink": allow,
            "scope": "synthetic user prompt; local non-forwarding HTTP sink only"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-exe", type=Path, default=default_codex())
    parser.add_argument("--report", type=Path,
                        default=ROOT / "runs" / "cli-prompt-probe" / "report.json")
    args = parser.parse_args()
    report = probe(args.codex_exe)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"report": str(args.report.resolve()),
                      "sensitive_block_verified": report["sensitive_block_verified"],
                      "benign_reached_local_sink": report["benign_reached_local_sink"]},
                     ensure_ascii=False))
    return 0 if report["sensitive_block_verified"] and report["benign_reached_local_sink"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
