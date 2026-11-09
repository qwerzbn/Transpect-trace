"""Opt-in live test of the native guard (guard.c) inside the running desktop backend.

Unlike the earlier Frida research probes, this injects the real guard DLL into
the current Codex desktop `codex.exe app-server` and serves its decisions with
`native_collection.NativeCollectionEngine`. The DLL cannot be unloaded: after
`run` ends, every desktop model request fails closed until the desktop app is
restarted. Run it only when the operator has agreed to restart Codex afterwards.

Scope: only a model request whose serialized body contains this run's random
synthetic marker is inspected, archived and judged. Any other request is
allowed untouched; for it only protocol and length are recorded, never content
or a digest. Prompts are typed by the operator into Local tasks rooted in
workspaces created by `prepare` outside any git checkout. The secret sits where
the desktop's own command hooks cannot see it (AGENTS.md, a tool's output), so
a block there can only come from the native route.

  prepare --root D:/ttrace-desktop-test --output runs/scratch/desktop-native-01
  run     --output runs/scratch/desktop-native-01 [--seconds 1800]
          (stop early by creating <output>/STOP)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import string
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

SCHEMA = "transpect.desktop-native-live/1.0"
PINNED_SHA256 = "925c7d0665ffa49b0dcf748e034a805a04da984164ac92301432073b47789b99"
PACKAGE_DIR = "OpenAI.Codex_26.1029.7803.0_x64__2p2nqsd0c76g0"


def _fake_key() -> str:
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


def prepare(root: Path, output: Path) -> dict:
    if root.exists():
        raise SystemExit(f"{root} exists; choose a new root")
    probe = subprocess.run(["git", "-C", str(root.parent), "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True)
    if probe.returncode == 0:
        raise SystemExit("workspace root must not be inside a git checkout")
    marker = "TTRACE_DESKTOP_" + secrets.token_hex(6).upper()
    key = _fake_key()
    clean, agents = root / "clean", root / "agents"
    clean.mkdir(parents=True)
    agents.mkdir(parents=True)
    (clean / "build_log.txt").write_text(f"{marker} build token {key}\n", encoding="utf-8")
    (agents / "AGENTS.md").write_text(
        f"# Project\nDeploy key {key} ({marker}). Reply briefly.\n", encoding="utf-8")
    output.mkdir(parents=True, exist_ok=False)
    fixtures = {
        "schema": SCHEMA, "marker": marker, "fake_key": key,
        "workspaces": {"clean": str(clean), "agents": str(agents)},
        "prompts": [
            {"id": "A1", "workspace": "clean", "expect": "allowed",
             "text": f"{marker} 请只回复 OK，不要调用任何工具。"},
            {"id": "A2", "workspace": "clean (same task as A1)", "expect": "blocked_after_tool",
             "text": f"{marker} 请运行 Get-Content build_log.txt 并把第一行原样告诉我。"},
            {"id": "B1", "workspace": "agents (new task)", "expect": "blocked_first_request",
             "text": f"{marker} 请只回复 OK，不要调用任何工具。"},
        ],
    }
    (output / "fixtures.json").write_text(json.dumps(fixtures, ensure_ascii=False, indent=2) + "\n",
                                          encoding="utf-8")
    return fixtures


def _cim(pid: int | None = None) -> list[dict]:
    query = ("Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'codex.exe','ChatGPT.exe' }"
             " | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine"
             " | ConvertTo-Json -Compress")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", query], capture_output=True,
                         text=True, encoding="utf-8", errors="replace", timeout=30).stdout
    rows = json.loads(out or "[]")
    return rows if isinstance(rows, list) else [rows]


def find_backend() -> dict:
    """The one app-server child of the pinned MSIX desktop, by path, hash and parent."""
    rows = _cim()
    by_pid = {row["ProcessId"]: row for row in rows}
    found = []
    for row in rows:
        path = row.get("ExecutablePath") or ""
        parent = by_pid.get(row.get("ParentProcessId")) or {}
        if (row["Name"].lower() == "codex.exe" and "app-server" in (row.get("CommandLine") or "")
                and PACKAGE_DIR.lower() in (parent.get("ExecutablePath") or "").lower()):
            found.append({"pid": row["ProcessId"], "path": path,
                          "parent_pid": row["ParentProcessId"]})
    if len(found) != 1:
        raise SystemExit(f"expected exactly one desktop app-server, found {len(found)}")
    backend = found[0]
    digest = hashlib.sha256(Path(backend["path"]).read_bytes()).hexdigest()
    if digest != PINNED_SHA256:
        raise SystemExit(f"desktop backend is not the pinned build: {digest}")
    backend["sha256"] = digest
    return backend


class ScopedEngine:
    """Judges only requests carrying the run marker; all others pass untouched."""

    def __init__(self, inner, marker: str, fake_key: str, events):
        self.inner, self.marker, self.key, self.events = inner, marker, fake_key, events
        self.policy = inner.policy
        self.passthrough: dict[str, int] = {}

    def evaluate(self, request):
        from transpect_trace.guard.policy import GuardDecision
        if request.kind != "model.request":
            return self.inner.evaluate(request)
        body = request.payload_utf8
        if self.marker not in body:
            self.passthrough[request.protocol] = self.passthrough.get(request.protocol, 0) + 1
            return (GuardDecision(request_id=request.request_id, decision="allow", action="none",
                                  reason="OUT_OF_SCOPE", policy_version=self.policy.version),
                    {"kind": "passthrough", "protocol": request.protocol, "bytes": len(body)})
        decision, row = self.inner.evaluate(request)
        row = {**(row or {}), "kind": "scoped", "protocol": request.protocol,
               "fake_key_in_body": self.key in body, "body_bytes": len(body),
               "response_create": '"response.create"' in body[:200]}
        self.events(row)
        return decision, row


def run(output: Path, seconds: int) -> dict:
    import probe_native_guard_backend as probe
    import install_codex_hook_gate as installer
    from transpect_trace.guard.native import inject, wait_ready
    from transpect_trace.guard.pipe import PipeServer
    from transpect_trace.protect.codex_hook_gate import GateConfig
    from transpect_trace.protect.native_collection import NativeCollectionEngine

    fixtures = json.loads((output / "fixtures.json").read_text(encoding="utf-8"))
    backend = find_backend()
    dll = probe.build_dll(output / "build")
    config = GateConfig.load(installer.write_gate_config(output / "gate", "enforce", None))
    log = (output / "events.jsonl").open("a", encoding="utf-8")

    def event(row: dict) -> None:
        line = {k: row.get(k) for k in ("kind", "protocol", "body_bytes", "decision", "action",
                                          "reason", "items_total", "items_new", "incremental",
                                          "duplicate_invocation", "fake_key_in_body",
                                          "response_create", "request_id")}
        line["at"] = time.strftime("%H:%M:%S")
        log.write(json.dumps(line) + "\n")
        log.flush()
        print(json.dumps(line), flush=True)

    engine = ScopedEngine(NativeCollectionEngine(config), fixtures["marker"],
                          fixtures["fake_key"], event)
    pipe = PipeServer(backend["pid"], engine, output / "native-audit.jsonl")
    identity = {"pid": backend["pid"], "creation_filetime": probe._creation_filetime(backend["pid"]),
                "baseline": {"path": backend["path"]}}
    identity["guard_session_id"] = f"{backend['pid']}-{identity['creation_filetime']}"
    status = {"injected": False, "ready": False}
    began = time.time()
    pipe.start()
    try:
        inject(backend["pid"], dll, identity, identity_resolver=lambda _pid: dict(identity))
        status["injected"] = True
        status["ready"] = wait_ready(identity)
        print(json.dumps({"ready": status["ready"], "backend_pid": backend["pid"]}), flush=True)
        if status["ready"]:
            stop = output / "STOP"
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline and not stop.exists():
                time.sleep(0.5)
    finally:
        pipe.close()
        log.close()
    scoped = [row for row in pipe.records if row.get("kind") == "scoped"]
    summary = {
        "schema": SCHEMA, "backend": backend, "status": status,
        "duration_s": round(time.time() - began),
        "passthrough_by_protocol": engine.passthrough,
        "scoped_by_protocol": {p: sum(r["protocol"] == p for r in scoped) for p in ("http", "wss")},
        "scoped_denied_with_fake_key": sum(r.get("decision") == "deny" and r["fake_key_in_body"]
                                           for r in scoped),
        "scoped_allowed_with_fake_key": sum(r.get("decision") == "allow" and r["fake_key_in_body"]
                                            for r in scoped),
        "scoped_allowed": sum(r.get("decision") == "allow" for r in scoped),
        "pipe_errors": list(pipe.errors),
        "note": "native DLL stays resident: restart Codex desktop now",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    r = sub.add_parser("run")
    r.add_argument("--output", type=Path, required=True)
    r.add_argument("--seconds", type=int, default=1800)
    sub.add_parser("find")
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.root, args.output.resolve())
    elif args.command == "find":
        result = find_backend()
    else:
        result = run(args.output.resolve(), args.seconds)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
