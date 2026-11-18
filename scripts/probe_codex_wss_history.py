"""Verify one real, isolated app-server conversation at a loopback WSS origin.

Requires aiohttp in the probe environment. Only the disposable client's trust
settings and home are changed. Use the production engine, controller and DLL.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from queue import Queue
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from uuid import uuid4

from aiohttp import WSMsgType, web
from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
import probe_desktop_backend_lab as lab
from probe_codex_tls import certificate, events
from probe_desktop_capture_current_lab import configure_provider
from probe_desktop_guard_failstop_current_lab import FAKE_KEY
from probe_desktop_guard_graceful_current_lab import (
    _completed_for, _message_reader, _thread_id, _turn_id, _wait_for,
)
from transpect_trace.guard import desktop_service as svc
from transpect_trace.protect.archive import EncryptedRequestArchive
from transpect_trace.protect.codex_hook_gate import GateConfig


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def client(root, folder, backend, dll, port, ca, prompts, phases):
    work, home = root / "work", root / "home"
    work.mkdir()
    model = configure_provider(home, port, "wss")
    env = lab.isolated_env(home)
    observed, messages, lock = [], Queue(), threading.Lock()
    worker = None
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        proxy = f"http://127.0.0.1:{unavailable.getsockname()[1]}"
        env.update(CODEX_CA_CERTIFICATE=str(ca), HTTP_PROXY=proxy, HTTPS_PROXY=proxy,
                   ALL_PROXY=proxy, NO_PROXY="localhost,127.0.0.1")
        with subprocess.Popen([str(backend), "app-server"], cwd=work, env=env,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              encoding="utf-8", text=True, bufsize=1) as process:
            try:
                threading.Thread(target=_message_reader, args=(process.stdout, messages, observed, lock),
                                 daemon=True).start()
                lab._request(process, 1, "initialize", {"clientInfo": {
                    "name": "wss_history_lab", "version": "1.0"}})
                if "result" not in lab._await_id(messages, 1, 15):
                    raise RuntimeError("initialize failed")
                process.stdin.write('{"method":"initialized","params":{}}\n')
                process.stdin.flush()
                gate = GateConfig(mode="enforce", archive_directory=folder / "archive",
                                  audit_file=folder / "audit.jsonl", registration_directory=None,
                                  review_override_ttl_seconds=0, collection_file=folder / "collection.jsonl")
                details = svc.process_details(process.pid)
                status = svc.BackendStatus(process.pid, details["creation_filetime"])
                worker = svc.BackendController(details, dll, svc.create_desktop_engine(gate),
                                               {}, folder, status, lambda _: None)
                worker.start()
                if not _wait_for(lambda: status.state != "STARTING", 20, process) or status.state != "PROTECTED":
                    raise RuntimeError(f"controller state {status.state} {status.detail}")
                lab._request(process, 2, "thread/start", {"model": model, "cwd": str(work),
                             "approvalPolicy": "never", "sandbox": "read-only"})
                thread = _thread_id(lab._await_id(messages, 2, 15))
                for number, (name, prompt) in enumerate(prompts.items(), 10):
                    lab._request(process, number, "turn/start", {"threadId": thread, "cwd": str(work),
                                 "input": [{"type": "text", "text": prompt}]})
                    turn = _turn_id(lab._await_id(messages, number, 15))
                    if not _wait_for(lambda: _completed_for(observed, lock, turn) is not None, 35, process):
                        raise TimeoutError(f"turn {name} did not finish")
                    done = _completed_for(observed, lock, turn)
                    with lock:
                        replies = [m["params"]["item"].get("text") for m in observed
                                   if m.get("method") == "item/completed" and m["params"].get("turnId") == turn
                                   and m["params"].get("item", {}).get("type") == "agentMessage"]
                    phases.append(dict(name=name, thread_id=thread, turn_id=turn,
                                       status=done["status"], error=done["error"],
                                       reply_from_fixture=replies == ["TLS probe received."]))
            finally:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)
                if worker is not None:
                    worker.stop_requested.set()
                    worker.finished.wait(10)
    return process.pid


async def run(buildfile, folder):
    build = json.loads(buildfile.read_text("utf-8"))
    backend, dll = Path(build["backend"]), Path(build["dll"])
    manifest = json.loads(dll.with_suffix(".json").read_text("utf-8"))
    if (svc.file_sha256(backend) != manifest["backend_sha256"]
            or svc.file_sha256(dll) != build["sha256"] or build["sha256"] != manifest["dll_sha256"]):
        raise ValueError("build identity mismatch")
    folder.mkdir(exist_ok=False, parents=True)
    archive = EncryptedRequestArchive(folder / "archive")
    tag = uuid4().hex[:10]
    secret = f"This deployment test uses a GitHub token {FAKE_KEY}."
    prompts = {"allow": f"Tell me about tea. Reference Tea{tag}.",
               "deny": secret, "continue": f"Answer only about coffee. Ticket Bean{tag}.",
               "repeat_deny": secret, "continue_again": f"Tell me about water. Ticket Rain{tag}."}
    frames, other_http, phases, errors = [], [], [], []

    async def receive(request):
        ws = web.WebSocketResponse(compress=False, max_msg_size=lab.MAX_BODY)
        if not ws.can_prepare(request).ok:
            raw = await request.read()
            other_http.append(dict(method=request.method, path=request.path, bytes=len(raw),
                                   token=FAKE_KEY.encode() in raw))
            return web.Response(status=404)
        await ws.prepare(request)
        async for msg in ws:
            if msg.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                errors.append(f"unexpected frame {msg.type.name}")
                break
            raw = msg.data.encode("utf-8") if isinstance(msg.data, str) else msg.data
            body = json.loads(raw)
            wire = body.get("response", body)
            metadata = wire.get("client_metadata") or {}
            serialized = json.dumps(body, ensure_ascii=False)
            frames.append(dict(path=request.path, type=body.get("type"), bytes=len(raw),
                               turn_id=metadata.get("turn_id"), sha256=digest(raw),
                               hmac=archive.keyed_digest(raw), token=FAKE_KEY in serialized,
                               prompts=[n for n, p in prompts.items() if p in serialized],
                               incremental=bool(wire.get("previous_response_id")),
                               warmup=wire.get("generate") is False))
            for event in events():
                if "response" in event:
                    event["response"]["id"] = f"resp_fixture_{len(frames)}"
                await ws.send_json(event)
        return ws

    app = web.Application(client_max_size=lab.MAX_BODY)
    app.router.add_route("*", "/{tail:.*}", receive)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        cert, key, ca = certificate(root)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.SockSite(runner, listener, ssl_context=context).start()
        pid = None
        try:
            pid = await asyncio.to_thread(client, root, folder, backend, dll, port, ca, prompts, phases)
        except Exception as exc:
            errors.append(str(exc))
        finally:
            await runner.cleanup()

    audit = []
    for path in folder.glob("native-audit-*.jsonl"):
        for line in path.read_text("utf-8").splitlines():
            row = json.loads(line)
            if row.get("category") != "request_envelope":
                continue
            receipt, raw = archive.read(row["archive_record_id"])
            obj = json.loads(raw)
            serialized = json.dumps(obj, ensure_ascii=False)
            wire = obj.get("response", obj)
            audit.append(dict(thread_id=row.get("thread_id"), turn_id=row.get("turn_id"),
                    request_id=row["request_id"], archive_id=receipt.record_id, protocol=row["protocol"],
                    action=row.get("decision"), reason=row.get("reason"), bytes=len(raw),
                    original_sha256=digest(raw), exact=receipt.body_sha256 == row["request_sha256"] == digest(raw),
                    forwarded_hmac=row.get("extra", {}).get("forwarded_body_hmac"),
                    contains_token=FAKE_KEY in serialized, incremental=bool(wire.get("previous_response_id")),
                    prompts=[n for n, p in prompts.items() if p in serialized]))
    for phase in phases:
        name = phase["name"]
        original = [a for a in audit if a["turn_id"] == phase["turn_id"]]
        received = [r for r in frames if r["turn_id"] == phase["turn_id"]]
        checks = dict(native_match=bool(original) and all(a["exact"] and a["protocol"] == "wss"
                      and a["thread_id"] == phase["thread_id"] for a in original))
        if name in ("deny", "repeat_deny"):
            checks.update(hard_block=phase["status"] == "failed" and (phase["error"] or {}).get(
                "message") == "Transpect: request denied by local policy", no_frame=not received,
                native_block=bool(original) and all(a["action"] == "deny" and a["contains_token"] for a in original))
        else:
            checks.update(assistant_reply=phase["status"] == "completed" and phase["reply_from_fixture"],
                one_frame=len(received) == 1 and name in received[0]["prompts"] and not received[0]["token"],
                native_allow=bool(original) and all(a["action"] == "allow" for a in original))
            if name == "allow":
                checks["unchanged_wire"] = any(a["original_sha256"] == r["sha256"] for a in original for r in received)
            else:
                checks["verified_rewrite"] = any(a["contains_token"] and name in a["prompts"]
                    and a["reason"] == "HISTORICAL_BLOCK_SCRUBBED" and a["forwarded_hmac"] == r["hmac"]
                    for a in original for r in received)
        phase["checks"] = checks
    turn_ids = {p["turn_id"] for p in phases}
    checks = dict(all_turns=len(phases) == len(prompts) == len(turn_ids),
                  same_thread=len({p["thread_id"] for p in phases}) == 1,
                  no_http_model_fallback=not any(r["method"] == "POST" for r in other_http),
                  no_received_token=not any(r["token"] for r in frames + other_http),
                  all_frame_types=bool(frames) and all(r["type"] == "response.create" for r in frames),
                  only_expected_turns=all(r["turn_id"] in turn_ids or
                      (not r["turn_id"] and r["warmup"] and not r["prompts"]) for r in frames),
                  every_received_frame_linked=all(any(a["protocol"] == "wss" and a["action"] == "allow"
                      and a["exact"] and (a["original_sha256"] == r["sha256"] or
                                         a["forwarded_hmac"] == r["hmac"]) for a in audit) for r in frames))
    report = dict(schema="transpect.codex.wss-history/1", backend_sha256=manifest["backend_sha256"],
                  dll_sha256=build["sha256"], native_sources=manifest["sources"],
                  python_sources={p:svc.file_sha256(ROOT / p) for p in (
                      "src/transpect_trace/protect/native_collection.py", "src/transpect_trace/guard/pipe.py",
                      "src/transpect_trace/guard/desktop_service.py", "scripts/probe_codex_wss_history.py")},
                  synthetic_only=True, local_origin_only=True, pid=pid,
                  phases=phases, frames=frames, other_http=other_http, native=audit, errors=errors, checks=checks,
                  passed=not errors and all(checks.values()) and all(all(p["checks"].values()) for p in phases))
    (folder / "report.json").write_text(json.dumps(report, indent=2) + "\n", "utf-8")
    print(json.dumps({"passed": report["passed"], "checks": checks, "errors": errors,
                      "failed": {p["name"]:[k for k,v in p["checks"].items() if not v] for p in phases}}))
    return int(not report["passed"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    sys.exit(asyncio.run(run(args.build.resolve(), args.output.resolve())))
