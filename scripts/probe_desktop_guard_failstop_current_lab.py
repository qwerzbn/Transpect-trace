"""Exercise the pinned 0.167 Native DLL against an isolated app-server child.

This lab uses a private CODEX_HOME and a non-forwarding local origin. It
injects before thread/start, so the WSS warmup and target turn can both be
accounted for. Denial terminates this disposable child; no live desktop
process, graceful Rust error ABI, or Codex command hook is involved.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import ntpath
import os
from pathlib import Path
from queue import Queue
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))

import probe_desktop_backend_lab as lab
from probe_desktop_capture_current_lab import (
    BACKEND_SHA256, BACKEND_VERSION, configure_provider, local_origin,
    trace_inventory,
)
from transpect_trace.guard.desktop import _cim_process, desktop_mode
from transpect_trace.guard.native import command_arguments, inject, wait_ready
from transpect_trace.guard.pipe import PipeServer
from transpect_trace.observe.windows import identity as image_identity
from transpect_trace.protect.codex_hook_gate import GateConfig
from transpect_trace.protect.native_collection import NativeCollectionEngine


SCHEMA = "transpect.desktop-guard-failstop-current-lab/1.0"
BUILD_SCHEMA = "transpect.guard.failstop-current-lab-build/1.0"
DEFAULT_DLL = ROOT / "build/guard-failstop-current-lab/ttrace-guard-failstop-current-lab.dll"
# The existing DLP fixture's fake GitHub token. Keep this lab independent of
# every script that installs or exercises a Codex command hook.
FAKE_KEY = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
FAKE_KEY_BYTES = FAKE_KEY.encode("ascii")
MAX_HTTP_BODY = 16 * 1024 * 1024


class _CountingHTTPServer(socketserver.ThreadingTCPServer):
    """Count every received HTTP body byte, including incomplete requests."""
    allow_reuse_address = True
    daemon_threads = False
    block_on_close = True

    def __init__(self, marker: bytes):
        super().__init__(("127.0.0.1", 0), _CountingHTTPHandler)
        self.marker = marker
        self.server_port = self.server_address[1]
        self.lock = threading.Lock()
        self.received: list[dict] = []


class _CountingHTTPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        peer = self.server
        self.request.settimeout(10)
        with peer.lock:
            row = {"connection": len(peer.received) + 1, "protocol": "http",
                   "wire_bytes": 0, "http_body_bytes_received": 0,
                   "complete": False, "framing_verified": False}
            peer.received.append(row)
        wire = bytearray()
        body = bytearray()
        try:
            while b"\r\n\r\n" not in wire:
                chunk = self.request.recv(65536)
                if not chunk:
                    raise EOFError("HTTP header ended early")
                with peer.lock:
                    row["wire_bytes"] += len(chunk)
                wire.extend(chunk)
                if len(wire) > 65536:
                    raise ValueError("HTTP header exceeds lab limit")
            header, initial = bytes(wire).split(b"\r\n\r\n", 1)
            lines = header.decode("ascii", errors="strict").split("\r\n")
            first = lines[0].split(" ")
            if len(first) < 3 or first[0] != "POST":
                raise ValueError("unexpected HTTP request method")
            lengths = [line.split(":", 1)[1].strip() for line in lines[1:]
                       if line.lower().startswith("content-length:")]
            if len(lengths) != 1:
                raise ValueError("missing or duplicate Content-Length")
            length = int(lengths[0])
            if not 0 <= length <= MAX_HTTP_BODY:
                raise ValueError("HTTP body length outside lab limit")
            with peer.lock:
                row.update(path="responses" if first[1].startswith("/v1/responses") else "other",
                           request_line=lines[0], framing_verified=True)
            body.extend(initial[:length])
            with peer.lock:
                row["http_body_bytes_received"] = len(body)
            while len(body) < length:
                chunk = self.request.recv(min(65536, length - len(body)))
                if not chunk:
                    raise EOFError("HTTP body ended early")
                body.extend(chunk)
                with peer.lock:
                    row["wire_bytes"] += len(chunk)
                    row["http_body_bytes_received"] = len(body)
            with peer.lock:
                row.update(complete=True, bytes=len(body),
                           sha256=hashlib.sha256(body).hexdigest(),
                           target=peer.marker in body,
                           body_complete_perf_ns=time.perf_counter_ns())
            # A bounded pause lets disposable multi-thread labs verify that a
            # second request reached the origin before this one completed.
            delay = getattr(peer, "success_delay_seconds", 0)
            if delay:
                time.sleep(delay)
            if getattr(peer, "success_for_allowed", False) and not row["target"]:
                item = {"id": "msg_probe", "type": "message", "role": "assistant",
                        "status": "completed", "content": [{"type": "output_text",
                        "text": "Local test reply.", "annotations": []}]}
                response = {"id": "resp_probe", "object": "response",
                            "model": "gpt-5.1-codex", "status": "completed",
                            "output": [item], "usage": {"input_tokens": 1,
                            "output_tokens": 1, "total_tokens": 2}}
                events = [
                    {"type": "response.created", "response": {
                        **response, "status": "in_progress", "output": []}},
                    {"type": "response.output_item.done", "output_index": 0,
                     "item": item},
                    {"type": "response.completed", "response": response},
                ]
                payload = b"".join(b"data: " + json.dumps(event).encode("utf-8") +
                                   b"\n\n" for event in events)
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                    b"Content-Length: " + str(len(payload)).encode("ascii") +
                    b"\r\nConnection: close\r\n\r\n" + payload)
                with peer.lock:
                    row["reply_sent_perf_ns"] = time.perf_counter_ns()
            else:
                self.request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                     b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        except Exception as error:
            with peer.lock:
                row["error"] = type(error).__name__
                row["partial_body_sha256"] = hashlib.sha256(body).hexdigest()


@contextmanager
def counted_local_origin(transport: str, root: Path, marker: bytes):
    if transport != "http":
        with local_origin(transport, root, marker) as sink:
            yield sink
        if sink.origin.thread.is_alive():
            sink.origin.thread.join(timeout=12)
        if sink.origin.thread.is_alive():
            raise RuntimeError("WSS origin did not quiesce before evidence snapshot")
        return
    sink = _CountingHTTPServer(marker)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    try:
        yield sink
    finally:
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=3)
        if thread.is_alive():
            raise RuntimeError("HTTP origin did not quiesce before evidence snapshot")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check_build(dll: Path, backend: Path) -> dict:
    manifest = json.loads((dll.parent / "build-manifest.json").read_text(encoding="utf-8"))
    if (manifest.get("schema") != BUILD_SCHEMA or manifest.get("lab_only") is not True
            or manifest.get("deny_behavior") != "terminate_process_exit_76"
            or manifest.get("backend", {}).get("sha256") != BACKEND_SHA256
            or manifest.get("backend", {}).get("version") != BACKEND_VERSION
            or manifest.get("artifact", {}).get("sha256") != sha256(dll)
            or manifest.get("backend", {}).get("path") != str(backend)):
        raise ValueError("DLL is not the pinned fail-stop lab build")
    if set(manifest.get("capture_evidence", {})) != {"http", "wss"}:
        raise ValueError("DLL manifest lacks both capture evidence routes")
    return {"sha256": manifest["artifact"]["sha256"],
            "manifest_sha256": sha256(dll.parent / "build-manifest.json"),
            "lab_only": True, "deny_behavior": manifest["deny_behavior"]}


def child_identity(pid: int, backend: Path, parent_sid: str,
                   creation_filetime: int | None = None) -> dict:
    """Pin one direct child process immediately before each native action."""
    row = _cim_process(pid)
    image = image_identity(pid)
    if (row.get("ParentProcessId") != os.getpid()
            or desktop_mode(command_arguments(row.get("CommandLine") or "")) != "app-server"
            or row.get("UserSid") != parent_sid
            or image.get("pid") != pid
            or not isinstance(image.get("creation_filetime"), int)
            or image["creation_filetime"] <= 0
            or ntpath.normcase(image["image_path"]) != ntpath.normcase(str(backend))
            or image["image_sha256"] != BACKEND_SHA256
            or (creation_filetime is not None
                and image["creation_filetime"] != creation_filetime)):
        raise ValueError("isolated app-server identity changed")
    birth = image["creation_filetime"]
    return {"pid": pid, "creation_filetime": birth,
            "guard_session_id": f"{pid}-{birth}",
            "baseline": {"path": str(backend), "sha256": BACKEND_SHA256,
                         "supported": True, "version": BACKEND_VERSION},
            "mode": "app-server", "user_sid": parent_sid,
            "parent_pid": os.getpid()}


def origin_rows(sink, transport: str) -> list[dict]:
    if transport == "http":
        with sink.lock:
            return [dict(row) for row in sink.received]
    return [{"protocol": row.get("protocol"),
             "connection": row.get("connection"),
             "request_line": row.get("request_line"),
             "bytes": row.get("payload_bytes"),
             "sha256": row.get("payload_sha256"),
             "target": row.get("marker_in_origin_payload"),
             "wire_bytes": row.get("wire_bytes", 0),
             "wss_wire_body_bytes_received": row.get("wss_wire_body_bytes_received", 0),
             "complete": isinstance(row.get("payload_bytes"), int),
             "error": row.get("error", "").split(":", 1)[0] or None}
            for row in list(sink.origin.records)]


def run_case(backend: Path, dll: Path, output: Path, transport: str,
             case: str, parent_sid: str) -> dict:
    marker = f"TTRACE_NATIVE_LAB_{uuid4().hex}".encode("ascii")
    prompt = marker.decode("ascii") + (f" deploy with {FAKE_KEY}" if case == "dlp_block" else " hello")
    case_dir = output / transport / case
    case_dir.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="ttrace-guard-current-",
                                     ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        home, work, trace = root / "home", root / "work", root / "trace"
        work.mkdir()
        with counted_local_origin(transport, root, marker) as sink:
            model = configure_provider(home, sink.server_port, transport)
            env = lab.isolated_env(home)
            env["CODEX_ROLLOUT_TRACE_ROOT"] = str(trace)
            if transport == "wss":
                env.update(CODEX_CA_CERTIFICATE=str(sink.ca), NO_PROXY="localhost,127.0.0.1",
                           HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9",
                           ALL_PROXY="http://127.0.0.1:9")
            process = subprocess.Popen([str(backend), "app-server"], cwd=work, env=env,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                                       bufsize=1)
            messages: Queue = Queue()
            methods: list[str] = []
            reader = threading.Thread(target=lab._drain_json,
                                      args=(process.stdout, messages, methods), daemon=True)
            reader.start()
            config = GateConfig(mode="enforce", archive_directory=case_dir / "archive",
                                audit_file=case_dir / "audit.jsonl", registration_directory=None,
                                review_override_ttl_seconds=0,
                                collection_file=case_dir / "collection.jsonl")
            engine = NativeCollectionEngine(config, archive_full_body=True)
            taps: list[dict] = []
            tap_lock = threading.Lock()

            def tap(request):
                if request.kind != "model.request":
                    return
                raw = request.payload_utf8.encode("utf-8")
                with tap_lock:
                    taps.append({"request_id": request.request_id, "protocol": request.protocol,
                                 "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                                 "target": marker in raw, "fake_key": FAKE_KEY_BYTES in raw})

            pipe = PipeServer(process.pid, engine, case_dir / "pipe-audit.jsonl",
                              request_tap=tap, client_sid=parent_sid)
            identity = None
            status = {"pipe_started": False, "injected": False, "hook_ready": False,
                      "pipe_ready": False, "injected_before_thread_start": False,
                      "pipe_stopped_before_turn": False,
                      "turn_start_sent_after_pipe_loss": False}
            handshake: list[str] = []
            errors: list[str] = []
            try:
                lab._request(process, 1, "initialize", {"clientInfo": {
                    "name": "transpect_guard_lab", "title": "Transpect guard lab", "version": "0.1.0"}})
                response = lab._await_id(messages, 1, 15)
                if "error" in response:
                    raise RuntimeError("app-server initialize failed")
                process.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
                process.stdin.flush()
                handshake.append("initialized")

                identity = child_identity(process.pid, backend, parent_sid)
                pipe.start()
                status["pipe_started"] = True
                inject(process.pid, dll, identity,
                       identity_resolver=lambda pid: child_identity(
                           pid, backend, parent_sid, identity["creation_filetime"]))
                status["injected"] = True
                status["hook_ready"] = wait_ready(identity, timeout=15)
                status["pipe_ready"] = pipe.ready.wait(3)
                if not status["hook_ready"] or not status["pipe_ready"]:
                    raise RuntimeError("native hooks did not attest readiness")
                child_identity(process.pid, backend, parent_sid, identity["creation_filetime"])
                status["injected_before_thread_start"] = True

                lab._request(process, 2, "thread/start", {"model": model, "cwd": str(work),
                                                          "approvalPolicy": "never",
                                                          "sandbox": "read-only"})
                response = lab._await_id(messages, 2, 15)
                if "error" in response:
                    raise RuntimeError("app-server thread/start failed")
                thread_id = response.get("result", {}).get("thread", {}).get("id")
                if not isinstance(thread_id, str):
                    raise RuntimeError("app-server returned no thread ID")
                handshake.append("thread/start")
                if case == "controller_loss":
                    if transport == "wss":
                        warmup_deadline = time.monotonic() + 10
                        while time.monotonic() < warmup_deadline and not any(
                                row.get("complete") is True and row.get("target") is False
                                for row in origin_rows(sink, transport)):
                            time.sleep(0.05)
                    pipe.close()
                    status["pipe_stopped_before_turn"] = True
                lab._request(process, 3, "turn/start", {"threadId": thread_id,
                                                        "input": [{"type": "text", "text": prompt}],
                                                        "cwd": str(work)})
                if case == "controller_loss":
                    status["turn_start_sent_after_pipe_loss"] = True
                else:
                    response = lab._await_id(messages, 3, 15)
                    if "error" in response:
                        raise RuntimeError("app-server turn/start failed")
                    handshake.append("turn/start")
                until = time.monotonic() + 30
                while time.monotonic() < until:
                    target_seen = any(row["target"] for row in taps)
                    target_arrived = any(row.get("target") is True and row.get("complete") is True
                                         for row in origin_rows(sink, transport))
                    if case == "controller_loss" and process.poll() is not None:
                        break
                    if case == "dlp_block" and target_seen and process.poll() is not None:
                        break
                    if case == "allow" and target_seen and target_arrived:
                        time.sleep(0.2)
                        break
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                reader.join(timeout=2)
                pipe.close()
        # The listener and all HTTP handler threads, or the WSS origin thread,
        # have stopped. Include late accepts, resets and partial reads.
        origin = origin_rows(sink, transport)
        traces = trace_inventory(trace, marker)
        hooks_file_present = (home / "hooks.json").exists()
        exit_code = process.returncode
    with tap_lock:
        requests = list(taps)
    decisions = [row for row in pipe.records if row.get("route_event") == "model.request"]
    by_id = {row.get("request_id"): row for row in decisions}
    archive_by_body: dict[tuple[int, str], tuple[str, str]] = {}
    for row in requests:
        decision = by_id.get(row["request_id"], {})
        row["decision"] = decision.get("decision")
        row["action"] = decision.get("action")
        record_id = decision.get("archive_record_id")
        body_key = (row["bytes"], row["sha256"])
        if isinstance(record_id, str):
            row["archive_record_id"] = record_id
            try:
                receipt, restored = engine.gate._archive.read(record_id)
                row["archive_readback_exact"] = (
                    receipt.body_bytes == row["bytes"]
                    and receipt.body_sha256 == row["sha256"]
                    and hashlib.sha256(restored).hexdigest() == row["sha256"])
            except Exception as error:
                row["archive_readback_exact"] = False
                row["archive_readback_error"] = type(error).__name__
            if row["archive_readback_exact"]:
                archive_by_body[body_key] = (record_id, row["request_id"])
        else:
            # HTTP calls the same gate twice for one body. The collection
            # engine intentionally reuses its first receipt on the second
            # invocation, so resolve the duplicate against that exact body.
            previous = archive_by_body.get(body_key)
            row["archive_readback_exact"] = previous is not None
            if previous:
                row["archive_record_id"] = previous[0]
                row["archive_reused_from_request_id"] = previous[1]
    target_trace = [row.get("compact_json") for row in traces
                    if row.get("marker_in_file") and isinstance(row.get("compact_json"), dict)]
    target_requests = [row for row in requests if row["target"]]
    origin_bodies = [row for row in origin if isinstance(row.get("bytes"), int)
                     and isinstance(row.get("sha256"), str)]
    sent = {(row["bytes"], row["sha256"]) for row in origin_bodies}
    allowed = [row for row in requests if row["decision"] == "allow"]
    blocked = [row for row in target_requests if row["decision"] == "deny"
               and row["action"] == "BLOCK"]
    all_origin_seen = all((row["bytes"], row["sha256"]) in
                          {(request["bytes"], request["sha256"]) for request in requests}
                          for row in origin_bodies)
    all_allowed_sent = all((row["bytes"], row["sha256"]) in sent for row in allowed)
    target_trace_exact = (len(target_trace) == 1 and bool(target_requests)
                          and all(row["bytes"] == target_trace[0].get("bytes")
                                  and row["sha256"] == target_trace[0].get("sha256")
                                  for row in target_requests))
    target_origin = [row for row in origin_bodies if row.get("target") is True]
    if transport == "wss":
        warmups = [row for row in origin if row.get("complete") is True
                   and row.get("target") is False and row.get("protocol") == "websocket"]
        warmup_connection = warmups[0]["connection"] if len(warmups) == 1 else None
        non_warmup = [row for row in origin if row.get("connection") != warmup_connection]
        non_warmup_body_bytes = sum(row.get("wss_wire_body_bytes_received", 0)
                                    for row in non_warmup)
        non_warmup_count_verified = all(
            row.get("protocol") == "websocket" or row.get("wire_bytes", 0) == 0
            for row in non_warmup)
    else:
        warmup_connection = None
        non_warmup_body_bytes = sum(row.get("http_body_bytes_received", 0)
                                    for row in origin)
        non_warmup_count_verified = all(row.get("framing_verified") is True
                                        for row in origin)
    expected_handshake = (["initialized", "thread/start"] if case == "controller_loss"
                          else ["initialized", "thread/start", "turn/start"])
    common = (handshake == expected_handshake
              and status["hook_ready"] and status["pipe_ready"]
              and status["injected_before_thread_start"] and not errors
              and not pipe.errors and not hooks_file_present and target_trace_exact
              and all(row["archive_readback_exact"] for row in requests)
              and all_origin_seen and all_allowed_sent)
    if case == "controller_loss":
        # The policy pipe is intentionally absent for the target, so there is
        # no native request tap or archive for it. Trace plus process exit and
        # independent receiver counters establish the failure-path outcome.
        validated = (
            handshake == expected_handshake and status["hook_ready"]
            and status["pipe_ready"] and status["injected_before_thread_start"]
            and status["pipe_stopped_before_turn"]
            and status["turn_start_sent_after_pipe_loss"]
            and not errors and not hooks_file_present and not pipe.errors
            and len(target_trace) == 1 and not target_requests
            and all_origin_seen and all_allowed_sent
            and all(row["archive_readback_exact"] for row in requests)
            and len(target_origin) == 0 and non_warmup_body_bytes == 0
            and non_warmup_count_verified and exit_code == 76)
    else:
        validated = (common and (bool(target_origin) and all_allowed_sent
                                 and all(row["decision"] == "allow" for row in target_requests)
                                 if case == "allow" else
                                 bool(blocked) and len(target_origin) == 0
                                 and non_warmup_body_bytes == 0
                                 and non_warmup_count_verified
                                 and exit_code == 76))
    return {"schema": SCHEMA, "transport": transport, "case": case,
            "backend_sha256": BACKEND_SHA256, "dll_sha256": sha256(dll),
            "synthetic_only": True, "local_origin_only": True,
            "codex_command_hooks_present": hooks_file_present,
            "identity": {"pid": process.pid,
                         "creation_filetime": identity["creation_filetime"] if identity else None,
                         "parent_pid": os.getpid(), "mode": "app-server",
                         "image_sha256": BACKEND_SHA256},
            "status": status, "handshake": handshake, "process_exit_code": exit_code,
            "origin": origin, "pipe_requests": requests,
            "target_trace": target_trace, "target_trace_exact": target_trace_exact,
            "all_origin_seen_by_native_pipe": all_origin_seen,
            "all_allowed_pipe_requests_sent": all_allowed_sent,
            "target_origin_requests": len(target_origin),
            "target_origin_body_bytes": sum(row["bytes"] for row in target_origin),
            "warmup_connection": warmup_connection,
            "non_warmup_wire_body_bytes_received": non_warmup_body_bytes,
            "non_warmup_body_counter_verified": non_warmup_count_verified,
            "collection_envelopes": len(decisions),
            "pipe_errors": list(pipe.errors), "errors": errors,
            "app_server_event_methods": sorted(set(methods)),
            "validated": validated, "lab_only": True,
            "production_desktop_coverage_validated": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--dll", type=Path, default=DEFAULT_DLL)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transports", default="http,wss")
    parser.add_argument("--cases", default="allow,dlp_block")
    args = parser.parse_args()
    backend, dll = args.backend.resolve(strict=True), args.dll.resolve(strict=True)
    if sha256(backend) != BACKEND_SHA256:
        raise SystemExit("backend does not match pinned 0.167 lab build")
    version = subprocess.run([str(backend), "--version"], capture_output=True, text=True,
                             timeout=10, check=True).stdout.strip()
    if version != BACKEND_VERSION:
        raise SystemExit("backend version differs from pinned 0.167 lab build")
    build = check_build(dll, backend)
    transports = args.transports.split(",")
    cases = args.cases.split(",")
    if (not transports or any(item not in {"http", "wss"} for item in transports)
            or len(set(transports)) != len(transports)
            or not cases or any(item not in {"allow", "dlp_block", "controller_loss"} for item in cases)
            or len(set(cases)) != len(cases)):
        raise SystemExit("unknown or duplicate transport/case")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    parent_sid = _cim_process(os.getpid()).get("UserSid")
    if not isinstance(parent_sid, str) or not parent_sid.startswith("S-"):
        raise SystemExit("cannot establish lab controller SID")
    results = []
    for transport in transports:
        for case in cases:
            try:
                report = run_case(backend, dll, output, transport, case, parent_sid)
            except Exception as error:
                report = {"schema": SCHEMA, "transport": transport, "case": case,
                          "validated": False, "error": type(error).__name__}
            results.append(report)
            (output / f"{transport}-{case}.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"transport": transport, "case": case,
                              "validated": report["validated"],
                              "target_origin_requests": report.get("target_origin_requests"),
                              "error": report.get("error"), "errors": report.get("errors")}), flush=True)
    summary = {"schema": SCHEMA, "backend_sha256": BACKEND_SHA256,
               "build": build, "synthetic_only": True,
               "production_desktop_coverage_validated": False,
               "results": results, "validated": all(row["validated"] for row in results)}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if summary["validated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
