"""Prove graceful denial in one disposable 0.167 app-server process per route.

Each case denies a synthetic request, starts a clean second thread in the same
process, and requires the second request to reach a non-forwarding local origin.
This never attaches to the live desktop backend or creates a desktop adapter.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import inspect
import json
import os
from pathlib import Path
from queue import Empty, Queue
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))

import probe_desktop_backend_lab as lab
from desktop_demo import _ControllerLease
from probe_desktop_capture_current_lab import (
    BACKEND_SHA256, BACKEND_VERSION, configure_provider, trace_inventory,
)
from probe_desktop_guard_failstop_current_lab import (
    FAKE_KEY, FAKE_KEY_BYTES, child_identity, counted_local_origin, origin_rows,
    sha256,
)
from transpect_trace.guard.desktop import _cim_process
from transpect_trace.guard.native import inject, wait_ready
from transpect_trace.guard.pipe import PipeServer
from transpect_trace.protect.codex_hook_gate import GateConfig
from transpect_trace.protect.native_collection import NativeCollectionEngine


SCHEMA = "transpect.desktop-guard-graceful-current-lab/1.0"
BUILD_SCHEMA = "transpect.guard.graceful-current-lab-build/1.0"
DEFAULT_DLL = ROOT / "build/guard-graceful-current-lab/ttrace-guard-graceful-current-lab.dll"
LEASE_SCHEMA = "transpect.desktop-guard-graceful-lease-content-lab/1.0"
LEASE_BUILD_SCHEMA = "transpect.guard.graceful-lease-current-lab-build/1.0"
DEFAULT_LEASE_DLL = (ROOT / "build/guard-graceful-lease-current-lab"
                     / "ttrace-guard-graceful-lease-current-lab.dll")
CONTROLLER_SOURCES = (
    "src/transpect_trace/protect/content_dlp.py",
    "src/transpect_trace/protect/native_collection.py",
    "src/transpect_trace/protect/collection_eval.py",
)


def controller_source_hashes() -> dict[str, str]:
    return {name: sha256(ROOT / name) for name in CONTROLLER_SOURCES}


def check_build(dll: Path, backend: Path, *, lease_mode: bool = False) -> dict:
    manifest = json.loads((dll.parent / "build-manifest.json").read_text(encoding="utf-8"))
    if (manifest.get("schema") != (LEASE_BUILD_SCHEMA if lease_mode else BUILD_SCHEMA)
            or manifest.get("lab_only") is not True
            or manifest.get("deny_behavior") != "return_rust_error_candidate"
            or (lease_mode and manifest.get("controller_loss_behavior")
                != "bypass_and_disable_hooks")
            or manifest.get("backend", {}).get("sha256") != BACKEND_SHA256
            or manifest.get("backend", {}).get("version") != BACKEND_VERSION
            or manifest.get("backend", {}).get("path") != str(backend)
            or manifest.get("artifact", {}).get("sha256") != sha256(dll)):
        raise ValueError("DLL is not the pinned graceful lab candidate")
    if set(manifest.get("capture_evidence", {})) != {"http", "wss"}:
        raise ValueError("graceful build has incomplete capture preflight")
    return {"sha256": sha256(dll),
            "manifest_sha256": sha256(dll.parent / "build-manifest.json"),
            "lab_only": True, "deny_behavior": manifest["deny_behavior"],
            "lease_mode": lease_mode}


def _message_reader(stream, messages: Queue, observed: list[dict], lock: threading.Lock) -> None:
    for line in stream:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        with lock:
            observed.append(row)
        messages.put(row)


def _wait_for(predicate, seconds: float, process: subprocess.Popen) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        if process.poll() is not None:
            return False
        time.sleep(0.05)
    return predicate()


def _completed_for(observed: list[dict], lock: threading.Lock, turn_id: str) -> dict | None:
    with lock:
        for row in observed:
            if row.get("method") == "turn/completed":
                params = row.get("params", {})
                turn = params.get("turn", {}) if isinstance(params, dict) else {}
                if isinstance(turn, dict) and turn.get("id") == turn_id:
                    error = turn.get("error")
                    return {"status": turn.get("status"),
                            "error": {"message": str(error.get("message", ""))[:300],
                                      "codexErrorInfo": error.get("codexErrorInfo")}
                            if isinstance(error, dict) else None}
    return None


def _turn_id(reply: dict) -> str:
    value = reply.get("result", {}).get("turn", {}).get("id")
    if not isinstance(value, str) or not value:
        raise ValueError("turn/start did not return a turn id")
    return value


def _thread_id(reply: dict) -> str:
    value = reply.get("result", {}).get("thread", {}).get("id")
    if not isinstance(value, str) or not value:
        raise ValueError("thread/start did not return a thread id")
    return value


def run_case(backend: Path, dll: Path, output: Path, transport: str,
             parent_sid: str, *, large_multi_item: bool = False,
             lease_mode: bool = False) -> dict:
    case_dir = output / transport
    case_dir.mkdir(parents=True, exist_ok=False)
    denied_marker = f"TTRACE_GRACEFUL_DENY_{uuid4().hex}".encode("ascii")
    allowed_marker = f"TTRACE_GRACEFUL_ALLOW_{uuid4().hex}".encode("ascii")
    denied_prompt = f"{denied_marker.decode()} deploy with {FAKE_KEY}"
    allowed_prompt = f"{allowed_marker.decode()} hello"
    denied_input = [{"type": "text", "text": denied_prompt}]
    if large_multi_item:
        # One turn with hundreds of benign content parts approximates the
        # desktop incident's 546-item, ~950 KiB serialized request without
        # importing any real user history or contents into the lab.
        for index in range(535):
            prefix = f"Synthetic context part {index:03d}: "
            repeated = ("Harmless sample context for a local test. " * 50)
            denied_input.append({"type": "text",
                                 "text": prefix + repeated[:1667 - len(prefix)]})
    taps: list[dict] = []
    taps_lock = threading.Lock()
    observed: list[dict] = []
    observed_lock = threading.Lock()
    messages: Queue = Queue()
    errors: list[str] = []
    denied_completion = allowed_completion = None
    deny_origin_snapshot: list[dict] = []
    post_deny_alive = post_deny_identity_stable = False
    backend_alive_after_followup = False
    followup_origin_match = False
    same_pid = False
    repeat_denied_completion = repeat_followup_completion = None
    repeat_deny_body_bytes_delta = None
    repeat_followup_origin_match = False
    backend_alive_after_repeat = False
    repeat_same_pid = False
    identity = None
    process = None
    pipe = None
    lease = None
    lease_released = lease_disabled_ack = False
    lease_cleanup_error = None
    trace = None
    with tempfile.TemporaryDirectory(prefix="ttrace-graceful-current-",
                                     ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        home, work, trace = root / "home", root / "work", root / "trace"
        work.mkdir()
        with counted_local_origin(transport, root, denied_marker) as sink:
            model = configure_provider(home, sink.server_port, transport)
            env = lab.isolated_env(home)
            env["CODEX_ROLLOUT_TRACE_ROOT"] = str(trace)
            if transport == "wss":
                env.update(CODEX_CA_CERTIFICATE=str(sink.ca),
                           NO_PROXY="localhost,127.0.0.1",
                           HTTP_PROXY="http://127.0.0.1:9",
                           HTTPS_PROXY="http://127.0.0.1:9",
                           ALL_PROXY="http://127.0.0.1:9")
            process = subprocess.Popen([str(backend), "app-server"], cwd=work,
                                       env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       text=True, encoding="utf-8", bufsize=1)
            reader = threading.Thread(target=_message_reader,
                                      args=(process.stdout, messages, observed,
                                            observed_lock), daemon=True)
            reader.start()
            config = GateConfig(mode="enforce", archive_directory=case_dir / "archive",
                                audit_file=case_dir / "audit.jsonl",
                                registration_directory=None,
                                review_override_ttl_seconds=0,
                                collection_file=case_dir / "collection.jsonl")
            engine = NativeCollectionEngine(config, archive_full_body=True,
                                            shared_request_archive=True)

            def tap(request) -> None:
                if request.kind != "model.request":
                    return
                raw = request.payload_utf8.encode("utf-8")
                with taps_lock:
                    taps.append({"request_id": request.request_id,
                                 "protocol": request.protocol,
                                 "bytes": len(raw),
                                 "sha256": hashlib.sha256(raw).hexdigest(),
                                 "denied_marker": denied_marker in raw,
                                 "allowed_marker": allowed_marker in raw,
                                 "fake_key": FAKE_KEY_BYTES in raw})

            pipe = PipeServer(process.pid, engine, case_dir / "pipe-audit.jsonl",
                              request_tap=tap, client_sid=parent_sid)
            try:
                lab._request(process, 1, "initialize", {"clientInfo": {
                    "name": "transpect_graceful_lab", "title": "Transpect graceful lab",
                    "version": "0.1.0"}})
                if "error" in lab._await_id(messages, 1, 15):
                    raise RuntimeError("app-server initialize failed")
                process.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
                process.stdin.flush()
                identity = child_identity(process.pid, backend, parent_sid)
                pipe.start()
                if lease_mode:
                    lease = _ControllerLease(process.pid,
                                             identity["creation_filetime"])
                inject(process.pid, dll, identity,
                       identity_resolver=lambda pid: child_identity(
                           pid, backend, parent_sid, identity["creation_filetime"]))
                if not wait_ready(identity, timeout=15) or not pipe.ready.wait(3):
                    raise RuntimeError("graceful native hook was not ready")
                child_identity(process.pid, backend, parent_sid,
                               identity["creation_filetime"])

                lab._request(process, 2, "thread/start", {"model": model,
                    "cwd": str(work), "approvalPolicy": "never", "sandbox": "read-only"})
                reply = lab._await_id(messages, 2, 15)
                if "error" in reply:
                    raise RuntimeError("first thread/start failed")
                thread_id = _thread_id(reply)
                if transport == "wss":
                    _wait_for(lambda: any(row.get("complete") is True
                                          and row.get("target") is False
                                          for row in origin_rows(sink, transport)),
                              10, process)
                lab._request(process, 3, "turn/start", {"threadId": thread_id,
                    "input": denied_input, "cwd": str(work)})
                reply = lab._await_id(messages, 3, 15)
                if "error" in reply:
                    raise RuntimeError("denied turn/start failed")
                denied_turn_id = _turn_id(reply)
                if not _wait_for(lambda: _completed_for(
                        observed, observed_lock, denied_turn_id) is not None, 25, process):
                    raise RuntimeError("denied turn did not complete")
                denied_completion = _completed_for(observed, observed_lock, denied_turn_id)
                _wait_for(lambda: any(row["denied_marker"] for row in taps), 3, process)
                if large_multi_item:
                    _wait_for(lambda: any(row.get("route_event") == "model.request"
                                          and row.get("request_id") in
                                          {tap["request_id"] for tap in taps
                                           if tap["denied_marker"]}
                                          for row in pipe.records), 20, process)
                deny_origin_snapshot = origin_rows(sink, transport)
                post_deny_alive = process.poll() is None
                if post_deny_alive:
                    child_identity(process.pid, backend, parent_sid,
                                   identity["creation_filetime"])
                    post_deny_identity_stable = True

                # A new thread avoids replaying the denied secret from the first
                # thread's conversation history in the allowed follow-up request.
                lab._request(process, 4, "thread/start", {"model": model,
                    "cwd": str(work), "approvalPolicy": "never", "sandbox": "read-only"})
                reply = lab._await_id(messages, 4, 15)
                if "error" in reply:
                    raise RuntimeError("follow-up thread/start failed")
                followup_thread_id = _thread_id(reply)
                same_pid = process.pid == identity["pid"]
                lab._request(process, 5, "turn/start", {"threadId": followup_thread_id,
                    "input": [{"type": "text", "text": allowed_prompt}], "cwd": str(work)})
                reply = lab._await_id(messages, 5, 15)
                if "error" in reply:
                    raise RuntimeError("follow-up turn/start failed")
                allowed_turn_id = _turn_id(reply)

                def followup_arrived() -> bool:
                    with taps_lock:
                        allowed = [row for row in taps if row["allowed_marker"]
                                   and not row["fake_key"]]
                    received = {(row.get("bytes"), row.get("sha256"))
                                for row in origin_rows(sink, transport)
                                if row.get("complete") is True}
                    return bool(allowed) and all(
                        (row["bytes"], row["sha256"]) in received for row in allowed)

                followup_origin_match = _wait_for(followup_arrived, 25, process)
                _wait_for(lambda: _completed_for(
                    observed, observed_lock, allowed_turn_id) is not None, 10, process)
                allowed_completion = _completed_for(observed, observed_lock,
                                                    allowed_turn_id)
                backend_alive_after_followup = process.poll() is None
                if backend_alive_after_followup:
                    child_identity(process.pid, backend, parent_sid,
                                   identity["creation_filetime"])

                # Repeat the deny/allow pair in the same process. Each turn
                # starts a fresh thread so its history cannot carry the fake
                # secret into the next allowed request.
                first_denied_count = sum(row["denied_marker"] for row in taps)
                first_allowed_count = sum(row["allowed_marker"] for row in taps)
                lab._request(process, 6, "thread/start", {"model": model,
                    "cwd": str(work), "approvalPolicy": "never", "sandbox": "read-only"})
                reply = lab._await_id(messages, 6, 15)
                if "error" in reply:
                    raise RuntimeError("repeat denied thread/start failed")
                repeat_thread_id = _thread_id(reply)
                if transport == "wss":
                    warmups_before = sum(row.get("complete") is True
                                         for row in origin_rows(sink, transport))
                    _wait_for(lambda: sum(row.get("complete") is True
                                          for row in origin_rows(sink, transport))
                              > warmups_before, 5, process)
                before_repeat_deny = origin_rows(sink, transport)

                def body_total(rows: list[dict]) -> int:
                    key = ("http_body_bytes_received" if transport == "http"
                           else "wss_wire_body_bytes_received")
                    return sum(row.get(key, 0) for row in rows)

                lab._request(process, 7, "turn/start", {"threadId": repeat_thread_id,
                    "input": denied_input, "cwd": str(work)})
                reply = lab._await_id(messages, 7, 15)
                if "error" in reply:
                    raise RuntimeError("repeat denied turn/start failed")
                repeat_denied_turn_id = _turn_id(reply)
                if not _wait_for(lambda: _completed_for(
                        observed, observed_lock, repeat_denied_turn_id) is not None,
                        25, process):
                    raise RuntimeError("repeat denied turn did not complete")
                repeat_denied_completion = _completed_for(
                    observed, observed_lock, repeat_denied_turn_id)
                _wait_for(lambda: sum(row["denied_marker"] for row in taps)
                          > first_denied_count, 3, process)
                after_repeat_deny = origin_rows(sink, transport)
                repeat_deny_body_bytes_delta = (
                    body_total(after_repeat_deny) - body_total(before_repeat_deny))
                repeat_same_pid = process.poll() is None and process.pid == identity["pid"]
                if repeat_same_pid:
                    child_identity(process.pid, backend, parent_sid,
                                   identity["creation_filetime"])

                lab._request(process, 8, "thread/start", {"model": model,
                    "cwd": str(work), "approvalPolicy": "never", "sandbox": "read-only"})
                reply = lab._await_id(messages, 8, 15)
                if "error" in reply:
                    raise RuntimeError("repeat allowed thread/start failed")
                repeat_allowed_thread_id = _thread_id(reply)
                lab._request(process, 9, "turn/start", {
                    "threadId": repeat_allowed_thread_id,
                    "input": [{"type": "text", "text": allowed_prompt}],
                    "cwd": str(work)})
                reply = lab._await_id(messages, 9, 15)
                if "error" in reply:
                    raise RuntimeError("repeat allowed turn/start failed")
                repeat_allowed_turn_id = _turn_id(reply)
                repeat_followup_origin_match = _wait_for(
                    lambda: sum(row["allowed_marker"] for row in taps)
                    > first_allowed_count and followup_arrived(), 25, process)
                _wait_for(lambda: _completed_for(
                    observed, observed_lock, repeat_allowed_turn_id) is not None,
                    10, process)
                repeat_followup_completion = _completed_for(
                    observed, observed_lock, repeat_allowed_turn_id)
                backend_alive_after_repeat = process.poll() is None
                if backend_alive_after_repeat:
                    child_identity(process.pid, backend, parent_sid,
                                   identity["creation_filetime"])
            except Exception as error:
                errors.append(f"{type(error).__name__}:{str(error)[:200]}")
            finally:
                if lease is not None:
                    try:
                        lease.release()
                        lease_released = True
                        lease_disabled_ack = lease.wait_disabled(5000)
                        if not lease_disabled_ack:
                            errors.append("lease_disable_not_attested")
                    except Exception as error:
                        lease_cleanup_error = f"{type(error).__name__}:{str(error)[:200]}"
                        errors.append(lease_cleanup_error)
                    finally:
                        lease.close()
                    pipe.close()
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                reader.join(timeout=2)
                pipe.close()
        origin = origin_rows(sink, transport)
        traces = trace_inventory(trace, denied_marker)
        hooks_file_present = (home / "hooks.json").exists()

    with taps_lock:
        requests = list(taps)
    decisions = {row.get("request_id"): row for row in pipe.records
                 if row.get("route_event") == "model.request"}
    archive_by_body: dict[tuple[int, str], str] = {}
    for row in requests:
        decision = decisions.get(row["request_id"], {})
        row["decision"] = decision.get("decision")
        row["action"] = decision.get("action")
        record_id = decision.get("archive_record_id")
        body_key = (row["bytes"], row["sha256"])
        if isinstance(record_id, str) and record_id:
            try:
                receipt, restored = engine.gate._archive.read(record_id)
                row["archive_readback_exact"] = (
                    receipt.body_bytes == row["bytes"]
                    and receipt.body_sha256 == row["sha256"]
                    and hashlib.sha256(restored).hexdigest() == row["sha256"])
            except Exception:
                row["archive_readback_exact"] = False
            if row["archive_readback_exact"]:
                archive_by_body[body_key] = record_id
        else:
            # An identical HTTP preparation can reuse the first receipt.
            row["archive_readback_exact"] = body_key in archive_by_body
    denied = [row for row in requests if row["denied_marker"]]
    allowed = [row for row in requests if row["allowed_marker"]]
    collection_rows = [json.loads(line) for line in
                       (case_dir / "collection.jsonl").read_text(encoding="utf-8").splitlines()
                       if line.strip()]
    model_rows = [row for row in collection_rows
                  if row.get("route_event") == "model.request"]
    by_request: dict[str, list[dict]] = {}
    for row in model_rows:
        by_request.setdefault(row.get("request_id"), []).append(row)
    shared_archive_layout_verified = bool(requests)
    for request in requests:
        rows = by_request.get(request["request_id"], [])
        envelopes = [row for row in rows
                     if row.get("category") == "request_envelope"]
        if len(envelopes) != 1:
            shared_archive_layout_verified = False
            continue
        record_id = envelopes[0].get("archive_record_id")
        if (not isinstance(record_id, str) or not record_id
                or any(row.get("archive_record_id") != record_id
                       or row.get("archive_kind") != "model_request"
                       or row.get("extra", {}).get("shared_request_archive") is not True
                       for row in rows if row.get("category") != "request_envelope")):
            shared_archive_layout_verified = False
    target_trace = [row.get("compact_json") for row in traces
                    if row.get("marker_in_file")
                    and isinstance(row.get("compact_json"), dict)]
    # A denied WSS serialization may be followed by the app's HTTP fallback.
    # Each attempt has its own exact trace body; compare the full multiset.
    target_trace_exact = (bool(denied) and
                          Counter((row["bytes"], row["sha256"]) for row in denied)
                          == Counter((row.get("bytes"), row.get("sha256"))
                                     for row in target_trace))
    denied_origin = [row for row in origin if row.get("target") is True]
    denied_origin_snapshot_bytes = sum(row.get("http_body_bytes_received", 0)
                                       if transport == "http" else
                                       row.get("wss_wire_body_bytes_received", 0)
                                       for row in deny_origin_snapshot
                                       if row.get("target") is True)
    # The origin marks each complete request by searching for denied_marker.
    # It additionally records partial wire bytes; a rejected target must not
    # have produced any non-warmup HTTP/WSS request body before follow-up.
    if transport == "http":
        deny_non_warmup_body_bytes = sum(row.get("http_body_bytes_received", 0)
                                        for row in deny_origin_snapshot)
    else:
        warmup = next((row.get("connection") for row in deny_origin_snapshot
                       if row.get("complete") is True
                       and row.get("target") is False), None)
        deny_non_warmup_body_bytes = sum(
            row.get("wss_wire_body_bytes_received", 0)
            for row in deny_origin_snapshot if row.get("connection") != warmup)
    validated = (not errors and not pipe.errors and not hooks_file_present
                 and (not lease_mode or (lease_released and lease_disabled_ack))
                 and target_trace_exact and bool(denied)
                 and all(row["archive_readback_exact"] for row in requests)
                 and shared_archive_layout_verified
                 and all(row["decision"] == "deny" and row["action"] == "BLOCK"
                         for row in denied)
                 and not denied_origin and denied_origin_snapshot_bytes == 0
                 and deny_non_warmup_body_bytes == 0
                 and post_deny_alive and post_deny_identity_stable
                 and denied_completion is not None
                 and denied_completion.get("status") == "failed"
                 and same_pid
                 and bool(allowed)
                 and all(row["decision"] == "allow" for row in allowed)
                 and followup_origin_match
                 and backend_alive_after_followup
                 and repeat_denied_completion is not None
                 and repeat_denied_completion.get("status") == "failed"
                 and repeat_deny_body_bytes_delta == 0
                 and repeat_same_pid and repeat_followup_origin_match
                 and repeat_followup_completion is not None
                 and backend_alive_after_repeat)
    return {
        "schema": LEASE_SCHEMA if lease_mode else SCHEMA,
        "transport": transport, "backend_sha256": BACKEND_SHA256,
        "lease_mode": lease_mode, "lease_released": lease_released,
        "lease_disabled_ack": lease_disabled_ack,
        "lease_cleanup_error": lease_cleanup_error,
        "collection_mode": "shared_request_archive",
        "large_multi_item": large_multi_item,
        "denied_input_items": len(denied_input),
        "dll_sha256": sha256(dll), "synthetic_only": True,
        "local_origin_only": True, "codex_command_hooks_present": hooks_file_present,
        "identity": {"pid": process.pid,
                     "creation_filetime": identity["creation_filetime"] if identity else None,
                     "parent_pid": os.getpid(), "mode": "app-server",
                     "image_sha256": BACKEND_SHA256},
        "pipe_requests": requests, "target_trace": target_trace,
        "target_trace_exact": target_trace_exact,
        "all_request_archive_readback_exact": all(
            row["archive_readback_exact"] for row in requests),
        "shared_archive_layout_verified": shared_archive_layout_verified,
        "deny_origin_snapshot": deny_origin_snapshot,
        "deny_origin_requests": len([row for row in deny_origin_snapshot
                                     if row.get("target") is True]),
        "deny_origin_body_bytes": denied_origin_snapshot_bytes,
        "deny_non_warmup_wire_body_bytes_received": deny_non_warmup_body_bytes,
        "denied_origin_requests_after_followup": len(denied_origin),
        "denied_turn_completion": denied_completion,
        "post_deny_alive": post_deny_alive,
        "post_deny_identity_stable": post_deny_identity_stable,
        "same_pid_for_followup": same_pid,
        "followup_origin_match": followup_origin_match,
        "followup_turn_completion": allowed_completion,
        "backend_alive_after_followup": backend_alive_after_followup,
        "repeat_denied_turn_completion": repeat_denied_completion,
        "repeat_deny_body_bytes_delta": repeat_deny_body_bytes_delta,
        "repeat_same_pid": repeat_same_pid,
        "repeat_followup_origin_match": repeat_followup_origin_match,
        "repeat_followup_turn_completion": repeat_followup_completion,
        "backend_alive_after_repeat": backend_alive_after_repeat,
        "origin": origin, "pipe_errors": list(pipe.errors), "errors": errors,
        "validated": validated, "lab_only": True,
        "production_desktop_coverage_validated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--dll", type=Path)
    parser.add_argument("--lease-mode", action="store_true",
                        help="use test-only controller-owned lease DLL")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transports", default="http,wss")
    parser.add_argument("--large-multi-item", action="store_true",
                        help="send 536 synthetic input parts totaling roughly 950 KiB")
    args = parser.parse_args()
    backend = args.backend.resolve(strict=True)
    dll = (args.dll or (DEFAULT_LEASE_DLL if args.lease_mode else DEFAULT_DLL)).resolve(strict=True)
    if sha256(backend) != BACKEND_SHA256:
        raise SystemExit("backend does not match pinned 0.167 lab build")
    version = subprocess.run([str(backend), "--version"], capture_output=True,
                             text=True, timeout=10, check=True).stdout.strip()
    if version != BACKEND_VERSION:
        raise SystemExit("backend version differs from pinned 0.167 lab build")
    build = check_build(dll, backend, lease_mode=args.lease_mode)
    sources_before = controller_source_hashes()
    transports = args.transports.split(",")
    if (not transports or any(item not in {"http", "wss"} for item in transports)
            or len(set(transports)) != len(transports)):
        raise SystemExit("unknown or duplicate transport")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    parent_sid = _cim_process(os.getpid()).get("UserSid")
    if not isinstance(parent_sid, str) or not parent_sid.startswith("S-"):
        raise SystemExit("cannot establish lab controller SID")
    results = []
    for transport in transports:
        try:
            report = run_case(backend, dll, output, transport, parent_sid,
                              large_multi_item=args.large_multi_item,
                              lease_mode=args.lease_mode)
        except Exception as error:
            report = {"schema": LEASE_SCHEMA if args.lease_mode else SCHEMA,
                      "transport": transport,
                      "validated": False, "error": f"{type(error).__name__}:{error}"}
        results.append(report)
        (output / f"{transport}.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"transport": transport, "validated": report["validated"],
                          "deny_origin_body_bytes": report.get("deny_origin_body_bytes"),
                          "post_deny_alive": report.get("post_deny_alive"),
                          "followup_origin_match": report.get("followup_origin_match"),
                          "backend_alive_after_followup": report.get(
                              "backend_alive_after_followup"),
                          "error": report.get("error"), "errors": report.get("errors")}),
              flush=True)
    sources_after = controller_source_hashes()
    summary = {"schema": LEASE_SCHEMA if args.lease_mode else SCHEMA,
               "backend_sha256": BACKEND_SHA256,
               "build": build, "synthetic_only": True,
               "lease_mode": args.lease_mode,
               "controller_lease_class_sha256": hashlib.sha256(
                   inspect.getsource(_ControllerLease).encode("utf-8")).hexdigest()
                   if args.lease_mode else None,
               "collection_mode": "shared_request_archive",
               "controller_sources_sha256": sources_before,
               "controller_sources_unchanged_during_lab": sources_before == sources_after,
               "production_desktop_coverage_validated": False,
               "results": results,
               "validated": len(results) == len(transports)
               and sources_before == sources_after
               and all(row["validated"] for row in results)}
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if summary["validated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
