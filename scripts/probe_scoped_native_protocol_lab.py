"""Disposable app-server trials of scoped or global Native pipe inspection.

The exact nonretry lease DLL is loaded only into this script's child process.
Its model provider points to a non-forwarding loopback HTTP origin. By default
an unmatched UUID bypasses content inspection; --global-enforce instead sends
each model request through the full collection and archive path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from queue import Queue
import subprocess
import sys
import tempfile
import threading
from uuid import UUID, uuid4

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))

import probe_desktop_backend_lab as lab
from build_guard_graceful_current_lab import _default_backend
from desktop_demo import (
    _ControllerLease, DEFAULT_NONRETRY_DLL, NONRETRY_DLL_SHA256,
)
from probe_desktop_capture_current_lab import (
    BACKEND_SHA256, BACKEND_VERSION, configure_provider,
)
from probe_desktop_guard_failstop_current_lab import (
    child_identity, counted_local_origin, origin_rows, sha256,
)
from probe_desktop_guard_graceful_current_lab import (
    _completed_for, _message_reader, _thread_id, _turn_id, _wait_for,
)
from transpect_trace.guard.desktop import _cim_process
from transpect_trace.guard.native import inject, wait_ready
from transpect_trace.guard.pipe import PipeServer, _wire_thread_ids
from transpect_trace.protect.codex_hook_gate import GateConfig
from transpect_trace.protect.native_collection import NativeCollectionEngine


SCHEMA = "transpect.scoped-native-protocol-lab/1.0"


def _reply_for(observed: list[dict], lock: threading.Lock,
               request_id: int) -> dict | None:
    with lock:
        return next((row for row in observed if row.get("id") == request_id), None)


def _benign_padding(size: int) -> str:
    # The DLP decoder rejects a single base64-looking token above 262,144
    # characters. Keep the synthetic filler inspectable at the same body size.
    chunk = "x" * 200_000 + " "
    return chunk * (size // len(chunk)) + "x" * (size % len(chunk))


def run(backend: Path, dll: Path, output: Path, scope: str,
        *, prompt_padding_bytes: int = 0,
        concurrent_threads: int = 1,
        global_enforce: bool = False,
        concurrent_safe_engine: bool = False,
        expected_dll_sha256: str = NONRETRY_DLL_SHA256,
        expect_diagnostic_outcomes: bool = False) -> dict:
    backend, dll = backend.resolve(strict=True), dll.resolve(strict=True)
    scope = None if global_enforce else str(UUID(scope))
    if not 0 <= prompt_padding_bytes <= 2_000_000:
        raise ValueError("prompt padding must be between 0 and 2,000,000 bytes")
    if concurrent_threads not in (1, 2):
        raise ValueError("concurrent threads must be one or two")
    if concurrent_safe_engine and not global_enforce:
        raise ValueError("concurrent-safe engine is only used in global enforcement lab")
    if sha256(backend) != BACKEND_SHA256 or sha256(dll) != expected_dll_sha256:
        raise ValueError("backend or DLL differs from exact frozen lab binary")
    version = subprocess.run([str(backend), "--version"], capture_output=True,
                             text=True, timeout=10, check=True).stdout.strip()
    if version != BACKEND_VERSION:
        raise ValueError("backend version differs from the pinned lab build")
    parent_sid = _cim_process(os.getpid()).get("UserSid")
    if not isinstance(parent_sid, str) or not parent_sid.startswith("S-"):
        raise ValueError("cannot establish lab controller SID")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    observed: list[dict] = []
    observed_lock = threading.Lock()
    messages: Queue = Queue()
    taps: list[dict] = []
    outcomes: list[dict] = []
    taps_lock = threading.Lock()
    errors: list[str] = []
    ready = disabled_ack = False
    identity = None
    thread_cases: list[dict] = []
    process = None
    pipe = None
    lease = None
    origin = []
    hooks_file_present = None
    marker_prefix = f"TTRACE_SCOPED_PROTOCOL_{uuid4().hex}_".encode("ascii")
    markers = [marker_prefix + str(index).encode("ascii")
               for index in range(concurrent_threads)]
    with tempfile.TemporaryDirectory(prefix="ttrace-scoped-protocol-",
                                     ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        home, work = root / "home", root / "work"
        work.mkdir()
        with counted_local_origin("http", root, b"NEVER_MATCH_THIS_MARKER") as sink:
            sink.success_for_allowed = True
            if concurrent_threads == 2:
                sink.success_delay_seconds = 0.8
            model = configure_provider(home, sink.server_port, "http")
            env = lab.isolated_env(home)
            process = subprocess.Popen([str(backend), "app-server"], cwd=work,
                                       env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       text=True, encoding="utf-8", bufsize=1,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            reader = threading.Thread(target=_message_reader,
                                      args=(process.stdout, messages, observed,
                                            observed_lock), daemon=True)
            reader.start()
            config = GateConfig(mode="enforce", archive_directory=output / "archive",
                                audit_file=output / "audit.jsonl",
                                registration_directory=None,
                                review_override_ttl_seconds=0,
                                collection_file=output / "collection.jsonl")
            engine = NativeCollectionEngine(config, archive_full_body=True,
                                            shared_request_archive=True)
            engine.concurrent_safe = concurrent_safe_engine

            def tap(request):
                if request.kind == "model.request":
                    raw = request.payload_utf8.encode("utf-8")
                    with taps_lock:
                        taps.append({"request_id": request.request_id,
                                     "protocol": request.protocol,
                                     "thread_ids": sorted(_wire_thread_ids(
                                         request.payload_utf8)),
                                     "bytes": len(raw),
                                     "sha256": hashlib.sha256(raw).hexdigest(),
                                     "marker_indices": [index for index, marker
                                                        in enumerate(markers)
                                                        if marker in raw],
                                     "marker_present": marker_prefix in raw})
                elif request.kind == "native.outcome":
                    with taps_lock:
                        outcomes.append({"request_id": request.outcome_for_request_id,
                                         "action": request.outcome_action,
                                         "stage": request.diagnostic_stage})

            pipe = PipeServer(process.pid, engine, output / "pipe-audit.jsonl",
                              request_tap=tap, client_sid=parent_sid,
                              target_thread_id=scope)
            try:
                lab._request(process, 1, "initialize", {"clientInfo": {
                    "name": "transpect_scoped_protocol_lab",
                    "title": "Transpect scoped protocol lab", "version": "0.1.0"}})
                if "error" in lab._await_id(messages, 1, 15):
                    raise RuntimeError("app-server initialize failed")
                process.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
                process.stdin.flush()
                identity = child_identity(process.pid, backend, parent_sid)
                lease = _ControllerLease(process.pid, identity["creation_filetime"])
                pipe.start()
                inject(process.pid, dll, identity,
                       identity_resolver=lambda pid: child_identity(
                           pid, backend, parent_sid, identity["creation_filetime"]))
                ready = wait_ready(identity, timeout=15) and pipe.ready.wait(3)
                if not ready:
                    raise RuntimeError("Native guard did not signal ready")
                for index in range(concurrent_threads):
                    request_id = 2 + index
                    lab._request(process, request_id, "thread/start", {
                        "model": model, "cwd": str(work),
                        "approvalPolicy": "never", "sandbox": "read-only"})
                    reply = lab._await_id(messages, request_id, 15)
                    if "error" in reply:
                        raise RuntimeError(f"thread/start {index} failed")
                    thread_id = _thread_id(reply)
                    if thread_id == scope or any(
                            row["thread_id"] == thread_id for row in thread_cases):
                        raise RuntimeError("chat thread identity was not distinct")
                    thread_cases.append({"index": index, "thread_id": thread_id,
                                         "turn_id": None, "status": None})
                # Both turn/start frames are delivered in one flush. The
                # origin's bounded delay proves whether requests overlapped.
                turn_request_base = 2 + concurrent_threads
                frames = []
                padding = (_benign_padding(prompt_padding_bytes)
                           if global_enforce else "x" * prompt_padding_bytes)
                for case in thread_cases:
                    index = case["index"]
                    frames.append({"method": "turn/start",
                                   "id": turn_request_base + index,
                                   "params": {"threadId": case["thread_id"],
                                       "input": [{"type": "text", "text":
                                           markers[index].decode() + " hello"
                                           + padding}],
                                       "cwd": str(work)}})
                process.stdin.write("".join(json.dumps(frame, ensure_ascii=False)
                                            + "\n" for frame in frames))
                process.stdin.flush()
                for case in thread_cases:
                    request_id = turn_request_base + case["index"]
                    if not _wait_for(lambda: _reply_for(observed, observed_lock,
                                                        request_id) is not None,
                                     15, process):
                        raise RuntimeError(f"turn/start {case['index']} timed out")
                    reply = _reply_for(observed, observed_lock, request_id)
                    if "error" in reply:
                        raise RuntimeError(f"turn/start {case['index']} failed")
                    case["turn_id"] = _turn_id(reply)
                if not _wait_for(lambda: all(_completed_for(
                        observed, observed_lock, case["turn_id"]) is not None
                        for case in thread_cases), 30, process):
                    raise RuntimeError("concurrent turns did not finish within 30 seconds")
                for case in thread_cases:
                    completed = _completed_for(observed, observed_lock,
                                               case["turn_id"])
                    case["status"] = completed.get("status") if completed else None
                    case["error"] = completed.get("error") if completed else None
                if expect_diagnostic_outcomes:
                    _wait_for(lambda: len(outcomes) >= len(taps), 3, process)
            except Exception as error:
                errors.append(f"{type(error).__name__}:{str(error)[:200]}")
            finally:
                if lease is not None:
                    try:
                        lease.release()
                        disabled_ack = lease.wait_disabled(5000)
                    except Exception as error:
                        errors.append(f"lease_cleanup_{type(error).__name__}")
                    finally:
                        lease.close()
                if pipe is not None:
                    pipe.close()
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                reader.join(timeout=2)
                origin = origin_rows(sink, "http")
                hooks_file_present = (home / "hooks.json").exists()
    with taps_lock:
        tap_rows = list(taps)
        outcome_rows = list(outcomes)
    validation = pipe.validation_snapshot() if pipe else {"count": 0, "recent": []}
    matches = {(row.get("bytes"), row.get("sha256")) for row in origin
               if row.get("complete") is True and row.get("target") is False}
    for case in thread_cases:
        linked = [row for row in tap_rows
                  if case["thread_id"] in row["thread_ids"]
                  and row["marker_indices"] == [case["index"]]]
        case["tap_request_ids"] = [row["request_id"] for row in linked]
        case["origin_sha_match"] = any(
            (row["bytes"], row["sha256"]) in matches for row in linked)
    allowed_origin_match = bool(thread_cases) and all(
        case["origin_sha_match"] for case in thread_cases)
    complete_origin = [row for row in origin
                       if row.get("complete") is True and row.get("target") is False
                       and isinstance(row.get("reply_sent_perf_ns"), int)]
    origin_overlap_verified = (concurrent_threads == 2
        and len({row["sha256"] for row in complete_origin}) >= 2
        and min(row["reply_sent_perf_ns"] for row in complete_origin)
            >= max(row["body_complete_perf_ns"] for row in complete_origin))
    scope_counts = pipe.scope_snapshot() if pipe else {}
    delivery = pipe.decision_delivery_snapshot() if pipe else []
    collection_file = output / "collection.jsonl"
    collection_rows = ([json.loads(line) for line in
                        collection_file.read_text(encoding="utf-8").splitlines()]
                       if collection_file.exists() else [])
    tap_by_id = {row["request_id"]: row for row in tap_rows}
    archive_readback = []
    if global_enforce:
        for record in pipe.records if pipe else []:
            if record.get("category") != "request_envelope":
                continue
            request_id = record.get("request_id")
            tap_row = tap_by_id.get(request_id)
            try:
                receipt, recovered = engine.gate._archive.read(
                    record["archive_record_id"])
                recovered_sha = hashlib.sha256(recovered).hexdigest()
                exact = bool(tap_row and receipt.kind == "model_request"
                             and len(recovered) == tap_row["bytes"]
                             and recovered_sha == tap_row["sha256"]
                             and record.get("request_sha256") == recovered_sha)
                archive_readback.append({"request_id": request_id,
                                         "bytes": len(recovered),
                                         "sha256": recovered_sha,
                                         "exact": exact,
                                         "decision": record.get("decision"),
                                         "reason": record.get("reason")})
            except Exception as error:
                archive_readback.append({"request_id": request_id,
                                         "exact": False,
                                         "error": type(error).__name__})
    validated = (not errors and ready and disabled_ack
                 and len(thread_cases) == concurrent_threads
                 and all(case["status"] == "completed" for case in thread_cases)
                 and validation["count"] == 0 and not pipe.errors
                 and (global_enforce or
                      (scope_counts.get("bypassed", 0) >= concurrent_threads
                       and scope_counts.get("target") == 0
                       and scope_counts.get("unidentified_scope_bypass") == 0))
                 and allowed_origin_match and hooks_file_present is False)
    if global_enforce:
        envelope_ids = {row["request_id"] for row in archive_readback
                        if row["exact"] is True and row["decision"] == "allow"}
        inspected_ids = {row.get("request_id") for row in collection_rows
                         if row.get("inspected") is True}
        validated = (validated and concurrent_safe_engine
                     and len(archive_readback) == len(tap_rows)
                     and envelope_ids == set(tap_by_id)
                     and all(any(request_id in inspected_ids
                                 for request_id in case["tap_request_ids"])
                             for case in thread_cases)
                     and scope_counts == {"target": 0, "bypassed": 0,
                                          "unidentified_scope_bypass": 0}
                     and len(delivery) == len(tap_rows)
                     and all(row["server_reply_write_complete"] is True
                             and row["server_flush_complete"] is True
                             and isinstance(row["age_at_reply_write_ms"], (int, float))
                             and row["age_at_reply_write_ms"] < 2000
                             for row in delivery))
    if concurrent_threads == 2:
        validated = validated and origin_overlap_verified
    if expect_diagnostic_outcomes:
        delivery_by_id = {row["request_id"]: row for row in delivery}
        validated = (validated and len(outcome_rows) == len(tap_rows)
                     and {row["request_id"] for row in outcome_rows}
                     == {row["request_id"] for row in tap_rows}
                     and all(row["action"] == "none" and row["stage"] == "parsed_allow"
                             for row in outcome_rows)
                     and all((row := delivery_by_id.get(tap["request_id"])) is not None
                             and row["server_reply_write_complete"] is True
                             and row["server_flush_complete"] is True
                             and row["native_acceptance_attested"] is True
                             and row["native_diagnostic_stage"] == "parsed_allow"
                             and isinstance(row["age_at_reply_write_ms"], (int, float))
                             and row["age_at_reply_write_ms"] < 2000
                             for tap in tap_rows))
    for case in thread_cases:
        linked_ids = set(case["tap_request_ids"])
        case["decision_delivery"] = [row for row in delivery
                                     if row["request_id"] in linked_ids]
    report = {"schema": SCHEMA, "synthetic_only": True, "local_origin_only": True,
              "production_desktop_coverage_validated": False,
              "backend_sha256": BACKEND_SHA256, "dll_sha256": expected_dll_sha256,
              "child_pid": process.pid, "child_creation_filetime":
                  identity["creation_filetime"] if identity else None,
              "scope": scope,
              "global_enforce": global_enforce,
              "concurrent_safe_engine": concurrent_safe_engine,
              "collection_mode": "shared_request_archive",
              "collection_records": len(collection_rows),
              "inspected_collection_records": sum(
                  row.get("inspected") is True for row in collection_rows),
              "archive_readback": archive_readback,
              "all_request_archive_readback_exact": bool(archive_readback) and all(
                  row["exact"] is True for row in archive_readback),
              "actual_thread_id": thread_cases[0]["thread_id"] if thread_cases else None,
              "actual_thread_ids": [case["thread_id"] for case in thread_cases],
              "concurrent_threads": concurrent_threads,
              "thread_cases": thread_cases,
              "prompt_padding_bytes": prompt_padding_bytes,
              "native_ready": ready, "disabled_ack": disabled_ack,
              "turn_status": thread_cases[0]["status"] if thread_cases else None,
              "tap_rows": tap_rows, "scope_counts": scope_counts,
              "diagnostic_outcomes": outcome_rows,
              "decision_delivery": delivery,
              "validation": validation, "pipe_errors": list(pipe.errors),
              "allowed_origin_match": allowed_origin_match,
              "origin_overlap_verified": origin_overlap_verified,
              "origin_metadata": [{key: row.get(key) for key in (
                  "bytes", "sha256", "complete", "body_complete_perf_ns",
                  "reply_sent_perf_ns")} for row in origin],
              "origin_requests": len(origin),
              "codex_command_hooks_present": hooks_file_present,
              "errors": errors,
              "validated": validated}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                        encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, default=_default_backend())
    parser.add_argument("--dll", type=Path, default=DEFAULT_NONRETRY_DLL)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scope", default="00000000-0000-4000-8000-000000000001")
    parser.add_argument("--prompt-padding-bytes", type=int, default=0)
    parser.add_argument("--concurrent-threads", type=int, choices=(1, 2), default=1)
    parser.add_argument("--global-enforce", action="store_true",
                        help="Inspect every model request in this disposable backend")
    parser.add_argument("--concurrent-safe-engine", action="store_true",
                        help="Opt into the desktop nonretry engine's parallel policy path")
    parser.add_argument("--diagnostic-manifest", type=Path,
                        help="Exact lab-only build manifest for a diagnostic DLL")
    args = parser.parse_args()
    expected_sha = NONRETRY_DLL_SHA256
    diagnostic = False
    if args.diagnostic_manifest:
        from build_guard_nonretry_diagnostic_lab import SCHEMA as DIAGNOSTIC_SCHEMA
        manifest = json.loads(args.diagnostic_manifest.read_text(encoding="utf-8"))
        if (manifest.get("schema") != DIAGNOSTIC_SCHEMA
                or manifest.get("lab_only") is not True
                or manifest.get("desktop_demo_admitted") is not False
                or Path(manifest.get("diagnostic_dll", "")).resolve() != args.dll.resolve()
                or manifest.get("backend_sha256") != BACKEND_SHA256):
            raise SystemExit("diagnostic manifest is not a pinned lab artifact")
        expected_sha = manifest["diagnostic_dll_sha256"]
        diagnostic = True
    report = run(args.backend, args.dll, args.output, args.scope,
                 prompt_padding_bytes=args.prompt_padding_bytes,
                 concurrent_threads=args.concurrent_threads,
                 global_enforce=args.global_enforce,
                 concurrent_safe_engine=args.concurrent_safe_engine,
                 expected_dll_sha256=expected_sha,
                 expect_diagnostic_outcomes=diagnostic)
    print(json.dumps({key: report[key] for key in (
        "validated", "native_ready", "turn_status", "scope_counts",
        "validation", "pipe_errors", "allowed_origin_match", "errors")}, indent=2))
    return 0 if report["validated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
