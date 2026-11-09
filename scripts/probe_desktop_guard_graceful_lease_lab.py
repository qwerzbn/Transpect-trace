"""Prove the graceful lease restores ordinary requests after controller loss.

Only disposable app-server children and non-forwarding local origins are used.
The installed desktop backend is never attached. The lease's owner thread is
released normally or exits without release, exercising Windows' abandoned
mutex path that a dead controller would take.
"""

from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import inspect
import json
import os
from pathlib import Path
from queue import Queue
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
    FAKE_KEY, child_identity, counted_local_origin, origin_rows, sha256,
)
from probe_desktop_guard_graceful_current_lab import (
    _completed_for, _message_reader, _thread_id, _turn_id, _wait_for,
    controller_source_hashes,
)
from transpect_trace.guard.desktop import _cim_process
from transpect_trace.guard.native import inject, wait_ready
from transpect_trace.guard.pipe import PipeServer
from transpect_trace.protect.codex_hook_gate import GateConfig
from transpect_trace.protect.native_collection import NativeCollectionEngine


SCHEMA = "transpect.desktop-guard-graceful-lease-current-lab/1.0"
BUILD_SCHEMA = "transpect.guard.graceful-lease-current-lab-build/1.0"
DEFAULT_DLL = ROOT / "build/guard-graceful-lease-current-lab/ttrace-guard-graceful-lease-current-lab.dll"


def _kernel():
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = [c.c_void_p, w.BOOL, w.LPCWSTR]
    kernel.CreateMutexW.restype = w.HANDLE
    kernel.ReleaseMutex.argtypes = [w.HANDLE]
    kernel.ReleaseMutex.restype = w.BOOL
    kernel.OpenEventW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
    kernel.OpenEventW.restype = w.HANDLE
    kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    kernel.WaitForSingleObject.restype = w.DWORD
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    return kernel


class _OwnerThread:
    def __init__(self, name: str):
        self.name = name
        self.kernel = _kernel()
        self.ready = threading.Event()
        self.finish = threading.Event()
        self.release = False
        self.handle = None
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            self.handle = self.kernel.CreateMutexW(None, True, self.name)
            if not self.handle:
                raise c.WinError(c.get_last_error())
            if c.get_last_error() == 183:
                raise RuntimeError("lease mutex already exists")
            self.ready.set()
            self.finish.wait(60)
            if self.release and not self.kernel.ReleaseMutex(self.handle):
                raise c.WinError(c.get_last_error())
            # For the loss case, returning without ReleaseMutex abandons it.
        except Exception as error:
            self.error = f"{type(error).__name__}:{error}"
            self.ready.set()

    def start(self):
        self.thread.start()
        if not self.ready.wait(5) or self.error:
            raise RuntimeError(f"lease owner did not start: {self.error}")

    def stop(self, *, explicit: bool):
        self.release = explicit
        self.finish.set()
        self.thread.join(5)
        if self.thread.is_alive() or self.error:
            raise RuntimeError(f"lease owner did not exit: {self.error}")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def _check_build(dll: Path, backend: Path) -> dict:
    manifest_path = dll.parent / "build-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("schema") != BUILD_SCHEMA
            or manifest.get("lab_only") is not True
            or manifest.get("controller_loss_behavior") != "bypass_and_disable_hooks"
            or manifest.get("backend", {}).get("path") != str(backend)
            or manifest.get("backend", {}).get("sha256") != BACKEND_SHA256
            or manifest.get("backend", {}).get("version") != BACKEND_VERSION
            or manifest.get("artifact", {}).get("sha256") != sha256(dll)):
        raise ValueError("DLL is not the pinned test-only graceful lease candidate")
    return {"dll_sha256": sha256(dll), "manifest_sha256": sha256(manifest_path),
            "controller_loss_behavior": manifest["controller_loss_behavior"],
            "lab_only": True}


def run_case(backend: Path, dll: Path, output: Path, transport: str,
             loss: str, parent_sid: str) -> dict:
    case_dir = output / f"{transport}-{loss}"
    case_dir.mkdir(parents=True, exist_ok=False)
    denied_marker = f"TTRACE_LEASE_DENY_{uuid4().hex}".encode()
    allowed_marker = f"TTRACE_LEASE_AFTER_{uuid4().hex}".encode()
    observed: list[dict] = []
    observed_lock = threading.Lock()
    messages: Queue = Queue()
    taps: list[dict] = []
    taps_lock = threading.Lock()
    errors: list[str] = []
    identity = None
    disabled_ack = protected_denied = post_lease_origin_match = False
    denied_archive_readback_exact = False
    same_pid_after_lease = no_post_lease_pipe_request = False
    denied_turn_status = None
    owner = None
    pipe = None
    process = None
    with tempfile.TemporaryDirectory(prefix="ttrace-graceful-lease-",
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

            def tap(request):
                if request.kind == "model.request":
                    raw = request.payload_utf8.encode()
                    with taps_lock:
                        taps.append({"request_id": request.request_id,
                                     "protocol": request.protocol,
                                     "denied_marker": denied_marker in raw,
                                     "allowed_marker": allowed_marker in raw,
                                     "bytes": len(raw),
                                     "sha256": hashlib.sha256(raw).hexdigest()})

            pipe = PipeServer(process.pid, engine, case_dir / "pipe-audit.jsonl",
                              request_tap=tap, client_sid=parent_sid)
            try:
                lab._request(process, 1, "initialize", {"clientInfo": {
                    "name": "transpect_lease_lab", "title": "Transpect lease lab",
                    "version": "0.1.0"}})
                if "error" in lab._await_id(messages, 1, 15):
                    raise RuntimeError("app-server initialize failed")
                process.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
                process.stdin.flush()
                identity = child_identity(process.pid, backend, parent_sid)
                lease_name = (f"Local\\ttrace-guard-lease-{process.pid}-"
                              f"{identity['creation_filetime']}")
                disabled_name = (f"Local\\ttrace-guard-disabled-{process.pid}-"
                                 f"{identity['creation_filetime']}")
                if loss == "release":
                    # Exercise the same owner-thread and acknowledgement code
                    # the desktop controller would use.
                    owner = _ControllerLease(process.pid,
                                             identity["creation_filetime"])
                else:
                    owner = _OwnerThread(lease_name)
                    owner.start()
                pipe.start()
                inject(process.pid, dll, identity,
                       identity_resolver=lambda pid: child_identity(
                           pid, backend, parent_sid, identity["creation_filetime"]))
                if not wait_ready(identity, timeout=15) or not pipe.ready.wait(3):
                    raise RuntimeError("lease native guard was not ready")
                disabled_event = None
                if loss == "abandon":
                    disabled_event = owner.kernel.OpenEventW(
                        0x100000, False, disabled_name)
                    if not disabled_event:
                        raise c.WinError(c.get_last_error())
                try:
                    lab._request(process, 2, "thread/start", {"model": model,
                        "cwd": str(work), "approvalPolicy": "never",
                        "sandbox": "read-only"})
                    reply = lab._await_id(messages, 2, 15)
                    if "error" in reply:
                        raise RuntimeError("denied thread/start failed")
                    thread_id = _thread_id(reply)
                    if transport == "wss":
                        _wait_for(lambda: any(row.get("complete") is True
                                              and row.get("target") is False
                                              for row in origin_rows(sink, transport)),
                                  10, process)
                    lab._request(process, 3, "turn/start", {"threadId": thread_id,
                        "input": [{"type": "text", "text":
                                   f"{denied_marker.decode()} deploy with {FAKE_KEY}"}],
                        "cwd": str(work)})
                    reply = lab._await_id(messages, 3, 15)
                    if "error" in reply:
                        raise RuntimeError("denied turn/start failed")
                    turn_id = _turn_id(reply)
                    if not _wait_for(lambda: _completed_for(
                            observed, observed_lock, turn_id) is not None, 25, process):
                        raise RuntimeError("denied turn did not complete")
                    denied_turn_status = _completed_for(
                        observed, observed_lock, turn_id)["status"]
                    _wait_for(lambda: any(row["denied_marker"] for row in taps), 3, process)
                    with taps_lock:
                        denied_taps = [row for row in taps if row["denied_marker"]]
                    decisions = {row.get("request_id"): row for row in pipe.records}
                    archive_checks = []
                    for row in denied_taps:
                        decision = decisions.get(row["request_id"], {})
                        record_id = decision.get("archive_record_id")
                        try:
                            receipt, restored = engine.gate._archive.read(record_id)
                            archive_checks.append(
                                receipt.body_bytes == row["bytes"]
                                and receipt.body_sha256 == row["sha256"]
                                and hashlib.sha256(restored).hexdigest()
                                == row["sha256"])
                        except Exception:
                            archive_checks.append(False)
                    denied_archive_readback_exact = (
                        bool(denied_taps) and all(archive_checks))
                    protected_denied = (bool(denied_taps)
                                        and denied_archive_readback_exact
                                        and all(decisions.get(row["request_id"], {}).get(
                                            "decision") == "deny" for row in denied_taps)
                                        and not any(row.get("target") is True
                                                    for row in origin_rows(sink, transport)))
                    before_release_count = len(taps)
                    # Both release and abandonment must make future requests
                    # pass through without requiring the controller's pipe.
                    if loss == "release":
                        owner.release()
                        disabled_ack = owner.wait_disabled(5000)
                    else:
                        owner.stop(explicit=False)
                        disabled_ack = (
                            owner.kernel.WaitForSingleObject(disabled_event, 5000)
                            == 0)
                    if not disabled_ack:
                        raise RuntimeError("native hooks did not acknowledge disable")
                    pipe.close()
                    lab._request(process, 4, "thread/start", {"model": model,
                        "cwd": str(work), "approvalPolicy": "never",
                        "sandbox": "read-only"})
                    reply = lab._await_id(messages, 4, 15)
                    if "error" in reply:
                        raise RuntimeError("post-lease thread/start failed")
                    allowed_thread = _thread_id(reply)
                    lab._request(process, 5, "turn/start", {"threadId": allowed_thread,
                        "input": [{"type": "text", "text":
                                   f"{allowed_marker.decode()} hello"}],
                        "cwd": str(work)})
                    reply = lab._await_id(messages, 5, 15)
                    if "error" in reply:
                        raise RuntimeError("post-lease turn/start failed")
                    _turn_id(reply)
                    def allowed_origin_match() -> bool:
                        traced = {(
                            row.get("compact_json", {}).get("bytes"),
                            row.get("compact_json", {}).get("sha256"))
                            for row in trace_inventory(trace, allowed_marker)
                            if row.get("marker_in_file")
                            and isinstance(row.get("compact_json"), dict)}
                        received = {(row.get("bytes"), row.get("sha256"))
                                    for row in origin_rows(sink, transport)
                                    if row.get("complete") is True}
                        return bool(traced) and traced.issubset(received)

                    post_lease_origin_match = _wait_for(
                        allowed_origin_match, 25, process)
                    # A disabled MinHook must not call the policy pipe, even
                    # though a new request reaches the non-forwarding origin.
                    time.sleep(0.3)
                    with taps_lock:
                        no_post_lease_pipe_request = len(taps) == before_release_count
                    same_pid_after_lease = process.poll() is None
                    if same_pid_after_lease:
                        child_identity(process.pid, backend, parent_sid,
                                       identity["creation_filetime"])
                finally:
                    if disabled_event:
                        owner.kernel.CloseHandle(disabled_event)
            except Exception as error:
                errors.append(f"{type(error).__name__}:{str(error)[:200]}")
            finally:
                if owner is not None:
                    if isinstance(owner, _OwnerThread) and owner.thread.is_alive():
                        try: owner.stop(explicit=True)
                        except Exception: pass
                    owner.close()
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
        hooks_file_present = (home / "hooks.json").exists()
    validated = (not errors and not pipe.errors and not hooks_file_present
                 and protected_denied and denied_turn_status == "failed"
                 and disabled_ack and post_lease_origin_match
                 and no_post_lease_pipe_request and same_pid_after_lease
                 and not any(row.get("target") is True for row in origin))
    return {"schema": SCHEMA, "transport": transport, "loss": loss,
            "backend_sha256": BACKEND_SHA256, "dll_sha256": sha256(dll),
            "synthetic_only": True, "local_origin_only": True,
            "identity": {"pid": process.pid, "creation_filetime":
                         identity["creation_filetime"] if identity else None,
                         "mode": "app-server"},
            "protected_denied": protected_denied,
            "denied_archive_readback_exact": denied_archive_readback_exact,
            "denied_turn_status": denied_turn_status,
            "disabled_ack": disabled_ack,
            "post_lease_origin_match": post_lease_origin_match,
            "no_post_lease_pipe_request": no_post_lease_pipe_request,
            "same_pid_after_lease": same_pid_after_lease,
            "denied_origin_requests_after_lease": sum(
                row.get("target") is True for row in origin),
            "pipe_errors": list(pipe.errors), "errors": errors,
            "validated": validated, "lab_only": True,
            "production_desktop_coverage_validated": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--dll", type=Path, default=DEFAULT_DLL)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transports", default="http,wss")
    parser.add_argument("--losses", default="release,abandon")
    args = parser.parse_args()
    backend, dll = args.backend.resolve(strict=True), args.dll.resolve(strict=True)
    if sha256(backend) != BACKEND_SHA256:
        raise SystemExit("backend does not match pinned 0.167 lab build")
    version = subprocess.run([str(backend), "--version"], capture_output=True,
                             text=True, timeout=10, check=True).stdout.strip()
    if version != BACKEND_VERSION:
        raise SystemExit("backend version differs from pinned 0.167 lab build")
    build = _check_build(dll, backend)
    transports = args.transports.split(",")
    losses = args.losses.split(",")
    if (set(transports) - {"http", "wss"} or len(set(transports)) != len(transports)
            or set(losses) - {"release", "abandon"}
            or len(set(losses)) != len(losses)):
        raise SystemExit("invalid transport or loss selection")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    parent_sid = _cim_process(os.getpid()).get("UserSid")
    if not isinstance(parent_sid, str) or not parent_sid.startswith("S-"):
        raise SystemExit("cannot establish lab controller SID")
    sources_before = controller_source_hashes()
    results = []
    for transport in transports:
        for loss in losses:
            try:
                row = run_case(backend, dll, output, transport, loss, parent_sid)
            except Exception as error:
                row = {"schema": SCHEMA, "transport": transport, "loss": loss,
                       "validated": False,
                       "error": f"{type(error).__name__}:{str(error)[:200]}"}
            results.append(row)
            (output / f"{transport}-{loss}.json").write_text(
                json.dumps(row, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"transport": transport, "loss": loss,
                              "validated": row["validated"],
                              "disabled_ack": row.get("disabled_ack"),
                              "post_lease_origin_match": row.get(
                                  "post_lease_origin_match"),
                              "errors": row.get("errors", row.get("error"))}),
                  flush=True)
    sources_after = controller_source_hashes()
    summary = {"schema": SCHEMA, "backend_sha256": BACKEND_SHA256,
               "build": build, "synthetic_only": True,
               "controller_lease_class_sha256": hashlib.sha256(
                   inspect.getsource(_ControllerLease).encode("utf-8")).hexdigest(),
               "controller_sources_sha256": sources_before,
               "controller_sources_unchanged_during_lab":
                   sources_before == sources_after,
               "production_desktop_coverage_validated": False,
               "results": results,
               "validated": sources_before == sources_after
               and len(results) == len(transports) * len(losses)
               and all(row["validated"] for row in results)}
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if summary["validated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
