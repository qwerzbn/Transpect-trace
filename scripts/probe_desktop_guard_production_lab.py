"""Isolated lifecycle lab for the production desktop guard DLL.

One disposable `codex.exe app-server` child with a local, non-forwarding origin
runs five phases against the production controller code:

  attach     inject; a synthetic secret is denied, a benign turn reaches origin
  stopped    controlled stop; a benign turn passes without the pipe
  reconnect  a new controller takes the lease of the same PID; deny + allow again
  lost       a controller dies holding the lease; a benign turn is denied
  recover    a new controller takes the abandoned lease; a benign turn passes

Ground truth is the origin's received rows (marker-bearing requests), never the
turn status alone. Only synthetic prompts and a fake key are used.
"""
from __future__ import annotations

import argparse
import json
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

import probe_desktop_backend_lab as lab  # noqa: E402
from probe_desktop_capture_current_lab import configure_provider  # noqa: E402
from probe_desktop_guard_failstop_current_lab import (  # noqa: E402
    FAKE_KEY, counted_local_origin, origin_rows,
)
from probe_desktop_guard_graceful_current_lab import (  # noqa: E402
    _completed_for, _message_reader, _thread_id, _turn_id,
)
from transpect_trace.guard import desktop_service as svc  # noqa: E402
from transpect_trace.protect.codex_hook_gate import GateConfig  # noqa: E402
from transpect_trace.protect.native_collection import NativeCollectionEngine  # noqa: E402

SCHEMA = "transpect.desktop-guard-production-lab/1.0"


def run(backend: Path, output: Path, transport: str) -> dict:
    pins = svc.load_pins()
    pin = pins[svc.file_sha256(backend)]
    dll = svc.ensure_dll(pin, backend)
    marker = f"TTRACE_PROD_LAB_{uuid4().hex}"
    case_dir = output / transport
    case_dir.mkdir(parents=True, exist_ok=False)
    phases: list[dict] = []
    errors: list[str] = []
    log_lines: list[str] = []
    observed: list[dict] = []
    observed_lock = threading.Lock()
    messages: Queue = Queue()
    request_id = [10]
    sid = svc.current_user_sid()

    with tempfile.TemporaryDirectory(prefix="ttrace-prod-lab-",
                                     ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        home, work = root / "home", root / "work"
        work.mkdir()
        with counted_local_origin(transport, root, marker.encode()) as sink:
            model = configure_provider(home, sink.server_port, transport)
            env = lab.isolated_env(home)
            if transport == "wss":
                env.update(CODEX_CA_CERTIFICATE=str(sink.ca), NO_PROXY="localhost,127.0.0.1",
                           HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9",
                           ALL_PROXY="http://127.0.0.1:9")
            process = subprocess.Popen([str(backend), "app-server"], cwd=work, env=env,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True,
                                       encoding="utf-8", bufsize=1)
            threading.Thread(target=_message_reader,
                             args=(process.stdout, messages, observed, observed_lock),
                             daemon=True).start()
            config = GateConfig(mode="enforce", archive_directory=case_dir / "archive",
                                audit_file=case_dir / "audit.jsonl",
                                registration_directory=None, review_override_ttl_seconds=0,
                                collection_file=case_dir / "collection.jsonl")
            engine = NativeCollectionEngine(config, archive_full_body=True,
                                            shared_request_archive=True)
            engine.concurrent_safe = True
            details = svc.process_details(process.pid)

            def targets() -> int:
                return sum(row.get("target") is True for row in origin_rows(sink, transport))

            def turn(text: str) -> str | None:
                request_id[0] += 2
                lab._request(process, request_id[0], "thread/start", {
                    "model": model, "cwd": str(work), "approvalPolicy": "never",
                    "sandbox": "read-only"})
                thread = _thread_id(lab._await_id(messages, request_id[0], 15))
                lab._request(process, request_id[0] + 1, "turn/start", {
                    "threadId": thread, "input": [{"type": "text", "text": text}],
                    "cwd": str(work)})
                turn_id = _turn_id(lab._await_id(messages, request_id[0] + 1, 15))
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    done = _completed_for(observed, observed_lock, turn_id)
                    if done is not None:
                        time.sleep(0.5)  # let the origin finish counting
                        return done.get("status")
                    time.sleep(0.1)
                return None

            def phase(name: str, text: str, expect_reach: bool) -> None:
                before = targets()
                status = turn(text)
                reached = targets() - before
                ok = (reached > 0) if expect_reach else (reached == 0)
                phases.append({"phase": name, "expect_reach_origin": expect_reach,
                               "origin_target_requests": reached, "turn_status": status,
                               "ok": ok})

            def controller() -> svc.BackendController:
                status = svc.BackendStatus(process.pid, details["creation_filetime"])
                worker = svc.BackendController(details, dll, engine, {}, case_dir, status,
                                               log_lines.append)
                worker.start()
                deadline = time.monotonic() + 20
                while status.state == "STARTING" and time.monotonic() < deadline:
                    time.sleep(0.05)
                if status.state != "PROTECTED":
                    raise RuntimeError(f"controller not protected: {status.state} {status.detail}")
                return worker

            def stop(worker: svc.BackendController) -> None:
                worker.stop_requested.set()
                worker.finished.wait(10)

            deny_text = f"{marker} deploy with {FAKE_KEY}"
            benign_text = f"{marker} hello"
            try:
                lab._request(process, 1, "initialize", {"clientInfo": {
                    "name": "transpect_prod_lab", "title": "Transpect production lab",
                    "version": "0.1.0"}})
                if "error" in lab._await_id(messages, 1, 15):
                    raise RuntimeError("app-server initialize failed")
                process.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
                process.stdin.flush()

                first = controller()
                attach_mode = first.status.mode
                phase("attach_deny", deny_text, expect_reach=False)
                phase("attach_allow", benign_text, expect_reach=True)
                stop(first)

                phase("stopped_pass", benign_text, expect_reach=True)

                second = controller()
                reconnect_mode = second.status.mode
                phase("reconnect_deny", deny_text, expect_reach=False)
                phase("reconnect_allow", benign_text, expect_reach=True)
                stop(second)

                # A controller that dies while holding the lease: its owner
                # thread exits without the controlled-stop signal.
                def die() -> None:
                    lease = svc.Lease(process.pid, details["creation_filetime"])
                    lease.acquire()
                    lease.resume()
                dying = threading.Thread(target=die)
                dying.start()
                dying.join()
                phase("lost_deny_benign", benign_text, expect_reach=False)

                third = controller()
                recover_mode = third.status.mode
                phase("recover_allow", benign_text, expect_reach=True)
                stop(third)
            except Exception as error:
                errors.append(f"{type(error).__name__}: {str(error)[:300]}")
                attach_mode = reconnect_mode = recover_mode = None
            finally:
                same_pid_alive = process.poll() is None
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()

    report = {"schema": SCHEMA, "transport": transport, "backend": str(backend),
              "dll": dll.name, "synthetic_only": True, "local_origin_only": True,
              "modes": {"attach": attach_mode, "reconnect": reconnect_mode,
                        "recover": recover_mode},
              "phases": phases, "same_pid_alive_throughout": same_pid_alive,
              "errors": errors, "controller_log": log_lines,
              "validated": (not errors and same_pid_alive and len(phases) == 7
                            and all(row["ok"] for row in phases)
                            and attach_mode == "已注入" and reconnect_mode == "已重连"
                            and recover_mode == "已重连")}
    (case_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                                          encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transports", default="http,wss")
    args = parser.parse_args()
    ok = True
    for transport in args.transports.split(","):
        report = run(args.backend.resolve(), args.output.resolve(), transport)
        ok &= report["validated"]
        print(transport, "validated" if report["validated"] else "FAILED")
        for row in report["phases"]:
            print(f"  {row['phase']:<18} origin+{row['origin_target_requests']}"
                  f"  turn={row['turn_status']}  {'ok' if row['ok'] else 'FAIL'}")
        for error in report["errors"]:
            print("  error:", error)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
