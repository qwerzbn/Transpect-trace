"""Observe synthetic model markers in the active, exact pinned Codex desktop.

This deliberately attaches only to the current user's app-server backend.
It does not block, inspect arbitrary plaintext, alter application files,
grant network access, or establish complete desktop request coverage.
Frida can still disrupt the active app; run only for a short synthetic local
task after accepting that the current conversation might be interrupted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import ntpath
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

from _build_support import ROOT, enter_repository

sys.path.insert(0, str(ROOT / "src"))

from probe_desktop_paths_host import (
    _read_frida_events, _stop_frida, hold_processes, registered_package,
    verify_archived_msix,
)
from probe_desktop_paths_vm import (
    _hash, agent_source, load_fixtures, prepare_fixtures, safe_event,
    verify_static_entries,
)
from transpect_trace.guard.desktop import (
    _cim_process, current_user_sid, desktop_mode, load_desktop_adapter,
    windows_powershell_env,
)
from transpect_trace.guard.native import command_arguments
from transpect_trace.observe.windows import identity as process_identity


SCHEMA = "transpect.desktop-current-observation/1.0"
BACKEND_SIGNER_SUBJECT = 'CN="OpenAI OpCo, LLC", O="OpenAI OpCo, LLC", L=San Francisco, S=California, C=US'
BACKEND_SIGNER_THUMBPRINT = "0467ED57E4A70CE35EB7284092F1FD5285225056"
_CACHE_DIR = re.compile(r"[a-f0-9]{16,64}\Z")
_SID = re.compile(r"S-1-5-21-(?:\d+-){3}\d+\Z")
_OBSERVED_KINDS = frozenset(("probe_ready", "hook_installed", "hook_unavailable",
                             "entry_mismatch", "candidate_entry", "marker_buffer",
                             "read_hypothesis_failed"))
_MODEL_HOOKS = frozenset(("model.http", "model.wss"))


def _same_path(left: str | Path, right: str | Path) -> bool:
    return ntpath.normcase(ntpath.normpath(str(left))) == ntpath.normcase(ntpath.normpath(str(right)))


def require_current_user(expected_sid: str) -> None:
    if os.name != "nt":
        raise RuntimeError("current desktop observation requires Windows")
    if not _SID.fullmatch(expected_sid) or current_user_sid() != expected_sid:
        raise ValueError("expected SID must identify the current interactive user")


def verify_backend_signer(image: Path) -> dict[str, str]:
    """Check the signed cached backend without interpolating a path into PS code."""
    env = windows_powershell_env()
    env["TTRACE_VERIFY_BACKEND_IMAGE"] = str(image)
    command = (
        '$s=Get-AuthenticodeSignature -LiteralPath $env:TTRACE_VERIFY_BACKEND_IMAGE; '
        '[pscustomobject]@{Status=$s.Status.ToString();'
        'Subject=$s.SignerCertificate.Subject;'
        'Thumbprint=$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress'
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=15, check=False,
        env=env,
    )
    if result.returncode or not result.stdout.strip():
        raise ValueError("cached backend signature check failed")
    signer = json.loads(result.stdout)
    if (not isinstance(signer, dict) or signer.get("Status") != "Valid"
            or signer.get("Subject") != BACKEND_SIGNER_SUBJECT
            or signer.get("Thumbprint") != BACKEND_SIGNER_THUMBPRINT):
        raise ValueError("cached backend signer differs from archived fixed build")
    return signer


def verify_current_targets(adapter: dict, package: dict[str, str],
                           desktop_pid: int, backend_pid: int,
                           expected_sid: str) -> dict[str, dict]:
    """Verify current app, copied backend, user, parent, command, and birth."""
    require_current_user(expected_sid)
    if (adapter.get("status") != "candidate_unvalidated"
            or adapter.get("production_ready") is not False
            or any(item.get("validated") is not False
                   for item in adapter.get("coverage", {}).values())):
        raise ValueError("live research requires an unvalidated static candidate")
    if registered_package(adapter) != package:
        raise ValueError("current-user desktop registration changed")
    if (type(desktop_pid) is not int or type(backend_pid) is not int
            or desktop_pid <= 0 or backend_pid <= 0 or desktop_pid == backend_pid):
        raise ValueError("current desktop and backend PIDs must be distinct")
    root = Path(package["Location"])
    desktop_path = root / "app" / "ChatGPT.exe"
    desktop = process_identity(desktop_pid)
    backend = process_identity(backend_pid)
    desktop_row, backend_row = _cim_process(desktop_pid), _cim_process(backend_pid)
    if (not _same_path(desktop["image_path"], desktop_path)
            or desktop["image_sha256"] != adapter["desktop_image_sha256"]
            or desktop_row.get("UserSid") != expected_sid):
        raise ValueError("target is not the current pinned desktop app")
    if (backend["image_sha256"] != adapter["binary_sha256"]
            or backend_row.get("ParentProcessId") != desktop_pid
            or backend_row.get("UserSid") != expected_sid
            or desktop_mode(command_arguments(backend_row.get("CommandLine") or "")) != "app-server"):
        raise ValueError("target is not the current pinned desktop app-server")
    cache_root = (Path(os.environ["LOCALAPPDATA"]) / "OpenAI" / "Codex" / "bin").resolve(strict=True)
    backend_path = Path(backend["image_path"]).resolve(strict=True)
    try:
        relative = backend_path.relative_to(cache_root)
    except ValueError as error:
        raise ValueError("current backend is outside its per-user binary cache") from error
    if (len(relative.parts) != 2 or not _CACHE_DIR.fullmatch(relative.parts[0])
            or relative.parts[1].lower() != "codex.exe"):
        raise ValueError("current backend cache path has unexpected structure")
    verify_backend_signer(backend_path)
    targets = {
        "desktop": {"pid": desktop_pid, "birth": desktop["creation_filetime"],
                    "image_sha256": desktop["image_sha256"]},
        "backend": {"pid": backend_pid, "birth": backend["creation_filetime"],
                    "image_sha256": backend["image_sha256"]},
    }
    if any(type(item["birth"]) is not int or item["birth"] <= 0
           for item in targets.values()):
        raise ValueError("current desktop process birth time unavailable")
    return targets


def _safe_model_event(payload: object) -> dict | None:
    """Retain only model-hook counters or synthetic marker matches."""
    event = safe_event(payload, "backend")
    if event is None or event["kind"] not in _OBSERVED_KINDS:
        return None
    if event["kind"] == "probe_ready":
        return event
    if event.get("hook") not in _MODEL_HOOKS:
        return None
    if event["kind"] in {"candidate_entry", "read_hypothesis_failed"}:
        # These can belong to another task. Keep only hook, event type and
        # receive time; do not persist caller, thread, arguments or data.
        result = {key: event[key] for key in ("kind", "role", "hook", "observed_unix_ns")}
        if event["kind"] == "read_hypothesis_failed" and "stage" in event:
            result["stage"] = event["stage"]
        return result
    return event


def summarize_candidate_entries(rows: list[dict]) -> dict[str, dict]:
    """Summarize bounded candidate calls without attributing them to a task."""
    summary = {}
    for hook in sorted(_MODEL_HOOKS):
        times = [row["observed_unix_ns"] for row in rows
                 if row.get("kind") == "candidate_entry" and row.get("hook") == hook
                 and type(row.get("observed_unix_ns")) is int]
        summary[hook] = {"count": len(times), "first_observed_unix_ns": min(times) if times else None,
                         "last_observed_unix_ns": max(times) if times else None}
    return summary


def _frida_worker(adapter: dict, package: dict[str, str],
                  targets: dict[str, dict], desktop_pid: int, backend_pid: int,
                  expected_sid: str, marker: str, prompt: Path, sender) -> None:
    """Killable native attach process; parent never waits on a stuck Frida call."""
    session = None
    send_lock = threading.Lock()
    try:
        require_current_user(expected_sid)
        import frida
        with send_lock:
            sender.send({"frida_version": getattr(frida, "__version__", "unknown")})
        with hold_processes(targets):
            if verify_current_targets(adapter, package, desktop_pid, backend_pid, expected_sid) != targets:
                raise ValueError("current target changed before Frida attach")
            session = frida.attach(backend_pid)
            script = session.create_script(agent_source(
                "backend", adapter, marker, prompt, observe_io=False))

            def receive(message, _data):
                if message.get("type") == "send":
                    event = _safe_model_event(message.get("payload"))
                    if event is None:
                        return
                    row = {"event": event}
                elif message.get("type") == "error":
                    row = {"error": "frida_script_error"}
                else:
                    return
                with send_lock:
                    sender.send(row)

            script.on("message", receive)
            script.load()
            if verify_current_targets(adapter, package, desktop_pid, backend_pid, expected_sid) != targets:
                raise ValueError("current target changed after Frida attach")
            threading.Event().wait()
    except Exception as error:
        try:
            with send_lock:
                sender.send({"error": f"frida_worker_{type(error).__name__}"})
        except (BrokenPipeError, OSError):
            pass
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        sender.close()


def run_trace(args) -> dict:
    if not (getattr(args, "active_current_client", False)
            and getattr(args, "observation_only", False)):
        raise ValueError("--active-current-client and --observation-only are required")
    require_current_user(args.expected_sid)
    adapter_path = args.adapter.resolve(strict=True)
    adapter = load_desktop_adapter(adapter_path, require_validated=False)
    fixture, prompt, _attachment = load_fixtures(args.fixtures)
    archive_hash = verify_archived_msix(args.msix, adapter)
    package = registered_package(adapter)
    targets = verify_current_targets(adapter, package, args.desktop_pid,
                                     args.backend_pid, args.expected_sid)
    static = verify_static_entries(
        adapter, Path(process_identity(args.backend_pid)["image_path"]))
    marker = fixture["prompt_marker"]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows: list[dict] = []
    errors: list[str] = []
    version: dict[str, str] = {}
    observer = receiver = collector = None
    source = agent_source("backend", adapter, marker, prompt, observe_io=False)
    began = time.time_ns()
    try:
        with hold_processes(targets):
            if verify_current_targets(adapter, package, args.desktop_pid,
                                      args.backend_pid, args.expected_sid) != targets:
                raise ValueError("current target changed before observer startup")
            context = multiprocessing.get_context("spawn")
            receiver, sender = context.Pipe(duplex=False)
            observer = context.Process(target=_frida_worker,
                                       args=(adapter, package, targets,
                                             args.desktop_pid, args.backend_pid,
                                             args.expected_sid, marker, prompt, sender),
                                       daemon=True)
            observer.start()
            sender.close()
            ready = threading.Event()
            collector = threading.Thread(target=_read_frida_events,
                                         args=(receiver, rows, errors, {"backend"}, ready, version),
                                         daemon=True)
            collector.start()
            if ready.wait(20):
                if errors:
                    raise RuntimeError("current-client observation hooks did not initialize")
                print(f"Current-client observation ready for {args.seconds}s. "
                      f"Submit only synthetic text from {prompt} in a separate Local task.",
                      flush=True)
                until = time.monotonic() + args.seconds
                while time.monotonic() < until:
                    if not observer.is_alive():
                        errors.append("frida_worker_exited_during_trace")
                        break
                    time.sleep(min(0.1, until - time.monotonic()))
            else:
                errors.append("frida_attach_or_load_timeout" if observer.is_alive()
                              else "frida_worker_exited_before_ready")
    except Exception as error:
        # Frida and process errors can carry arbitrary target bytes; retain type only.
        errors.append(type(error).__name__)
    finally:
        _stop_frida(observer, receiver, collector, errors)
        try:
            if verify_current_targets(adapter, package, args.desktop_pid,
                                      args.backend_pid, args.expected_sid) != targets:
                errors.append("target_identity_changed")
        except Exception:
            errors.append("target_identity_unavailable_after_trace")
        event_bytes = b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")
                               for row in rows)
        (output / "events.jsonl").write_bytes(event_bytes)
        report = {
            "schema": SCHEMA, "observation_only": True, "can_enforce": False,
            "coverage_status": "unvalidated", "raw_body_persisted": False,
            "network_permit_opened": False, "active_client_attached": observer is not None,
            "desktop_ui_coverage_verified": False,
            "archived_msix_sha256": archive_hash,
            "adapter_sha256": _hash(adapter_path),
            "fixture_manifest_sha256": _hash(args.fixtures),
            "marker_sha256": hashlib.sha256(marker.encode("ascii")).hexdigest(),
            "expected_sid_sha256": hashlib.sha256(args.expected_sid.encode()).hexdigest(),
            "target_images": targets, "frida_version": version.get("value"),
            "static_candidate_hash": hashlib.sha256(
                json.dumps(static["candidates"], sort_keys=True).encode()).hexdigest(),
            "agent_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
            "event_count": len(rows),
            "candidate_entries_by_hook": summarize_candidate_entries(rows),
            "read_hypothesis_failed_by_hook": {
                hook: sum(row.get("kind") == "read_hypothesis_failed"
                          and row.get("hook") == hook for row in rows)
                for hook in sorted(_MODEL_HOOKS)},
            "model_marker_hits": sum(row.get("kind") == "marker_buffer"
                                     and row.get("hook") in _MODEL_HOOKS for row in rows),
            "errors": sorted(set(errors)),
            "elapsed_ms": (time.time_ns() - began) / 1_000_000,
            "interpretation": (
                "a synthetic marker match correlates one candidate request and checks only its JSON shape; it does not establish exact wire bytes, path coverage, denial, or zero-byte proof"
                if any(row.get("kind") == "marker_buffer" and row.get("hook") in _MODEL_HOOKS
                       for row in rows) else
                "candidate calls may be unrelated background traffic; without a marker hit they do not establish request correlation, completeness, denial, or zero-byte proof"
            ),
        }
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="Write synthetic text and unused file fixtures")
    prepare.add_argument("--output", type=Path, required=True)
    trace = sub.add_parser("trace", help="Bounded observation of the active current backend")
    trace.add_argument("--active-current-client", action="store_true", required=True)
    trace.add_argument("--observation-only", action="store_true", required=True)
    trace.add_argument("--msix", type=Path, required=True)
    trace.add_argument("--adapter", type=Path, required=True)
    trace.add_argument("--fixtures", type=Path, required=True)
    trace.add_argument("--desktop-pid", type=int, required=True)
    trace.add_argument("--backend-pid", type=int, required=True)
    trace.add_argument("--expected-sid", required=True)
    trace.add_argument("--seconds", type=int, choices=range(5, 121), metavar="5..120", required=True)
    trace.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    enter_repository()
    if args.command == "prepare":
        print(json.dumps(prepare_fixtures(args.output), indent=2))
        return
    report = run_trace(args)
    print(json.dumps({key: report[key] for key in
                      ("coverage_status", "candidate_entries_by_hook",
                       "read_hypothesis_failed_by_hook", "model_marker_hits", "errors")}, indent=2))
    if report["errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
