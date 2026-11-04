"""Observe one synthetic local-file attachment in the pinned current desktop.

This is a short-lived, observation-only research probe. It cannot submit an
attachment through the Codex UI and cannot establish upload coverage. It never
exports file or model bytes: only an exact synthetic marker match can produce
bounded path-free metadata. Do not run it against real files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import ntpath
from pathlib import Path
import re
import sys
import threading
import time

from _build_support import ROOT, enter_repository

sys.path.insert(0, str(ROOT / "src"))

from probe_desktop_paths_current import require_current_user, verify_current_targets
from probe_desktop_paths_host import _stop_frida, hold_processes, registered_package, verify_archived_msix
from probe_desktop_paths_vm import _hash, agent_source, load_fixtures, prepare_fixtures, safe_event, verify_static_entries
from transpect_trace.guard.desktop import _cim_process, load_desktop_adapter
from transpect_trace.observe.windows import identity as process_identity


SCHEMA = "transpect.desktop-current-attachment-observation/1.0"
MAX_EVENTS = 1024
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_OBSERVED_BUFFER = 256 * 1024
_MARKER = re.compile(r"FAKE_DESKTOP_UPLOAD_[a-f0-9]{32}\Z")
_ROLES = frozenset(("desktop", "backend", "network"))
_FILE_HOOKS = frozenset(("CreateFileW", "ReadFile", "NtReadFile", "WriteFile"))
_NETWORK_HOOKS = frozenset(("WinHttpWriteData", "WinHttpSendRequest"))
_MODEL_HOOKS = frozenset(("model.http", "model.wss"))
_HOOKS = _FILE_HOOKS | _NETWORK_HOOKS | _MODEL_HOOKS


def attachment_agent_source(role: str, adapter: dict, marker: str,
                            attachment: Path) -> str:
    """Cap each in-process scan; oversized buffers remain unobserved."""
    source = agent_source(role, adapter, marker, attachment, observe_io=True)
    pinned = '"max_buffer":16777216'
    if source.count(pinned) != 1:
        raise ValueError("fixed observation-agent configuration changed")
    return source.replace(pinned, f'"max_buffer":{MAX_OBSERVED_BUFFER}', 1)


def network_identity_matches(network: dict, row: dict, *, desktop_pid: int,
                             desktop_image: str, package_location: str,
                             expected_sid: str) -> bool:
    """Require a child NetworkService from the pinned package and user."""
    expected_path = ntpath.join(package_location, "app", "ChatGPT.exe")
    return (
        isinstance(network, dict) and isinstance(row, dict)
        and ntpath.normcase(ntpath.normpath(str(network.get("image_path", ""))))
        == ntpath.normcase(ntpath.normpath(expected_path))
        and network.get("image_sha256") == desktop_image
        and type(network.get("creation_filetime")) is int
        and network["creation_filetime"] > 0
        and row.get("ParentProcessId") == desktop_pid
        and row.get("UserSid") == expected_sid
        and "network.mojom.NetworkService" in (row.get("CommandLine") or "")
    )


def verify_targets(adapter: dict, package: dict, desktop_pid: int,
                   backend_pid: int, network_pid: int | None,
                   expected_sid: str) -> dict[str, dict]:
    targets = verify_current_targets(adapter, package, desktop_pid,
                                     backend_pid, expected_sid)
    if network_pid is None:
        return targets
    if (type(network_pid) is not int or network_pid <= 0
            or network_pid in {desktop_pid, backend_pid}):
        raise ValueError("invalid distinct network service PID")
    network = process_identity(network_pid)
    row = _cim_process(network_pid)
    if not network_identity_matches(
            network, row, desktop_pid=desktop_pid,
            desktop_image=adapter["desktop_image_sha256"],
            package_location=package["Location"], expected_sid=expected_sid):
        raise ValueError("network target is not the pinned desktop NetworkService")
    targets["network"] = {
        "pid": network_pid, "birth": network["creation_filetime"],
        "image_sha256": network["image_sha256"],
    }
    return targets


def safe_attachment_event(payload: object, role: str, *, fixture_size: int,
                          fixture_sha256: str, marker_offset: int) -> dict | None:
    """Remove arbitrary paths, bytes, hashes, thread IDs and foreign fields."""
    if role not in _ROLES or not 0 < fixture_size <= MAX_FIXTURE_BYTES:
        return None
    event = safe_event(payload, role)
    if event is None:
        return None
    kind = event["kind"]
    hook = event.get("hook")
    if kind == "probe_ready":
        return {"kind": kind, "role": role, "observed_unix_ns": event["observed_unix_ns"]}
    if hook not in _HOOKS:
        return None
    row = {"kind": kind, "role": role, "hook": hook,
           "observed_unix_ns": event["observed_unix_ns"]}
    if kind == "candidate_entry":
        if hook not in _MODEL_HOOKS:
            return None
        return row
    if kind == "fixture_open":
        if hook != "CreateFileW":
            return None
    elif kind == "marker_buffer":
        size = event.get("bytes")
        offset = event.get("marker_offset")
        if (type(size) is not int or not 0 < size <= MAX_OBSERVED_BUFFER
                or type(offset) is not int or not 0 <= offset < size):
            return None
        row.update(bytes=size, marker_offset=offset,
                   exact_fixture_buffer=(size == fixture_size
                                         and event.get("sha256") == fixture_sha256
                                         and offset == marker_offset))
        if "request_shape" in event:
            row["request_shape"] = event["request_shape"]
    elif kind == "read_hypothesis_failed":
        if "stage" in event:
            row["stage"] = event["stage"]
    elif kind not in {"hook_installed", "hook_unavailable", "entry_mismatch"}:
        return None
    # Modules and relative code offsets help locate a candidate read path.
    # They contain neither file paths nor content and are kept only on matches.
    if kind in {"fixture_open", "marker_buffer"}:
        for field in ("caller", "stack"):
            if field in event:
                row[field] = event[field]
    return row


def summarize_events(rows: list[dict], errors: list[str], roles: set[str]) -> dict:
    ready = {row["role"] for row in rows if row.get("kind") == "probe_ready"}
    matched = [row for row in rows if row.get("kind") == "marker_buffer"]
    hooks = {row["hook"] for row in rows if row.get("kind") == "hook_installed"}
    status = ("unvalidated_probe_error" if errors or ready != roles else
              "synthetic_marker_seen_at_candidates" if matched else
              "no_synthetic_marker_observed")
    return {
        "status": status,
        "ready_roles": sorted(ready), "installed_hooks": sorted(hooks),
        "fixture_open_events": sum(row.get("kind") == "fixture_open" for row in rows),
        "file_read_marker_events": sum(row.get("kind") == "marker_buffer"
                                       and row.get("hook") in {"ReadFile", "NtReadFile"}
                                       for row in rows),
        "copy_write_marker_events": sum(row.get("kind") == "marker_buffer"
                                         and row.get("hook") == "WriteFile" for row in rows),
        "winhttp_marker_events": sum(row.get("kind") == "marker_buffer"
                                     and row.get("hook") in _NETWORK_HOOKS for row in rows),
        "model_marker_events": sum(row.get("kind") == "marker_buffer"
                                   and row.get("hook") in _MODEL_HOOKS for row in rows),
        "exact_fixture_buffer_events": sum(row.get("kind") == "marker_buffer"
                                           and row.get("exact_fixture_buffer") is True
                                           for row in rows),
        "unattributed_candidate_calls": sum(row.get("kind") == "candidate_entry"
                                            for row in rows),
    }


def _worker(adapter: dict, package: dict, targets: dict, desktop_pid: int,
            backend_pid: int, network_pid: int | None, expected_sid: str,
            marker: str, attachment: Path, fixture_sha256: str,
            fixture_size: int, marker_offset: int, sender) -> None:
    sessions = []
    send_lock = threading.Lock()

    def send_safe(value: dict) -> None:
        with send_lock:
            sender.send(value)

    try:
        import frida
        send_safe({"frida_version": getattr(frida, "__version__", "unknown")})
        with hold_processes(targets):
            if verify_targets(adapter, package, desktop_pid, backend_pid,
                              network_pid, expected_sid) != targets:
                raise ValueError("target identity changed before attachment")
            for role, target in targets.items():
                session = frida.attach(target["pid"])
                sessions.append(session)
                source = attachment_agent_source(role, adapter, marker, attachment)
                script = session.create_script(source)

                def receive(message, _data, *, role=role):
                    if message.get("type") == "error":
                        send_safe({"error": "frida_script_error"})
                        return
                    if message.get("type") != "send":
                        return
                    event = safe_attachment_event(
                        message.get("payload"), role, fixture_size=fixture_size,
                        fixture_sha256=fixture_sha256,
                        marker_offset=marker_offset)
                    if event is not None:
                        send_safe({"event": event})

                script.on("message", receive)
                script.load()
            if verify_targets(adapter, package, desktop_pid, backend_pid,
                              network_pid, expected_sid) != targets:
                raise ValueError("target identity changed after attachment")
            threading.Event().wait()
    except Exception as error:
        try:
            send_safe({"error": "worker_" + type(error).__name__})
        except (BrokenPipeError, OSError):
            pass
    finally:
        for session in reversed(sessions):
            try:
                session.detach()
            except Exception:
                pass
        sender.close()


def _collect(receiver, rows: list[dict], errors: list[str], ready: threading.Event,
             roles: set[str], version: dict) -> None:
    try:
        while True:
            item = receiver.recv()
            if not isinstance(item, dict):
                errors.append("unexpected_worker_message")
            elif isinstance(item.get("frida_version"), str):
                version["value"] = item["frida_version"][:64]
            elif isinstance(item.get("error"), str):
                errors.append(item["error"][:80])
            elif isinstance(item.get("event"), dict):
                if len(rows) >= MAX_EVENTS:
                    errors.append("event_limit")
                    continue
                row = item["event"]
                if row.get("role") not in roles:
                    errors.append("unexpected_role")
                    continue
                rows.append(row)
                if row["kind"] == "entry_mismatch":
                    errors.append("fixed_model_entry_mismatch")
                if roles.issubset({r["role"] for r in rows if r["kind"] == "probe_ready"}):
                    ready.set()
            else:
                errors.append("unexpected_worker_message")
    except EOFError:
        pass
    except (BrokenPipeError, OSError):
        errors.append("worker_pipe_error")


def require_opt_in(args) -> None:
    if not (getattr(args, "active_current_client", False)
            and getattr(args, "observation_only", False)
            and getattr(args, "synthetic_file_only", False)):
        raise ValueError("explicit current-client, observation, synthetic-file flags required")
    if type(args.seconds) is not int or not 5 <= args.seconds <= 120:
        raise ValueError("trace duration must be 5..120 seconds")


def run_trace(args) -> dict:
    require_opt_in(args)
    require_current_user(args.expected_sid)
    adapter_path = args.adapter.resolve(strict=True)
    adapter = load_desktop_adapter(adapter_path, require_validated=False)
    fixture, _prompt, attachment = load_fixtures(args.fixtures)
    marker = fixture["upload_marker"]
    data = attachment.read_bytes()
    if (not _MARKER.fullmatch(marker) or not 0 < len(data) <= MAX_FIXTURE_BYTES
            or hashlib.sha256(data).hexdigest() != fixture["attachment_sha256"]
            or data.count(marker.encode("ascii")) != 1):
        raise ValueError("synthetic attachment fixture changed")
    marker_offset = data.index(marker.encode("ascii"))
    msix_sha256 = verify_archived_msix(args.msix, adapter)
    package = registered_package(adapter)
    targets = verify_targets(adapter, package, args.desktop_pid,
                             args.backend_pid, args.network_pid,
                             args.expected_sid)
    static = verify_static_entries(adapter, Path(process_identity(args.backend_pid)["image_path"]))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows: list[dict] = []
    errors: list[str] = []
    version: dict = {}
    source_hashes = {role: hashlib.sha256(attachment_agent_source(
        role, adapter, marker, attachment).encode()).hexdigest()
        for role in targets}
    observer = receiver = collector = None
    began = time.time_ns()
    try:
        with hold_processes(targets):
            if verify_targets(adapter, package, args.desktop_pid, args.backend_pid,
                              args.network_pid, args.expected_sid) != targets:
                raise ValueError("target identity changed before observer startup")
            receiver, sender = multiprocessing.get_context("spawn").Pipe(duplex=False)
            observer = multiprocessing.get_context("spawn").Process(
                target=_worker,
                args=(adapter, package, targets, args.desktop_pid, args.backend_pid,
                      args.network_pid, args.expected_sid, marker, attachment,
                      fixture["attachment_sha256"], len(data), marker_offset, sender),
                daemon=True)
            observer.start()
            sender.close()
            ready = threading.Event()
            collector = threading.Thread(
                target=_collect,
                args=(receiver, rows, errors, ready, set(targets), version), daemon=True)
            collector.start()
            if ready.wait(20) and not errors:
                print(f"Synthetic attachment observation ready for {args.seconds}s; "
                      "no automated Codex UI upload trigger is available.", flush=True)
                until = time.monotonic() + args.seconds
                while time.monotonic() < until:
                    if not observer.is_alive():
                        errors.append("frida_worker_exited_during_trace")
                        break
                    time.sleep(min(0.1, max(0, until - time.monotonic())))
            else:
                errors.append("frida_attach_or_load_timeout" if observer.is_alive()
                              else "frida_worker_exited_before_ready")
    except Exception as error:
        errors.append(type(error).__name__)
    finally:
        if observer is not None and receiver is not None and collector is not None:
            _stop_frida(observer, receiver, collector, errors)
        if _hash(attachment) != fixture["attachment_sha256"]:
            errors.append("synthetic_attachment_changed_during_trace")
        try:
            if verify_targets(adapter, package, args.desktop_pid, args.backend_pid,
                              args.network_pid, args.expected_sid) != targets:
                errors.append("target_identity_changed")
        except Exception:
            errors.append("target_identity_unavailable_after_trace")
        evidence = summarize_events(rows, errors, set(targets))
        event_bytes = b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode()
                               for row in rows)
        (output / "events.jsonl").write_bytes(event_bytes)
        report = {
            "schema": SCHEMA, **evidence,
            "observation_only": True, "can_enforce": False,
            "coverage_status": "unvalidated", "attachment_upload_covered": False,
            "raw_file_or_model_bytes_persisted": False,
            "ui_attachment_submitted_by_script": False,
            "network_service_traced": "network" in targets,
            "remote_origin_zero_bytes_verified": False,
            "msix_sha256": msix_sha256, "adapter_sha256": _hash(adapter_path),
            "fixture_manifest_sha256": _hash(args.fixtures),
            "fixture_file_sha256": fixture["attachment_sha256"],
            "fixture_file_bytes": len(data),
            "marker_sha256": hashlib.sha256(marker.encode()).hexdigest(),
            "target_images": targets,
            "agent_source_sha256": source_hashes,
            "static_candidates_sha256": hashlib.sha256(json.dumps(
                static["candidates"], sort_keys=True).encode()).hexdigest(),
            "frida_version": version.get("value"),
            "event_count": len(rows), "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
            "elapsed_ms": (time.time_ns() - began) / 1_000_000,
            "errors": sorted(set(errors)),
        }
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n",
                                             encoding="utf-8")
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="Create a bounded synthetic attachment fixture")
    prepare.add_argument("--output", type=Path, required=True)
    trace = sub.add_parser("trace", help="Observe exact-fixture file and model candidates")
    trace.add_argument("--active-current-client", action="store_true", required=True)
    trace.add_argument("--observation-only", action="store_true", required=True)
    trace.add_argument("--synthetic-file-only", action="store_true", required=True)
    trace.add_argument("--msix", type=Path, required=True)
    trace.add_argument("--adapter", type=Path, required=True)
    trace.add_argument("--fixtures", type=Path, required=True)
    trace.add_argument("--desktop-pid", type=int, required=True)
    trace.add_argument("--backend-pid", type=int, required=True)
    trace.add_argument("--network-pid", type=int)
    trace.add_argument("--expected-sid", required=True)
    trace.add_argument("--seconds", type=int, choices=range(5, 121), metavar="5..120", required=True)
    trace.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    enter_repository()
    if args.command == "prepare":
        result = prepare_fixtures(args.output)
        print(json.dumps({"schema": result["schema"],
                          "attachment_sha256": result["attachment_sha256"]}, indent=2))
        return
    report = run_trace(args)
    print(json.dumps({key: report[key] for key in (
        "status", "coverage_status", "file_read_marker_events",
        "model_marker_events", "errors")}, indent=2))
    if report["errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
