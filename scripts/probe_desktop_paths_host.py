"""Observe pinned Codex desktop send-path candidates under a separate host user.

This research probe does not block requests, grant network access, or validate
an adapter. Run it as the dedicated standard Windows user that owns the pinned
desktop installation, never as the user of the already-active desktop client.
Only synthetic fixture markers may be submitted while it is attached.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
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

from discover_desktop_guard import inspect_msix, verify_msix_signature
from probe_desktop_paths_vm import (
    MAX_EVENTS, _hash, agent_source, load_fixtures, prepare_fixtures,
    safe_event, verify_static_entries,
)
from transpect_trace.guard.desktop import (
    PINNED_MSIX_SHA256, _cim_process, current_user_sid, desktop_mode,
    load_desktop_adapter, windows_powershell_env,
)
from transpect_trace.guard.native import command_arguments
from transpect_trace.observe.windows import identity as process_identity


HOST_TRACE_SCHEMA = "transpect.desktop-path-host-observation/1.0"
_LOCAL_SID = re.compile(r"S-1-5-21-(?:\d+-){2}\d+-\d+\Z")
_COPIED_BACKEND = re.compile(r"[a-f0-9]{16}\\codex\.exe\Z", re.IGNORECASE)
# The fixed codex.exe is independently signed; this is its signer, not the
# MSIX package signer. A new backend build needs a new reviewed pin.
_BACKEND_SIGNER_SHA1 = "0467ED57E4A70CE35EB7284092F1FD5285225056"


def require_dedicated_user(expected_sid: str, protected_sid: str) -> None:
    """The observer may attach only to its own separate local user processes."""
    if os.name != "nt":
        raise RuntimeError("host desktop observation requires Windows")
    if (not _LOCAL_SID.fullmatch(expected_sid)
            or not _LOCAL_SID.fullmatch(protected_sid)
            or expected_sid == protected_sid):
        raise ValueError("dedicated and protected desktop SIDs must be distinct local users")
    if current_user_sid() != expected_sid:
        raise ValueError("run the probe as the dedicated desktop user")


def verify_archived_msix(package: Path, adapter: dict) -> str:
    """Recheck the original signed, pinned MSIX without modifying registration."""
    package = Path(package).resolve(strict=True)
    digest = _hash(package)
    if digest != PINNED_MSIX_SHA256 or digest != adapter["package_sha256"]:
        raise ValueError("archived desktop MSIX hash differs from the fixed version")
    signer = verify_msix_signature(package)
    manifest = inspect_msix(package, adapter["package_full_name"])
    for field in ("package_full_name", "package_version", "package_publisher",
                  "desktop_image_sha256", "package_sha256"):
        if manifest[field] != adapter[field]:
            raise ValueError("archived desktop MSIX identity differs from adapter")
    if signer["package_signer_thumbprint"] != adapter["package_signer_thumbprint"]:
        raise ValueError("archived desktop signer differs from adapter")
    return digest


def registered_package(adapter: dict) -> dict[str, str]:
    """Read only the current dedicated user's Appx registration."""
    if os.name != "nt":
        raise RuntimeError("Appx registration requires Windows")
    command = (
        '$p=@(Get-AppxPackage -Name OpenAI.Codex); '
        'if ($p.Count -ne 1) { exit 2 }; '
        '[pscustomobject]@{FullName=$p[0].PackageFullName;'
        'Version=$p[0].Version.ToString();Publisher=$p[0].Publisher;'
        'Location=$p[0].InstallLocation}|ConvertTo-Json -Compress'
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=15, check=False,
        env=windows_powershell_env(),
    )
    if result.returncode or not result.stdout.strip():
        raise ValueError("dedicated user has no unique pinned Codex Appx registration")
    package = json.loads(result.stdout)
    if (not isinstance(package, dict)
            or package.get("FullName") != adapter["package_full_name"]
            or package.get("Version") != adapter["package_version"]
            or package.get("Publisher") != adapter["package_publisher"]
            or not isinstance(package.get("Location"), str)
            or ntpath.basename(ntpath.normpath(package["Location"])).lower()
            != adapter["package_full_name"].lower()):
        raise ValueError("current user's Codex Appx registration is not the fixed package")
    return package


def _same_path(left: str, right: str) -> bool:
    return ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(ntpath.normpath(right))


def _profile_directory(expected_sid: str) -> str:
    """Get the account's OS profile path, not a caller-controlled env value."""
    if not _LOCAL_SID.fullmatch(expected_sid):
        raise ValueError("invalid dedicated user SID")
    command = (
        f'$p=Get-CimInstance Win32_UserProfile -Filter "SID=\'{expected_sid}\'"; '
        'if ($null -eq $p -or [string]::IsNullOrWhiteSpace($p.LocalPath)) { exit 2 }; '
        '$p.LocalPath'
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=15, check=False,
        env=windows_powershell_env(),
    )
    value = result.stdout.strip()
    if result.returncode or not value or not ntpath.isabs(value):
        raise ValueError("dedicated Windows user profile is unavailable")
    return ntpath.normpath(value)


def _is_app_managed_backend(path: str, expected_sid: str) -> bool:
    """Accept only the desktop's versioned copy in this user's profile."""
    root = ntpath.join(_profile_directory(expected_sid), "AppData", "Local",
                       "OpenAI", "Codex", "bin")
    try:
        relative = ntpath.relpath(ntpath.normpath(path), root)
    except ValueError:
        return False
    return _COPIED_BACKEND.fullmatch(relative) is not None


def verify_backend_build(path: str, adapter: dict) -> dict[str, str]:
    """Check the signed copied executable and its reported fixed version."""
    escaped = path.replace("'", "''")
    command = (
        f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped}'; "
        'if ($null -eq $s.SignerCertificate) { exit 2 }; '
        '[pscustomobject]@{Status=$s.Status.ToString();'
        'Thumbprint=$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress'
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=15, check=False,
        env=windows_powershell_env(),
    )
    if result.returncode or not result.stdout.strip():
        raise ValueError("desktop backend signature unavailable")
    signature = json.loads(result.stdout)
    if (not isinstance(signature, dict) or signature.get("Status") != "Valid"
            or signature.get("Thumbprint", "").upper() != _BACKEND_SIGNER_SHA1):
        raise ValueError("desktop backend signer differs from fixed build")
    version = subprocess.run(
        [path, "--version"], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=10, check=False,
    )
    if version.returncode or version.stdout.strip() != adapter["backend_version"]:
        raise ValueError("desktop backend version differs from fixed build")
    return {"signer_sha1": _BACKEND_SIGNER_SHA1, "version": version.stdout.strip()}


def verify_host_targets(adapter: dict, package: dict[str, str], desktop_pid: int,
                        backend_pid: int, network_pid: int | None,
                        expected_sid: str, protected_sid: str) -> dict[str, dict]:
    """Pin exact package paths, hashes, owner, ancestry, role and birth time."""
    require_dedicated_user(expected_sid, protected_sid)
    if (adapter.get("status") != "candidate_unvalidated"
            or adapter.get("production_ready") is not False
            or any(item.get("validated") is not False
                   for item in adapter.get("coverage", {}).values())):
        raise ValueError("host observation requires an unvalidated static candidate")
    pids = [desktop_pid, backend_pid] + ([network_pid] if network_pid is not None else [])
    if any(type(pid) is not int or pid <= 0 for pid in pids) or len(set(pids)) != len(pids):
        raise ValueError("host trace process IDs must be distinct positive integers")
    root = package["Location"]
    expected_desktop = ntpath.join(root, "app", "ChatGPT.exe")
    expected_backend = ntpath.join(root, "app", "resources", "codex.exe")
    desktop, backend = process_identity(desktop_pid), process_identity(backend_pid)
    deskrow, backrow = _cim_process(desktop_pid), _cim_process(backend_pid)
    if (not _same_path(desktop["image_path"], expected_desktop)
            or desktop["image_sha256"] != adapter["desktop_image_sha256"]
            or deskrow.get("UserSid") != expected_sid):
        raise ValueError("host target is not the dedicated pinned desktop")
    if (not (_same_path(backend["image_path"], expected_backend)
             or _is_app_managed_backend(backend["image_path"], expected_sid))
            or backend["image_sha256"] != adapter["binary_sha256"]
            or backrow.get("ParentProcessId") != desktop_pid
            or backrow.get("UserSid") != expected_sid
            or desktop_mode(command_arguments(backrow.get("CommandLine") or "")) != "app-server"):
        raise ValueError("host backend is not the pinned desktop app-server")
    targets = {"desktop": {"pid": desktop_pid, "birth": desktop["creation_filetime"],
                            "image_sha256": desktop["image_sha256"]},
               "backend": {"pid": backend_pid, "birth": backend["creation_filetime"],
                            "image_sha256": backend["image_sha256"],
                            "image_path": backend["image_path"]}}
    if network_pid is not None:
        network, row = process_identity(network_pid), _cim_process(network_pid)
        if (not _same_path(network["image_path"], expected_desktop)
                or network["image_sha256"] != adapter["desktop_image_sha256"]
                or row.get("ParentProcessId") != desktop_pid
                or row.get("UserSid") != expected_sid
                or "network.mojom.NetworkService" not in (row.get("CommandLine") or "")):
            raise ValueError("host network service is not a pinned desktop child")
        targets["network"] = {"pid": network_pid, "birth": network["creation_filetime"],
                              "image_sha256": network["image_sha256"]}
    if any(type(target["birth"]) is not int or target["birth"] <= 0
           for target in targets.values()):
        raise ValueError("host target process birth time unavailable")
    return targets


@contextmanager
def hold_processes(targets: dict[str, dict]):
    """Keep process objects open so a checked PID cannot be silently reused."""
    if os.name != "nt":
        raise RuntimeError("process pinning requires Windows")

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(FileTime)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handles = []
    try:
        for target in targets.values():
            handle = kernel.OpenProcess(0x00100000 | 0x1000, False, target["pid"])
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.append(handle)
            times = [FileTime() for _ in range(4)]
            if (not kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in times))
                    or (times[0].low | (times[0].high << 32)) != target["birth"]
                    or kernel.WaitForSingleObject(handle, 0) != 258):
                raise ValueError("host target exited or changed before attach")
        yield
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


def _frida_worker(adapter: dict, package: dict[str, str], targets: dict[str, dict],
                  desktop_pid: int, backend_pid: int, network_pid: int | None,
                  expected_sid: str, protected_sid: str, marker: str,
                  attachment: Path, sender) -> None:
    """Disposable same-user observer; native attach/load may never return."""
    sessions = []
    scripts = []
    send_lock = threading.Lock()
    try:
        require_dedicated_user(expected_sid, protected_sid)
        verify_backend_build(targets["backend"]["image_path"], adapter)
        import frida  # Research-only dependency; never an enforcement gate.
        with send_lock:
            sender.send({"frida_version": getattr(frida, "__version__", "unknown")})
        with hold_processes(targets):
            for role, target in targets.items():
                before = verify_host_targets(adapter, package, desktop_pid, backend_pid,
                                             network_pid, expected_sid, protected_sid)
                if before != targets:
                    raise ValueError("host target identity changed before Frida attach")
                session = frida.attach(target["pid"])
                sessions.append(session)
                script = session.create_script(agent_source(role, adapter, marker, attachment))
                scripts.append(script)

                def receive(message, _data, *, role=role):
                    if message.get("type") == "send":
                        event = safe_event(message.get("payload"), role)
                        row = {"event": event} if event is not None else {"error": "unexpected_agent_message"}
                    elif message.get("type") == "error":
                        row = {"error": "agent_script_error"}
                    else:
                        return
                    with send_lock:
                        sender.send(row)

                script.on("message", receive)
                script.load()
                after = verify_host_targets(adapter, package, desktop_pid, backend_pid,
                                            network_pid, expected_sid, protected_sid)
                if after != targets:
                    raise ValueError("host target identity changed after Frida attach")
            # Parent terminates this child after the observation interval.
            threading.Event().wait()
    except Exception as error:
        try:
            with send_lock:
                sender.send({"error": f"frida_worker_{type(error).__name__}"})
        except (BrokenPipeError, OSError):
            pass
    finally:
        for session in reversed(sessions):
            try:
                session.detach()
            except Exception:
                pass
        sender.close()


def _read_frida_events(receiver, rows: list[dict], errors: list[str],
                       ready_roles: set[str], ready: threading.Event,
                       version: dict[str, str]) -> None:
    """Drain sanitized metadata so a callback cannot block the request path."""
    try:
        while True:
            row = receiver.recv()
            if not isinstance(row, dict):
                errors.append("unexpected_frida_worker_message")
            elif isinstance(row.get("frida_version"), str):
                version["value"] = row["frida_version"][:64]
            elif isinstance(row.get("error"), str):
                errors.append(row["error"][:80])
            elif isinstance(row.get("event"), dict):
                event = row["event"]
                if event.get("role") not in ready_roles:
                    errors.append("unexpected_frida_role")
                elif len(rows) >= MAX_EVENTS:
                    errors.append("event_bound_exceeded")
                else:
                    rows.append(event)
                    if event.get("kind") in {"entry_mismatch", "hook_unavailable"}:
                        errors.append(event["kind"])
                    if event.get("kind") == "probe_ready":
                        if ready_roles.issubset({item["role"] for item in rows
                                                 if item.get("kind") == "probe_ready"}):
                            ready.set()
            else:
                errors.append("unexpected_frida_worker_message")
    except EOFError:
        pass
    except (BrokenPipeError, OSError):
        errors.append("frida_worker_pipe_error")


def _start_frida_bounded(adapter: dict, package: dict[str, str],
                         targets: dict[str, dict], args, marker: str,
                         attachment: Path, rows: list[dict], errors: list[str],
                         version: dict[str, str], timeout: float = 20):
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    observer = context.Process(target=_frida_worker,
                               args=(adapter, package, targets, args.desktop_pid,
                                     args.backend_pid, args.network_pid,
                                     args.expected_sid, args.protected_sid,
                                     marker, attachment, sender), daemon=True)
    observer.start()
    sender.close()
    ready = threading.Event()
    collector = threading.Thread(target=_read_frida_events,
                                 args=(receiver, rows, errors, set(targets), ready, version),
                                 daemon=True)
    collector.start()
    if not ready.wait(timeout):
        errors.append("frida_attach_or_load_timeout" if observer.is_alive()
                      else "frida_worker_exited_before_ready")
    return observer, receiver, collector, ready.is_set()


def _stop_frida(observer, receiver, collector, errors: list[str]) -> None:
    if observer is None:
        return
    if observer.is_alive():
        observer.terminate()
    observer.join(timeout=2)
    if observer.is_alive():
        observer.kill()
        observer.join(timeout=2)
    if observer.is_alive():
        errors.append("frida_worker_termination_failed")
    collector.join(timeout=2)
    receiver.close()


def run_trace(args) -> dict:
    if not getattr(args, "observation_only", False):
        raise ValueError("--observation-only is required; host probe cannot enforce")
    require_dedicated_user(args.expected_sid, args.protected_sid)
    adapter_path = args.adapter.resolve(strict=True)
    adapter = load_desktop_adapter(adapter_path, require_validated=False)
    fixture, prompt, attachment = load_fixtures(args.fixtures)
    msix_hash = verify_archived_msix(args.msix, adapter)
    package = registered_package(adapter)
    targets = verify_host_targets(adapter, package, args.desktop_pid, args.backend_pid,
                                  args.network_pid, args.expected_sid, args.protected_sid)
    backend_build = verify_backend_build(targets["backend"]["image_path"], adapter)
    static = verify_static_entries(adapter, Path(package["Location"]) / "app" / "resources" / "codex.exe")
    marker = (fixture["prompt_marker"] if args.case == "text" else
              fixture["upload_marker"] if args.case == "upload" else "")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows: list[dict] = []
    errors: list[str] = []
    observer = receiver = collector = None
    source_hashes = {role: hashlib.sha256(agent_source(role, adapter, marker, attachment)
                                          .encode("utf-8")).hexdigest() for role in targets}
    frida_version: dict[str, str] = {}
    began = time.time_ns()
    try:
        with hold_processes(targets):
            before = verify_host_targets(adapter, package, args.desktop_pid, args.backend_pid,
                                         args.network_pid, args.expected_sid, args.protected_sid)
            if before != targets:
                raise ValueError("host target identity changed before observer startup")
            observer, receiver, collector, ready = _start_frida_bounded(
                adapter, package, targets, args, marker, attachment, rows, errors,
                frida_version)
            after = verify_host_targets(adapter, package, args.desktop_pid, args.backend_pid,
                                        args.network_pid, args.expected_sid, args.protected_sid)
            if after != targets:
                raise ValueError("host target identity changed after observer startup")
            if ready:
                print(f"Observation-only host trace ready for {args.case}; {args.seconds}s.", flush=True)
                if args.case == "text":
                    print(f"Submit only the synthetic text in {prompt} from the dedicated desktop user.", flush=True)
                elif args.case == "upload":
                    print(f"Attach only the synthetic file {attachment} from the dedicated desktop user.", flush=True)
                until = time.monotonic() + args.seconds
                while time.monotonic() < until:
                    if not observer.is_alive():
                        errors.append("frida_worker_exited_during_trace")
                        break
                    time.sleep(min(0.1, until - time.monotonic()))
    except Exception as error:
        # Never persist exception text: a Frida/runtime error may embed buffer data.
        errors.append(type(error).__name__)
    finally:
        _stop_frida(observer, receiver, collector, errors)
        try:
            after = verify_host_targets(adapter, package, args.desktop_pid, args.backend_pid,
                                        args.network_pid, args.expected_sid, args.protected_sid)
            if after != targets:
                errors.append("target_identity_changed")
        except Exception:
            errors.append("target_identity_unavailable_after_trace")
        evidence = list(rows)
        event_bytes = b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")
                               for row in evidence)
        (output / "events.jsonl").write_bytes(event_bytes)
        report = {"schema": HOST_TRACE_SCHEMA, "observation_only": True,
                  "can_enforce": False, "coverage_status": "unvalidated",
                  "network_permit_opened": False, "raw_body_persisted": False,
                  "case": args.case, "adapter_sha256": _hash(adapter_path),
                  "archived_msix_sha256": msix_hash,
                  "frida_version": frida_version.get("value"),
                  "fixture_manifest_sha256": _hash(args.fixtures),
                  "marker_sha256": hashlib.sha256(marker.encode("ascii")).hexdigest() if marker else None,
                  "fixture_file_sha256": fixture["attachment_sha256"],
                  "dedicated_user_sid_sha256": hashlib.sha256(args.expected_sid.encode()).hexdigest(),
                  "protected_user_sid_sha256": hashlib.sha256(args.protected_sid.encode()).hexdigest(),
                  "target_images": targets,
                  "backend_build": backend_build,
                  "static_candidate_hash": hashlib.sha256(
                      json.dumps(static["candidates"], sort_keys=True).encode()).hexdigest(),
                  "network_service_traced": "network" in targets,
                  "agent_source_sha256": source_hashes,
                  "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
                  "event_count": len(evidence), "errors": sorted(set(errors)),
                  "elapsed_ms": (time.time_ns() - began) / 1_000_000,
                  "http_candidate_entries": sum(row.get("hook") == "model.http" and row["kind"] == "candidate_entry"
                                                for row in evidence),
                  "wss_candidate_entries": sum(row.get("hook") == "model.wss" and row["kind"] == "candidate_entry"
                                               for row in evidence),
                  "marker_buffer_hits": sum(row["kind"] == "marker_buffer" for row in evidence),
                  "interpretation": "metadata-only research; no request completeness, denial, or zero-byte proof"}
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="Create synthetic text and upload fixtures")
    prepare.add_argument("--output", type=Path, required=True)
    trace = sub.add_parser("trace", help="Observation only on the dedicated host user")
    trace.add_argument("--observation-only", action="store_true", required=True)
    trace.add_argument("--adapter", type=Path, required=True)
    trace.add_argument("--msix", type=Path, required=True)
    trace.add_argument("--fixtures", type=Path, required=True)
    trace.add_argument("--desktop-pid", type=int, required=True)
    trace.add_argument("--backend-pid", type=int, required=True)
    trace.add_argument("--network-pid", type=int)
    trace.add_argument("--expected-sid", required=True)
    trace.add_argument("--protected-sid", required=True)
    trace.add_argument("--case", choices=("idle", "text", "upload"), required=True)
    trace.add_argument("--seconds", type=int, choices=range(5, 301), metavar="5..300", required=True)
    trace.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    enter_repository()
    if args.command == "prepare":
        print(json.dumps(prepare_fixtures(args.output), indent=2))
    else:
        report = run_trace(args)
        print(json.dumps({key: report[key] for key in (
            "case", "coverage_status", "event_count", "http_candidate_entries",
            "wss_candidate_entries", "marker_buffer_hits", "errors")}, indent=2))
        if report["errors"]:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
