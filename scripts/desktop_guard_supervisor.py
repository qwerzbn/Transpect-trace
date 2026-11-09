"""Watch Windows Codex desktop backends without using Codex command hooks.

This per-user process watcher deliberately does not turn a synthetic Native
lab result into a live coverage claim. ``watch --activate`` starts a controller
only if its own exact-build preflight explicitly admits a live trial. A new
backend may send requests before a polling watcher attaches, so every-prompt
coverage is never inferred from the watcher's heartbeat or controller state.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import desktop_demo


SCHEMA = "transpect.desktop-guard-supervisor/1.0"
GUARD_KIND = "nonretry_lease"
MODEL_NOT_COVERED = desktop_demo.MODEL_NOT_COVERED
DEFAULT_STATE_DIR = (Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
                     / "TranspectTrace" / "desktop-guard")
_FILETIME_UNIX_OFFSET = 11644473600


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _process_generation_alive(pid: int, creation_filetime: int) -> bool:
    """Check the process handle and birth time, so a recycled PID is not reused."""
    if os.name != "nt" or pid < 1 or creation_filetime < 1:
        return False
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle:
        return False
    try:
        values = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in values)):
            return False
        birth = values[0].dwLowDateTime + (values[0].dwHighDateTime << 32)
        return birth == creation_filetime and kernel.WaitForSingleObject(handle, 0) == 258
    finally:
        kernel.CloseHandle(handle)


class _SingleWatcher:
    """Keep a named mutex held for this Windows logon session."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("desktop guard supervisor requires Windows")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CreateMutexW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.CreateMutexW(None, True, r"Local\TranspectTraceDesktopGuardSupervisor")
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            kernel.CloseHandle(handle)
            raise RuntimeError("a desktop guard supervisor already runs in this logon session")
        self.kernel = kernel
        self.handle = handle

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


@dataclass
class _Controller:
    pid: int
    creation_filetime: int
    output: Path
    process: subprocess.Popen
    started_utc: str
    stopped_requested: bool = False


class Supervisor:
    def __init__(self, state_dir: Path, *, activate: bool, poll_seconds: float = 2.0):
        if not 0.25 <= poll_seconds <= 60:
            raise ValueError("poll-seconds must be between 0.25 and 60")
        self.state_dir = state_dir.resolve()
        self.activate = activate
        self.poll_seconds = poll_seconds
        self.generation = uuid.uuid4().hex
        self.controllers: dict[tuple[int, int], _Controller] = {}
        self.blocked: set[tuple[int, int]] = set()
        self.subjects: dict[int, dict] = {}
        self.first_observed_at: dict[tuple[int, int], float] = {}
        self.identity_rejections: dict[int, str] = {}
        self.preflights: dict[tuple[int, int], dict] = {}
        self.last_inventory: tuple[int, ...] | None = None
        self.last_full_scan = 0.0
        self.started_utc = _utc_now()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        # A previous watcher could have died after spawning a controller but
        # before its next heartbeat. Never launch twice into that generation.
        for intent in (self.state_dir / "launch_intents").glob("*.json"):
            saved = _read_json(intent) or {}
            try:
                self.blocked.add((int(saved["pid"]), int(saved["creation_filetime"])))
            except (KeyError, TypeError, ValueError):
                continue
        watcher = desktop_demo.image_identity(os.getpid())
        self.state: dict = {
            "schema": SCHEMA, "state": "starting", "guard_kind": GUARD_KIND,
            "watcher_generation": self.generation, "watcher_pid": os.getpid(),
            "watcher_creation_filetime": watcher["creation_filetime"],
            "started_utc": self.started_utc, "heartbeat_utc": self.started_utc,
            "poll_seconds": poll_seconds, "activation_requested": activate,
            "codex_command_hooks_used": False,
            "pinned_package_full_name": desktop_demo.PACKAGE_FULL_NAME,
            "pinned_backend_version": desktop_demo.BACKEND_VERSION,
            "pinned_backend_sha256": desktop_demo.BACKEND_IMAGE_SHA256,
            "model_egress_status": MODEL_NOT_COVERED,
            "every_prompt_coverage_attested": False,
            "startup_gap_possible": True,
            "backends": [], "errors": [],
        }

    @staticmethod
    def _birth_unix(subject: dict) -> float:
        return subject["creation_filetime"] / 10_000_000 - _FILETIME_UNIX_OFFSET

    def _discover(self) -> list[dict]:
        pids = tuple(desktop_demo._candidate_pids())
        # Full package/hash/SID checks run at every inventory change. A stable
        # PID is checked against its creation time on every iteration.
        if pids != self.last_inventory or time.monotonic() - self.last_full_scan >= 15:
            self.subjects = {}
            self.identity_rejections = {}
            for pid in pids:
                try:
                    self.subjects[pid] = desktop_demo.collect_desktop_observation_identity(pid)
                except (OSError, RuntimeError, ValueError) as error:
                    self.identity_rejections[pid] = f"{type(error).__name__}: {error}"
            self.last_inventory = pids
            self.last_full_scan = time.monotonic()
        else:
            for pid, subject in list(self.subjects.items()):
                if not _process_generation_alive(pid, subject["creation_filetime"]):
                    try:
                        self.subjects[pid] = desktop_demo.collect_desktop_observation_identity(pid)
                        self.identity_rejections.pop(pid, None)
                    except (OSError, RuntimeError, ValueError) as error:
                        del self.subjects[pid]
                        self.identity_rejections[pid] = f"{type(error).__name__}: {error}"
        return list(self.subjects.values())

    def _preflight(self, subject: dict) -> dict:
        key = subject["pid"], subject["creation_filetime"]
        if key not in self.preflights:
            result = desktop_demo.status(subject["pid"], guard=GUARD_KIND)
            checked = result.get("backend") or {}
            if (checked.get("pid") != key[0]
                    or checked.get("creation_filetime") != key[1]):
                raise ValueError("desktop backend changed during Native preflight")
            self.preflights[key] = result
        return self.preflights[key]

    def _launch(self, subject: dict) -> _Controller:
        key = subject["pid"], subject["creation_filetime"]
        # The controller revalidates the package, image, parent, SID, process
        # birth and exact lab artifacts immediately before native injection.
        output = self.state_dir / "runs" / f"{key[0]}-{key[1]}"
        if output.exists():
            raise ValueError("controller run directory already exists for this generation")
        output.parent.mkdir(parents=True, exist_ok=True)
        _write_json(self.state_dir / "launch_intents" / f"{key[0]}-{key[1]}.json", {
            "schema": SCHEMA, "pid": key[0], "creation_filetime": key[1],
            "watcher_generation": self.generation, "controller_output": str(output),
            "requested_utc": _utc_now(),
        })
        command = [sys.executable, str(Path(desktop_demo.__file__).resolve()),
                   "run", "--pid", str(key[0]), "--output", str(output),
                   "--guard", GUARD_KIND, "--until-stopped"]
        log_path = self.state_dir / "controller.log"
        with log_path.open("a", encoding="utf-8") as log:
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                cwd=str(Path(desktop_demo.__file__).resolve().parent.parent),
            )
        return _Controller(key[0], key[1], output, process, _utc_now())

    @staticmethod
    def _controller_status(controller: _Controller) -> dict:
        return _read_json(controller.output / "status.json") or {}

    def _stop_controller(self, controller: _Controller) -> bool:
        if controller.stopped_requested or controller.process.poll() is not None:
            return controller.stopped_requested
        # The controller checks STOP after entering its loop. Never terminate
        # it while a Native decision or lease release may be in progress. The
        # controller claims its own run directory with mkdir(exist_ok=False),
        # so creating that directory here before it starts would make it fail.
        if not controller.output.is_dir():
            return False
        (controller.output / "STOP").write_text("supervisor stop requested\n", encoding="ascii")
        controller.stopped_requested = True
        return True

    def tick(self) -> dict:
        now = time.time()
        try:
            subjects = self._discover()
            inventory_error = None
        except (OSError, RuntimeError, ValueError) as error:
            # A transient CIM inventory failure must not tear down a healthy
            # controller. Keep only exact generations still alive. Do not
            # launch a new controller from this stale inventory.
            subjects = [subject for subject in self.subjects.values()
                        if _process_generation_alive(subject["pid"],
                                                     subject["creation_filetime"])]
            inventory_error = f"{type(error).__name__}: {error}"
        current = {(row["pid"], row["creation_filetime"]): row for row in subjects}
        for key, controller in self.controllers.items():
            if key not in current:
                self._stop_controller(controller)
        rows = []
        for key, subject in sorted(current.items()):
            pid, birth = key
            first_seen = self.first_observed_at.setdefault(key, now)
            row = {
                "pid": pid, "creation_filetime": birth,
                "desktop_pid": subject["desktop_pid"],
                "package_full_name": subject["package_full_name"],
                "backend_version": subject["baseline"]["version"],
                "backend_sha256": subject["baseline"]["sha256"],
                "identity_verified": True,
                "identity_inventory_fresh": inventory_error is None,
                "first_observation_gap_seconds": max(0, round(first_seen - self._birth_unix(subject), 3)),
                "model_egress_status": MODEL_NOT_COVERED,
                "controller_state": "not_started",
                "native_requests_observed": None,
                "every_prompt_coverage_attested": False,
            }
            controller = self.controllers.get(key)
            if controller is not None:
                controller_state = self._controller_status(controller)
                exit_code = controller.process.poll()
                row["controller_state"] = controller_state.get("state", "starting")
                row["native_requests_observed"] = controller_state.get("live_model_requests_observed")
                row["native_ready"] = controller_state.get("native_ready") is True
                row["pipe_ready"] = controller_state.get("pipe_ready") is True
                row["controller_exit_code"] = exit_code
                row["controller_output"] = str(controller.output)
                if exit_code is not None:
                    row["controller_state"] = "exited"
                    self.blocked.add(key)
            elif key in self.blocked:
                row["controller_state"] = "not_restarted_same_generation"
            else:
                try:
                    preflight = self._preflight(subject)
                    row["preflight_gaps"] = preflight.get("gaps", [])
                    row["native_guard_resident"] = preflight.get("live_guard_resident")
                    row["live_preflight_ready"] = preflight.get("ready_for_live_trial") is True
                    if self.activate and inventory_error is not None:
                        row["controller_state"] = "inventory_unavailable"
                    elif self.activate and row["live_preflight_ready"]:
                        # Recheck process generation at launch; controller
                        # repeats the complete pinned identity check.
                        if not _process_generation_alive(pid, birth):
                            raise ValueError("desktop backend changed before controller launch")
                        controller = self._launch(subject)
                        self.controllers[key] = controller
                        row["controller_state"] = "starting"
                        row["controller_output"] = str(controller.output)
                    elif self.activate:
                        row["controller_state"] = "preflight_rejected"
                    else:
                        row["controller_state"] = "observation_only"
                except (OSError, RuntimeError, ValueError) as error:
                    row["controller_state"] = "preflight_failed"
                    row["preflight_error"] = f"{type(error).__name__}: {error}"
                    self.blocked.add(key)
            rows.append(row)
        self.state.update({
            "state": "watching", "heartbeat_utc": _utc_now(),
            "model_egress_status": MODEL_NOT_COVERED,
            "every_prompt_coverage_attested": False,
            "startup_gap_possible": True, "backends": rows,
            "identity_inventory_fresh": inventory_error is None,
            "unmatched_codex_processes": [
                {"pid": pid, "identity_rejection": reason}
                for pid, reason in sorted(self.identity_rejections.items())],
            "errors": [inventory_error] if inventory_error else [],
        })
        _write_json(self.state_dir / "status.json", self.state)
        return self.state

    def should_stop(self) -> bool:
        signal = _read_json(self.state_dir / "STOP")
        return bool(signal and signal.get("watcher_generation") == self.generation)

    def close(self) -> dict:
        # Allow a just-spawned controller to claim its run directory before
        # signaling STOP. Keep retrying until each child exits or is signaled.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            pending = False
            for controller in self.controllers.values():
                if controller.process.poll() is None:
                    pending = True
                    self._stop_controller(controller)
            if not pending:
                break
            time.sleep(0.1)
        shutdowns = []
        for controller in self.controllers.values():
            final = self._controller_status(controller)
            shutdowns.append({
                "pid": controller.pid,
                "creation_filetime": controller.creation_filetime,
                "controller_exit_code": controller.process.poll(),
                "controller_state": final.get("state"),
                "lease_released": final.get("lease_released"),
                "native_hooks_disabled_attested": final.get("native_hooks_disabled_attested"),
                "controller_never_created_run_dir": (
                    controller.process.poll() is not None
                    and not controller.output.exists()),
                "backend_generation_alive": _process_generation_alive(
                    controller.pid, controller.creation_filetime),
            })
        self.state.update({
            "state": "stopped", "heartbeat_utc": _utc_now(),
            "model_egress_status": MODEL_NOT_COVERED,
            "every_prompt_coverage_attested": False,
            "controller_shutdowns": shutdowns,
        })
        _write_json(self.state_dir / "status.json", self.state)
        return self.state


def watch(state_dir: Path, *, activate: bool, poll_seconds: float) -> dict:
    lock = _SingleWatcher()
    try:
        supervisor = Supervisor(state_dir, activate=activate, poll_seconds=poll_seconds)
        try:
            while not supervisor.should_stop():
                supervisor.tick()
                time.sleep(poll_seconds)
        except KeyboardInterrupt:
            pass
        finally:
            supervisor.close()
        return supervisor.state
    finally:
        lock.close()


def status(state_dir: Path) -> dict:
    state = _read_json(state_dir.resolve() / "status.json")
    if state is None or state.get("schema") != SCHEMA:
        return {"schema": SCHEMA, "state": "not_running",
                "model_egress_status": MODEL_NOT_COVERED,
                "every_prompt_coverage_attested": False}
    try:
        updated = datetime.fromisoformat(state["heartbeat_utc"]).timestamp()
        fresh = time.time() - updated <= max(10, 3 * float(state["poll_seconds"]))
        watcher_alive = fresh and _process_generation_alive(
            int(state["watcher_pid"]), int(state["watcher_creation_filetime"]))
    except (KeyError, TypeError, ValueError):
        watcher_alive = False
    result = dict(state)
    result["watcher_alive"] = watcher_alive
    if not watcher_alive:
        result["state"] = "stale_or_stopped"
        result["model_egress_status"] = MODEL_NOT_COVERED
        result["every_prompt_coverage_attested"] = False
    return result


def stop(state_dir: Path, *, timeout_seconds: float = 40) -> dict:
    state_dir = state_dir.resolve()
    state = status(state_dir)
    if not state.get("watcher_alive"):
        raw = _read_json(state_dir / "status.json") or {}
        shutdowns = raw.get("controller_shutdowns", [])
        known_controller = any(row.get("controller_output") for row in raw.get("backends", []))
        launch_intents = list((state_dir / "launch_intents").glob("*.json"))
        clean_shutdowns = bool(shutdowns) and all(
            row.get("controller_exit_code") is not None
            and (row.get("native_hooks_disabled_attested") is True
                 or row.get("backend_generation_alive") is False
                 or row.get("controller_never_created_run_dir") is True)
            for row in shutdowns)
        idle = ((not known_controller and not launch_intents)
                or (raw.get("state") == "stopped" and clean_shutdowns))
        return {"schema": SCHEMA, "stop_requested": False,
                "stop_confirmed": idle,
                "reason": ("no live supervisor or active controller" if idle else
                           "supervisor is stale but prior controller shutdown is unverified")}
    _write_json(state_dir / "STOP", {
        "schema": SCHEMA, "watcher_generation": state["watcher_generation"],
        "requested_utc": _utc_now(),
    })
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        latest = _read_json(state_dir / "status.json") or {}
        if (latest.get("watcher_generation") == state["watcher_generation"]
                and latest.get("state") == "stopped"):
            shutdowns = latest.get("controller_shutdowns", [])
            clean = all(row.get("controller_exit_code") is not None
                        and (row.get("native_hooks_disabled_attested") is True
                             or row.get("backend_generation_alive") is False
                             or row.get("controller_never_created_run_dir") is True)
                        for row in shutdowns)
            return {"schema": SCHEMA, "stop_requested": True,
                    "stop_confirmed": clean,
                    "controller_shutdowns": shutdowns,
                    "watcher_generation": state["watcher_generation"]}
        time.sleep(0.2)
    return {"schema": SCHEMA, "stop_requested": True,
            "stop_confirmed": False, "reason": "supervisor stop or Native lease release unconfirmed",
            "watcher_generation": state["watcher_generation"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("watch", "status", "stop"):
        command = commands.add_parser(name)
        command.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
        if name == "watch":
            command.add_argument("--poll-seconds", type=float, default=2.0)
            command.add_argument("--activate", action="store_true",
                                 help="request Native activation only when live preflight admits it")
    args = parser.parse_args()
    if args.command == "watch":
        result = watch(args.state_dir, activate=args.activate,
                       poll_seconds=args.poll_seconds)
    elif args.command == "stop":
        result = stop(args.state_dir)
    else:
        result = status(args.state_dir)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
