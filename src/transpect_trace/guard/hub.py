"""Unified resident supervisor and truthful, payload-free monitor snapshots.

The hub owns neither client processes nor their pins. Existing per-client
supervisors remain responsible for identity validation and injection.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
STATE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TranspectTrace" / "guard-hub"
MUTEX = "Local\\ttrace-unified-guard-hub"
STOP_EVENT = "Local\\ttrace-unified-guard-hub-stop"
MONITOR_MUTEX = "Local\\ttrace-unified-guard-monitor"
STOP_INTENT_FILE = "stop-request.json"
SERVICE_MUTEXES = {
    "codex": "Local\\ttrace-desktop-guard-supervisor",
    "claude": "Local\\ttrace-claude-guard-supervisor",
}
SERVICE_DIRS = {"codex": "desktop-guard", "claude": "claude-guard"}
SERVICE_SCRIPTS = {"codex": "desktop_guard.py", "claude": "claude_guard.py"}


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for attempt in range(20):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def service_environment(name: str, *, live_test: bool = False) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    if name == "claude":
        # Do not inherit the old daemon's implicit acceptance bypass.
        env.pop("TTRACE_CLAUDE_LIVE_TEST", None)
        env["TTRACE_CLAUDE_ALLOW_ATTACH"] = "1"
        if live_test:
            env["TTRACE_CLAUDE_LIVE_TEST"] = "1"
    return env


def recovery_allowed(state: dict, *, stop_requested: bool, expected_pid: int) -> bool:
    """A watchdog may restore only the observed unexpected hub exit."""
    return (not stop_requested and state.get("status") == "RUNNING"
            and isinstance(expected_pid, int) and expected_pid > 0 and state.get("pid") == expected_pid)


@dataclass
class Recovery:
    failures: int = 0
    next_attempt: float = 0.0
    started: float | None = None
    last_error: str = ""

    def failed(self, now: float, error: str) -> None:
        self.failures += 1
        self.next_attempt = now + min(30.0, 2.0 ** min(self.failures, 5))
        self.last_error = error
        self.started = None

    def healthy(self, now: float) -> None:
        if self.started is None:
            self.started = now
        if now - self.started >= 30:
            self.failures = 0
            self.last_error = ""


def service_snapshot(name: str, state: dict, *, running: bool, now: datetime | None = None,
                     experimental: bool = False) -> dict:
    """Never equate a live supervisor (or the legacy Codex label) with full coverage."""
    now = now or datetime.now()
    try:
        age = max(0.0, (now - datetime.fromisoformat(state["updated_at"])).total_seconds())
    except (KeyError, ValueError, TypeError):
        age = None
    fresh = age is not None and age <= 15 and not state.get("stopped_at")
    full = bool(not experimental and state.get("coverage", {}).get("ready")
                and state.get("egress", {}).get("ready"))
    rows = []
    for original in state.get("backends" if name == "codex" else "processes", []):
        if original.get("state") == "EXITED":
            continue
        row = {key: original.get(key) for key in
               ("pid", "state", "requests", "allowed", "denied", "detail", "mode")}
        row["source_state"] = row["state"]
        if row["state"] == "PROTECTED" and not full:
            row["state"] = "HOOK_READY_LIMITED"
        if not running or not fresh:
            row["state"] = "OFFLINE" if not running else "STALE"
        rows.append(row)
    scoped = [row for row in rows if row["source_state"] != "OUT_OF_SCOPE"]
    status = ("OFFLINE" if not running else "STARTING" if not state else "STALE" if not fresh
              else "PROTECTED" if scoped and full and all(r["state"] == "PROTECTED" for r in scoped)
              else "ATTENTION" if any(r["state"] in {"FAILED", "UNSUPPORTED_VERSION", "ATTACH_DISABLED",
                                                     "WAITING_ACCEPTANCE", "FAILED_CLOSED"} for r in rows)
              else "HOOK_READY_LIMITED" if any(r["state"] == "HOOK_READY_LIMITED" for r in rows)
              else "WATCHING")
    return {"name": name, "running": running, "status": status, "state_age_seconds": age,
            "supervisor_pid": state.get("supervisor_pid"), "processes": rows,
            "run_dir": state.get("run_dir", ""), "updated_at": state.get("updated_at", ""),
            "coverage": state.get("coverage", {"ready": False, "reason": "仅报告模型 Hook；完整覆盖未验收"}),
            "egress": state.get("egress", {"ready": False, "reason": "工具出口尚无完整验收证据"})}


def kernel():
    from ctypes import wintypes
    from .desktop_service import _kernel
    result = _kernel()
    result.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    result.OpenMutexW.restype = wintypes.HANDLE
    return result


def mutex_running(name: str) -> bool:
    k = kernel()
    handle = k.OpenMutexW(0x00100000, False, name)
    if not handle:
        return False
    k.CloseHandle(handle)
    return True


def signal_stop(name: str = STOP_EVENT) -> bool:
    k = kernel()
    event = k.OpenEventW(0x0002, False, name)
    if not event:
        return False
    try:
        return bool(k.SetEvent(event))
    finally:
        k.CloseHandle(event)


def hidden_process(args: list[str], *, env=None, log_name="hub-process.log"):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with (STATE_DIR / log_name).open("ab", buffering=0) as stream:
        return subprocess.Popen(args, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=stream,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


class Hub:
    def __init__(self, *, live_test=False, new_session=False):
        self.live_test = live_test
        self.new_session = new_session
        self.children = {}
        self.recovery = {name: Recovery() for name in (*SERVICE_SCRIPTS, "monitor")}
        self.owned = set()
        self.observed = set()

    def launch(self, name):
        if name == "monitor":
            args = ["powershell.exe", "-NoProfile", "-STA", "-WindowStyle", "Hidden",
                    "-File", str(ROOT / "scripts" / "guard_monitor.ps1"),
                    "-StatePath", str(STATE_DIR / "state.json")]
            return hidden_process(args, log_name="monitor.log")
        args = [sys.executable, str(ROOT / "scripts" / SERVICE_SCRIPTS[name]), "start", "--background"]
        return hidden_process(args, env=service_environment(name, live_test=self.live_test),
                              log_name=f"{name}-startup.log")

    def maintain(self, name: str, now: float) -> bool:
        mutex = MONITOR_MUTEX if name == "monitor" else SERVICE_MUTEXES[name]
        running = mutex_running(mutex)
        recovery = self.recovery[name]
        child = self.children.get(name)
        if running:
            recovery.healthy(now)
            self.observed.add(name)
            return True
        if name in self.observed:
            self.observed.remove(name)
            recovery.failed(now, "进程已退出；等待自动恢复")
        if child is not None:
            if child.poll() is None:
                # A live but hung process is visible as stale, never killed here.
                return False
            if recovery.started is not None:
                recovery.failed(now, f"退出码 {child.returncode}")
            self.children.pop(name, None)
        if now >= recovery.next_attempt:
            try:
                self.children[name] = self.launch(name)
                self.owned.add(name)
                recovery.started = now
            except OSError as error:
                recovery.failed(now, f"{type(error).__name__}: {error}")
        return False

    def snapshot(self, running: dict, now: float) -> dict:
        services = {}
        for name, directory in SERVICE_DIRS.items():
            state = read_json(STATE_DIR.parent / directory / "state.json")
            services[name] = service_snapshot(name, state, running=running[name],
                                             experimental=name == "claude" and self.live_test)
            services[name]["managed_start"] = name in self.owned
            services[name]["restart_attempts"] = self.recovery[name].failures
            services[name]["recovery_error"] = self.recovery[name].last_error
            services[name]["retry_in_seconds"] = max(0, round(self.recovery[name].next_attempt - now))
        monitor_pid = getattr(self.children.get("monitor"), "pid", None)
        if monitor_pid is None and running["monitor"]:
            monitor_pid = read_json(STATE_DIR / "monitor-state.json").get("pid")
        return {"schema": "transpect.guard-hub.state/1.0", "pid": os.getpid(),
                "updated_at": datetime.now().isoformat(timespec="seconds"), "status": "RUNNING",
                "claude_live_test": self.live_test, "monitor_running": running["monitor"],
                "monitor_pid": monitor_pid,
                "services": services}

    def run(self) -> int:
        import ctypes
        k = kernel()
        handle = k.CreateMutexW(None, True, MUTEX)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == 183:
            k.CloseHandle(handle)
            return 0
        if self.new_session:
            (STATE_DIR / STOP_INTENT_FILE).unlink(missing_ok=True)
        event = k.CreateEventW(None, True, False, STOP_EVENT)
        if not event:
            k.ReleaseMutex(handle)
            k.CloseHandle(handle)
            raise ctypes.WinError(ctypes.get_last_error())
        k.ResetEvent(event)
        try:
            while (not (STATE_DIR / STOP_INTENT_FILE).exists()
                   and k.WaitForSingleObject(event, 1000) != 0):
                now = time.monotonic()
                running = {name: self.maintain(name, now) for name in self.recovery}
                atomic_json(STATE_DIR / "state.json", self.snapshot(running, now))
            # Only explicit stop reaches here. Do not terminate clients or DLLs.
            from . import desktop_service, claude_service
            desktop_service.request_stop()
            claude_service.request_claude_stop()
            state = read_json(STATE_DIR / "state.json")
            state.update(status="STOPPING", updated_at=datetime.now().isoformat(timespec="seconds"))
            atomic_json(STATE_DIR / "state.json", state)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and any(mutex_running(m) for m in SERVICE_MUTEXES.values()):
                time.sleep(0.25)
            state["status"] = "STOPPED" if not any(mutex_running(m) for m in SERVICE_MUTEXES.values()) else "STOP_INCOMPLETE"
            state["updated_at"] = datetime.now().isoformat(timespec="seconds")
            atomic_json(STATE_DIR / "state.json", state)
            return 0 if state["status"] == "STOPPED" else 2
        finally:
            k.CloseHandle(event)
            k.ReleaseMutex(handle)
            k.CloseHandle(handle)
