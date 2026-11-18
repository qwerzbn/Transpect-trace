"""Real process recovery in isolated mutex namespaces; never touches client guards."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

import pytest

from transpect_trace.guard import hub

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows mutex integration")


def test_batch_launch_bootstraps_locked_project_and_forwards_arguments(tmp_path):
    uv = shutil.which("uv.exe")
    if not uv:
        pytest.skip("first-run installation requires uv")
    project = tmp_path / "project with spaces"
    scripts = project / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(hub.ROOT / "guard-service.bat", project / "guard-service.bat")
    (project / "pyproject.toml").write_text(
        '[project]\nname = "launcher-fixture"\nversion = "0.1.0"\n'
        'requires-python = ">=3.12"\n[project.optional-dependencies]\nnative-build = []\n',
        encoding="utf-8")
    (scripts / "guard_hub.py").write_text(
        "import sys\nprint('arguments', *sys.argv[1:])\nsys.exit(7 if 'stop' in sys.argv else 0)\n",
        encoding="utf-8")
    env = {**os.environ, "UV_OFFLINE": "true", "UV_PYTHON_DOWNLOADS": "never",
           "UV_PYTHON": sys._base_executable}
    env.pop("VIRTUAL_ENV", None)
    subprocess.run([uv, "lock", "--quiet"], cwd=project, env=env, check=True, timeout=30)

    def invoke(*args):
        return subprocess.run([env["COMSPEC"], "/d", "/c", "call", str(project / "guard-service.bat"), *args],
                              cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)

    lock = project / "uv.lock"
    lock.rename(project / "saved.lock")
    failed = invoke()
    assert failed.returncode != 0 and "arguments" not in failed.stdout
    (project / "saved.lock").rename(lock)
    started = invoke()
    assert started.returncode == 0 and started.stdout.strip() == "arguments", started.stderr
    assert (project / ".venv" / "Scripts" / "python.exe").is_file()
    env["PATH"] = str(Path(env["COMSPEC"]).parent)
    result = invoke("status", "--json")
    assert result.returncode == 0 and result.stdout.strip() == "arguments status --json"
    assert invoke("stop").returncode == 7


def test_real_monitor_and_supervisor_process_recovery_is_isolated(monkeypatch):
    suffix = uuid.uuid4().hex
    names = {name: f"Local\\ttrace-hub-test-{suffix}-{name}" for name in ("codex", "claude", "monitor")}
    monkeypatch.setattr(hub, "SERVICE_MUTEXES", {name: names[name] for name in ("codex", "claude")})
    monkeypatch.setattr(hub, "MONITOR_MUTEX", names["monitor"])
    children = []
    manager = hub.Hub()

    def launch(name):
        # This worker only holds a private test mutex. No injector, pipe, or network.
        code = ("import ctypes,sys,time; from ctypes import wintypes as w; "
                "k=ctypes.WinDLL('kernel32',use_last_error=True); "
                "k.CreateMutexW.argtypes=[ctypes.c_void_p,w.BOOL,w.LPCWSTR]; "
                "k.CreateMutexW.restype=w.HANDLE; "
                "h=k.CreateMutexW(None,True,sys.argv[1]); assert h; time.sleep(30)")
        # A Windows venv launcher may spawn a second Python process; use the
        # stdlib-only base executable so kill targets the actual test worker.
        child = subprocess.Popen([sys._base_executable, "-c", code, names[name]],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        children.append(child)
        return child

    def wait_running(name):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if manager.maintain(name, time.monotonic()):
                return
            time.sleep(0.05)
        raise AssertionError(f"private worker {name} did not recover")

    monkeypatch.setattr(manager, "launch", launch)
    try:
        wait_running("codex")
        wait_running("monitor")
        backend = manager.children["codex"]
        monitor = manager.children["monitor"]
        monitor.kill()
        monitor.wait(timeout=3)
        wait_running("monitor")
        assert manager.children["monitor"].pid != monitor.pid
        assert backend.poll() is None
        assert manager.children["codex"].pid == backend.pid
        backend.kill()
        backend.wait(timeout=3)
        wait_running("codex")
        assert manager.children["codex"].pid != backend.pid
        assert manager.children["monitor"].poll() is None
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
