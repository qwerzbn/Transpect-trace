"""Resident Claude discovery must never turn a lab hook into full protection."""
from __future__ import annotations

from pathlib import Path
import threading

from transpect_trace.guard import claude_service as svc


def _supervisor(tmp_path, monkeypatch, *, coverage=False, boundary=False):
    monkeypatch.setattr(svc.common, "_kernel", lambda: object())
    supervisor = svc.ClaudeSupervisor(
        state_dir=tmp_path, log=lambda message: None,
        coverage_check=lambda: (coverage, "coverage test"),
        boundary_check=lambda: (boundary, "boundary test"))
    supervisor.pin = svc.load_pin()
    supervisor.user_sid = "S-1-5-21-1"
    supervisor.target_path = tmp_path / "claude.exe"
    supervisor.engine = object()
    supervisor.run_dir = tmp_path / "run"
    return supervisor


def _details(path: Path, birth=7):
    return {"pid": 42, "creation_filetime": birth,
            "image_path": str(path), "command_line": f'"{path}"',
            "user_sid": "S-1-5-21-1"}


def test_fixed_version_waits_for_both_acceptance_gates(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path, monkeypatch)
    monkeypatch.setattr(supervisor.hashes, "sha256", lambda path: supervisor.pin["binary"]["sha256"])
    monkeypatch.setattr(svc, "ensure_dll", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("unaccepted build must not be injected")))
    supervisor._refresh_readiness()
    supervisor._consider(42, _details(supervisor.target_path))
    row = supervisor.processes[(42, 7)]
    assert row.state == "ATTACH_DISABLED"
    assert supervisor.state()["overall"] == "NOT_READY"
    assert not supervisor.controllers


def test_other_claude_distribution_is_visible_but_not_attached(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path, monkeypatch, coverage=True, boundary=True)
    supervisor._refresh_readiness()
    supervisor._consider(42, _details(tmp_path / "extension" / "claude.exe"))
    row = supervisor.processes[(42, 7)]
    assert row.state == "OUT_OF_SCOPE" and "VS Code" in row.detail
    assert not supervisor.controllers


def test_changed_binary_is_unsupported_even_when_boundary_ready(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path, monkeypatch, coverage=True, boundary=True)
    monkeypatch.setattr(supervisor.hashes, "sha256", lambda path: "f" * 64)
    supervisor._refresh_readiness()
    supervisor._consider(42, _details(supervisor.target_path))
    assert supervisor.processes[(42, 7)].state == "UNSUPPORTED_VERSION"
    assert not supervisor.controllers


def test_full_status_requires_both_gates_and_degrades_on_loss(tmp_path, monkeypatch):
    conditions = {"coverage": False, "boundary": False}
    monkeypatch.setattr(svc.common, "_kernel", lambda: object())
    supervisor = svc.ClaudeSupervisor(
        state_dir=tmp_path, log=lambda message: None,
        coverage_check=lambda: (conditions["coverage"], "model coverage"),
        boundary_check=lambda: (conditions["boundary"], "tool boundary"))
    row = svc.ClaudeProcessStatus(42, 7, str(tmp_path / "claude.exe"),
                                  state="HOOK_READY_LIMITED")
    supervisor.processes[(42, 7)] = row
    supervisor._refresh_readiness()
    assert row.state == "HOOK_READY_LIMITED"
    conditions["coverage"] = True
    supervisor._refresh_readiness()
    assert row.state == "HOOK_READY_LIMITED"
    conditions["boundary"] = True
    supervisor._refresh_readiness()
    assert row.state == "PROTECTED"
    class Controller:
        controlled_stop = True
        finished = threading.Event()
        stop_requested = threading.Event()

    controller = Controller()
    supervisor.controllers[(42, 7)] = controller
    conditions["boundary"] = False
    supervisor._refresh_readiness()
    assert row.state == "HOOK_READY_LIMITED"
    assert controller.stop_requested.is_set() and controller.controlled_stop is False


def test_pid_reuse_exits_old_generation(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path, monkeypatch)
    old = svc.ClaudeProcessStatus(42, 7, "old", state="ATTACH_DISABLED")
    new = svc.ClaudeProcessStatus(42, 8, "new", state="HOOK_READY_LIMITED")
    supervisor.processes[(42, 7)] = old
    supervisor.processes[(42, 8)] = new
    supervisor._mark_exits({42}, {42: 8})
    assert old.state == "EXITED" and new.state == "HOOK_READY_LIMITED"


def test_accepted_generation_starts_one_controller(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path, monkeypatch, coverage=True, boundary=True)
    supervisor._refresh_readiness()
    monkeypatch.setattr(supervisor.hashes, "sha256", lambda path: supervisor.pin["binary"]["sha256"])
    monkeypatch.setattr(svc, "check_binary", lambda pin, path: None)
    monkeypatch.setattr(svc, "ensure_dll", lambda pin, path: tmp_path / "guard.dll")
    started = []

    class Controller:
        def __init__(self, details, dll, engine, run_dir, status, log):
            self.status = status

        def start(self):
            started.append(self.status.pid)
            self.status.state = "ATTACHING"

    monkeypatch.setattr(svc, "ClaudeController", Controller)
    details = _details(supervisor.target_path)
    supervisor._consider(42, details)
    supervisor._consider(42, details)
    assert started == [42]
    assert supervisor.processes[(42, 7)].state == "ATTACHING"
    assert supervisor.state()["overall"] == "NOT_READY"
