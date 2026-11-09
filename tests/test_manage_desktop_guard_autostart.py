"""The logon task installer must not turn on a paused Native experiment."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import manage_desktop_guard_autostart as installer  # noqa: E402


def _fixture(monkeypatch, tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    supervisor = scripts / "desktop_guard_supervisor.py"
    supervisor.write_text("# fixture\n", encoding="utf-8")
    runner = tmp_path / ".venv" / "Scripts" / "pythonw.exe"
    runner.parent.mkdir(parents=True)
    runner.write_bytes(b"fixture")
    (tmp_path / "runs").mkdir()
    monkeypatch.setattr(installer, "ROOT", tmp_path)
    monkeypatch.setattr(installer, "SUPERVISOR", supervisor)
    monkeypatch.setattr(installer, "_pythonw", lambda: runner)
    return tmp_path / "runs" / "supervisor"


def _return(operation, *, matches=True, present=False):
    return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({
        "schema": installer.SCHEMA, "operation": operation,
        "configuration_matches": matches, "task_present": present,
    }))


def test_default_install_registers_observation_without_activation(monkeypatch, tmp_path):
    state = _fixture(monkeypatch, tmp_path)
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(argv=argv, env=kwargs["env"])
        return _return("install")

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    result = installer.operate("install", state_dir=state)
    assert result["configuration_matches"]
    assert state.is_dir()
    assert seen["env"]["TTRACE_DESKTOP_TASK_ACTIVATE"] == "0"
    assert seen["env"]["TTRACE_DESKTOP_TASK_START"] == "1"
    assert seen["env"]["TTRACE_DESKTOP_TASK_SCRIPT"] == str(installer.SUPERVISOR)
    assert "-AtLogOn" in seen["argv"][-1]
    assert "remove it gracefully before reinstalling" in seen["argv"][-1]


def test_activation_gate_blocks_scheduled_task_mutation(monkeypatch, tmp_path):
    state = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(installer, "_activation_preflight",
                        lambda: (_ for _ in ()).throw(ValueError("paused")))
    monkeypatch.setattr(installer.subprocess, "run",
                        lambda *_args, **_kwargs: pytest.fail("must not register"))
    with pytest.raises(ValueError, match="paused"):
        installer.operate("install", state_dir=state, activate=True)
    assert not state.exists()


def test_status_and_remove_never_request_activation(monkeypatch, tmp_path):
    state = _fixture(monkeypatch, tmp_path)
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(kwargs["env"].copy())
        return _return(kwargs["env"]["TTRACE_DESKTOP_TASK_OPERATION"])

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    assert installer.operate("status", state_dir=state)["configuration_matches"]
    assert installer.operate("remove", state_dir=state)["configuration_matches"]
    assert [entry["TTRACE_DESKTOP_TASK_ACTIVATE"] for entry in seen] == ["0", "0", "0"]
    assert not state.exists()


def test_state_dir_must_stay_within_repository_runs(monkeypatch, tmp_path):
    _fixture(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="child of repository runs"):
        installer._state_dir(tmp_path / "outside")
    with pytest.raises(ValueError, match="child of repository runs"):
        installer._state_dir(tmp_path / "runs")


def test_unexpected_task_scheduler_response_is_rejected(monkeypatch, tmp_path):
    state = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(installer.subprocess, "run",
                        lambda *_args, **_kwargs: _return("wrong"))
    with pytest.raises(RuntimeError, match="unexpected result"):
        installer.operate("status", state_dir=state)


def test_scheduler_failure_is_reported(monkeypatch, tmp_path):
    state = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(installer.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=1, stderr="Access is denied", stdout=""))
    with pytest.raises(RuntimeError, match="Access is denied"):
        installer.operate("install", state_dir=state)


def test_remove_waits_for_supervisor_stop_confirmation(monkeypatch, tmp_path):
    state = _fixture(monkeypatch, tmp_path)
    python = tmp_path / ".venv" / "Scripts" / "python.exe"
    python.write_bytes(b"fixture")
    called = []

    def fake_run(argv, **kwargs):
        if argv[0] == "powershell.exe":
            op = kwargs["env"]["TTRACE_DESKTOP_TASK_OPERATION"]
            called.append(op)
            return _return(op, present=True)
        called.append("supervisor_stop")
        assert argv[-3:] == ["stop", "--state-dir", str(state)]
        return SimpleNamespace(returncode=0, stderr="",
                               stdout=json.dumps({"stop_confirmed": True}))

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    assert installer.operate("remove", state_dir=state)["configuration_matches"]
    assert called == ["status", "supervisor_stop", "remove"]


def test_remove_retains_task_when_lease_release_unconfirmed(monkeypatch, tmp_path):
    state = _fixture(monkeypatch, tmp_path)
    (tmp_path / ".venv" / "Scripts" / "python.exe").write_bytes(b"fixture")
    called = []

    def fake_run(argv, **kwargs):
        if argv[0] == "powershell.exe":
            op = kwargs["env"]["TTRACE_DESKTOP_TASK_OPERATION"]
            called.append(op)
            return _return(op, present=True)
        called.append("supervisor_stop")
        return SimpleNamespace(returncode=0, stderr="",
                               stdout=json.dumps({"stop_confirmed": False}))

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="task was retained"):
        installer.operate("remove", state_dir=state)
    assert called == ["status", "supervisor_stop"]


def test_remove_rejects_foreign_task_before_stop(monkeypatch, tmp_path):
    state = _fixture(monkeypatch, tmp_path)
    called = []

    def fake_run(argv, **kwargs):
        called.append(kwargs["env"]["TTRACE_DESKTOP_TASK_OPERATION"])
        return _return("status", matches=False, present=True)

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="unrecognized scheduled task"):
        installer.operate("remove", state_dir=state)
    assert called == ["status"]
