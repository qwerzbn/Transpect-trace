"""A watcher heartbeat is never evidence that every desktop prompt was gated."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import desktop_guard_supervisor as supervisor  # noqa: E402


def _subject(pid: int = 401, birth: int = 11644473600 * 10_000_000) -> dict:
    return {
        "pid": pid, "creation_filetime": birth, "desktop_pid": 100,
        "package_full_name": supervisor.desktop_demo.PACKAGE_FULL_NAME,
        "baseline": {"version": supervisor.desktop_demo.BACKEND_VERSION,
                     "sha256": supervisor.desktop_demo.BACKEND_IMAGE_SHA256},
    }


def _setup(monkeypatch, tmp_path, *, activate: bool, ready: bool = False):
    monkeypatch.setattr(supervisor.desktop_demo, "image_identity",
                        lambda pid: {"creation_filetime": 123})
    monkeypatch.setattr(supervisor.desktop_demo, "_candidate_pids", lambda: [401])
    monkeypatch.setattr(supervisor.desktop_demo, "collect_desktop_observation_identity",
                        lambda pid: _subject(pid))
    monkeypatch.setattr(supervisor, "_process_generation_alive", lambda pid, birth: True)
    monkeypatch.setattr(supervisor.desktop_demo, "status", lambda pid, guard: {
        "backend": {"pid": pid, "creation_filetime": _subject(pid)["creation_filetime"]},
        "ready_for_live_trial": ready, "live_guard_resident": False,
        "gaps": [] if ready else ["live_activation_paused_after_desktop_error"],
    })
    return supervisor.Supervisor(tmp_path, activate=activate)


def test_watcher_is_observation_only_by_default(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=False, ready=True)
    monkeypatch.setattr(watch, "_launch", lambda subject: pytest.fail("unexpected Native launch"))
    state = watch.tick()
    assert state["pinned_backend_sha256"] == supervisor.desktop_demo.BACKEND_IMAGE_SHA256
    assert state["backends"][0]["controller_state"] == "observation_only"
    assert state["backends"][0]["identity_verified"] is True
    assert state["backends"][0]["first_observation_gap_seconds"] > 0
    assert state["model_egress_status"] == supervisor.MODEL_NOT_COVERED
    assert state["every_prompt_coverage_attested"] is False
    assert state["startup_gap_possible"] is True
    first_gap = state["backends"][0]["first_observation_gap_seconds"]
    monkeypatch.setattr(supervisor.time, "time", lambda: 2_000_000_000)
    assert watch.tick()["backends"][0]["first_observation_gap_seconds"] == first_gap


def test_activation_request_obeys_paused_controller_preflight(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=True, ready=False)
    monkeypatch.setattr(watch, "_launch", lambda subject: pytest.fail("unexpected Native launch"))
    row = watch.tick()["backends"][0]
    assert row["controller_state"] == "preflight_rejected"
    assert row["preflight_gaps"] == ["live_activation_paused_after_desktop_error"]
    assert row["model_egress_status"] == supervisor.MODEL_NOT_COVERED


def test_launch_exact_generation_once_without_claiming_coverage(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=True, ready=True)

    class Process:
        def __init__(self):
            self.exit_code = None

        def poll(self):
            return self.exit_code

        def wait(self, timeout):
            self.exit_code = 0
            return 0

    process = Process()
    launched = []

    def launch(subject):
        launched.append(subject)
        output = tmp_path / "runs" / "401-test"
        output.mkdir(parents=True)
        (output / "status.json").write_text(json.dumps({
            "state": "ready", "native_ready": True, "pipe_ready": True,
            "live_model_requests_observed": 3,
        }), encoding="utf-8")
        return supervisor._Controller(401, subject["creation_filetime"], output,
                                      process, "2026-11-08T00:00:00+00:00")

    monkeypatch.setattr(watch, "_launch", launch)
    first = watch.tick()["backends"][0]
    second = watch.tick()["backends"][0]
    assert len(launched) == 1
    assert first["controller_state"] == "starting"
    assert second["controller_state"] == "ready"
    assert second["native_requests_observed"] == 3
    assert second["model_egress_status"] == supervisor.MODEL_NOT_COVERED
    assert second["every_prompt_coverage_attested"] is False
    process.exit_code = 2
    assert watch.tick()["backends"][0]["controller_state"] == "exited"
    assert len(launched) == 1


def test_pid_reuse_rechecks_process_birth(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=False)
    watch.tick()
    new = _subject(birth=_subject()["creation_filetime"] + 1)
    monkeypatch.setattr(supervisor, "_process_generation_alive", lambda pid, birth: False)
    monkeypatch.setattr(supervisor.desktop_demo, "collect_desktop_observation_identity",
                        lambda pid: new)
    monkeypatch.setattr(supervisor.desktop_demo, "status", lambda pid, guard: {
        "backend": {"pid": pid, "creation_filetime": new["creation_filetime"]},
        "ready_for_live_trial": False, "live_guard_resident": False, "gaps": [],
    })
    assert watch.tick()["backends"][0]["creation_filetime"] == new["creation_filetime"]


def test_preflight_rejects_changed_generation(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=True, ready=True)
    monkeypatch.setattr(supervisor.desktop_demo, "status", lambda pid, guard: {
        "backend": {"pid": pid, "creation_filetime": 1},
        "ready_for_live_trial": True,
    })
    monkeypatch.setattr(watch, "_launch", lambda subject: pytest.fail("unexpected Native launch"))
    row = watch.tick()["backends"][0]
    assert row["controller_state"] == "preflight_failed"
    assert "changed" in row["preflight_error"]


def test_auto_update_rejection_is_visible_without_activation(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=True, ready=True)
    monkeypatch.setattr(supervisor.desktop_demo, "collect_desktop_observation_identity",
                        lambda pid: (_ for _ in ()).throw(
                            ValueError("desktop observation package pin mismatch")))
    monkeypatch.setattr(watch, "_launch", lambda subject: pytest.fail("unexpected Native launch"))
    state = watch.tick()
    assert state["backends"] == []
    assert state["unmatched_codex_processes"] == [
        {"pid": 401, "identity_rejection":
         "ValueError: desktop observation package pin mismatch"}]
    assert state["model_egress_status"] == supervisor.MODEL_NOT_COVERED


def test_stale_status_cannot_claim_a_live_watcher(tmp_path):
    supervisor._write_json(tmp_path / "status.json", {
        "schema": supervisor.SCHEMA, "state": "watching",
        "heartbeat_utc": "2020-01-01T00:00:00+00:00", "poll_seconds": 2,
        "watcher_pid": 400, "watcher_creation_filetime": 1,
    })
    result = supervisor.status(tmp_path)
    assert result["state"] == "stale_or_stopped"
    assert result["watcher_alive"] is False
    assert result["model_egress_status"] == supervisor.MODEL_NOT_COVERED


def test_stop_confirms_absent_supervisor_without_prior_controller(tmp_path):
    assert supervisor.stop(tmp_path)["stop_confirmed"] is True


def test_fast_stop_waits_for_controller_to_claim_run_directory(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=False)

    class Process:
        def poll(self):
            return None

    output = tmp_path / "runs" / "new-generation"
    child = supervisor._Controller(401, 42, output, Process(), "now")
    assert watch._stop_controller(child) is False
    assert not output.exists()
    assert child.stopped_requested is False
    output.mkdir(parents=True)
    assert watch._stop_controller(child) is True
    assert (output / "STOP").read_text(encoding="ascii") == "supervisor stop requested\n"
    assert child.stopped_requested is True


def test_stop_signal_write_failure_can_be_retried(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=False)

    class Process:
        def poll(self):
            return None

    output = tmp_path / "runs" / "new-generation"
    output.mkdir(parents=True)
    child = supervisor._Controller(401, 42, output, Process(), "now")
    write_text = Path.write_text

    def fail_stop(path, *args, **kwargs):
        if path == output / "STOP":
            raise OSError("synthetic write failure")
        return write_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_stop)
    with pytest.raises(OSError, match="synthetic write failure"):
        watch._stop_controller(child)
    assert child.stopped_requested is False
    monkeypatch.setattr(Path, "write_text", write_text)
    assert watch._stop_controller(child) is True


def test_transient_inventory_error_keeps_existing_controller(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=False)
    watch.tick()

    class Process:
        def poll(self):
            return None

    subject = _subject()
    output = tmp_path / "runs" / "running"
    output.mkdir(parents=True)
    (output / "status.json").write_text('{"state":"ready"}', encoding="utf-8")
    watch.controllers[(subject["pid"], subject["creation_filetime"])] = (
        supervisor._Controller(subject["pid"], subject["creation_filetime"],
                               output, Process(), "now"))
    monkeypatch.setattr(supervisor.desktop_demo, "_candidate_pids",
                        lambda: (_ for _ in ()).throw(OSError("CIM unavailable")))
    state = watch.tick()
    assert state["backends"][0]["controller_state"] == "ready"
    assert state["backends"][0]["identity_inventory_fresh"] is False
    assert state["identity_inventory_fresh"] is False
    assert state["errors"] == ["OSError: CIM unavailable"]
    assert not (output / "STOP").exists()


def test_inventory_error_cannot_start_new_controller(monkeypatch, tmp_path):
    watch = _setup(monkeypatch, tmp_path, activate=False, ready=True)
    watch.tick()
    watch.activate = True
    monkeypatch.setattr(supervisor.desktop_demo, "_candidate_pids",
                        lambda: (_ for _ in ()).throw(OSError("CIM unavailable")))
    monkeypatch.setattr(watch, "_launch", lambda subject: pytest.fail("unexpected Native launch"))
    assert watch.tick()["backends"][0]["controller_state"] == "inventory_unavailable"


def test_stop_accepts_controller_that_exited_before_claiming_output(tmp_path):
    supervisor._write_json(tmp_path / "status.json", {
        "schema": supervisor.SCHEMA, "state": "stopped",
        "controller_shutdowns": [{"controller_exit_code": 2,
                                  "controller_never_created_run_dir": True,
                                  "backend_generation_alive": True}],
        "backends": [{"controller_output": str(tmp_path / "never-created")}],
    })
    assert supervisor.stop(tmp_path)["stop_confirmed"] is True

