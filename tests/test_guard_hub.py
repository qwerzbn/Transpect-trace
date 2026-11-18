"""Recovery and monitor labels must not silently turn limited hooks into full DLP."""
from datetime import datetime, timedelta

from transpect_trace.guard import hub


def state(now, **kwargs):
    return {"updated_at": now.isoformat(), "backends": [
        {"pid": 123, "state": "PROTECTED", "requests": 3, "allowed": 2, "denied": 1}], **kwargs}


def test_legacy_codex_protected_is_only_hook_ready():
    now = datetime.now()
    row = hub.service_snapshot("codex", state(now), running=True, now=now)
    assert row["status"] == "HOOK_READY_LIMITED"
    assert row["processes"][0]["state"] == "HOOK_READY_LIMITED"
    assert row["processes"][0]["source_state"] == "PROTECTED"


def test_full_state_requires_both_acceptance_fields_and_fresh_liveness():
    now = datetime.now()
    complete = state(now, coverage={"ready": True}, egress={"ready": True})
    assert hub.service_snapshot("codex", complete, running=True, now=now)["status"] == "PROTECTED"
    assert hub.service_snapshot("codex", complete, running=False, now=now)["status"] == "OFFLINE"
    stale = hub.service_snapshot("codex", complete, running=True, now=now + timedelta(seconds=16))
    assert stale["status"] == "STALE"
    assert stale["processes"][0]["state"] == "STALE"
    complete["egress"]["ready"] = False
    assert hub.service_snapshot("codex", complete, running=True, now=now)["status"] == "HOOK_READY_LIMITED"


def test_missing_state_and_unsupported_version_never_green():
    assert hub.service_snapshot("claude", {}, running=True)["status"] == "STARTING"
    row = {"updated_at": datetime.now().isoformat(), "processes": [{"pid": 1, "state": "UNSUPPORTED_VERSION"}]}
    assert hub.service_snapshot("claude", row, running=True)["status"] == "ATTENTION"


def test_failed_backend_has_priority_over_another_ready_backend():
    now = datetime.now()
    mixed = state(now)
    mixed['backends'].append({'pid': 456, 'state': 'UNSUPPORTED_VERSION'})
    assert hub.service_snapshot('codex', mixed, running=True, now=now)['status'] == 'ATTENTION'


def test_experimental_attachment_never_claims_complete_protection():
    now = datetime.now()
    complete = state(now, coverage={'ready': True}, egress={'ready': True})
    result = hub.service_snapshot('codex', complete, running=True, now=now, experimental=True)
    assert result['status'] == 'HOOK_READY_LIMITED'


def test_claude_explicit_mode_does_not_inherit_legacy_bypass(monkeypatch):
    monkeypatch.setenv("TTRACE_CLAUDE_LIVE_TEST", "1")
    regular = hub.service_environment("claude")
    assert regular["TTRACE_CLAUDE_ALLOW_ATTACH"] == "1"
    assert "TTRACE_CLAUDE_LIVE_TEST" not in regular
    assert hub.service_environment("claude", live_test=True)["TTRACE_CLAUDE_LIVE_TEST"] == "1"


class Process:
    returncode = None

    def poll(self):
        return self.returncode


def test_supervisor_crash_is_restarted_after_backoff_without_client_stop(monkeypatch):
    alive = {name: False for name in hub.SERVICE_MUTEXES.values()}
    monkeypatch.setattr(hub, "mutex_running", lambda name: alive[name])
    manager = hub.Hub()
    launches = []

    def launch(name):
        process = Process()
        launches.append((name, process))
        return process

    monkeypatch.setattr(manager, "launch", launch)
    assert not manager.maintain("codex", 0)
    assert len(launches) == 1
    alive[hub.SERVICE_MUTEXES["codex"]] = True
    assert manager.maintain("codex", 1)
    assert manager.maintain("codex", 32)
    alive[hub.SERVICE_MUTEXES["codex"]] = False
    launches[0][1].returncode = 1
    assert not manager.maintain("codex", 33)
    assert len(launches) == 1
    assert manager.recovery["codex"].failures == 1
    assert not manager.maintain("codex", 34)
    assert len(launches) == 1
    manager.maintain("codex", 35)
    assert len(launches) == 2


def test_adopt_running_supervisor_and_never_replace_a_hung_child(monkeypatch):
    monkeypatch.setattr(hub, "mutex_running", lambda name: True)
    manager = hub.Hub()
    monkeypatch.setattr(manager, "launch", lambda name: (_ for _ in ()).throw(AssertionError("must not duplicate")))
    assert manager.maintain("codex", 1)
    assert "codex" not in manager.owned
    monkeypatch.setattr(hub, "mutex_running", lambda name: False)
    manager.children["codex"] = Process()
    manager.maintain("codex", 40)
    manager.maintain("codex", 80)


def test_monitor_recovery_does_not_mutate_backend_children(monkeypatch):
    manager = hub.Hub()
    backend = Process()
    manager.children["codex"] = backend
    monkeypatch.setattr(hub, "mutex_running", lambda name: False)
    launched = []
    monkeypatch.setattr(manager, "launch", lambda name: launched.append(name) or Process())
    manager.maintain("monitor", 0)
    manager.children["monitor"].returncode = 1
    manager.maintain("monitor", 1)
    manager.maintain("monitor", 3)
    assert launched == ["monitor", "monitor"]
    assert manager.children["codex"] is backend


def test_repeated_crash_backoff_is_bounded():
    recovery = hub.Recovery()
    for index in range(10):
        recovery.failed(100, "crash")
    assert recovery.next_attempt == 130
    recovery.healthy(101)
    recovery.healthy(132)
    assert recovery.failures == 0


def test_partial_state_write_is_not_reported_as_protected(tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"unfinished":', encoding="utf-8")
    assert hub.read_json(path) == {}
    hub.atomic_json(path, {"status": "RUNNING"})
    assert hub.read_json(path) == {"status": "RUNNING"}


def test_watchdog_requires_unexpected_matching_generation():
    active = {"pid": 42, "status": "RUNNING", "claude_live_test": True}
    assert hub.recovery_allowed(active, stop_requested=False, expected_pid=42)
    assert not hub.recovery_allowed(active, stop_requested=True, expected_pid=42)
    assert not hub.recovery_allowed(active, stop_requested=False, expected_pid=43)
    for status in ("STOPPING", "STOPPED", "STOP_INCOMPLETE"):
        assert not hub.recovery_allowed({**active, "status": status}, stop_requested=False, expected_pid=42)


def _launcher_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("guard_hub_launcher_test", hub.ROOT / "scripts" / "guard_hub.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_explicit_stop_marker_prevents_watchdog_launch(tmp_path, monkeypatch):
    launcher = _launcher_module()
    monkeypatch.setattr(hub, "STATE_DIR", tmp_path)
    hub.atomic_json(tmp_path / "state.json", {"pid": 42, "status": "RUNNING", "claude_live_test": True})
    hub.atomic_json(tmp_path / hub.STOP_INTENT_FILE, {"hub_pid": 42})
    monkeypatch.setattr(hub, "hidden_process", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not relaunch")))
    assert launcher.start(recover_pid=42) == 0
    assert (tmp_path / hub.STOP_INTENT_FILE).exists()


def test_stop_persists_intent_before_signalling(tmp_path, monkeypatch):
    launcher = _launcher_module()
    monkeypatch.setattr(hub, "STATE_DIR", tmp_path)
    hub.atomic_json(tmp_path / "state.json", {"pid": 42, "status": "RUNNING"})

    def signal():
        assert hub.read_json(tmp_path / hub.STOP_INTENT_FILE)["hub_pid"] == 42
        return False

    monkeypatch.setattr(hub, "signal_stop", signal)
    assert launcher.stop() == 1
    assert not hub.recovery_allowed(hub.read_json(tmp_path / "state.json"),
                                    stop_requested=True, expected_pid=42)


def test_watchdog_inherits_mode_and_manual_start_clears_old_stop(tmp_path, monkeypatch):
    launcher = _launcher_module()
    monkeypatch.setattr(hub, "STATE_DIR", tmp_path)
    hub.atomic_json(tmp_path / "state.json", {"pid": 42, "status": "RUNNING", "claude_live_test": True})
    launches = []
    monkeypatch.setattr(hub, "hidden_process", lambda args, **kwargs: launches.append(args) or Process())
    running = iter([False, True])
    monkeypatch.setattr(hub, "mutex_running", lambda _: next(running))
    assert launcher.start(live_test=False, recover_pid=42) == 0
    assert "--claude-live-test" in launches[-1]
    hub.atomic_json(tmp_path / hub.STOP_INTENT_FILE, {"hub_pid": 42})
    running = iter([False, True])
    assert launcher.start(live_test=False) == 0
    assert not (tmp_path / hub.STOP_INTENT_FILE).exists()
    assert "--claude-live-test" not in launches[-1]
