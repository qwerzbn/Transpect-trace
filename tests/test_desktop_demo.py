"""Live controller preflight stays fail closed without touching a live PID."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import desktop_demo as demo  # noqa: E402


def _subject(backend: Path) -> dict:
    return {"pid": 1234, "creation_filetime": 42, "desktop_pid": 4321,
            "baseline": {"path": str(backend), "sha256": demo.BACKEND_IMAGE_SHA256,
                         "version": demo.BACKEND_VERSION},
            "user_sid": "S-1-5-21-1", "package_full_name": demo.PACKAGE_FULL_NAME}


def _artifacts(tmp_path: Path, monkeypatch):
    backend, dll = tmp_path / "codex.exe", tmp_path / "lab.dll"
    backend.write_bytes(b"synthetic backend path fixture")
    dll.write_bytes(b"synthetic DLL fixture")
    dll_hash = hashlib.sha256(dll.read_bytes()).hexdigest()
    source_hashes = {name.replace("/", "\\"): demo._hash(demo.ROOT / name)
                     for name in demo.EXPECTED_SOURCES}
    manifest = {"schema": demo.BUILD_SCHEMA, "lab_only": True,
                "status": "synthetic_collection_only_not_desktop_validated",
                "deny_behavior": "terminate_process_exit_76",
                "backend": {"path": str(backend), "sha256": demo.BACKEND_IMAGE_SHA256,
                            "version": demo.BACKEND_VERSION},
                "artifact": {"path": str(dll), "sha256": dll_hash},
                "pins": dict(demo.EXPECTED_PINS),
                "capture_evidence": {route: {"full_body_readback_exact": True,
                                             "observation_only": True,
                                             "decrypted_archive_verified": True,
                                             "collection_envelope_verified": True}
                                     for route in ("http", "wss")},
                "sources_sha256": source_hashes}
    (tmp_path / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    results = []
    for transport in ("http", "wss"):
        for case in ("allow", "dlp_block"):
            blocked = case == "dlp_block"
            results.append({"transport": transport, "case": case, "validated": True,
                            "dll_sha256": dll_hash,
                            "backend_sha256": demo.BACKEND_IMAGE_SHA256,
                            "synthetic_only": True, "local_origin_only": True,
                            "codex_command_hooks_present": False,
                            "target_trace_exact": True,
                            "all_origin_seen_by_native_pipe": True,
                            "all_allowed_pipe_requests_sent": True,
                            "status": {"injected_before_thread_start": True,
                                       "hook_ready": True, "pipe_ready": True},
                            "pipe_requests": [{"target": True,
                                               "decision": "deny" if blocked else "allow",
                                               "archive_readback_exact": True}],
                            "target_origin_requests": 0 if blocked else 1,
                            "target_origin_body_bytes": 0 if blocked else 100,
                            "non_warmup_wire_body_bytes_received": 0,
                            "non_warmup_body_counter_verified": True,
                            "process_exit_code": 76 if blocked else 1,
                            "pipe_errors": [], "errors": []})
    report = {"schema": demo.LAB_SCHEMA,
              "backend_sha256": demo.BACKEND_IMAGE_SHA256, "validated": True,
              "synthetic_only": True, "production_desktop_coverage_validated": False,
              "build": {"sha256": dll_hash}, "results": results}
    report_path = tmp_path / "summary.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    real_hash = demo._hash
    monkeypatch.setattr(demo, "_hash", lambda path: (
        demo.BACKEND_IMAGE_SHA256 if Path(path) == backend else real_hash(path)))
    return backend, dll, report_path, manifest, report


def _graceful_artifacts(tmp_path: Path, monkeypatch):
    backend, dll = tmp_path / "codex.exe", tmp_path / "graceful.dll"
    backend.write_bytes(b"synthetic pinned backend")
    dll.write_bytes(b"synthetic graceful DLL")
    dll_sha = hashlib.sha256(dll.read_bytes()).hexdigest()
    source_hashes = {name.replace("/", "\\"): demo._hash(demo.ROOT / name)
                     for name in demo.EXPECTED_SOURCES}
    manifest = {
        "schema": demo.GRACEFUL_BUILD_SCHEMA, "lab_only": True,
        "status": "unvalidated_graceful_candidate_not_desktop_adapter",
        "deny_behavior": "return_rust_error_candidate",
        "desktop_adapter_created": False,
        "backend": {"path": str(backend), "version": demo.BACKEND_VERSION,
                    "sha256": demo.BACKEND_IMAGE_SHA256},
        "artifact": {"path": str(dll), "sha256": dll_sha},
        "pins": demo.GRACEFUL_PINS, "abi": demo.GRACEFUL_ABI,
        "capture_evidence": {route: {
            "full_body_readback_exact": True, "observation_only": True,
            "decrypted_archive_verified": True,
            "collection_envelope_verified": True}
            for route in ("http", "wss")},
        "sources_sha256": source_hashes,
    }
    manifest_path = tmp_path / "build-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    def case(transport):
        return {
            "schema": demo.GRACEFUL_LAB_SCHEMA, "transport": transport,
            "collection_mode": "shared_request_archive",
            "dll_sha256": dll_sha, "backend_sha256": demo.BACKEND_IMAGE_SHA256,
            "validated": True, "synthetic_only": True, "local_origin_only": True,
            "codex_command_hooks_present": False, "target_trace_exact": True,
            "shared_archive_layout_verified": True,
            "all_request_archive_readback_exact": True,
            "deny_origin_requests": 0, "deny_origin_body_bytes": 0,
            "deny_non_warmup_wire_body_bytes_received": 0,
            "denied_origin_requests_after_followup": 0,
            "denied_turn_completion": {"status": "failed"},
            "post_deny_alive": True, "post_deny_identity_stable": True,
            "same_pid_for_followup": True, "followup_origin_match": True,
            "backend_alive_after_followup": True,
            "repeat_denied_turn_completion": {"status": "failed"},
            "repeat_deny_body_bytes_delta": 0, "repeat_same_pid": True,
            "repeat_followup_origin_match": True,
            "backend_alive_after_repeat": True,
            "identity": {"pid": 1234, "creation_filetime": 42,
                         "mode": "app-server",
                         "image_sha256": demo.BACKEND_IMAGE_SHA256},
            "pipe_requests": [
                {"denied_marker": True, "decision": "deny", "action": "BLOCK",
                 "bytes": 1000},
                {"allowed_marker": True, "decision": "allow", "action": "ALLOW"}],
            "pipe_errors": [], "errors": [],
        }

    summary = {
        "schema": demo.GRACEFUL_LAB_SCHEMA,
        "backend_sha256": demo.BACKEND_IMAGE_SHA256,
        "validated": True, "synthetic_only": True,
        "production_desktop_coverage_validated": False,
        "collection_mode": "shared_request_archive",
        "controller_sources_unchanged_during_lab": True,
        "controller_sources_sha256": dict(demo.GRACEFUL_CONTROLLER_SOURCES),
        "build": {"sha256": dll_sha, "manifest_sha256": manifest_sha,
                  "lab_only": True, "deny_behavior": "return_rust_error_candidate"},
        "results": [case("http"), case("wss")],
    }
    repeat = json.loads(json.dumps(summary))
    repeat["results"] = [repeat["results"][0]]
    repeat_row = repeat["results"][0]
    repeat_row["identity"] = {**repeat_row["identity"], "pid": 5678,
                              "creation_filetime": 43}
    repeat_row["large_multi_item"] = True
    repeat_row["denied_input_items"] = 536
    repeat_row["pipe_requests"][0]["bytes"] = 950001
    report_path, repeat_path = tmp_path / "summary.json", tmp_path / "repeat.json"
    report_path.write_text(json.dumps(summary), encoding="utf-8")
    repeat_path.write_text(json.dumps(repeat), encoding="utf-8")
    monkeypatch.setattr(demo, "GRACEFUL_DLL_SHA256", dll_sha)
    monkeypatch.setattr(demo, "GRACEFUL_MANIFEST_SHA256", manifest_sha)
    monkeypatch.setattr(demo, "GRACEFUL_LAB_REPORT_SHA256",
                        hashlib.sha256(report_path.read_bytes()).hexdigest())
    monkeypatch.setattr(demo, "GRACEFUL_REPEAT_REPORT_SHA256",
                        hashlib.sha256(repeat_path.read_bytes()).hexdigest())
    real_hash = demo._hash
    monkeypatch.setattr(demo, "_hash", lambda path: (
        demo.BACKEND_IMAGE_SHA256 if Path(path) == backend else real_hash(path)))
    return backend, dll, report_path, repeat_path, manifest, summary, repeat


def _lease_artifacts(tmp_path: Path, monkeypatch):
    backend, dll = tmp_path / "codex.exe", tmp_path / "lease.dll"
    backend.write_bytes(b"synthetic pinned backend")
    dll.write_bytes(b"synthetic lease DLL")
    dll_sha = hashlib.sha256(dll.read_bytes()).hexdigest()
    sources = {name.replace("/", "\\"): demo._hash(demo.ROOT / name)
               for name in demo.EXPECTED_SOURCES}
    manifest = {
        "schema": demo.LEASE_BUILD_SCHEMA, "lab_only": True,
        "status": "unvalidated_test_only_graceful_lease_candidate",
        "deny_behavior": "return_rust_error_candidate",
        "controller_loss_behavior": "bypass_and_disable_hooks",
        "desktop_adapter_created": False,
        "backend": {"path": str(backend), "version": demo.BACKEND_VERSION,
                    "sha256": demo.BACKEND_IMAGE_SHA256},
        "artifact": {"path": str(dll), "sha256": dll_sha},
        "pins": demo.GRACEFUL_PINS, "abi": demo.GRACEFUL_ABI,
        "lease": {"mutex": "Local\\ttrace-guard-lease-<pid>-<creation_filetime>",
                  "disabled_event": "Local\\ttrace-guard-disabled-<pid>-<creation_filetime>",
                  "owner": "controller_main_thread", "dll_stays_mapped": True},
        "capture_evidence": {transport: {
            "full_body_readback_exact": True, "observation_only": True,
            "decrypted_archive_verified": True,
            "collection_envelope_verified": True}
            for transport in ("http", "wss")},
        "sources_sha256": sources,
    }
    manifest_path = tmp_path / "build-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    report = {
        "schema": demo.LEASE_LAB_SCHEMA,
        "backend_sha256": demo.BACKEND_IMAGE_SHA256,
        "build": {"dll_sha256": dll_sha, "manifest_sha256": manifest_sha,
                  "controller_loss_behavior": "bypass_and_disable_hooks",
                  "lab_only": True},
        "synthetic_only": True,
        "production_desktop_coverage_validated": False,
        "controller_sources_unchanged_during_lab": True,
        "controller_sources_sha256": dict(demo.GRACEFUL_CONTROLLER_SOURCES),
        "controller_lease_class_sha256": hashlib.sha256(
            demo.inspect.getsource(demo._ControllerLease).encode("utf-8")).hexdigest(),
        "validated": True,
        "results": [{
            "schema": demo.LEASE_LAB_SCHEMA,
            "transport": transport, "loss": loss,
            "backend_sha256": demo.BACKEND_IMAGE_SHA256,
            "dll_sha256": dll_sha,
            "synthetic_only": True, "local_origin_only": True,
            "identity": {"pid": 100 + index, "creation_filetime": 200 + index,
                         "mode": "app-server"},
            "protected_denied": True, "denied_archive_readback_exact": True,
            "denied_turn_status": "failed", "disabled_ack": True,
            "post_lease_origin_match": True,
            "no_post_lease_pipe_request": True,
            "same_pid_after_lease": True,
            "denied_origin_requests_after_lease": 0,
            "pipe_errors": [], "errors": [], "validated": True,
            "lab_only": True, "production_desktop_coverage_validated": False,
        } for index, (transport, loss) in enumerate(
            (t, l) for t in ("http", "wss") for l in ("release", "abandon"))],
    }
    report_path = tmp_path / "summary.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    lease_class_sha = report["controller_lease_class_sha256"]

    def content_case(transport, index, large=False):
        return {
            "schema": demo.LEASE_CONTENT_LAB_SCHEMA,
            "transport": transport,
            "backend_sha256": demo.BACKEND_IMAGE_SHA256,
            "dll_sha256": dll_sha,
            "identity": {"pid": 104 + index, "creation_filetime": 204 + index,
                         "mode": "app-server", "image_sha256": demo.BACKEND_IMAGE_SHA256},
            "validated": True, "synthetic_only": True, "local_origin_only": True,
            "lab_only": True, "production_desktop_coverage_validated": False,
            "codex_command_hooks_present": False,
            "lease_mode": True, "lease_released": True,
            "lease_disabled_ack": True, "lease_cleanup_error": None,
            "collection_mode": "shared_request_archive",
            "large_multi_item": large, "denied_input_items": 536 if large else 1,
            "target_trace_exact": True,
            "all_request_archive_readback_exact": True,
            "shared_archive_layout_verified": True,
            "deny_origin_requests": 0, "deny_origin_body_bytes": 0,
            "deny_non_warmup_wire_body_bytes_received": 0,
            "denied_origin_requests_after_followup": 0,
            "denied_turn_completion": {"status": "failed"},
            "repeat_denied_turn_completion": {"status": "failed"},
            "post_deny_alive": True, "post_deny_identity_stable": True,
            "same_pid_for_followup": True, "followup_origin_match": True,
            "backend_alive_after_followup": True,
            "repeat_deny_body_bytes_delta": 0, "repeat_same_pid": True,
            "repeat_followup_origin_match": True,
            "backend_alive_after_repeat": True,
            "pipe_errors": [], "errors": [],
            "pipe_requests": [
                {"denied_marker": True, "decision": "deny", "action": "BLOCK",
                 "bytes": 950001 if large else 1000},
                {"allowed_marker": True, "decision": "allow", "action": "ALLOW"}],
        }

    def content_summary(cases):
        return {
            "schema": demo.LEASE_CONTENT_LAB_SCHEMA,
            "backend_sha256": demo.BACKEND_IMAGE_SHA256,
            "build": {"sha256": dll_sha, "manifest_sha256": manifest_sha,
                      "lab_only": True,
                      "deny_behavior": "return_rust_error_candidate",
                      "lease_mode": True},
            "validated": True, "synthetic_only": True,
            "production_desktop_coverage_validated": False,
            "lease_mode": True, "collection_mode": "shared_request_archive",
            "controller_lease_class_sha256": lease_class_sha,
            "controller_sources_unchanged_during_lab": True,
            "controller_sources_sha256": dict(demo.GRACEFUL_CONTROLLER_SOURCES),
            "results": cases,
        }

    repeat_path, large_path = tmp_path / "repeat.json", tmp_path / "large.json"
    repeat = content_summary([content_case("http", 0), content_case("wss", 1)])
    large = content_summary([content_case("http", 2, large=True)])
    repeat_path.write_text(json.dumps(repeat), encoding="utf-8")
    large_path.write_text(json.dumps(large), encoding="utf-8")
    monkeypatch.setattr(demo, "LEASE_DLL_SHA256", dll_sha)
    monkeypatch.setattr(demo, "LEASE_MANIFEST_SHA256", manifest_sha)
    monkeypatch.setattr(demo, "LEASE_LAB_REPORT_SHA256", hashlib.sha256(
        report_path.read_bytes()).hexdigest())
    monkeypatch.setattr(demo, "LEASE_REPEAT_REPORT_SHA256", hashlib.sha256(
        repeat_path.read_bytes()).hexdigest())
    monkeypatch.setattr(demo, "LEASE_LARGE_REPORT_SHA256", hashlib.sha256(
        large_path.read_bytes()).hexdigest())
    real_hash = demo._hash
    monkeypatch.setattr(demo, "_hash", lambda path: (
        demo.BACKEND_IMAGE_SHA256 if Path(path) == backend else real_hash(path)))
    return backend, dll, report_path, repeat_path, large_path, manifest, report, repeat, large


def _nonretry_artifacts():
    dll = demo.DEFAULT_NONRETRY_DLL
    report = demo.DEFAULT_NONRETRY_REPORT
    backend = Path(json.loads((dll.parent / "build-manifest.json").read_text(
        encoding="utf-8"))["backend"]["path"])
    return backend, dll, report


def test_status_pauses_failstop_trial_even_when_prerequisites_pass(tmp_path, monkeypatch):
    backend = tmp_path / "codex.exe"
    backend.write_bytes(b"fixture")
    monkeypatch.setattr(demo, "_subject", lambda _pid: _subject(backend))
    monkeypatch.setattr(demo, "_lab_artifacts", lambda *_args: {"synthetic_cases_validated": 4})
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: False)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    result = demo.status(1234, dll=tmp_path / "lab.dll", lab_report=tmp_path / "summary.json")
    assert result["trial_prerequisites_met"] is True
    assert result["ready_for_live_trial"] is False
    assert result["model_egress_status"] == "MODEL_EGRESS_NOT_COVERED"
    assert result["tool_egress_status"] == "NOT_ATTESTED"
    assert result["foreground_controller_active"] is False
    assert "fail_stop_build_exits_backend_on_deny" in result["gaps"]
    assert "GPT error" in result["operational_note"]


def test_status_reports_identity_failure_without_claiming_coverage(monkeypatch):
    monkeypatch.setattr(demo, "_subject", lambda _pid: (_ for _ in ()).throw(
        ValueError("package changed")))
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    result = demo.status(1234)
    assert result["ready_for_live_trial"] is False
    assert result["model_egress_status"] == "MODEL_EGRESS_NOT_COVERED"
    assert "package changed" in result["gaps"][0]


def test_scoped_status_normalizes_uuid_and_never_claims_global_coverage(
        tmp_path, monkeypatch):
    backend = tmp_path / "codex.exe"
    backend.write_bytes(b"fixture")
    monkeypatch.setattr(demo, "_subject", lambda _pid: _subject(backend))
    monkeypatch.setattr(demo, "_graceful_lab_artifacts", lambda *_args: {
        "synthetic_cases_validated": 4})
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: False)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    value = "01A1B9F0-F1D8-7F82-AF4E-2E437F6C605A"
    result = demo.status(1234, guard="graceful", protect_thread_id=value)
    assert result["scope"] == {"kind": "thread",
                               "thread_id": value.lower(),
                               "coverage": "partial_test_only"}
    assert result["ready_for_live_trial"] is False
    assert result["model_egress_status"] == demo.MODEL_NOT_COVERED
    assert result["target_request_observed"] is False
    assert "all other" in result["operational_note"]


@pytest.mark.parametrize("value", ["not-a-uuid", "", "{", "1234"])
def test_scoped_status_rejects_invalid_thread_uuid(value):
    with pytest.raises(ValueError, match="must be a UUID"):
        demo.status(guard="graceful", protect_thread_id=value)


def test_thread_scope_rejects_failstop_guard():
    with pytest.raises(ValueError, match="requires the graceful"):
        demo.status(guard="failstop",
                    protect_thread_id="01a1b9f0-f1d8-7f82-af4e-2e437f6c605a")


def test_graceful_engine_uses_one_durable_request_archive(monkeypatch):
    calls = []
    def fake_engine(config, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(demo, "NativeCollectionEngine", fake_engine)
    graceful = demo._collection_engine(object(), "graceful")
    failstop = demo._collection_engine(object(), "failstop")
    nonretry = demo._collection_engine(object(), "nonretry_lease")
    assert calls == [
        {"archive_full_body": True, "shared_request_archive": True},
        {"archive_full_body": True, "shared_request_archive": False},
        {"archive_full_body": True, "shared_request_archive": True},
    ]
    assert graceful.concurrent_safe is False
    assert failstop.concurrent_safe is False
    assert nonretry.concurrent_safe is True


def test_generation_lease_releases_before_disabled_ack(monkeypatch):
    events = []

    class Fn:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    kernel = SimpleNamespace(
        CreateMutexW=Fn(lambda _acl, owned, name: (
            events.append(("create", owned, name)) or 99)),
        ReleaseMutex=Fn(lambda handle: (events.append(("release", handle)) or True)),
        OpenEventW=Fn(lambda _access, _inherit, name: (
            events.append(("open", name)) or 77)),
        WaitForSingleObject=Fn(lambda handle, _timeout: (
            events.append(("wait", handle)) or 0)),
        CloseHandle=Fn(lambda handle: (events.append(("close", handle)) or True)),
    )
    monkeypatch.setattr(demo, "api", lambda: kernel)
    monkeypatch.setattr(demo.c, "get_last_error", lambda: 0)
    lease = demo._ControllerLease(1234, 42)
    assert lease.lease_name == "Local\\ttrace-guard-lease-1234-42"
    assert lease.disabled_name == "Local\\ttrace-guard-disabled-1234-42"
    with pytest.raises(ValueError, match="release the Native lease"):
        lease.wait_disabled()
    lease.release()
    assert lease.wait_disabled(timeout_ms=100) is True
    lease.close()
    assert [item[0] for item in events] == [
        "create", "release", "open", "wait", "close", "close"]
    assert events[0][1:] == (True, lease.lease_name)


def test_generation_lease_missing_disabled_event_is_not_attested(monkeypatch):
    class Fn:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    kernel = SimpleNamespace(
        CreateMutexW=Fn(lambda *_args: 99),
        ReleaseMutex=Fn(lambda _handle: True),
        OpenEventW=Fn(lambda *_args: 0),
        CloseHandle=Fn(lambda _handle: True),
    )
    monkeypatch.setattr(demo, "api", lambda: kernel)
    monkeypatch.setattr(demo.c, "get_last_error", lambda: 0)
    lease = demo._ControllerLease(1234, 42)
    lease.release()
    assert lease.wait_disabled(timeout_ms=0) is False
    lease.close()


@pytest.mark.parametrize("ack", [True, False])
@pytest.mark.parametrize("guard", ["graceful_lease", "nonretry_lease"])
@pytest.mark.parametrize("seconds", [1, None])
def test_lease_run_attests_disable_before_closing_pipe(
        tmp_path, monkeypatch, ack, guard, seconds):
    monkeypatch.setattr(demo, "LIVE_TRIALS_PAUSED", False)
    backend, dll, report = (tmp_path / name for name in
                            ("codex.exe", "lease.dll", "summary.json"))
    for path in (backend, dll, report):
        path.write_bytes(b"fixture")
    subject = _subject(backend)
    events = []
    monkeypatch.setattr(demo, "_guard_config", lambda guard, _dll, _report: (
        dll, report, lambda *_args: {}))
    monkeypatch.setattr(demo, "status", lambda *_args, **_kwargs: {
        "ready_for_live_trial": True,
        "backend": {"creation_filetime": 42, "desktop_pid": 4321}})
    monkeypatch.setattr(demo, "collect_desktop_observation_identity",
                        lambda _pid: subject)
    monkeypatch.setattr(demo, "same_desktop_observation_subject", lambda *_args: True)
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: False)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    monkeypatch.setattr(demo, "_collection_engine", lambda *_args: object())
    monkeypatch.setattr(demo, "wait_ready", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(demo, "inject", lambda _pid, _dll, _baseline, *, identity_resolver:
                        (events.append("inject"), identity_resolver(1234)))
    monkeypatch.setattr(demo, "image_identity", lambda pid: (
        {"pid": pid, "creation_filetime": 7, "image_sha256": "f" * 64}
        if pid == demo.os.getpid() else
        {"pid": pid, "creation_filetime": 42,
         "image_sha256": demo.BACKEND_IMAGE_SHA256}))
    monkeypatch.setattr(demo, "_terminate_same_instance", lambda *_args: (
        events.append("terminate") or True))

    class FakeProcess:
        def __init__(self, *_args):
            pass

        def poll(self):
            return None

        def close(self):
            events.append("process_close")

    class FakeLease:
        def __init__(self, pid, creation):
            assert (pid, creation) == (1234, 42)
            events.append("lease_create")

        def release(self):
            events.append("lease_release")

        def wait_disabled(self):
            events.append("disabled_ack")
            return ack

        def close(self):
            events.append("lease_close")

    class FakePipe:
        def __init__(self, _pid, _engine, audit, **_kwargs):
            self.output = audit.parent
            self.errors = []
            self.ready = threading.Event()
            self.ready.set()
            self.lock = threading.Lock()
            self.records = []

        def start(self):
            (self.output / "STOP").write_text("test", encoding="ascii")

        def close(self):
            events.append("pipe_close")

    monkeypatch.setattr(demo, "_BackendProcess", FakeProcess)
    monkeypatch.setattr(demo, "_ControllerLease", FakeLease)
    monkeypatch.setattr(demo, "PipeServer", FakePipe)
    result = demo.run(1234, tmp_path / "output", guard=guard,
                      protect_thread_id="01a1b9f0-f1d8-7f82-af4e-2e437f6c605a",
                      seconds=seconds)
    assert result["state"] == "stopped"
    assert result["native_hooks_disabled_attested"] is ack
    assert result["lease_released"] is True
    if not ack:
        assert "not attested" in result["warning"]
    assert "terminate" not in events
    assert events.index("lease_create") < events.index("inject")
    assert events.index("lease_release") < events.index("disabled_ack")
    assert events.index("disabled_ack") < events.index("pipe_close")


def test_graceful_status_admits_two_labs_but_stays_uncovered(tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, *_ = _graceful_artifacts(tmp_path, monkeypatch)
    monkeypatch.setattr(demo, "_subject", lambda _pid: _subject(backend))
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: False)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    result = demo.status(1234, guard="graceful", dll=dll,
                         lab_report=report_path, repeat_report=repeat_path)
    assert result["ready_for_live_trial"] is False
    assert result["trial_prerequisites_met"] is True
    assert result["synthetic_native_lab_validated"] is True
    assert result["lab_gate"]["synthetic_cases_validated"] == 3
    assert result["lab_gate"]["post_deny_same_pid_followup_verified"] is True
    assert result["lab_gate"]["shared_request_archive_verified"] is True
    assert result["lab_gate"]["large_http_request_verified"] is True
    assert result["model_egress_status"] == demo.MODEL_NOT_COVERED
    assert result["foreground_controller_active"] is False
    assert "live_activation_paused_after_desktop_error" in result["gaps"]


def test_lease_status_admits_seven_labs_and_stays_uncovered(
        tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, large_path, *_ = _lease_artifacts(
        tmp_path, monkeypatch)
    monkeypatch.setattr(demo, "_subject", lambda _pid: _subject(backend))
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: False)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    result = demo.status(1234, guard="graceful_lease", dll=dll,
                         lab_report=report_path, repeat_report=repeat_path,
                         large_report=large_path,
                         protect_thread_id="01A1B9F0-F1D8-7F82-AF4E-2E437F6C605A")
    assert result["synthetic_native_lab_validated"] is True
    assert result["lab_gate"]["synthetic_cases_validated"] == 7
    assert result["lab_gate"]["safe_teardown_attested_in_lab"] is True
    assert result["lab_gate"]["integrated_model_guard_validated"] is True
    assert result["ready_for_live_trial"] is False
    assert result["model_egress_status"] == demo.MODEL_NOT_COVERED
    assert result["scope"]["coverage"] == "partial_test_only"
    assert "live_activation_paused_after_desktop_error" in result["gaps"]
    assert "lease_model_guard_lab_pending" not in result["gaps"]


@pytest.mark.parametrize("field,bad", [
    ("disabled_ack", False), ("denied_archive_readback_exact", False),
    ("post_lease_origin_match", False), ("no_post_lease_pipe_request", False),
    ("same_pid_after_lease", False), ("denied_origin_requests_after_lease", 1),
])
def test_lease_gate_rejects_missing_lifecycle_proof(tmp_path, monkeypatch, field, bad):
    backend, dll, report_path, repeat_path, large_path, _manifest, report, *_ = (
        _lease_artifacts(tmp_path, monkeypatch))
    report["results"][0][field] = bad
    report_path.write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(demo, "LEASE_LAB_REPORT_SHA256", hashlib.sha256(
        report_path.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="safe teardown proof"):
        demo._lease_lab_artifacts(backend, dll, report_path, repeat_path, large_path)


def test_lease_gate_rejects_stale_report_hash(tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, large_path, *_ = _lease_artifacts(
        tmp_path, monkeypatch)
    report_path.write_text(report_path.read_text() + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exact SHA pins"):
        demo._lease_lab_artifacts(backend, dll, report_path, repeat_path, large_path)


def test_lease_gate_rejects_controller_lease_class_drift(tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, large_path, _manifest, report, *_ = (
        _lease_artifacts(tmp_path, monkeypatch))
    report["controller_lease_class_sha256"] = "0" * 64
    report_path.write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(demo, "LEASE_LAB_REPORT_SHA256", hashlib.sha256(
        report_path.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="pinned build or controller"):
        demo._lease_lab_artifacts(backend, dll, report_path, repeat_path, large_path)


@pytest.mark.parametrize("field,bad", [
    ("lease_disabled_ack", False),
    ("deny_origin_body_bytes", 1),
    ("shared_archive_layout_verified", False),
    ("same_pid_for_followup", False),
])
def test_lease_gate_rejects_missing_content_proof(tmp_path, monkeypatch, field, bad):
    backend, dll, report_path, repeat_path, large_path, *_rest, repeat, _large = (
        _lease_artifacts(tmp_path, monkeypatch))
    repeat["results"][0][field] = bad
    repeat_path.write_text(json.dumps(repeat), encoding="utf-8")
    monkeypatch.setattr(demo, "LEASE_REPEAT_REPORT_SHA256", hashlib.sha256(
        repeat_path.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="zero-egress and recovery proof"):
        demo._lease_lab_artifacts(backend, dll, report_path, repeat_path, large_path)


def test_lease_gate_rejects_incomplete_large_request_proof(tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, large_path, *_rest, large = (
        _lease_artifacts(tmp_path, monkeypatch))
    large["results"][0]["denied_input_items"] = 100
    large_path.write_text(json.dumps(large), encoding="utf-8")
    monkeypatch.setattr(demo, "LEASE_LARGE_REPORT_SHA256", hashlib.sha256(
        large_path.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="large-request proof"):
        demo._lease_lab_artifacts(backend, dll, report_path, repeat_path, large_path)


def test_lease_gate_rejects_native_source_drift(tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, large_path, *_ = _lease_artifacts(
        tmp_path, monkeypatch)
    original_hash = demo._hash
    source = demo.ROOT / "native/guard/guard.c"
    monkeypatch.setattr(demo, "_hash", lambda path: (
        "0" * 64 if Path(path) == source else original_hash(path)))
    with pytest.raises(ValueError, match="source tree differs"):
        demo._lease_lab_artifacts(backend, dll, report_path, repeat_path, large_path)


def test_lease_status_attests_disabled_hooks_but_never_claims_coverage(
        tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, large_path, *_ = _lease_artifacts(
        tmp_path, monkeypatch)
    monkeypatch.setattr(demo, "_subject", lambda _pid: _subject(backend))
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: True)
    monkeypatch.setattr(demo, "_lease_disabled_event_signaled",
                        lambda _pid, _birth: True)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    result = demo.status(1234, guard="graceful_lease", dll=dll,
                         lab_report=report_path, repeat_report=repeat_path,
                         large_report=large_path)
    assert result["live_guard_resident"] is True
    assert result["native_hooks_disabled_attested"] is True
    assert result["trial_prerequisites_met"] is False
    assert result["model_egress_status"] == demo.MODEL_NOT_COVERED


def test_nonretry_gate_accepts_exact_ten_isolated_reports():
    backend, dll, report = _nonretry_artifacts()
    result = demo._nonretry_lease_lab_artifacts(backend, dll, report)
    assert result["synthetic_cases_validated"] == 10
    assert result["no_retry_attested_in_lab"] is True
    assert result["benign_http_completion_attested_in_lab"] is True
    assert result["desktop_frontend_rendering_validated"] is False


@pytest.mark.parametrize("pin", ["NONRETRY_DLL_SHA256", "NONRETRY_MANIFEST_SHA256",
                                  "NONRETRY_REPORT_SHA256"])
def test_nonretry_gate_rejects_exact_hash_drift(monkeypatch, pin):
    backend, dll, report = _nonretry_artifacts()
    monkeypatch.setattr(demo, pin, "0" * 64)
    with pytest.raises(ValueError, match="exact SHA pins"):
        demo._nonretry_lease_lab_artifacts(backend, dll, report)


def test_nonretry_gate_rejects_native_source_drift(monkeypatch):
    backend, dll, report = _nonretry_artifacts()
    original_hash = demo._hash
    source = demo.ROOT / "native/guard/guard.c"
    monkeypatch.setattr(demo, "_hash", lambda path: (
        "0" * 64 if Path(path) == source else original_hash(path)))
    with pytest.raises(ValueError, match="Native source tree differs"):
        demo._nonretry_lease_lab_artifacts(backend, dll, report)


def test_nonretry_gate_rejects_evidence_file_hash_drift(monkeypatch):
    backend, dll, report = _nonretry_artifacts()
    original_hash = demo._hash
    target = demo.NONRETRY_EVIDENCE_ROOT / demo.NONRETRY_EVIDENCE["deep_http-small"]
    monkeypatch.setattr(demo, "_hash", lambda path: (
        "0" * 64 if Path(path) == target else original_hash(path)))
    with pytest.raises(ValueError, match="evidence hash or path drift"):
        demo._nonretry_lease_lab_artifacts(backend, dll, report)


@pytest.mark.parametrize("evidence_key,mutate,message", [
    ("deep_http-small",
     lambda value: value["pipe_requests"].append(
         dict(value["pipe_requests"][0])),
     "no-retry proof"),
    ("successful_http_followup",
     lambda value: value["report"]["followup_turn_completion"].update(status="failed"),
     "successful benign HTTP follow-up"),
])
def test_nonretry_gate_rejects_semantic_evidence_drift(
        monkeypatch, evidence_key, mutate, message):
    backend, dll, report = _nonretry_artifacts()
    target = demo.NONRETRY_EVIDENCE_ROOT / demo.NONRETRY_EVIDENCE[evidence_key]
    original_json = demo._json

    def altered_json(path):
        value = original_json(path)
        if Path(path) == target:
            mutate(value)
        return value

    monkeypatch.setattr(demo, "_json", altered_json)
    with pytest.raises(ValueError, match=message):
        demo._nonretry_lease_lab_artifacts(backend, dll, report)


def test_nonretry_status_accepts_lab_but_stays_paused(monkeypatch):
    backend, _dll, _report = _nonretry_artifacts()
    monkeypatch.setattr(demo, "_subject", lambda _pid: _subject(backend))
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: False)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    result = demo.status(1234, guard="nonretry_lease")
    assert result["synthetic_native_lab_validated"] is True
    assert result["lab_gate"]["synthetic_cases_validated"] == 10
    assert result["trial_prerequisites_met"] is True
    assert result["ready_for_live_trial"] is False
    assert result["model_egress_status"] == demo.MODEL_NOT_COVERED
    assert "live_activation_paused_after_desktop_error" in result["gaps"]


@pytest.mark.parametrize("guard", ["failstop", "graceful", "graceful_lease",
                                   "nonretry_lease"])
def test_run_paused_before_preflight_or_injection(tmp_path, monkeypatch, guard):
    monkeypatch.setattr(demo, "status", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("preflight should not run")))
    monkeypatch.setattr(demo, "inject", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("injection should not run")))
    with pytest.raises(ValueError, match="activation is paused"):
        demo.run(1234, tmp_path / "never-created", guard=guard, seconds=1)
    assert not (tmp_path / "never-created").exists()


@pytest.mark.parametrize("mutate", [
    lambda manifest, report, repeat: report["results"][0].update(deny_origin_body_bytes=1),
    lambda manifest, report, repeat: report["results"][1].update(
        post_deny_identity_stable=False),
    lambda manifest, report, repeat: report["results"][0]["denied_turn_completion"].update(
        status="completed"),
    lambda manifest, report, repeat: report["results"][1]["pipe_requests"][0].update(
        decision="allow"),
    lambda manifest, report, repeat: repeat["results"][0].update(
        repeat_deny_body_bytes_delta=1),
    lambda manifest, report, repeat: repeat["results"][0].update(
        backend_alive_after_repeat=False),
    lambda manifest, report, repeat: repeat["results"][0].update(
        all_request_archive_readback_exact=False),
    lambda manifest, report, repeat: repeat["results"][0].update(
        shared_archive_layout_verified=False),
    lambda manifest, report, repeat: repeat["results"][0].update(
        denied_input_items=100),
    lambda manifest, report, repeat: repeat.update(
        collection_mode="per_item_archive"),
    lambda manifest, report, repeat: report.update(
        controller_sources_unchanged_during_lab=False),
    lambda manifest, report, repeat: report["controller_sources_sha256"].update(
        {"src/transpect_trace/protect/native_collection.py": "0" * 64}),
    lambda manifest, report, repeat: repeat["results"][0].update(
        identity=report["results"][0]["identity"]),
    lambda manifest, report, repeat: repeat["build"].update(manifest_sha256="0" * 64),
    lambda manifest, report, repeat: repeat["results"].pop(),
    lambda manifest, report, repeat: manifest["abi"].update(wss_denied_tag=12),
])
def test_graceful_gate_rejects_missing_or_changed_proof(tmp_path, monkeypatch,
                                                        mutate):
    backend, dll, report_path, repeat_path, manifest, report, repeat = (
        _graceful_artifacts(tmp_path, monkeypatch))
    mutate(manifest, report, repeat)
    (tmp_path / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    report_path.write_text(json.dumps(report), encoding="utf-8")
    repeat_path.write_text(json.dumps(repeat), encoding="utf-8")
    monkeypatch.setattr(demo, "GRACEFUL_MANIFEST_SHA256", hashlib.sha256(
        (tmp_path / "build-manifest.json").read_bytes()).hexdigest())
    monkeypatch.setattr(demo, "GRACEFUL_LAB_REPORT_SHA256", hashlib.sha256(
        report_path.read_bytes()).hexdigest())
    monkeypatch.setattr(demo, "GRACEFUL_REPEAT_REPORT_SHA256", hashlib.sha256(
        repeat_path.read_bytes()).hexdigest())
    with pytest.raises(ValueError):
        demo._graceful_lab_artifacts(backend, dll, report_path, repeat_path)


def test_graceful_gate_rejects_stale_report_hash(tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, *_ = _graceful_artifacts(tmp_path, monkeypatch)
    report_path.write_text(report_path.read_text() + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exact SHA pins"):
        demo._graceful_lab_artifacts(backend, dll, report_path, repeat_path)


def test_graceful_gate_rejects_python_collection_source_drift(tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, *_ = _graceful_artifacts(tmp_path, monkeypatch)
    original_hash = demo._hash
    drifted = demo.ROOT / "src/transpect_trace/protect/native_collection.py"
    monkeypatch.setattr(demo, "_hash", lambda path: (
        "0" * 64 if Path(path) == drifted else original_hash(path)))
    with pytest.raises(ValueError, match="Python collection sources"):
        demo._graceful_lab_artifacts(backend, dll, report_path, repeat_path)


def test_graceful_gate_requires_independent_repeat_report(tmp_path, monkeypatch):
    backend, dll, report_path, repeat_path, *_ = _graceful_artifacts(tmp_path, monkeypatch)
    repeat_path.unlink()
    with pytest.raises(ValueError, match="independent same-PID labs"):
        demo._graceful_lab_artifacts(backend, dll, report_path, repeat_path)


@pytest.mark.parametrize("mutate", [
    lambda manifest, report: manifest.update(backend=None),
    lambda manifest, report: manifest.update(pins={**manifest["pins"], "wss_success_tag": "0x1f"}),
    lambda manifest, report: report.update(build=None),
    lambda manifest, report: report["results"].__setitem__(0, None),
    lambda manifest, report: report["results"][1].update(non_warmup_body_counter_verified=False),
])
def test_artifact_preflight_rejects_malformed_or_mismatched_evidence(
        tmp_path, monkeypatch, mutate):
    backend, dll, report_path, manifest, report = _artifacts(tmp_path, monkeypatch)
    mutate(manifest, report)
    (tmp_path / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError):
        demo._lab_artifacts(backend, dll, report_path)


def test_unvalidated_graceful_candidate_cannot_enter_failstop_gate(
        tmp_path, monkeypatch):
    backend, dll, report_path, manifest, _report = _artifacts(tmp_path, monkeypatch)
    manifest["schema"] = "transpect.guard.graceful-current-lab-build/1.0"
    manifest["status"] = "unvalidated_graceful_candidate_not_desktop_adapter"
    manifest["deny_behavior"] = "return_rust_error_candidate"
    (tmp_path / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="fail-stop DLL manifest"):
        demo._lab_artifacts(backend, dll, report_path)


@pytest.mark.parametrize("identity_accepted", [False, True])
def test_activation_failure_termination_depends_on_resolver(
        tmp_path, monkeypatch, identity_accepted):
    monkeypatch.setattr(demo, "LIVE_TRIALS_PAUSED", False)
    backend = tmp_path / "codex.exe"
    dll = tmp_path / "lab.dll"
    backend.write_bytes(b"fixture")
    dll.write_bytes(b"fixture")
    (tmp_path / "report.json").write_text("{}", encoding="utf-8")
    subject = _subject(backend)
    monkeypatch.setattr(demo, "status", lambda *_args, **_kwargs: {
        "ready_for_live_trial": True, "backend": {"creation_filetime": 42,
                                                    "desktop_pid": 4321}})
    monkeypatch.setattr(demo, "collect_desktop_observation_identity", lambda _pid: subject)
    monkeypatch.setattr(demo, "_lab_artifacts", lambda *_args: {})
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: False)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    monkeypatch.setattr(demo, "same_desktop_observation_subject",
                        lambda *_args: identity_accepted)
    monkeypatch.setattr(demo, "NativeCollectionEngine",
                        lambda *_args, **_kwargs: SimpleNamespace())
    def image_identity(pid):
        if pid == demo.os.getpid():
            return {"pid": pid, "creation_filetime": 7, "image_sha256": "f" * 64}
        raise ValueError("not inspected")

    monkeypatch.setattr(demo, "image_identity", image_identity)
    terminated = []
    monkeypatch.setattr(demo, "_terminate_same_instance",
                        lambda *_args: (terminated.append(True) or True))

    class FakePipe:
        def __init__(self, *_args, **_kwargs):
            self.errors = []
            self.ready = threading.Event()
            self.lock = threading.Lock()
            self.records = []

        def start(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(demo, "PipeServer", FakePipe)

    class FakeBackendProcess:
        def __init__(self, *_args):
            pass

        def poll(self):
            return None

        def close(self):
            pass

    monkeypatch.setattr(demo, "_BackendProcess", FakeBackendProcess)

    def inject(_pid, _dll, _expected, *, identity_resolver):
        identity_resolver(_pid)
        raise RuntimeError("inject failed")

    monkeypatch.setattr(demo, "inject", inject)
    result = demo.run(1234, tmp_path / "output", dll=dll,
                      lab_report=tmp_path / "report.json", seconds=1)
    assert result["state"] == "failed"
    assert ("inject failed" if identity_accepted else "desktop process instance changed") in result["failure"]
    assert terminated == ([True] if identity_accepted else [])
    assert result["terminated_on_activation_failure"] is identity_accepted


@pytest.mark.parametrize("code,records,expected_state", [
    (76, [{"route_event": "model.request", "decision": "deny"}],
     "blocked_backend_exit"),
    (76, [{"route_event": "model.request", "decision": "allow"}], "failed"),
    (76, [{"route_event": "native.ready", "decision": "deny"}], "failed"),
    (1, [{"route_event": "model.request", "decision": "deny"}], "failed"),
])
def test_backend_exit_requires_failstop_code_and_model_denial(
        code, records, expected_state):
    state = {"state": "ready", "foreground_controller_active": True}
    pipe = SimpleNamespace(lock=threading.Lock(), records=records)
    process = SimpleNamespace(poll=lambda: code)
    assert demo._record_backend_exit(state, pipe, process) is True
    assert state["state"] == expected_state
    assert state["foreground_controller_active"] is False
    assert state.get("expected_backend_exit", False) is (expected_state == "blocked_backend_exit")
    assert state["backend_exit_code"] == code


def test_graceful_backend_exit_is_unexpected_even_after_recorded_denial():
    state = {"state": "ready", "guard_kind": "graceful",
             "foreground_controller_active": True}
    pipe = SimpleNamespace(lock=threading.Lock(), records=[
        {"route_event": "model.request", "decision": "deny"}])
    process = SimpleNamespace(poll=lambda: 76)
    assert demo._record_backend_exit(state, pipe, process) is True
    assert state["state"] == "failed"
    assert state["foreground_controller_active"] is False
    assert state["backend_exit_code"] == 76
    assert state.get("expected_backend_exit", False) is False


def test_run_classifies_backend_exit_when_identity_query_gets_winerror_87(
        tmp_path, monkeypatch):
    monkeypatch.setattr(demo, "LIVE_TRIALS_PAUSED", False)
    backend = tmp_path / "codex.exe"
    dll = tmp_path / "lab.dll"
    backend.write_bytes(b"fixture")
    dll.write_bytes(b"fixture")
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")
    subject = _subject(backend)
    monkeypatch.setattr(demo, "status", lambda *_args, **_kwargs: {
        "ready_for_live_trial": True,
        "backend": {"creation_filetime": 42, "desktop_pid": 4321}})
    calls = []

    def collect(_pid):
        calls.append(_pid)
        if len(calls) == 3:
            raise OSError(87, "parameter incorrect")
        return subject

    monkeypatch.setattr(demo, "collect_desktop_observation_identity", collect)
    monkeypatch.setattr(demo, "_lab_artifacts", lambda *_args: {})
    monkeypatch.setattr(demo, "_resident_guard", lambda _pid: False)
    monkeypatch.setattr(demo, "_command_hooks_present", lambda: False)
    monkeypatch.setattr(demo, "same_desktop_observation_subject", lambda *_args: True)
    monkeypatch.setattr(demo, "NativeCollectionEngine",
                        lambda *_args, **_kwargs: SimpleNamespace())
    monkeypatch.setattr(demo, "wait_ready", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(demo, "inject", lambda pid, dll, expected, *, identity_resolver:
                        identity_resolver(pid))

    def image_identity(pid):
        if pid == demo.os.getpid():
            return {"pid": pid, "creation_filetime": 7, "image_sha256": "f" * 64}
        raise OSError(87, "parameter incorrect")

    monkeypatch.setattr(demo, "image_identity", image_identity)
    terminated = []
    monkeypatch.setattr(demo, "_terminate_same_instance",
                        lambda *_args: terminated.append(True))

    class FakePipe:
        def __init__(self, *_args, **_kwargs):
            self.errors = []
            self.ready = threading.Event()
            self.ready.set()
            self.lock = threading.Lock()
            self.records = [{"route_event": "model.request", "decision": "deny"}]

        def start(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(demo, "PipeServer", FakePipe)

    class FakeBackendProcess:
        def __init__(self, *_args):
            self.polls = 0

        def poll(self):
            self.polls += 1
            return None if self.polls == 1 else 76

        def close(self):
            pass

    monkeypatch.setattr(demo, "_BackendProcess", FakeBackendProcess)
    result = demo.run(1234, tmp_path / "output", dll=dll,
                      lab_report=report, seconds=1)
    assert result["state"] == "blocked_backend_exit"
    assert result["expected_backend_exit"] is True
    assert result["backend_exit_code"] == 76
    assert result["recorded_model_denials"] == 1
    assert result["foreground_controller_active"] is False
    assert result["model_egress_status"] == demo.MODEL_NOT_COVERED
    assert "failure" not in result
    assert terminated == []
    assert json.loads((tmp_path / "output" / "status.json").read_text())["state"] == (
        "blocked_backend_exit")


def test_stop_checks_foreground_controller_generation(tmp_path, monkeypatch):
    output = tmp_path / "run"
    output.mkdir()
    state = {"schema": demo.SCHEMA, "state": "ready", "pid": 1234,
             "controller_pid": 4321, "controller_creation_filetime": 42,
             "controller_image_sha256": "a" * 64}
    (output / "status.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(demo, "image_identity", lambda _pid: {
        "pid": 4321, "creation_filetime": 43, "image_sha256": "a" * 64})
    with pytest.raises(ValueError, match="identity changed"):
        demo.stop(output)
    assert not (output / "STOP").exists()
    monkeypatch.setattr(demo, "image_identity", lambda _pid: {
        "pid": 4321, "creation_filetime": 42, "image_sha256": "a" * 64})
    first = demo.stop(output)
    second = demo.stop(output)
    assert first["stop_requested"] is True and first["dll_unloaded"] is False
    assert first["already_requested"] is False
    assert second["already_requested"] is True
