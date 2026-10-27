import io
import json

from transpect_trace.protect.content_analysis import ContentAnalysisEngine
from transpect_trace.protect.content_analysis.runtime import ContentAnalysisRuntime


class FakeServer:
    def __init__(self, _engine, audit):
        self.audit = audit
        self.name = r"\\.\pipe\ttrace-content-policy-test"
        self.errors = []
        self.expected = None
        self.closed = False

    def start(self):
        return None

    def set_expected_process(self, pid):
        self.expected = pid

    def close(self):
        self.closed = True


class FakeProcess:
    pid = 4242

    def __init__(self, command, **kwargs):
        self.command = command
        self.kwargs = kwargs
        self.stdout = io.StringIO('{"event":"ready","sdk_path":"path_user"}\n')
        self.stderr = io.StringIO("")
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def send_signal(self, _signal):
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class InvalidReadyProcess(FakeProcess):
    def __init__(self, command, **kwargs):
        super().__init__(command, **kwargs)
        self.stdout = io.StringIO('{"event":"unexpected","sdk_path":"path_user"}\n')


def test_runtime_starts_only_protocol_and_never_changes_managed_chrome_policy(tmp_path):
    agent = tmp_path / "agent.exe"
    chrome = tmp_path / "chrome.exe"
    agent.write_bytes(b"fixture")
    chrome.write_bytes(b"fixture")
    made = []

    def server_factory(engine, audit):
        server = FakeServer(engine, audit)
        made.append(server)
        return server

    runtime = ContentAnalysisRuntime(
        agent=agent,
        chrome=chrome,
        engine=ContentAnalysisEngine(),
        run_dir=tmp_path / "run",
        server_factory=server_factory,
        popen_factory=FakeProcess,
    )
    status = runtime.start()
    assert made[0].expected == 4242
    assert status["state"] == "sdk_protocol_ready"
    assert status["sdk_protocol_gate_ready"] is True
    assert status["sdk_protocol_can_enforce"] is False
    assert status["normal_chrome_can_enforce"] is False
    assert status["managed_chrome_policy_changed_by_runtime"] is False
    assert "--user" in runtime.process.command
    assert "--policy-pid" in runtime.process.command
    assert "--allow-sdk-test-client" not in runtime.process.command
    assert runtime.native_events == [
        {"event": "ready", "sdk_path": "path_user"}
    ]
    runtime.close()
    assert made[0].closed


def test_sdk_test_client_requires_explicit_runtime_option(tmp_path):
    agent = tmp_path / "agent.exe"
    chrome = tmp_path / "chrome.exe"
    agent.write_bytes(b"fixture")
    chrome.write_bytes(b"fixture")
    runtime = ContentAnalysisRuntime(
        agent=agent,
        chrome=chrome,
        engine=ContentAnalysisEngine(),
        run_dir=tmp_path / "run",
        allow_sdk_test_client=True,
        server_factory=FakeServer,
        popen_factory=FakeProcess,
    )
    runtime.start()
    assert "--allow-sdk-test-client" in runtime.process.command
    runtime.close()


def test_runtime_reports_native_exit_as_fail_closed(tmp_path):
    agent = tmp_path / "agent.exe"
    chrome = tmp_path / "chrome.exe"
    agent.write_bytes(b"fixture")
    chrome.write_bytes(b"fixture")
    runtime = ContentAnalysisRuntime(
        agent=agent,
        chrome=chrome,
        engine=ContentAnalysisEngine(),
        run_dir=tmp_path / "run",
        server_factory=FakeServer,
        popen_factory=FakeProcess,
    )
    runtime.start()
    runtime.process.returncode = 7
    status = runtime.update_health()
    assert status["state"] == "degraded_fail_closed"
    assert status["native_agent_exit_code"] == 7
    runtime.close()


def test_runtime_command_never_contains_shell_or_policy_mutation(tmp_path):
    runtime = ContentAnalysisRuntime(
        agent=tmp_path / "agent.exe",
        chrome=tmp_path / "chrome.exe",
        engine=ContentAnalysisEngine(),
        run_dir=tmp_path / "run",
    )
    command = runtime.command(r"\\.\pipe\safe")
    joined = " ".join(command).lower()
    assert "powershell" not in joined
    assert "reg.exe" not in joined
    assert "onfileattachedenterpriseconnector" not in joined
    assert command[0].endswith("agent.exe")


def test_invalid_readiness_remains_initialization_failed_after_cleanup(tmp_path):
    agent = tmp_path / "agent.exe"
    chrome = tmp_path / "chrome.exe"
    agent.write_bytes(b"fixture")
    chrome.write_bytes(b"fixture")
    runtime = ContentAnalysisRuntime(
        agent=agent,
        chrome=chrome,
        engine=ContentAnalysisEngine(),
        run_dir=tmp_path / "run",
        server_factory=FakeServer,
        popen_factory=InvalidReadyProcess,
    )
    import pytest

    with pytest.raises(RuntimeError, match="readiness"):
        runtime.start()
    status = json.loads(
        (tmp_path / "run" / "status.json").read_text(encoding="utf-8")
    )
    assert status["state"] == "initialization_failed_fail_closed"


def test_native_event_audit_rejects_unknown_or_sensitive_fields(tmp_path):
    runtime = ContentAnalysisRuntime(
        agent=tmp_path / "agent.exe",
        chrome=tmp_path / "chrome.exe",
        engine=ContentAnalysisEngine(),
        run_dir=tmp_path / "run",
    )
    runtime.run_dir.mkdir()
    runtime._record_native_event(
        {
            "event": "response_acknowledged",
            "request_token_sha256": "a" * 64,
            "status": "SUCCESS",
            "final_action": "BLOCK",
        }
    )
    runtime._record_native_event(
        {"event": "response_acknowledged", "raw_token": "must-not-persist"}
    )
    assert len(runtime.native_events) == 1
    saved = (runtime.run_dir / "native-events.jsonl").read_text(encoding="utf-8")
    assert "must-not-persist" not in saved


def test_controlled_round_trip_attestation_does_not_certify_normal_chrome(tmp_path):
    runtime = ContentAnalysisRuntime(
        agent=tmp_path / "agent.exe",
        chrome=tmp_path / "client.exe",
        engine=ContentAnalysisEngine(),
        run_dir=tmp_path / "run",
        allow_sdk_test_client=True,
    )
    runtime.run_dir.mkdir()
    runtime.server = FakeServer(runtime.engine, tmp_path / "audit.jsonl")
    runtime.server.records = [
        {"request_token_sha256": "a" * 64, "decision": "ALLOW"},
        {"request_token_sha256": "b" * 64, "decision": "BLOCK"},
    ]
    runtime.native_events = [
        {
            "event": "response_acknowledged",
            "request_token_sha256": "a" * 64,
            "status": "SUCCESS",
            "final_action": "ALLOW",
        },
        {
            "event": "response_acknowledged",
            "request_token_sha256": "b" * 64,
            "status": "SUCCESS",
            "final_action": "BLOCK",
        },
    ]
    status = runtime.attest_controlled_protocol(2)
    assert status["sdk_protocol_can_enforce"] is True
    assert status["sdk_protocol_certification"] == "controlled_sdk_client_round_trip"
    assert status["normal_chrome_can_enforce"] is False
