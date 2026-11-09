"""Resident service, native client and health check.

The native client is built once per session with the pinned zig toolchain.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect import codex_gate_service as service  # noqa: E402
from transpect_trace.protect import codex_hook_gate as gate  # noqa: E402

import check_codex_gate_health as health  # noqa: E402
import install_codex_hook_gate as installer  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "nt", reason="named pipes and DPAPI are Windows-only")

SECRET = {"hook_event_name": "UserPromptSubmit", "session_id": "s", "turn_id": "t",
          "prompt": "deploy with password=Ab3x7Q2m9Pv4Na6Ty8Rz0Ls5Kb1Dc3Fh"}
BENIGN = {"hook_event_name": "UserPromptSubmit", "session_id": "s", "turn_id": "t",
          "prompt": "请总结这段公开文档"}
OUTPUT = {"hook_event_name": "PostToolUse", "session_id": "s", "turn_id": "t",
          "tool_use_id": "u", "tool_name": "Bash", "tool_input": {"command": "type a.txt"},
          "tool_response": "token ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\n"}
FIXTURE = ROOT / "tests" / "fixtures" / "codex_hooks" / "pinned-hook-schemas.json"
TITLES = {"UserPromptSubmit": "user-prompt-submit.command.output",
          "PreToolUse": "pre-tool-use.command.output",
          "PostToolUse": "post-tool-use.command.output"}


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    import build_codex_gate_client as builder
    return builder.build(tmp_path_factory.mktemp("client"))


@pytest.fixture()
def config(tmp_path):
    return installer.write_gate_config(tmp_path / "gate", "enforce", None)


@pytest.fixture()
def running(config):
    svc = service.GateService(config, workers=4)
    svc.start()
    yield svc
    svc.shutdown()


def _run(client, config, event, *, pipe=None, python=None):
    command = [str(client), pipe or service.pipe_name(config),
               str(python or Path(sys.executable)),
               str(ROOT / "scripts" / "codex_hook_gate.py"), str(config)]
    done = subprocess.run(command, input=json.dumps(event).encode("utf-8"),
                          capture_output=True, timeout=60)
    assert done.returncode == 0
    return json.loads(done.stdout) if done.stdout.strip() else {}


def test_service_reply_equals_per_event_reply(running, config):
    for event in (SECRET, BENIGN, OUTPUT):
        raw = json.dumps(event).encode("utf-8")
        reply = service.query(running.name, raw)
        expected = gate.run_event(event, event["hook_event_name"], str(config))
        assert (json.loads(reply) if reply else {}) == expected


def test_service_writes_audit_rows(running, config):
    service.query(running.name, json.dumps(SECRET).encode("utf-8"))
    rows = Path(gate.GateConfig.load(config).audit_file).read_text(encoding="utf-8")
    assert '"hook_event_name": "UserPromptSubmit"' in rows
    assert "Ab3x7Q2m9Pv4Na6Ty8Rz0Ls5Kb1Dc3Fh" not in rows


def test_service_reloads_a_changed_config(running, config):
    raw = json.dumps(SECRET).encode("utf-8")
    assert json.loads(service.query(running.name, raw))["decision"] == "block"
    installer.write_gate_config(Path(config).parent, "observe", None)
    time.sleep(0.05)
    assert service.query(running.name, raw) == b""


def test_second_service_on_the_same_pipe_refuses_to_start(running, config):
    with pytest.raises(RuntimeError):
        service.GateService(config, workers=1).start()


def test_native_client_uses_the_service(client, running, config):
    assert _run(client, config, SECRET, python=Path("C:/absent/python.exe"))["decision"] == "block"
    assert _run(client, config, BENIGN, python=Path("C:/absent/python.exe")) == {}
    assert _run(client, config, OUTPUT, python=Path("C:/absent/python.exe"))["decision"] == "block"


def test_native_client_falls_back_to_the_python_gate(client, config):
    pipe = service.pipe_name(config) + "-absent"
    assert _run(client, config, SECRET, pipe=pipe)["decision"] == "block"
    assert _run(client, config, BENIGN, pipe=pipe) == {}


@pytest.mark.parametrize("event", [SECRET, BENIGN, OUTPUT,
                                   {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                    "tool_input": {"command": "ls"}}])
def test_native_client_denies_when_nothing_can_decide(client, config, event):
    reply = _run(client, config, event, pipe=r"\\.\pipe\absent-ttrace",
                 python=Path("C:/absent/python.exe"))
    pinned = json.loads(FIXTURE.read_text(encoding="utf-8"))["schemas"]
    Draft7Validator(pinned[TITLES[event["hook_event_name"]]]).validate(reply)
    assert reply == gate.fallback_denial(event["hook_event_name"])


def test_native_client_allows_unenforced_events_when_nothing_can_decide(client, config):
    reply = _run(client, config, {"hook_event_name": "PreModelRequest"},
                 pipe=r"\\.\pipe\absent-ttrace", python=Path("C:/absent/python.exe"))
    assert reply == {}


def test_install_command_with_native_client(client, config):
    command = installer.build_command(Path(sys.executable), ROOT / "scripts" / "codex_hook_gate.py",
                                      config, client)
    parts = command.split(" ")
    assert parts[0] == str(client) and parts[1] == service.pipe_name(config)
    assert len(parts) == 5  # Codex splits on whitespace: every token must be one path


# ---- health check ----

def _rollout(path: Path, turns):
    rows = []
    for turn_id, trigger, tool in turns:
        rows.append({"timestamp": "2020-01-01T00:00:00Z", "type": "event_msg",
                     "payload": {"type": "task_started", "turn_id": turn_id,
                                 "turn_attribution": {"turn_trigger": trigger}}})
        rows.append({"type": "response_item", "payload": {"type": "message", "role": "user",
                                                          "content": []}})
        if tool:
            rows.append({"type": "response_item", "payload": {"type": "function_call",
                                                              "call_id": "c"}})
            rows.append({"type": "response_item", "payload": {"type": "function_call_output",
                                                              "call_id": "c"}})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")


def _audit(config_path, rows):
    cfg = gate.GateConfig.load(config_path)
    for row in rows:
        gate.append_audit_line(cfg.audit_file, json.dumps({
            "schema": gate.AUDIT_SCHEMA, "decided_at": "2020-01-01T00:00:00+00:00",
            "allowed": True, **row}))
    return cfg


def test_coverage_flags_turns_the_gate_never_saw(tmp_path, config):
    home = tmp_path / "home"
    _rollout(home / "sessions" / "r.jsonl",
             [("gated", "composer", True), ("ungated", "composer", True),
              ("subagent", "send_user_message_async_question", False)])
    cfg = _audit(config, [
        {"hook_event_name": "UserPromptSubmit", "turn_id": "gated"},
        {"hook_event_name": "PreToolUse", "turn_id": "gated"},
        {"hook_event_name": "PostToolUse", "turn_id": "gated"}])
    indexes = {event: 0 for event in installer.INSTALLED_EVENTS}
    result = health.check_coverage(home, cfg, indexes, None)
    assert result["status"] == "FAIL"
    assert [gap["turn_id"] for gap in result["gaps"]] == ["ungated"]
    assert set(result["gaps"][0]["problems"]) == {"PROMPT_NOT_GATED", "TOOL_CALLS_NOT_GATED"}


def test_coverage_does_not_expect_output_for_a_denied_call(tmp_path, config):
    home = tmp_path / "home"
    _rollout(home / "sessions" / "r.jsonl", [("t", "exec", True)])
    cfg = _audit(config, [{"hook_event_name": "UserPromptSubmit", "turn_id": "t"},
                          {"hook_event_name": "PreToolUse", "turn_id": "t", "allowed": False}])
    indexes = {event: 0 for event in installer.INSTALLED_EVENTS}
    assert health.check_coverage(home, cfg, indexes, None)["status"] == "OK"


def test_integrity_detects_changed_gate_code(tmp_path):
    source = tmp_path / "gate.py"
    source.write_text("one", encoding="utf-8")
    manifest_path = installer.write_manifest(tmp_path, "cmd", [source])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert health.check_integrity(manifest)["status"] == "OK"
    source.write_text("two", encoding="utf-8")
    result = health.check_integrity(manifest)
    assert result["status"] == "FAIL" and result["changed"] == ["gate.py"]


def test_install_and_trust_checks(tmp_path, config):
    home = tmp_path / "home"
    installer.install_user_layer(home, "cmd", dry_run=False)
    manifest = {"events": list(installer.INSTALLED_EVENTS), "command": "cmd"}
    install, indexes = health.check_install(home, manifest)
    assert install["status"] == "OK"
    assert health.check_trust(home, indexes)["status"] == "FAIL"
    hooks = str((home / "hooks.json").resolve())
    (home / "config.toml").write_text("".join(
        f"[hooks.state.'{hooks}:{installer._TOML_EVENT_KEY[event]}:0:0']\n"
        f'trusted_hash = "sha256:00"\n\n' for event in installer.INSTALLED_EVENTS),
        encoding="utf-8")
    assert health.check_trust(home, indexes)["status"] == "OK"
    manifest["command"] = "other"
    assert health.check_install(home, manifest)[0]["status"] == "FAIL"
