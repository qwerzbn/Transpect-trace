"""Verify the isolated CLI probe never needs credentials or persists prompt text."""
from __future__ import annotations

import importlib.util
from http.client import HTTPConnection
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "probe_cli_prompt_hook.py"
SPEC = importlib.util.spec_from_file_location("probe_cli_prompt_hook", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def test_non_forwarding_receiver_counts_actual_body_bytes():
    with probe.receiver() as sink:
        connection = HTTPConnection("127.0.0.1", sink.server_port, timeout=3)
        connection.request("POST", "/v1/responses", b"synthetic body")
        reply = connection.getresponse()
        assert reply.status == 503
        reply.read()
        connection.close()
        assert sink.snapshot() == {"requests": 1, "body_bytes": len(b"synthetic body")}


def test_isolated_environment_drops_auth_and_global_codex_state(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_ACCESS_TOKEN", "token-for-test")
    monkeypatch.setenv("CODEX_SQLITE_HOME", "C:/global-state")
    monkeypatch.setenv("OPENAI_API_KEY", "key-for-test")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "other-key-for-test")
    home, archive = tmp_path / "home", tmp_path / "archive"
    env = probe.isolated_env(home, archive)
    assert env["CODEX_HOME"] == str(home)
    assert env["TTRACE_CLI_PROMPT_DEMO_DIR"] == str(archive)
    assert "CODEX_ACCESS_TOKEN" not in env
    assert "CODEX_SQLITE_HOME" not in env
    assert "OPENAI_API_KEY" not in env
    assert "AZURE_OPENAI_API_KEY" not in env


def test_configure_copies_hook_and_routes_only_to_loopback(tmp_path):
    home, hooks = tmp_path / "home", tmp_path / "hooks"
    hashes = probe.configure(home, hooks, 54321)
    config = (home / "config.toml").read_text(encoding="utf-8")
    hook_config = json.loads((home / "hooks.json").read_text(encoding="utf-8"))
    command = hook_config["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
    assert 'base_url = "http://127.0.0.1:54321/v1"' in config
    assert "requires_openai_auth = false" in config
    assert str((hooks / "cli_prompt_dlp_hook.py").resolve()) in command
    assert set(hashes) == {"cli_prompt_dlp_hook.py", "cli_prompt_detector.py"}


def test_event_summary_excludes_prompt_or_model_text():
    secret = "synthetic-sensitive-prompt"
    events = (json.dumps({"type": "item.completed", "item": {"type": "agent_message",
                        "text": secret}}) + "\n" +
              json.dumps({"type": "turn.completed", "usage": {"input_tokens": 0,
                          "output_tokens": 0, "untrusted": secret}})).encode()
    summary = probe.event_summary(events)
    assert summary["event_types"] == ["item.completed", "turn.completed"]
    assert summary["item_types"] == ["agent_message"]
    assert summary["token_usage"] == {"input_tokens": 0, "output_tokens": 0}
    assert secret not in json.dumps(summary)


def test_binary_pin_rejects_mismatch_before_execution(tmp_path):
    fake_exe = tmp_path / "codex.exe"
    fake_exe.write_bytes(b"wrong binary")
    with pytest.raises(ValueError, match="hash mismatch"):
        probe.probe(fake_exe)
