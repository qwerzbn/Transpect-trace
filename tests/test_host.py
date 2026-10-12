from __future__ import annotations

import io
import sys
import tomllib

import pytest

from transpect_trace import host


def test_host_codex_config_routes_to_gateway_and_hides_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host.os, "name", "nt")
    config = tomllib.loads(host._codex_config("http://127.0.0.1:9123/agents/main", "read-only", "unelevated"))
    assert config["model_provider"] == "transpect"
    assert config["model_providers"]["transpect"]["base_url"] == "http://127.0.0.1:9123/agents/main"
    assert config["model_providers"]["transpect"]["env_key"] == "TRANSPECT_PROXY_TOKEN"
    assert config["sandbox_mode"] == "read-only"
    assert config["windows"]["sandbox"] == "unelevated"
    assert {"API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY"} <= set(config["shell_environment_policy"]["exclude"])


def test_echo_survives_legacy_console_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buffer, encoding="gbk"))
    host._echo("profile.ps1 \ufffd ok")
    sys.stdout.flush()
    assert buffer.getvalue().decode("gbk").startswith("profile.ps1 ? ok")
