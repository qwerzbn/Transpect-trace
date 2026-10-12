from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from transpect_trace.codex_config import restore, use_gateway

ORIGINAL = """model = "gpt-6.1-sol"
model_reasoning_effort = "high"

[mcp_servers.node_repl]
command = "node"

[projects.'d:\\code']
trust_level = "trusted"
"""


def test_use_gateway_keeps_other_settings_and_restore_matches(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(ORIGINAL, encoding="utf-8", newline="\n")
    result = use_gateway(config, port=9100, model="deepseek-flash")
    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    assert parsed["model"] == "deepseek-flash"
    assert parsed["model_provider"] == "transpect"
    assert parsed["model_reasoning_effort"] == "high"
    assert parsed["mcp_servers"]["node_repl"]["command"] == "node"
    assert parsed["model_providers"]["transpect"]["base_url"] == "http://127.0.0.1:9100/agents/desktop"
    assert Path(result["backup"]).read_text(encoding="utf-8") == ORIGINAL

    with pytest.raises(ValueError):
        use_gateway(config, port=9100, model="deepseek-flash")

    restored = restore(config)
    assert config.read_text(encoding="utf-8") == ORIGINAL
    assert restored["sha256"] == result["backup_sha256"]
