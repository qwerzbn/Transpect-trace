"""Load the isolated Claude model proxy addon for mitmdump regular mode.

Requires TTRACE_CLAUDE_MODEL_PROXY_CONFIG pointing at a per-session JSON file.
Launch mitmdump with connection_strategy=lazy, upstream_cert=false, and
ssl_insecure=false; the addon's configure hook rejects weaker settings.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard.claude_model_proxy import (  # noqa: E402
    ClaudeModelProxyAddon, ModelProxyConfig,
)

raw_config = os.environ.get("TTRACE_CLAUDE_MODEL_PROXY_CONFIG")
if not raw_config:
    raise RuntimeError("TTRACE_CLAUDE_MODEL_PROXY_CONFIG is required")
addons = [ClaudeModelProxyAddon(ModelProxyConfig.load(Path(raw_config)))]
