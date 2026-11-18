"""Load the isolated-VM Claude egress addon with mitmdump regular proxy mode."""
from __future__ import annotations

import os
from pathlib import Path
import sys

root_override = os.environ.get("TTRACE_ROOT")
if root_override:
    ROOT = Path(root_override).resolve(strict=True)
else:
    from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard.claude_proxy import ClaudeToolProxyAddon  # noqa: E402


raw_state = os.environ.get("TTRACE_CLAUDE_PROXY_STATE")
if not raw_state:
    raise RuntimeError("TTRACE_CLAUDE_PROXY_STATE is required")
addons = [ClaudeToolProxyAddon(Path(raw_state))]
