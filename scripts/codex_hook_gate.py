"""Entry point Codex invokes for each hook event.

Codex tokenizes a hook `command` on whitespace and does not honor quotes, so
every path in the configured command line must be free of spaces. The installer
checks that; this file only wires stdin/stdout to the gate.
"""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from transpect_trace.protect.codex_hook_gate import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
