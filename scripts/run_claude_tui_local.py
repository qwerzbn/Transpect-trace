"""Run the pinned interactive Claude CLI against a no-forward local receiver."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from _build_support import ROOT

import sys
sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import claude_service as lab  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--workspace", type=Path,
                        help="TUI working directory (defaults to receiver directory)")
    parser.add_argument("--tools", default="",
                        help="Claude tool allowlist; empty disables tools")
    parser.add_argument("--color", action="store_true",
                        help="enable true color in terminals inheriting NO_COLOR or TERM=dumb")
    args = parser.parse_args()
    env_path = args.env_file.resolve(strict=True)
    directory = env_path.parent
    env = json.loads(env_path.read_text(encoding="utf-8"))
    if (not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                              for k, v in env.items())
            or not env.get("ANTHROPIC_BASE_URL", "").startswith("https://127.0.0.1:")):
        raise ValueError("isolated local receiver configuration required")
    binary = lab.installed_claude().resolve(strict=True)
    lab.check_binary(lab.load_pin(), binary)
    workspace = args.workspace.resolve(strict=True) if args.workspace else directory
    if not workspace.is_dir():
        raise ValueError("workspace must be a directory")
    if args.color:
        env.pop("NO_COLOR", None)
        if env.get("TERM") == "dumb":
            env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"
    return subprocess.call([str(binary), "--tools", args.tools],
                           cwd=workspace, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
