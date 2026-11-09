#!/usr/bin/env bash
# One-click Codex desktop guard (Windows, Git Bash).
#   ./start.sh            start in this window (Ctrl+C to stop)
#   ./start.sh install    start in background and at every logon
#   ./start.sh status | stop | uninstall
set -euo pipefail
cd "$(dirname "$0")"
command -v uv >/dev/null || { echo "需要先安装 uv: https://docs.astral.sh/uv/getting-started/installation/"; exit 1; }
uv sync --locked --inexact --extra native-build --quiet
export PYTHONUTF8=1
exec uv run --no-sync python scripts/desktop_guard.py "${@:-start}"
