#!/usr/bin/env bash
# Unified Codex desktop + fixed Claude CLI guard (Windows, Git Bash).
#   ./start.sh            hidden supervisors + persistent independent monitor
#   ./start.sh start --claude-live-test   explicit fixed-version limited test
#   ./start.sh install    logon startup only after full acceptance
#   ./start.sh status | stop | uninstall
#   ./start.sh codex ...         previous single-client commands
#   ./start.sh claude hook       fixed-version in-process Hook route
#   ./start.sh claude proxy ...  explicit local model proxy route
set -euo pipefail
cd "$(dirname "$0")"
extras=(--extra native-build)
case "${1:-}" in
  codex)
    shift
    launcher=scripts/desktop_guard.py
    ;;
  claude)
    shift
    launcher=scripts/claude_guard.py
    case "${1:-}" in
      hook) shift ;;
      proxy)
        shift
        extras+=(--extra claude-proxy)
        launcher=scripts/claude_model_proxy.py
        ;;
    esac
    ;;
  *) exec ./guard-service.bat "$@" ;;
esac

command -v uv >/dev/null || { echo "请安装 uv 后重试。" >&2; exit 1; }
uv sync --locked --inexact "${extras[@]}" --quiet
export PYTHONUTF8=1
exec uv run --no-sync python "$launcher" "$@"
