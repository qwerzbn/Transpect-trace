#!/usr/bin/env bash
# Run one host-native Codex trace on macOS and verify the evidence bundle.
# Requires uv and Node/npm. The model key comes from API_KEY or the checkout's .env;
# BASE_URL and MODEL_ID are optional and fall back to the project defaults.
set -euo pipefail

CODEX_VERSION="${CODEX_VERSION:-0.114.0}"
cd "$(dirname "$0")/.."

if [[ -z "${API_KEY:-}" && ! -f .env ]]; then
  echo "API_KEY is not set and no .env was found" >&2
  exit 1
fi

if ! command -v codex >/dev/null 2>&1; then
  npm install --global "@openai/codex@${CODEX_VERSION}"
fi
codex --version

uv sync
run_dir="$(uv run ttrace host-codex --runs-dir runs/host "$@" | tail -n 1)"
uv run ttrace verify "$run_dir"
echo "$run_dir"
