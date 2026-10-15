# Transpect Trace Core

Transpect Trace Core captures reproducible evidence from real LLM agent clients. Version 0.3 traces isolated Codex CLI and Claude Code processes through controlled DeepSeek Responses API and Anthropic Messages API gateways. It records four planes and can optionally enforce an exact-marker task policy before forwarding:

- client events from `codex exec --json`, Claude `stream-json`, and OpenTelemetry;
- model requests, SSE chunks, and responses before TLS at a controlled gateway;
- Linux process, file, and network activity from `strace` plus in-process libc observations from Frida Gadget;
- run configuration, versions, collector status, checksums, and quality metrics.

The tracing Gateway uses deterministic marker and upstream policies. The separate Windows Guard and Observe modules also detect configured credentials and registered text; Observe produces risk recommendations. Semantic classification, OCR, general file decoding and byte-level taint tracking remain outside the verified scope.

## Install

Windows multi-channel visibility is available separately through `ttrace observe inventory/run/report`. It uses pinned eCapture Windows research and passive Native adapters, with redacted evidence and risk recommendations. Verified paths and unsupported Chrome/IDE UI coverage are documented in [Windows Observe](docs/windows-observe.md); it does not add enforcement to unverified clients.

Python 3.12 is selected by `.python-version`. Docker Desktop with Linux containers is required for the container tracing commands; Windows Guard and Observe run on the host.

The separate [Windows fixed-version Codex request gate](docs/codex-guard.md) uses native runtime instrumentation and a language-neutral local policy protocol, without a model traffic proxy or TLS replacement. It does not require Docker. HTTP JSON and selected WSS messages have synthetic-origin validation; full streaming, uploads, daemon mode and whole-system protection are not claimed. Live ETW validation currently requires privileges unavailable in the recorded session.

The project uses `uv` for Python, virtual environment, dependency, and lockfile management.

```powershell
cd D:\code\transpect-trace
uv sync --locked --dev
uv run --locked pytest
```

Install only the optional capability you use:

| Capability | Sync command |
|---|---|
| Runtime only | `uv sync --locked --no-dev` |
| Windows observation and native build tools | `uv sync --locked --extra observe --extra native-build --dev` |
| Frida research and TUI experiments | `uv sync --locked --extra guard-probe --dev` |
| Parquet export | `uv sync --locked --extra export` |
| Historical proxy experiments | `uv sync --locked --extra mitm` |
| Word report generation | `uv sync --locked --extra reports` |
| Official InjecAgent evaluator | `uv sync --locked --extra benchmarks` |

`pyproject.toml` declares dependencies and `uv.lock` fixes their resolved versions. Use `uv lock` after intentional dependency changes, then `uv lock --check` and `uv pip check` to verify them. Container Python dependencies also use `uv sync --locked --no-dev`; Dockerfiles no longer keep separate pip dependency lists. Go, Node/npm, Docker, Windows SDK/system APIs and pinned native sources are managed separately from Python. See the [review and cleanup record](docs/review-and-cleanup-2026-10-15.md).

The optional LivePI tests require the pinned `.external/LivePI` checkout and skip when it is absent. Generated report-render caches and the unpacked Frida Gadget stay local and ignored; Docker extracts the checked `.so.xz` source instead.

Put provider settings in the checkout-local `.env`. It is ignored by Git and Docker. Existing generic names are supported:

```powershell
API_KEY=...
BASE_URL=https://api.deepseek.com
MODEL_ID=deepseek-chat
```

Provider-specific `DEEPSEEK_API_KEY` and `ANTHROPIC_API_KEY` variables are also supported.

## Run a controlled trace

### Interactive trace demo and custom prompts

```powershell
uv run ttrace demo
uv run ttrace trace --workspace D:\demo\my-project --prompt "Explain the program entry point"
uv run ttrace report runs\demo\<run-id>
```

Runs automatically produce an offline HTML/JSON report with an Agent call tree,
an OS process tree, file-to-request/tool content matches, and inspectable evidence.
The demo uses a real independent Codex child via an explicit MCP adapter and a
local receipt sink. `trace` accepts ordinary workspaces without fixture markers,
runs in a copy, and records full task payloads. See [demo instructions and limits](docs/trace-demo.md).

The original `run`/`codex`/`claude` fixture commands below require an isolated workspace containing fake `TRANSPECT_MARKER_*` data. Use `trace` for an ordinary task workspace.

The shortest Codex command uses the included fake-data workspace and prompt:

```powershell
uv run ttrace codex
```

Use `uv run ttrace run --help` for custom clients, workspaces, prompts, models, and output directories.

The command creates a run under `runs/<run-id>`. It snapshots the workspace, starts isolated agent, gateway, and OpenTelemetry containers, records raw evidence, normalizes it, builds causal/content indexes, writes a quality report, and seals the bundle with SHA-256 checksums.

```powershell
uv run ttrace verify runs\<run-id>
uv run ttrace export runs\<run-id> --format parquet
```

The same TraceEvent and bundle format supports Claude Code:

```powershell
uv run ttrace claude
```

## Run an official InjecAgent case through Codex

The Codex experiment uses the official InjecAgent data unchanged, exposes the selected case's three
tools through a local stdio MCP adapter, and runs the official `@openai/codex` CLI behind the tracing
Gateway. With no `--policy-file`, the Gateway is observe-only and forwards every supported model
request. The exfiltration tool is a local simulated sink and never sends an email or accesses an
external account.

```powershell
uv run python scripts/run_injecagent_codex.py --case 1
```

The command validates the pinned official InjecAgent commit and dataset hash, snapshots the exact
case under `input/injecagent-case.json`, and captures MCP calls in
`raw/client/mcp-events.jsonl` alongside Codex JSON events, Gateway request bodies, OpenTelemetry,
strace, and Frida evidence. `--case` selects one of the same reproducible diverse 20-case subset used
by `scripts/run_injecagent_subset.py`.

## Test pre-forward blocking

The exfiltration fixture contains a benign task prompt, an indirect prompt injection in `public.txt`, a fake credential file, the Gateway policy, and expected results. No real secrets are used.

Run the deterministic Gateway tests first. They prove that a denied request returns HTTP 403 and that the mock upstream receives zero requests:

```powershell
uv run pytest tests/test_gateway_policy.py
```

Run the real Codex scenario separately. Model behavior is nondeterministic: if the agent resists the injected instruction, the attack was not attempted; if it puts the fake-secret marker in a model request, the Gateway records `policy.decision` and blocks before forwarding.

```powershell
uv run ttrace run `
  --workspace tests/fixtures/exfiltration/workspace `
  --prompt-file tests/fixtures/exfiltration/prompt.txt `
  --policy-file tests/fixtures/exfiltration/policy.json `
  --client codex `
  --provider deepseek
```

`policy.decision` is the auditable pre-forward verdict. It records the request and decision IDs, policy version, matched rule, matched marker IDs and source paths, requested upstream, and whether a denied request was forwarded. Marker values and credentials are not copied into the decision event.

See [docs/gateway-policy-testing.md](docs/gateway-policy-testing.md) for the test oracle and evidence locations.

## Evidence layout

```text
runs/<run-id>/
├── manifest.json
├── raw/{client,gateway,otel,system,frida}/
├── blobs/sha256/
├── normalized/{events,causal_edges,content_index}.jsonl
├── analytics/
├── quality/trace-quality.json
├── logs/
└── checksums.sha256
```

Raw JSONL is append-only during collection. Large bodies use compressed, content-addressed blobs. Normalized evidence is regenerated deterministically after all collectors stop. Parquet is a derived analysis format and is never the only evidence copy.

`raw/system/strace.<pid>` is the kernel-boundary record. `raw/frida/events.<pid>.jsonl` is the function-boundary record produced by an injected Frida agent. strace starts first; Frida 17.18 then uses its Linux `/proc/<pid>/mem` fallback because the target's ptrace slot is already occupied. See [docs/system-observation.md](docs/system-observation.md) for the design and limitations.

## Development

```powershell
uv run pytest
```

The existing `D:\code\Transpect` repository is not a runtime dependency. The new implementation retains only its validated ideas: external credential isolation, Codex JSON parsing, layered correlation keys, and system evidence collection.
# 实时树文件

默认导出 JSON/TXT，网页可选。桌面聊天监听、后台启动和改写来源标签的使用与限制见
[持续追踪说明](docs/live-tracing.md)。
