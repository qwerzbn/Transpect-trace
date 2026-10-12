from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from transpect_trace import __version__
from transpect_trace.config import load_project_env, project_root, provider_api_key, provider_key_names
from transpect_trace.core.models import CollectorState, Manifest, utc_now
from transpect_trace.core.storage import TraceBundle, atomic_write, sha256_bytes
from transpect_trace.correlation import correlate_run
from transpect_trace.gateway.policy import load_policy
from transpect_trace.normalization import normalize_run
from transpect_trace.verification import verify_bundle


GATEWAY_IMAGE = "transpect-trace-gateway:0.3.1"
AGENT_IMAGE = "transpect-trace-codex:0.3.1"
CLAUDE_IMAGE = "transpect-trace-claude:0.3.1"
OTEL_IMAGE = "otel/opentelemetry-collector-contrib:0.114.0"
FRIDA_VERSION = "17.18.0"


class RunFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class RunConfig:
    workspace: Path
    prompt_file: Path
    runs_dir: Path
    client: str = "codex"
    provider: str = "deepseek"
    model: str | None = None
    auto_build: bool = True
    timeout_seconds: int = 1800
    upstream: str | None = None
    policy_file: Path | None = None
    benchmark_case_file: Path | None = None
    supplemental_inputs: dict[str, Path] | None = None
    codex_paper_mode: bool = False
    agent_home: str | None = None
    demo_tools: bool = False
    require_markers: bool = True


def _command(args: list[str], *, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[-4000:]
        raise RunFailure(f"command failed ({completed.returncode}): {' '.join(args[:4])}: {detail}")
    return completed


def _docker(args: list[str], *, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _command(["docker", *args], timeout=timeout, check=check)


def _project_root() -> Path:
    return project_root()


def _image_exists(name: str) -> bool:
    return _docker(["image", "inspect", name], timeout=30, check=False).returncode == 0


def _ensure_images(auto_build: bool, client: str) -> None:
    root = _project_root()
    client_image = CLAUDE_IMAGE if client == "claude" else AGENT_IMAGE
    missing = [name for name in (GATEWAY_IMAGE, client_image) if not _image_exists(name)]
    if missing and not auto_build:
        raise RunFailure(f"required Docker images are missing: {', '.join(missing)}")
    if GATEWAY_IMAGE in missing:
        _docker(["build", "-f", str(root / "deploy/gateway/Dockerfile"), "-t", GATEWAY_IMAGE, str(root)], timeout=1800)
    if AGENT_IMAGE in missing:
        _docker(["build", "-f", str(root / "deploy/agent/Dockerfile"), "-t", AGENT_IMAGE, str(root)], timeout=1800)
    if CLAUDE_IMAGE in missing:
        _docker(["build", "-f", str(root / "deploy/agent-claude/Dockerfile"), "-t", CLAUDE_IMAGE, str(root)], timeout=1800)
    if not _image_exists(OTEL_IMAGE):
        if not auto_build:
            raise RunFailure(f"required Docker image is missing: {OTEL_IMAGE}")
        _docker(["pull", OTEL_IMAGE], timeout=1800)


def _mount(source: Path, target: str, *, readonly: bool = False) -> list[str]:
    specification = f"type=bind,source={source.resolve()},target={target}"
    if readonly:
        specification += ",readonly"
    return ["--mount", specification]


def _safe_name(run_id: str, suffix: str) -> str:
    return f"ttrace-{run_id.replace('-', '')[:12]}-{suffix}"


def _snapshot_workspace(
    source: Path,
    destination: Path,
    *,
    writable: bool = False,
    require_markers: bool = True,
) -> list[str]:
    if not source.is_dir():
        raise RunFailure(f"workspace is not a directory: {source}")
    source, destination = source.resolve(), destination.resolve()
    if source == destination or destination in source.parents:
        raise RunFailure("snapshot destination must not contain the source workspace")
    if destination.exists():
        raise RunFailure(f"snapshot destination already exists: {destination}")
    excluded = {".git", "__pycache__", ".pytest_cache", ".venv", "node_modules", ".env"}
    # A run can live below the selected workspace. Exclude that whole branch
    # before walking it, preventing a recursively copied snapshot of itself.
    if source in destination.parents:
        excluded.add(destination.relative_to(source).parts[0])
    def ignore(directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in excluded or name.startswith(".env.") or (Path(directory) / name).is_symlink()}
    shutil.copytree(source, destination, symlinks=False, ignore=ignore)
    markers: set[str] = set()
    for path in destination.rglob("*"):
        if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            continue
        data = path.read_bytes()
        for token in data.split():
            if token.startswith(b"TRANSPECT_MARKER_"):
                markers.add(token.decode("ascii", errors="ignore").strip("\"'`,.;:()[]{}"))
    if require_markers and not markers:
        raise RunFailure("workspace must contain at least one TRANSPECT_MARKER_ fake-data marker")
    if writable:
        for directory in [destination, *[path for path in destination.rglob("*") if path.is_dir()]]:
            try:
                directory.chmod(0o777)
            except OSError:
                pass
    return sorted(markers)


def _make_collector_directories_writable(bundle: TraceBundle) -> None:
    for relative in ("raw/client", "raw/gateway", "raw/otel", "raw/system", "raw/frida", "blobs", "blobs/sha256"):
        directory = bundle.root / relative
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.chmod(0o777)
        except OSError:
            pass


def _wait_healthy(container: str, *, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _docker(
            ["inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", container],
            timeout=10,
            check=False,
        )
        state = result.stdout.strip()
        if state in {"healthy", "running"}:
            return
        if state in {"exited", "dead", "unhealthy"}:
            logs = _docker(["logs", container], timeout=10, check=False)
            raise RunFailure(f"container {container} is {state}: {(logs.stderr or logs.stdout)[-2000:]}")
        time.sleep(0.5)
    raise RunFailure(f"container did not become healthy: {container}")


def run_trace(config: RunConfig) -> Path:
    load_project_env()
    supported = {("codex", "deepseek"), ("claude", "anthropic")}
    if (config.client, config.provider) not in supported:
        raise RunFailure("supported pairs are codex/deepseek and claude/anthropic")
    if not provider_api_key(config.provider):
        raise RunFailure(f"API key for {config.provider} is required")
    _docker(["info"], timeout=30)
    _ensure_images(config.auto_build, config.client)
    selected_model = config.model or os.environ.get("MODEL_ID") or ("default" if config.client == "claude" else "deepseek-flash")

    run_id = str(uuid4())
    run_dir = (config.runs_dir / run_id).resolve()
    bundle = TraceBundle(run_dir)
    _make_collector_directories_writable(bundle)
    markers = _snapshot_workspace(
        config.workspace.resolve(),
        bundle.root / "input/workspace",
        require_markers=config.require_markers and config.benchmark_case_file is None,
    )
    shutil.copytree(bundle.root / "input/workspace", bundle.root / "workspace", dirs_exist_ok=True)
    for directory in [bundle.root / "workspace", *[path for path in (bundle.root / "workspace").rglob("*") if path.is_dir()]]:
        try:
            directory.chmod(0o777)
        except OSError:
            pass
    prompt = config.prompt_file.resolve().read_text(encoding="utf-8")
    atomic_write(bundle.root / "input/prompt.txt", prompt.encode("utf-8"))
    # Snapshot and mount the actual Python implementation, so cached images
    # cannot silently run a previous collector version during development.
    runtime_source = bundle.root / "input/runtime-source"
    shutil.copytree(_project_root() / "src", runtime_source,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name, source in (config.supplemental_inputs or {}).items():
        if name != Path(name).name or name in {"prompt.txt", "policy.json", "injecagent-case.json"}:
            raise RunFailure(f"unsupported supplemental input name: {name}")
        atomic_write(bundle.root / "input" / name, source.resolve().read_bytes())
    policy_snapshot: Path | None = None
    policy_configuration: dict[str, Any] | None = None
    if config.policy_file is not None:
        policy_source = config.policy_file.resolve()
        policy = load_policy(policy_source)
        policy_bytes = policy_source.read_bytes()
        policy_snapshot = bundle.root / "input/policy.json"
        atomic_write(policy_snapshot, policy_bytes)
        policy_configuration = {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "sha256": f"sha256:{sha256_bytes(policy_bytes)}",
        }
    benchmark_snapshot: Path | None = None
    benchmark_configuration: dict[str, Any] | None = None
    if config.benchmark_case_file is not None:
        benchmark_source = config.benchmark_case_file.resolve()
        benchmark_bytes = benchmark_source.read_bytes()
        benchmark_document = json.loads(benchmark_bytes)
        if benchmark_document.get("schema") != "transpect.injecagent.case/1.0":
            raise RunFailure("unsupported benchmark case schema")
        benchmark_snapshot = bundle.root / "input/injecagent-case.json"
        atomic_write(benchmark_snapshot, benchmark_bytes)
        benchmark_configuration = {
            "name": "InjecAgent",
            "source": benchmark_document.get("source"),
            "user_tool": benchmark_document.get("official_case", {}).get("User Tool"),
            "attacker_tools": benchmark_document.get("official_case", {}).get("Attacker Tools"),
            "sha256": f"sha256:{sha256_bytes(benchmark_bytes)}",
        }
    manifest = Manifest(
        run_id=run_id,
        client=config.client,
        provider=config.provider,
        model=selected_model,
        workspace=str(config.workspace.resolve()),
        host={
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "transpect_trace": __version__,
        },
        container={"agent_image": CLAUDE_IMAGE if config.client == "claude" else AGENT_IMAGE, "gateway_image": GATEWAY_IMAGE, "otel_image": OTEL_IMAGE},
        collectors=[
            CollectorState(name=f"client.{config.client}", started=False),
            CollectorState(name=f"gateway.{config.provider}", started=False),
            CollectorState(name="client.otel", started=False),
            CollectorState(name="system.strace", started=False),
            CollectorState(name="system.frida", version=FRIDA_VERSION, started=False),
        ],
        configuration={
            "markers": markers,
            "full_payload_capture": True,
            "fixture_markers_required": config.require_markers,
            "demo_tools": config.demo_tools,
            "gateway_policy": policy_configuration,
            "benchmark": benchmark_configuration,
            "system_observation": {
                "strace": {"mode": "ptrace", "scope": "agent_process_tree"},
                "frida": {
                    "version": FRIDA_VERSION,
                    "mode": "gadget_preload",
                    "scope": "dynamically_linked_agent_processes",
                    "capture_bytes_per_call": 4096,
                    "reason": "Gadget loads through LD_PRELOAD and does not take strace's ptrace slot. Static binaries and processes that drop LD_PRELOAD stay strace-only.",
                },
            },
        },
    )
    bundle.write_manifest(manifest)

    from transpect_trace.live import RunLiveWriter
    live_writer = RunLiveWriter(bundle.root)
    live_writer.start()
    internal_network = _safe_name(run_id, "internal")
    egress_network = _safe_name(run_id, "egress")
    gateway_name = _safe_name(run_id, "gateway")
    otel_name = _safe_name(run_id, "otel")
    agent_name = _safe_name(run_id, "agent")
    created_networks: list[str] = []
    created_containers: list[str] = []
    failure: Exception | None = None
    agent_result: subprocess.CompletedProcess[str] | None = None

    try:
        _docker(["network", "create", "--internal", internal_network])
        created_networks.append(internal_network)
        _docker(["network", "create", egress_network])
        created_networks.append(egress_network)

        key_env_names = [name for name in provider_key_names(config.provider) if os.environ.get(name)]
        upstream = config.upstream or os.environ.get("BASE_URL") or ("https://api.anthropic.com" if config.provider == "anthropic" else "https://api.deepseek.com")
        gateway_args = [
            "run", "-d", "--name", gateway_name, "--network", egress_network,
            "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined",
            *[item for name in key_env_names for item in ("--env", name)],
            "--env", f"TTRACE_RUN_ID={run_id}", "--env", "TTRACE_RUN_DIR=/evidence",
            "--env", f"TTRACE_PROVIDER={config.provider}", "--env", f"TTRACE_UPSTREAM={upstream}",
            "--env", "PYTHONPATH=/runtime-src", *_mount(runtime_source, "/runtime-src", readonly=True),
            *(["--env", "TTRACE_POLICY_FILE=/evidence/input/policy.json"] if policy_snapshot else []),
            *_mount(bundle.root / "raw/gateway", "/evidence/raw/gateway"),
            *_mount(bundle.root / "raw/system", "/evidence/raw/system"),
            *_mount(bundle.root / "raw/frida", "/evidence/raw/frida"),
            *_mount(bundle.root / "blobs", "/evidence/blobs"),
            *(_mount(bundle.root / "input", "/evidence/input", readonly=True) if policy_snapshot else []),
            GATEWAY_IMAGE,
        ]
        _docker(gateway_args)
        created_containers.append(gateway_name)
        _docker(["network", "connect", "--alias", "gateway", internal_network, gateway_name])
        _wait_healthy(gateway_name)
        next(collector for collector in manifest.collectors if collector.name == f"gateway.{config.provider}").started = True
        bundle.write_manifest(manifest)

        otel_config = _project_root() / "deploy/otel-collector.yaml"
        _docker(
            [
                "run", "-d", "--name", otel_name, "--network", internal_network,
                "--network-alias", "otel", *_mount(bundle.root / "raw/otel", "/evidence/raw/otel"),
                *_mount(otel_config, "/etc/otelcol-contrib/config.yaml", readonly=True), OTEL_IMAGE,
                "--config=/etc/otelcol-contrib/config.yaml",
            ]
        )
        created_containers.append(otel_name)
        _wait_healthy(otel_name)
        next(collector for collector in manifest.collectors if collector.name == "client.otel").started = True
        bundle.write_manifest(manifest)

        agent_args = [
            "run", "--name", agent_name, "--network", internal_network,
            "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined",
            "--env", f"TTRACE_RUN_ID={run_id}", "--env", "TTRACE_RUN_DIR=/evidence",
            "--env", "TTRACE_PROMPT_FILE=/evidence/input/prompt.txt", "--env", "TTRACE_WORKSPACE=/workspace",
            "--env", "TTRACE_MODEL_BASE_URL=http://gateway:9000", "--env", "TTRACE_OTEL_ENDPOINT=http://otel:4318",
            "--env", f"TTRACE_MODEL={selected_model}",
            "--env", "PYTHONPATH=/runtime-src", *_mount(runtime_source, "/runtime-src", readonly=True),
            *(["--env", "TTRACE_DEMO_TOOLS=1"] if config.demo_tools else []),
            *(["--env", "TTRACE_CODEX_PAPER_MODE=1"] if config.codex_paper_mode else []),
            *(["--env", f"TTRACE_AGENT_HOME={config.agent_home}"] if config.agent_home else []),
            *(
                [
                    "--env", "TTRACE_INJECAGENT_CASE_FILE=/evidence/input/injecagent-case.json",
                    "--env", "TTRACE_MCP_LOG_FILE=/evidence/raw/client/mcp-events.jsonl",
                ]
                if benchmark_snapshot else []
            ),
            *_mount(bundle.root / "raw/client", "/evidence/raw/client"),
            *_mount(bundle.root / "raw/system", "/evidence/raw/system"),
            *_mount(bundle.root / "raw/frida", "/evidence/raw/frida"),
            *_mount(bundle.root / "input/prompt.txt", "/evidence/input/prompt.txt", readonly=True),
            *(
                _mount(benchmark_snapshot, "/evidence/input/injecagent-case.json", readonly=True)
                if benchmark_snapshot else []
            ),
            *_mount(bundle.root / "workspace", "/workspace"),
            CLAUDE_IMAGE if config.client == "claude" else AGENT_IMAGE,
        ]
        next(collector for collector in manifest.collectors if collector.name == f"client.{config.client}").started = True
        next(collector for collector in manifest.collectors if collector.name == "system.strace").started = True
        next(collector for collector in manifest.collectors if collector.name == "system.frida").started = True
        bundle.write_manifest(manifest)
        created_containers.append(agent_name)
        agent_result = _docker(agent_args, timeout=config.timeout_seconds, check=False)
        atomic_write(
            bundle.root / "logs/agent-container.log",
            ((agent_result.stdout or "") + (agent_result.stderr or "")).encode("utf-8", errors="replace"),
        )
        if agent_result.returncode != 0:
            raise RunFailure(f"{config.client} container exited with {agent_result.returncode}")
    except Exception as error:
        failure = error
    finally:
        for name in (agent_name, otel_name, gateway_name):
            if name in created_containers:
                _docker(["stop", "--time", "10", name], timeout=30, check=False)
                logs = _docker(["logs", name], timeout=30, check=False)
                if name != agent_name:
                    atomic_write(
                        bundle.root / f"logs/{name.rsplit('-', 1)[-1]}-container.log",
                        ((logs.stdout or "") + (logs.stderr or "")).encode("utf-8", errors="replace"),
                    )
                _docker(["rm", "-f", name], timeout=30, check=False)
        for name in reversed(created_networks):
            _docker(["network", "rm", name], timeout=30, check=False)

    live_writer.stop()
    for collector in manifest.collectors:
        if collector.started:
            collector.stopped = True
    manifest.ended_at = utc_now()
    manifest.status = "complete" if failure is None else "incomplete"
    if failure is not None:
        manifest.failure = {"type": type(failure).__name__, "message": str(failure)}
        for collector in manifest.collectors:
            if collector.started and collector.name.startswith(f"client.{config.client}"):
                collector.errors.append(str(failure))
    metadata_path = bundle.root / "raw/client/metadata.json"
    if metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            manifest.client_version = str(metadata.get("version") or "unknown")
            manifest.configuration["client_binary_sha256"] = metadata.get("sha256")
        except (OSError, json.JSONDecodeError):
            pass
    bundle.write_manifest(manifest)

    try:
        events = normalize_run(bundle.root)
        correlate_run(bundle.root, events)
        preliminary = verify_bundle(bundle.root, check_checksums=False, write_report=True)
        if preliminary["status"] != "complete":
            manifest.status = "incomplete"
            bundle.write_manifest(manifest)
            normalize_run(bundle.root)
            correlate_run(bundle.root)
            verify_bundle(bundle.root, check_checksums=False, write_report=True)
        bundle.write_checksums()
    except Exception as post_error:
        manifest.status = "incomplete"
        manifest.failure = manifest.failure or {"type": type(post_error).__name__, "message": str(post_error)}
        bundle.write_manifest(manifest)
        bundle.write_checksums()
        if failure is None:
            failure = post_error

    from transpect_trace.tree_export import export_run
    export_run(bundle.root)
    from transpect_trace.tree_export import export_data
    from transpect_trace.reporting import project_report
    final_projection = project_report(bundle.root)
    final_projection['revision'] = live_writer.revision + 1
    export_data(final_projection, live_writer.destination)
    if failure is not None:
        raise RunFailure(f"trace run is incomplete at {bundle.root}: {failure}") from failure
    return bundle.root
