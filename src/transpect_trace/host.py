"""Trace a Codex CLI process running natively on the host (Windows or macOS).

The client talks plain HTTP to a Gateway on 127.0.0.1, so request bodies are
recorded before the Gateway opens TLS to the provider. Kernel-level collectors
(strace, Frida Gadget) are Linux-only and are not started here.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from transpect_trace import __version__
from transpect_trace.config import provider_api_key
from transpect_trace.core.models import CollectorState, Manifest, utc_now
from transpect_trace.core.storage import TraceBundle, atomic_write
from transpect_trace.correlation import correlate_run
from transpect_trace.normalization import normalize_run
from transpect_trace.supervisor import RunFailure, _snapshot_workspace
from transpect_trace.verification import verify_bundle

SECRET_ENV_NAMES = ("API_KEY", "DEEPSEEK_API_KEY", "TRANSPECT_MODEL_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
PROXY_TOKEN = "transpect-internal-proxy"


@dataclass(frozen=True)
class HostRunConfig:
    workspace: Path
    prompt_file: Path
    runs_dir: Path
    codex_executable: Path
    model: str | None = None
    sandbox_mode: str = "read-only"
    windows_sandbox: str = "unelevated"
    timeout_seconds: int = 900
    require_markers: bool = False


def find_codex() -> Path | None:
    found = shutil.which("codex")
    if found:
        return Path(found)
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", "")) / "OpenAI" / "Codex" / "bin"
        candidates = sorted(root.glob("*/codex.exe"), key=lambda path: path.stat().st_mtime, reverse=True)
        return candidates[0] if candidates else None
    return None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for_gateway(port: int, process: subprocess.Popen[bytes], timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RunFailure(f"gateway exited with {process.returncode}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.3)
    raise RunFailure("gateway did not become healthy")


def _codex_config(base_url: str, sandbox_mode: str, windows_sandbox: str) -> str:
    content = (
        'model_provider = "transpect"\n'
        'approval_policy = "never"\n'
        f"sandbox_mode = {json.dumps(sandbox_mode)}\n\n"
        "[model_providers.transpect]\n"
        'name = "Transpect Gateway"\n'
        f"base_url = {json.dumps(base_url)}\n"
        'env_key = "TRANSPECT_PROXY_TOKEN"\n'
        'wire_api = "responses"\n'
        "requires_openai_auth = false\n\n"
        "[shell_environment_policy]\n"
        f"exclude = {json.dumps(['TRANSPECT_PROXY_TOKEN', *SECRET_ENV_NAMES])}\n"
    )
    # Without a Windows sandbox, approval_policy=never rejects every non-trivial command.
    if os.name == "nt":
        content += f"\n[windows]\nsandbox = {json.dumps(windows_sandbox)}\n"
    return content


def _metadata(executable: Path) -> dict[str, object]:
    version = subprocess.run([str(executable), "--version"], capture_output=True, text=True, check=False)
    digest = hashlib.sha256()
    with executable.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "captured_at": utc_now(),
        "executable": str(executable),
        "version": (version.stdout or version.stderr).strip(),
        "sha256": f"sha256:{digest.hexdigest()}",
    }


def _echo(text: str) -> None:
    # Windows consoles often use a legacy code page; never let echoing abort collection.
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.buffer.write((text + "\n").encode(encoding, errors="replace"))
    sys.stdout.flush()


def _client_row(run_id: str, sequence: int, kind: str, **fields: object) -> dict[str, object]:
    return {
        "schema": "transpect.raw.client/1.0",
        "run_id": run_id,
        "collector_seq": sequence,
        "captured_at": utc_now(),
        "monotonic_ns": time.monotonic_ns(),
        "kind": kind,
        **fields,
    }


def run_host_codex(config: HostRunConfig) -> Path:
    api_key = provider_api_key("deepseek")
    if not api_key:
        raise RunFailure("API key for deepseek is required")
    if not config.codex_executable.is_file():
        raise RunFailure(f"codex executable not found: {config.codex_executable}")
    upstream = os.environ.get("BASE_URL") or "https://api.deepseek.com"
    model = config.model or os.environ.get("MODEL_ID") or "deepseek-flash"

    run_id = str(uuid4())
    bundle = TraceBundle((config.runs_dir / run_id).resolve())
    markers = _snapshot_workspace(
        config.workspace.resolve(),
        bundle.root / "input" / "workspace",
        require_markers=config.require_markers,
    )
    shutil.copytree(bundle.root / "input" / "workspace", bundle.root / "workspace", dirs_exist_ok=True)
    prompt = config.prompt_file.resolve().read_text(encoding="utf-8")
    atomic_write(bundle.root / "input" / "prompt.txt", prompt.encode("utf-8"))
    metadata = _metadata(config.codex_executable)
    atomic_write(bundle.root / "raw" / "client" / "metadata.json", (json.dumps(metadata, indent=2) + "\n").encode("utf-8"))

    manifest = Manifest(
        run_id=run_id,
        client="codex",
        client_version=str(metadata["version"]),
        provider="deepseek",
        model=model,
        workspace=str(config.workspace.resolve()),
        host={
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "transpect_trace": __version__,
        },
        collectors=[CollectorState(name="client.codex"), CollectorState(name="gateway.deepseek")],
        configuration={
            "mode": "host_native",
            "os": sys.platform,
            "markers": markers,
            "sandbox_mode": config.sandbox_mode,
            "windows_sandbox": config.windows_sandbox if os.name == "nt" else None,
            "client_binary_sha256": metadata["sha256"],
            "system_observation": "not collected; strace and Frida Gadget are Linux-only",
        },
    )
    bundle.write_manifest(manifest)

    port = _free_port()
    gateway_env = dict(os.environ)
    gateway_log = (bundle.root / "logs" / "gateway.log").open("wb")
    gateway = subprocess.Popen(
        [
            sys.executable, "-m", "transpect_trace.gateway.server",
            "--run-dir", str(bundle.root), "--run-id", run_id,
            "--upstream", upstream, "--provider", "deepseek",
            "--host", "127.0.0.1", "--port", str(port),
        ],
        env=gateway_env,
        stdout=gateway_log,
        stderr=subprocess.STDOUT,
    )
    failure: Exception | None = None
    process: subprocess.Popen[str] | None = None
    timer: threading.Timer | None = None
    codex_home = Path(tempfile.mkdtemp(prefix="ttrace-codex-home-"))
    try:
        _wait_for_gateway(port, gateway)
        manifest.collectors[1].started = True
        codex_config = _codex_config(f"http://127.0.0.1:{port}/agents/main", config.sandbox_mode, config.windows_sandbox)
        atomic_write(codex_home / "config.toml", codex_config.encode("utf-8"))
        atomic_write(bundle.root / "input" / "codex-config.toml", codex_config.encode("utf-8"))

        env = {name: value for name, value in os.environ.items() if name not in SECRET_ENV_NAMES}
        env["CODEX_HOME"] = str(codex_home)
        env["TRANSPECT_PROXY_TOKEN"] = PROXY_TOKEN
        command = [
            str(config.codex_executable), "exec", "--json", "--ephemeral", "--skip-git-repo-check",
            "--model", model, "--cd", str(bundle.root / "workspace"), prompt,
        ]
        bundle.append_jsonl("raw/client/events.jsonl", _client_row(run_id, 1, "client.user_message", prompt=prompt))
        manifest.collectors[0].started = True
        bundle.write_manifest(manifest)
        process = subprocess.Popen(
            command, cwd=bundle.root / "workspace", env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
        )
        stderr_parts: list[str] = []
        stderr_thread = threading.Thread(target=lambda: stderr_parts.append(process.stderr.read()), daemon=True)
        stderr_thread.start()
        timer = threading.Timer(config.timeout_seconds, process.kill)
        timer.daemon = True
        timer.start()
        sequence = 1
        assert process.stdout is not None
        for line in process.stdout:
            text = line.rstrip("\r\n")
            try:
                event = json.loads(text)
            except json.JSONDecodeError:
                event = {"type": "unparsed", "text": text}
            sequence += 1
            bundle.append_jsonl("raw/client/events.jsonl", _client_row(run_id, sequence, "client.codex_event", pid=process.pid, event=event))
            _echo(text)
        return_code = process.wait()
        stderr_thread.join(timeout=10)
        atomic_write(bundle.root / "raw" / "client" / "stderr.log", "".join(stderr_parts).encode("utf-8", errors="replace"))
        bundle.append_jsonl("raw/client/events.jsonl", _client_row(run_id, sequence + 1, "client.process_exited", return_code=return_code))
        if return_code != 0:
            raise RunFailure(f"codex exited with {return_code}")
    except Exception as error:
        failure = error
    finally:
        if timer is not None:
            timer.cancel()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=30)
        gateway.terminate()
        try:
            gateway.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gateway.kill()
        gateway_log.close()
        shutil.rmtree(codex_home, ignore_errors=True)

    for collector in manifest.collectors:
        collector.stopped = collector.started
    manifest.ended_at = utc_now()
    manifest.status = "complete" if failure is None else "incomplete"
    if failure is not None:
        manifest.failure = {"type": type(failure).__name__, "message": str(failure)}
    bundle.write_manifest(manifest)

    events = normalize_run(bundle.root)
    correlate_run(bundle.root, events)
    report = verify_bundle(bundle.root, check_checksums=False, write_report=True)
    if report["status"] != "complete" and manifest.status == "complete":
        manifest.status = "incomplete"
        bundle.write_manifest(manifest)
        normalize_run(bundle.root)
        correlate_run(bundle.root)
        verify_bundle(bundle.root, check_checksums=False, write_report=True)
    bundle.write_checksums()
    from transpect_trace.tree_export import export_run
    export_run(bundle.root)
    if failure is not None:
        raise RunFailure(f"trace run is incomplete at {bundle.root}: {failure}") from failure
    return bundle.root
