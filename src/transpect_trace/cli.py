from __future__ import annotations

import json
import tempfile
from pathlib import Path

import typer

from transpect_trace.doctor import doctor as run_doctor
from transpect_trace.exporter import export_parquet
from transpect_trace.config import load_project_env
from transpect_trace.supervisor import RunConfig, RunFailure, run_trace
from transpect_trace.verification import verify_bundle


app = typer.Typer(no_args_is_help=True, help="Capture and verify evidence-first traces from real LLM agent clients.")
from transpect_trace.guard.cli import app as guard_app
app.add_typer(guard_app,name="guard")
from transpect_trace.observe.cli import app as observe_app
app.add_typer(observe_app,name="observe")


def _execute_run(config: RunConfig) -> Path:
    try:
        destination = run_trace(config)
    except RunFailure as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error
    typer.echo(str(destination))
    from transpect_trace.reporting import report_path
    typer.echo(f"Trees: {report_path(destination).parent}")
    return destination


@app.command("demo")
def demo_command(
    runs_dir: Path = typer.Option(Path("runs/demo"), file_okay=False, resolve_path=True),
    model: str | None = typer.Option(None),
    timeout_seconds: int = typer.Option(1200, min=30),
) -> None:
    """Run the real Codex + child-agent + local receipt demo and build HTML."""
    from transpect_trace.demo import create_demo
    with tempfile.TemporaryDirectory(prefix="ttrace-demo-") as directory:
        workspace, prompt = create_demo(Path(directory))
        destination = _execute_run(RunConfig(workspace=workspace, prompt_file=prompt, runs_dir=runs_dir,
                                             model=model, demo_tools=True, timeout_seconds=timeout_seconds))
        from transpect_trace.reporting import validate_demo
        checks = validate_demo(destination)
        typer.echo(json.dumps(checks, ensure_ascii=False, indent=2))
        if not checks["passed"]:
            raise typer.Exit(1)


@app.command("trace")
def trace_command(
    workspace: Path = typer.Option(..., exists=True, file_okay=False, resolve_path=True),
    prompt: str | None = typer.Option(None, help="Task text; alternatively use --prompt-file."),
    prompt_file: Path | None = typer.Option(None, exists=True, dir_okay=False, resolve_path=True),
    runs_dir: Path = typer.Option(Path("runs/tasks"), file_okay=False, resolve_path=True),
    model: str | None = typer.Option(None),
    demo_tools: bool = typer.Option(False, help="Expose the explicit Codex child adapter and local receipt sink."),
    timeout_seconds: int = typer.Option(1800, min=30),
) -> None:
    """Trace a real prompt in an isolated copy of a workspace; no markers required.

    Full task data is recorded locally and model requests go to the configured
    provider. Outputs are kept in the run's workspace, not copied back.
    """
    if (prompt is None) == (prompt_file is None):
        raise typer.BadParameter("provide exactly one of --prompt or --prompt-file")
    with tempfile.TemporaryDirectory(prefix="ttrace-prompt-") as directory:
        path = prompt_file or Path(directory) / "prompt.txt"
        if prompt is not None:
            path.write_text(prompt, encoding="utf-8")
        _execute_run(RunConfig(workspace=workspace, prompt_file=path, runs_dir=runs_dir,
                               model=model, demo_tools=demo_tools, require_markers=False,
                               timeout_seconds=timeout_seconds))


@app.command("report")
def report_command(
    run_directory: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    output: Path | None = typer.Option(None, resolve_path=True),
) -> None:
    """Build an offline HTML/JSON replay without changing sealed evidence."""
    from transpect_trace.reporting import build_report
    typer.echo(str(build_report(run_directory, output)))


@app.command("doctor")
def doctor_command() -> None:
    """Check runtime prerequisites without exposing credentials."""
    result = run_doctor()
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["ok"]:
        raise typer.Exit(1)


@app.command("run")
def run_command(
    workspace: Path = typer.Option(..., exists=True, file_okay=False, resolve_path=True),
    prompt_file: Path = typer.Option(..., exists=True, dir_okay=False, resolve_path=True),
    runs_dir: Path = typer.Option(Path("runs"), file_okay=False, resolve_path=True),
    client: str = typer.Option("codex"),
    provider: str = typer.Option("deepseek"),
    model: str | None = typer.Option(None, help="Defaults to MODEL_ID from .env."),
    build_images: bool = typer.Option(True, "--build-images/--no-build-images"),
    timeout_seconds: int = typer.Option(1800, min=30),
    upstream: str | None = typer.Option(None, help="Override provider base URL for controlled integration tests."),
    policy_file: Path | None = typer.Option(
        None, exists=True, dir_okay=False, resolve_path=True,
        help="JSON policy evaluated by the Gateway before forwarding.",
    ),
    benchmark_case_file: Path | None = typer.Option(
        None, exists=True, dir_okay=False, resolve_path=True,
        help="Prepared InjecAgent adapter case exposed to Codex as local MCP tools.",
    ),
) -> None:
    """Run one isolated real-client trace."""
    _execute_run(
        RunConfig(
            workspace=workspace,
            prompt_file=prompt_file,
            runs_dir=runs_dir,
            client=client,
            provider=provider,
            model=model,
            auto_build=build_images,
            timeout_seconds=timeout_seconds,
            upstream=upstream,
            policy_file=policy_file,
            benchmark_case_file=benchmark_case_file,
        )
    )


@app.command("codex")
def codex_command(
    workspace: Path = typer.Option(Path("tests/fixtures/workspace"), file_okay=False, resolve_path=True),
    prompt_file: Path = typer.Option(Path("tests/fixtures/prompts/summarize.txt"), dir_okay=False, resolve_path=True),
    runs_dir: Path = typer.Option(Path("runs"), file_okay=False, resolve_path=True),
    model: str | None = typer.Option(None, help="Defaults to MODEL_ID from .env."),
    policy_file: Path | None = typer.Option(None, exists=True, dir_okay=False, resolve_path=True),
) -> None:
    """Run the default Codex and DeepSeek trace."""
    _execute_run(
        RunConfig(
            workspace=workspace,
            prompt_file=prompt_file,
            runs_dir=runs_dir,
            client="codex",
            provider="deepseek",
            model=model,
            policy_file=policy_file,
        )
    )


@app.command("claude")
def claude_command(
    workspace: Path = typer.Option(Path("tests/fixtures/workspace"), file_okay=False, resolve_path=True),
    prompt_file: Path = typer.Option(Path("tests/fixtures/prompts/summarize.txt"), dir_okay=False, resolve_path=True),
    runs_dir: Path = typer.Option(Path("runs"), file_okay=False, resolve_path=True),
    model: str | None = typer.Option(None, help="Defaults to MODEL_ID from .env."),
    policy_file: Path | None = typer.Option(None, exists=True, dir_okay=False, resolve_path=True),
) -> None:
    """Run the default Claude and Anthropic trace."""
    _execute_run(
        RunConfig(
            workspace=workspace,
            prompt_file=prompt_file,
            runs_dir=runs_dir,
            client="claude",
            provider="anthropic",
            model=model,
            policy_file=policy_file,
        )
    )


@app.command("verify")
def verify_command(run_directory: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True)) -> None:
    """Verify schemas, blobs, checksums and correlation coverage."""
    result = verify_bundle(run_directory, check_checksums=True, write_report=False)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    if result["status"] != "complete":
        raise typer.Exit(1)


@app.command("export")
def export_command(
    run_directory: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    format: str = typer.Option("parquet", "--format"),
) -> None:
    """Export normalized evidence for analysis."""
    if format != "parquet":
        raise typer.BadParameter("only parquet is supported")
    typer.echo(str(export_parquet(run_directory)))


@app.command('trees')
def trees_command(run_directory: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
                  html: bool = typer.Option(False)) -> None:
    """Export JSON/TXT trees; HTML is optional."""
    from transpect_trace.tree_export import export_run
    typer.echo(str(export_run(run_directory, html=html)))


@app.command("host-codex")
def host_codex_command(
    workspace: Path = typer.Option(Path("tests/fixtures/workspace"), exists=True, file_okay=False, resolve_path=True),
    prompt: str | None = typer.Option(None, help="Task text; alternatively use --prompt-file."),
    prompt_file: Path | None = typer.Option(None, exists=True, dir_okay=False, resolve_path=True),
    runs_dir: Path = typer.Option(Path("runs/host"), file_okay=False, resolve_path=True),
    codex: Path | None = typer.Option(None, help="codex executable; defaults to PATH or the desktop app's bundled codex.exe."),
    model: str | None = typer.Option(None),
    sandbox_mode: str = typer.Option("read-only", help="Codex sandbox_mode for the host run."),
    windows_sandbox: str = typer.Option("unelevated", help="Codex [windows] sandbox: unelevated or elevated."),
    timeout_seconds: int = typer.Option(900, min=30),
) -> None:
    """Run Codex natively on this host with requests routed through a local Gateway."""
    from transpect_trace.host import HostRunConfig, find_codex, run_host_codex
    if prompt is not None and prompt_file is not None:
        raise typer.BadParameter("provide at most one of --prompt or --prompt-file")
    executable = codex or find_codex()
    if executable is None:
        raise typer.BadParameter("codex executable not found; pass --codex")
    with tempfile.TemporaryDirectory(prefix="ttrace-host-") as directory:
        path = prompt_file or Path("tests/fixtures/prompts/summarize.txt").resolve()
        if prompt is not None:
            path = Path(directory) / "prompt.txt"
            path.write_text(prompt, encoding="utf-8")
        try:
            destination = run_host_codex(HostRunConfig(
                workspace=workspace, prompt_file=path, runs_dir=runs_dir, codex_executable=executable,
                model=model, sandbox_mode=sandbox_mode, windows_sandbox=windows_sandbox,
                timeout_seconds=timeout_seconds,
            ))
        except RunFailure as error:
            typer.echo(str(error), err=True)
            raise typer.Exit(1) from error
    typer.echo(str(destination))


@app.command("gateway")
def gateway_command(
    port: int = typer.Option(9100, min=1, max=65535),
    runs_dir: Path = typer.Option(Path("runs/desktop-gateway"), file_okay=False, resolve_path=True),
    provider: str = typer.Option("deepseek"),
    upstream: str | None = typer.Option(None, help="Defaults to BASE_URL from .env."),
) -> None:
    """Run a standalone Gateway on 127.0.0.1 for desktop or CLI clients; Ctrl+C stops it."""
    import os
    from datetime import datetime

    from aiohttp import web

    from transpect_trace.config import provider_api_key
    from transpect_trace.gateway.server import GatewayConfig, create_app

    api_key = provider_api_key(provider)
    if not api_key:
        raise typer.BadParameter(f"API key for {provider} is required in .env")
    run_id = f"gateway-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    target = upstream or os.environ.get("BASE_URL") or (
        "https://api.anthropic.com" if provider == "anthropic" else "https://api.deepseek.com"
    )
    typer.echo(f"Gateway: http://127.0.0.1:{port}  ->  {target}")
    typer.echo(f"Evidence: {run_dir}")
    app_instance = create_app(GatewayConfig(run_id=run_id, run_dir=run_dir, upstream=target, api_key=api_key, provider=provider))
    web.run_app(app_instance, host="127.0.0.1", port=port, print=None)


@app.command("mitm")
def mitm_command(
    port: int = typer.Option(8080, min=1, max=65535),
    runs_dir: Path = typer.Option(Path("runs/mitm"), file_okay=False, resolve_path=True),
    hosts: str = typer.Option(
        # mitmproxy matches allow_hosts against "host:port", so tolerate an optional port.
        r"^(.+\.)?(chatgpt\.com|api\.openai\.com|api\.anthropic\.com|api\.deepseek\.com)(:\d+)?$",
        help="Regex of hosts to intercept; everything else is tunneled untouched.",
    ),
) -> None:
    """Run an HTTPS man-in-the-middle proxy that records decrypted LLM traffic.

    Keeps the client's own account and model. Point the client at this proxy with
    HTTPS_PROXY and trust the mitmproxy CA (per-process via CODEX_CA_CERTIFICATE /
    NODE_EXTRA_CA_CERTS, or in the user cert store). Ctrl+C stops it.
    """
    import os
    import shutil
    import subprocess
    from datetime import datetime

    mitmdump = shutil.which("mitmdump")
    if mitmdump is None:
        raise typer.BadParameter("mitmdump not found; run `uv sync --extra mitm`")
    run_id = f"mitm-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    env = dict(os.environ)
    env["TTRACE_RUN_DIR"] = str(run_dir)
    env["TTRACE_RUN_ID"] = run_id
    env["TTRACE_MITM_HOSTS"] = hosts
    addon = Path(__file__).resolve().parent / "mitm_addon.py"
    typer.echo(f"Proxy: http://127.0.0.1:{port}  | intercept hosts: {hosts}")
    typer.echo(f"CA certificate (after first run): {ca}")
    typer.echo(f"Evidence: {run_dir}")
    typer.echo("Stop with Ctrl+C, then clear HTTPS_PROXY and remove the CA when done.")
    subprocess.run(
        [mitmdump, "-s", str(addon),
         "--listen-host", "127.0.0.1", "--listen-port", str(port),
         "--set", f"allow_hosts={hosts}"],
        env=env, check=False,
    )


@app.command("gateway-summary")
def gateway_summary_command(run_directory: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True)) -> None:
    """List requests a standalone Gateway recorded, with client, model, prompt and answer."""
    from transpect_trace.gateway_summary import summarize
    typer.echo(json.dumps(summarize(run_directory), ensure_ascii=False, indent=2))


codex_config_app = typer.Typer(help="Point ~/.codex/config.toml at the local Gateway, or restore it.")
app.add_typer(codex_config_app, name="codex-config")


@codex_config_app.command("gateway")
def codex_config_gateway_command(
    port: int = typer.Option(9100, min=1, max=65535),
    model: str | None = typer.Option(None, help="Defaults to MODEL_ID from .env."),
    config: Path | None = typer.Option(None, help="Defaults to ~/.codex/config.toml."),
) -> None:
    """Back up the Codex config, then route its model requests to the local Gateway."""
    import os
    from transpect_trace.codex_config import default_config_path, use_gateway
    result = use_gateway(config or default_config_path(), port=port, model=model or os.environ.get("MODEL_ID") or "deepseek-flash")
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    typer.echo("Restart the Codex desktop app so it reloads the configuration.")


@codex_config_app.command("restore")
def codex_config_restore_command(
    config: Path | None = typer.Option(None, help="Defaults to ~/.codex/config.toml."),
    backup: Path | None = typer.Option(None, exists=True, dir_okay=False, help="Defaults to the newest backup."),
) -> None:
    """Copy the newest backup back and check its SHA-256."""
    from transpect_trace.codex_config import default_config_path, restore
    typer.echo(json.dumps(restore(config or default_config_path(), backup), ensure_ascii=False, indent=2))
    typer.echo("Restart the Codex desktop app so it reloads the configuration.")


@app.command('desktop-watch')
def desktop_watch_command(
    sessions: Path = typer.Option(Path.home() / '.codex/sessions', exists=True, file_okay=False),
    output: Path = typer.Option(Path('runs/desktop'), file_okay=False, resolve_path=True),
    thread: str | None = typer.Option(None),
    interval: float = typer.Option(3, min=1),
    once: bool = typer.Option(False),
    sample_processes: bool = typer.Option(True, '--sample-processes/--no-sample-processes'),
) -> None:
    """Continuously project local Codex chat logs without changing Codex settings."""
    from transpect_trace.desktop import watch_desktop
    typer.echo(f'Desktop trees: {output}')
    watch_desktop(sessions, output, thread, interval, once, sample_processes)


def main() -> None:
    load_project_env()
    app()


if __name__ == "__main__":
    main()
