from __future__ import annotations

import json
from pathlib import Path

import typer

from transpect_trace.doctor import doctor as run_doctor
from transpect_trace.exporter import export_parquet
from transpect_trace.config import load_project_env
from transpect_trace.supervisor import RunConfig, RunFailure, run_trace
from transpect_trace.verification import verify_bundle


app = typer.Typer(no_args_is_help=True, help="Capture and verify evidence-first traces from real LLM agent clients.")


def _execute_run(config: RunConfig) -> None:
    try:
        destination = run_trace(config)
    except RunFailure as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error
    typer.echo(str(destination))


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


def main() -> None:
    load_project_env()
    app()


if __name__ == "__main__":
    main()
