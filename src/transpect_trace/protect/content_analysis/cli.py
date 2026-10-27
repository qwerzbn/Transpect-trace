"""Operate the local Chrome Content Analysis SDK prototype.

This command starts the SDK agent and policy service.  It deliberately does
not install Chrome connector policies; those are cloud-managed deployment
configuration and must be attested separately.
"""
from __future__ import annotations

import json
from pathlib import Path
import time
from uuid import uuid4

import typer

from transpect_trace.protect.detection import ContentIndex

from .policy import ContentAnalysisEngine, ContentAnalysisPolicy
from .runtime import ContentAnalysisRuntime


app = typer.Typer(no_args_is_help=True, help="Chrome local content analysis prototype.")


@app.command("run")
def run(
    agent: Path = typer.Option(
        Path("build/content-analysis-agent/ttrace-content-agent.exe"),
        exists=True,
        dir_okay=False,
    ),
    chrome: Path = typer.Option(
        Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
        exists=True,
        dir_okay=False,
    ),
    allow_host: list[str] = typer.Option(["chatgpt.com"], "--allow-host"),
    pii_rules: bool = typer.Option(
        False,
        "--pii-rules",
        help="Enable the existing contextual personal-information rules.",
    ),
    index_file: Path | None = typer.Option(None, exists=True, dir_okay=False),
    runs_dir: Path = typer.Option(Path("runs/content-analysis")),
    sdk_test_client: bool = typer.Option(
        False,
        help="Allow the pinned SDK demo browser for a controlled protocol test.",
    ),
) -> None:
    """Start the local agent; normal Chrome still requires cloud connector policy."""
    try:
        index = (
            ContentIndex.model_validate_json(index_file.read_text(encoding="utf-8"))
            if index_file
            else None
        )
        engine = ContentAnalysisEngine(
            ContentAnalysisPolicy(allowed_hosts=allow_host, pii_rules=pii_rules),
            index=index,
        )
        runtime = ContentAnalysisRuntime(
            agent=agent,
            chrome=chrome,
            engine=engine,
            run_dir=runs_dir / uuid4().hex,
            allow_sdk_test_client=sdk_test_client,
        )
        runtime.start()
        typer.echo(json.dumps(runtime.status, indent=2, sort_keys=True))
        while runtime.process.poll() is None:
            runtime.update_health()
            time.sleep(0.5)
        runtime.update_health()
        raise RuntimeError("native content analysis agent stopped")
    except KeyboardInterrupt:
        if "runtime" in locals():
            runtime.close()
    except (OSError, RuntimeError, ValueError) as error:
        if "runtime" in locals():
            runtime.close()
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error


@app.command("status")
def status(run_directory: Path = typer.Argument(..., exists=True, file_okay=False)) -> None:
    """Read a persisted snapshot; this does not attest a live Chrome policy."""
    value = json.loads((run_directory / "status.json").read_text(encoding="utf-8"))
    value["snapshot_only"] = True
    value["live_managed_chrome_policy_attestation"] = "not_performed"
    value["normal_chrome_can_enforce"] = False
    typer.echo(json.dumps(value, indent=2, sort_keys=True))
