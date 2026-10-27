"""Controlled multi-application experiments and redacted evidence summaries."""
from __future__ import annotations

import json
from pathlib import Path

import typer

from .models import BusinessRuntimeStatus

app = typer.Typer(no_args_is_help=True, help=__doc__)


def _unavailable(error):
    # Neither pydantic input dumps nor OSError paths may reach CLI output.
    return {'state': 'unavailable', 'error_type': type(error).__name__,
            'certified': False, 'can_enforce': False}


def read_status(directory):
    value = BusinessRuntimeStatus.model_validate_json((Path(directory) / 'runtime.json').read_bytes())
    result = value.model_dump(mode='json')
    if value.state in {'initializing', 'observing'}:
        try:
            from transpect_trace.observe.windows import identity
            if value.controller is None:
                raise ValueError('controller_missing')
            actual = identity(value.controller.pid)
            if any(actual.get(key) != getattr(value.controller, key)
                   for key in ('pid', 'creation_filetime', 'image_sha256')):
                raise ValueError('controller_identity_changed')
            result['controller_live'] = True
        except (KeyError, ValueError, OSError, AttributeError):
            result['recorded_state'] = result['state']
            result['state'] = 'unavailable'
            result['controller_live'] = False
            result['certified'] = False
            result['gaps'] = sorted(set(result['gaps'] + ['controller_identity_unavailable']))
    return result


@app.command('run')
def run_command(manifest: Path = typer.Option(..., exists=True, dir_okay=False)):
    try:
        from .runtime import run
        result = run(manifest)
    except (ValueError, OSError, RuntimeError) as error:
        typer.echo(json.dumps(_unavailable(error)))
        raise typer.Exit(2)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get('state') != 'complete':
        raise typer.Exit(2)


@app.command('status')
def status_command(directory: Path = typer.Argument(..., exists=True, file_okay=False)):
    try:
        result = read_status(directory)
    except (ValueError, OSError) as error:
        typer.echo(json.dumps(_unavailable(error)))
        raise typer.Exit(2)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))


@app.command('report')
def report_command(directory: Path = typer.Argument(..., exists=True, file_okay=False)):
    from .evidence import read_report
    try:
        result = read_report(directory)
    except (ValueError, OSError) as error:
        typer.echo(json.dumps(_unavailable(error)))
        raise typer.Exit(2)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
