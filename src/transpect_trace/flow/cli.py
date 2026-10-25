"""Observation-only controlled cross-application experiments."""
import json
from pathlib import Path
import typer

app = typer.Typer(no_args_is_help=True, help=__doc__)
from .agents.cli import app as agents_app
app.add_typer(agents_app, name='agents')


@app.command('run')
def run_command(manifest: Path = typer.Option(..., exists=True, dir_okay=False)):
    from .runtime import run
    try:
        result = run(manifest)
    except (ValueError, OSError) as error:
        # Validation errors may contain manifest inputs. Print only the class.
        typer.echo(json.dumps({'state': 'unavailable', 'error_type': type(error).__name__, 'can_enforce': False}))
        raise typer.Exit(2)
    typer.echo(json.dumps(result, indent=2))
    if result['state'] != 'complete': raise typer.Exit(2)


@app.command('status')
def status_command(directory: Path = typer.Argument(..., exists=True, file_okay=False)):
    typer.echo(json.dumps(read_status(directory), indent=2))


def read_status(directory):
    value = json.loads((Path(directory)/'runtime.json').read_text(encoding='utf-8'))
    if value.get('state') in {'initializing','observing'}:
        try:
            from transpect_trace.observe.windows import identity
            expected = value['controller']
            actual = identity(expected['pid'])
            if any(actual[k] != expected[k] for k in ('creation_filetime','image_sha256')):
                raise ValueError('controller_generation_changed')
            value['controller_live'] = True
        except (KeyError, ValueError, OSError, AttributeError):
            value['recorded_state'] = value['state']
            value['state'] = 'unavailable'
            value['controller_live'] = False
            value['gaps'] = [*value.get('gaps', []), 'controller_identity_unavailable']
    return value


@app.command('report')
def report_command(directory: Path = typer.Argument(..., exists=True, file_okay=False)):
    from .report import report
    typer.echo(json.dumps(report(directory), ensure_ascii=False, indent=2))
