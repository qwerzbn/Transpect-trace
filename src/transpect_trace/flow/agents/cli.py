"""Controlled two-test-agent propagation; observation only."""
import json
from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True, help=__doc__)


@app.command('run')
def run_command(manifest: Path = typer.Option(..., exists=True, dir_okay=False)):
    from .runtime import run
    try:
        result = run(manifest)
    except (ValueError, OSError) as error:
        typer.echo(json.dumps({'state':'unavailable', 'error_type':type(error).__name__, 'can_enforce':False}))
        raise typer.Exit(2)
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    if result['state'] != 'complete':
        raise typer.Exit(2)


@app.command('status')
def status_command(directory: Path = typer.Argument(..., exists=True, file_okay=False)):
    from ..cli import read_status
    result = read_status(directory)
    if result.get('schema_version') != 'transpect.agent-flow.runtime/1.0' or result.get('can_enforce') is not False:
        raise typer.BadParameter('not an agent flow runtime')
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))


def read_report(directory):
    directory = Path(directory)
    path = directory/'agent-evidence.json'
    if not path.is_file():
        return {'schema_version':'transpect.agent.report/1.0', 'status':'unavailable',
                'limitations':['agent_evidence_not_available'], 'can_enforce':False}
    result = json.loads(path.read_text(encoding='utf-8'))
    if result.get('schema_version') != 'transpect.agent.report/1.0' or result.get('can_enforce') is not False:
        raise ValueError('invalid agent flow evidence')
    result['independent_evidence_files'] = [name for name in
        ('flow-evidence.json', 'etw/events.jsonl', 'etw/status.json', 'runtime.json')
        if (directory/name).is_file()]
    return result


@app.command('report')
def report_command(directory: Path = typer.Argument(..., exists=True, file_okay=False)):
    typer.echo(json.dumps(read_report(directory), ensure_ascii=False, indent=2))
