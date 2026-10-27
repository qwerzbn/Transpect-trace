"""Real Codex reads BookStack and submits text mail through a Native gate."""
import json
from pathlib import Path
import typer

app = typer.Typer(no_args_is_help=True, help=__doc__)


@app.command('run')
def run_command(output: Path = typer.Option(...), codex: Path = typer.Option(..., exists=True, dir_okay=False),
                gate_dll: Path = typer.Option(Path('build/python-outbound-20261026/_ttrace_native_gate.pyd'), exists=True),
                gate_manifest: Path = typer.Option(Path('build/python-outbound-20261026/native-build.json'), exists=True),
                repeat: int = typer.Option(1, min=1, max=3),
                database_image: str = typer.Option('mysql:8.0.36'),
                fake_data_only: bool = typer.Option(False, '--fake-data-only')):
    if not fake_data_only:
        raise typer.BadParameter('This experiment requires --fake-data-only')
    from .experiment import run
    try:
        result = run(output, codex, gate_dll, gate_manifest, repeat=repeat, database_image=database_image)
    except (ValueError, OSError) as error:
        typer.echo(json.dumps({'state': 'unavailable', 'error_type': type(error).__name__, 'passed': False}))
        raise typer.Exit(2)
    typer.echo(json.dumps({'state': result['state'], 'passed': result['passed'],
                           'cases': [{'case': c['case'], 'passed': c['passed']} for c in result['cases']],
                           'errors': result['errors']}, ensure_ascii=False, indent=2))
    if not result['passed']:
        raise typer.Exit(2)


@app.command('status')
@app.command('report')
def report_command(directory: Path = typer.Argument(..., exists=True, file_okay=False)):
    from .models import KnowledgeMailReport
    value = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    if value.get('schema_version') != 'transpect.knowledge-mail.report/1.0':
        raise typer.BadParameter('Unsupported knowledge-mail report')
    try:
        value = KnowledgeMailReport.model_validate(value).model_dump()
    except ValueError:
        raise typer.BadParameter('Invalid knowledge-mail report') from None
    if value['state'] in {'starting_services', 'running_codex'}:
        try:
            from transpect_trace.observe.windows import identity
            if identity(value['controller']['pid']) != value['controller']:
                raise ValueError('controller_changed')
        except (OSError, ValueError, KeyError, AttributeError):
            value['state'] = 'unavailable'
            value['passed'] = False
            value['errors'] = [*value['errors'], 'controller_not_live']
    typer.echo(json.dumps(value, ensure_ascii=False, indent=2))
