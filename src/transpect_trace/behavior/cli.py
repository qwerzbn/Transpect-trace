import json
from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True, help='Fixed Codex system behavior evidence; separate from Native request protection.')


@app.command('attach')
def attach(pid: int = typer.Option(..., min=1),
           output: Path = typer.Option(...),
           collector: Path = typer.Option(Path('build/behavior/etw.exe'), exists=True),
           expected_creation_filetime: int | None = typer.Option(None, min=1),
           duration: int = typer.Option(30, min=1, max=300)):
    from transpect_trace.guard.native import process_identity
    from .collector import CodexBehaviorCollector
    from .report import build_report
    subject = process_identity(pid)
    if expected_creation_filetime is not None and subject['creation_filetime'] != expected_creation_filetime:
        raise typer.BadParameter('Process generation changed before collector attachment')
    session = CodexBehaviorCollector(subject, collector, output, duration=duration)
    session.start(); session.wait()
    report = build_report(output)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    typer.echo(json.dumps(session.index.health()))
    if session.index.health()['state'] != 'stopped':
        raise typer.Exit(2)


@app.command('report')
def report(directory: Path = typer.Argument(..., exists=True),
           guard_directory: Path | None = typer.Option(None, exists=True),
           policy_file: Path | None = typer.Option(None, exists=True)):
    from .report import build_report
    from .models import EgressRule
    rules = [EgressRule.model_validate(r) for r in json.loads(policy_file.read_text())] if policy_file else []
    value = build_report(directory, guard_directory=guard_directory, rules=rules)
    (directory / 'report.json').write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    typer.echo(str(directory / 'report.json'))


@app.command('status')
def status(directory: Path = typer.Argument(..., exists=True)):
    value = json.loads((directory / 'status.json').read_text(encoding='utf-8'))
    value['snapshot_only'] = True
    if value['health']['state'] == 'ready':
        from transpect_trace.observe.windows import identity
        expected = value.get('controller_identity', {})
        try:
            actual = identity(expected['pid'])
            alive = actual['creation_filetime'] == expected['creation_filetime'] and actual['image_sha256'] == expected['image_sha256']
        except (OSError, ValueError, KeyError, RuntimeError):
            alive = False
        if not alive:
            value['health']['state'] = 'degraded'
            value['health']['gaps'].append('controller_dead_or_identity_unavailable')
    typer.echo(json.dumps(value, indent=2))
