import json
import sys
from types import SimpleNamespace

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from transpect_trace.cli import app
from transpect_trace.flow.scenarios.cli import read_status
from transpect_trace.flow.scenarios.models import BusinessRuntimeStatus, ScenarioProcess


def status(tmp_path):
    row = BusinessRuntimeStatus(session_id='session', scenario='webhook', state='observing',
                                controller=ScenarioProcess(role='controller', pid=5,
                                                           creation_filetime=10, image_sha256='a' * 64))
    path = tmp_path / 'runtime.json'
    path.write_text(row.model_dump_json(), encoding='utf-8')
    return path


def test_cli_registration_preserves_independent_flow_and_agents():
    flow = get_command(app).commands['flow'].commands
    assert {'run', 'status', 'report', 'agents', 'scenarios', 'knowledge-mail'} == set(flow)
    assert set(flow['scenarios'].commands) == {'run', 'status', 'report'}
    assert set(flow['agents'].commands) == {'run', 'status', 'report'}


@pytest.mark.parametrize('changed', ['pid', 'creation_filetime', 'image_sha256'])
def test_running_status_checks_full_controller_identity(tmp_path, monkeypatch, changed):
    import transpect_trace.observe.windows as windows
    path = status(tmp_path)
    original = path.read_bytes()
    actual = {'pid': 5, 'creation_filetime': 10, 'image_sha256': 'a' * 64}
    actual[changed] = 'b' * 64 if changed == 'image_sha256' else actual[changed] + 1
    monkeypatch.setattr(windows, 'identity', lambda pid: actual)
    result = read_status(tmp_path)
    assert result['state'] == 'unavailable' and result['controller_live'] is False
    assert result['recorded_state'] == 'observing'
    assert path.read_bytes() == original


def test_alive_controller_retains_observing_state(tmp_path, monkeypatch):
    import transpect_trace.observe.windows as windows
    status(tmp_path)
    monkeypatch.setattr(windows, 'identity', lambda pid: {'pid': 5, 'creation_filetime': 10, 'image_sha256': 'a' * 64})
    result = read_status(tmp_path)
    assert result['state'] == 'observing' and result['controller_live']


def test_status_errors_are_redacted_and_missing_report_is_explicit(tmp_path):
    (tmp_path / 'runtime.json').write_text('{"body":"SECRET_MUST_NOT_PRINT"}', encoding='utf-8')
    result = CliRunner().invoke(app, ['flow', 'scenarios', 'status', str(tmp_path)])
    assert result.exit_code == 2 and 'SECRET_MUST_NOT_PRINT' not in result.output
    assert json.loads(result.output)['state'] == 'unavailable'
    result = CliRunner().invoke(app, ['flow', 'scenarios', 'report', str(tmp_path)])
    assert result.exit_code == 0 and 'business_evidence_not_available' in result.output


def test_run_exception_does_not_disclose_manifest_inputs(tmp_path, monkeypatch):
    def run(_):
        raise RuntimeError('Authorization Bearer SECRET_MUST_NOT_PRINT')
    monkeypatch.setitem(sys.modules, 'transpect_trace.flow.scenarios.runtime', SimpleNamespace(run=run))
    path = tmp_path / 'manifest.json'
    path.write_text('{}')
    result = CliRunner().invoke(app, ['flow', 'scenarios', 'run', '--manifest', str(path)])
    assert result.exit_code == 2 and 'SECRET_MUST_NOT_PRINT' not in result.output
    assert json.loads(result.output)['error_type'] == 'RuntimeError'


def test_report_revalidates_saved_complete_claim(tmp_path):
    (tmp_path / 'business-report.json').write_text(json.dumps({
        'session_id': 'session', 'scenario': 'webhook', 'case': 'public', 'state': 'complete', 'certified': True}), encoding='utf-8')
    result = CliRunner().invoke(app, ['flow', 'scenarios', 'report', str(tmp_path)])
    body = json.loads(result.output)
    assert body['state'] == 'unavailable' and not body['certified']
