"""Fixed-task tests; they do not certify Windows capture or native execution."""
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from transpect_trace.flow.scenarios import participant, runtime
from transpect_trace.flow.scenarios.manifest import default_steps
from transpect_trace.flow.scenarios.models import BusinessScenarioReport, ScenarioEvidence, ScenarioProcess, ScenarioStage


def test_model_reply_issues_only_fixed_command_and_does_not_echo_input():
    secret = 'SYNTHETIC_DO_NOT_ECHO_BUSINESS_SECRET'
    rows = runtime.model_events('fixed-local-task', Path('isolated'), json.dumps({
        'input': [{'type': 'message', 'role': 'user', 'content': secret}]}).encode())
    text = json.dumps(rows)
    assert secret not in text
    calls = rows[-1]['response']['output']
    assert len(calls) == 1 and calls[0]['call_id'] == 'call_business'
    assert calls[0]['name'] == 'exec_command'
    args = json.loads(calls[0]['arguments'])
    assert args['cmd'] == 'fixed-local-task' and args['login'] is False
    assert args['workdir'] == 'isolated'


def test_model_reply_completes_only_after_corresponding_tool_result():
    body = json.dumps({'input': [{'type': 'function_call_output', 'call_id': 'call_business',
                                  'output': 'SYNTHETIC_TOOL_RESULT_SECRET'}]}).encode()
    rows = runtime.model_events('fixed-local-task', Path('isolated'), body)
    assert rows[-1]['response']['output'] == []
    assert 'SYNTHETIC_TOOL_RESULT_SECRET' not in json.dumps(rows)
    unrelated = json.dumps({'input': [{'type': 'function_call_output', 'call_id': 'other-task', 'output': 'done'}]}).encode()
    rows = runtime.model_events('fixed-local-task', Path('isolated'), unrelated)
    assert rows[-1]['response']['output'][0]['call_id'] == 'call_business'


def test_running_business_tool_is_polled_instead_of_finishing_the_agent():
    body=json.dumps({'input':[{'type':'function_call_output','call_id':'call_business',
                              'output':'Process running with session ID 8123\nSYNTHETIC_NOT_TO_ECHO'}]}).encode()
    rows=runtime.model_events('fixed-local-task',Path('isolated'),body)
    call=rows[-1]['response']['output'][0]
    assert call['name']=='write_stdin'
    assert json.loads(call['arguments'])=={'session_id':8123,'chars':'','yield_time_ms':1000}
    assert 'SYNTHETIC_NOT_TO_ECHO' not in json.dumps(rows)
    followup=json.dumps({'input':[{'type':'function_call_output','call_id':call['call_id'],
                                 'output':'Process exited with code 0'}]}).encode()
    assert runtime.model_events('fixed-local-task',Path('isolated'),followup)[-1]['response']['output']==[]


def test_powershell_fixed_script_only_embeds_quoted_paths(tmp_path):
    config = tmp_path / "contains-CONTROL-CONFIG-'quote'" / 'task.json'
    control = tmp_path / "control 'path'"
    script = runtime.powershell_task(config, control)
    assert runtime.ps_quote(config) in script
    assert runtime.ps_quote(control) in script
    assert 'Invoke-RestMethod' in script
    assert 'SkipCertificateCheck' not in script and 'ExecutionPolicy' not in script
    assert 'CertificateValidationCallback' not in script
    assert '1048576' in script or '1024*1024' in script


def test_powershell_script_does_not_read_configuration_at_generation_time(tmp_path):
    source = tmp_path / 'task.json'
    source.write_text('{"secret":"SYNTHETIC_CONFIG_SECRET"}')
    script = runtime.powershell_task(source, tmp_path)
    assert 'SYNTHETIC_CONFIG_SECRET' not in script
    assert '::ReadAllText' in script and 'Wait-Flag' in script


def test_runtime_child_environment_does_not_inherit_model_auth_or_proxy(tmp_path, monkeypatch):
    for key in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CODEX_API_KEY', 'OPENAI_BASE_URL',
                'CODEX_CA_CERTIFICATE', 'SSL_CERT_FILE', 'SSLKEYLOGFILE', 'HTTPS_PROXY'):
        monkeypatch.setenv(key, 'SYNTHETIC_ENV_SECRET')
    result = runtime.clean_environment(tmp_path)
    assert 'SYNTHETIC_ENV_SECRET' not in json.dumps(result)
    assert result['CODEX_HOME'] == str(tmp_path)


def test_non_windows_runtime_never_releases_or_launches(tmp_path, monkeypatch):
    output = tmp_path / 'audit'
    manifest = SimpleNamespace(scenario='webhook', case='public', steps=default_steps('webhook'))
    monkeypatch.setattr(runtime, 'load', lambda path: (manifest, {}, output))
    monkeypatch.setattr(runtime.sys, 'platform', 'linux')
    monkeypatch.setattr(runtime.subprocess, 'Popen', lambda *a, **kw: pytest.fail('unsupported host launched a child'))
    result = runtime.run(tmp_path / 'manifest.json')
    assert result['state'] == 'unavailable'
    assert result['data_released'] is False and result['certified'] is False
    assert result['gaps'] == ['requires_windows_x64']


def execute_transform(tmp_path, monkeypatch, case, returncode=0):
    incident = tmp_path / 'incident.json'
    incident.write_text(json.dumps({'secret': 'SYNTHETIC_GIT_SOURCE_SECRET', 'public': 'ordinary'}), encoding='utf-8')
    control = tmp_path / 'control'
    control.mkdir()
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    generated = workspace / 'diagnostics.json'
    commands = []

    def run(args, **kwargs):
        commands.append((args, kwargs))
        return SimpleNamespace(returncode=returncode if 'push' in args else 0, stdout=b'', stderr=b'')

    monkeypatch.setattr(participant, 'rendezvous', lambda *a, **kw: None)
    monkeypatch.setattr(participant, 'wait', lambda *a, **kw: None)
    monkeypatch.setattr(participant.subprocess, 'run', run)
    participant.transform({'incident': str(incident), 'generated': str(generated), 'case': case,
                           'git': 'frozen-git.exe', 'git_tls_backend': 'schannel',
                           'url': 'https://localhost:443/target.git'}, control)
    return commands, generated, json.loads((control / 'transformer.done.json').read_text())


@pytest.mark.parametrize('case', ['public', 'untracked', 'old_commit', 'deleted_history', 'sensitive', 'repeat', 'reject_ref'])
def test_git_fixed_case_selection_and_audit_redaction(tmp_path, monkeypatch, case):
    commands, generated, result = execute_transform(tmp_path, monkeypatch, case,
                                                    returncode=1 if case == 'reject_ref' else 0)
    args = [row[0] for row in commands]
    pushes = [row for row in args if 'push' in row]
    assert len(pushes) == (2 if case == 'repeat' else 1)
    assert all('http.sslVerify=true' in row and 'http.sslBackend=schannel' in row for row in pushes)
    assert all(row[0] == 'frozen-git.exe' for row in args)
    assert 'SYNTHETIC_GIT_SOURCE_SECRET' not in json.dumps(result)
    if case == 'public':
        assert 'SYNTHETIC_GIT_SOURCE_SECRET' not in generated.read_text()
    if case in {'untracked', 'old_commit'}:
        assert any(row[-2:] == ['add', 'ordinary.txt'] for row in args)
    if case == 'untracked':
        assert not any(row[-2:] == ['add', 'diagnostics.json'] for row in args)
    if case == 'old_commit':
        assert pushes[0][-1] == 'HEAD~1:refs/heads/fixture'
    if case == 'deleted_history':
        assert any(row[-2:] == ['rm', 'diagnostics.json'] for row in args)
        assert sum('commit' in row for row in args) == 2
    if case == 'reject_ref':
        assert result['success'] is False and result['expected_ref_rejection'] is True


def test_git_environment_ignores_existing_helper_and_proxy(monkeypatch):
    for key in ('GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_SSH_COMMAND', 'HTTPS_PROXY'):
        monkeypatch.setenv(key, 'SYNTHETIC_GIT_ENV_SECRET')
    env = participant.git_environment()
    assert 'SYNTHETIC_GIT_ENV_SECRET' not in json.dumps(env)
    assert env['GIT_CONFIG_GLOBAL'] == 'NUL' and env['GIT_CONFIG_NOSYSTEM'] == '1'


def test_git_credential_rendezvous_precedes_emitting_fake_auth(tmp_path, monkeypatch):
    monkeypatch.setattr(participant.os, 'getpid', lambda: 3)
    monkeypatch.setattr(participant, 'parent_map', lambda: {3: (2, 'python.exe'), 2: (1, 'git-remote-https.exe')})
    stdin, stdout = io.StringIO('protocol=https\nhost=localhost\n\n'), io.StringIO()
    monkeypatch.setattr(participant.sys, 'stdin', stdin)
    monkeypatch.setattr(participant.sys, 'stdout', stdout)
    observed = []

    def ready(*args, **kwargs):
        assert stdout.getvalue() == ''
        observed.append((args, kwargs))

    monkeypatch.setattr(participant, 'rendezvous', ready)
    participant.credential(tmp_path)
    assert observed[0][1]['helper_pid'] == 2
    assert stdout.getvalue() == 'username=fixture\npassword=fixture\n\n'


def test_git_credential_cannot_redirect_to_unrelated_process(tmp_path, monkeypatch):
    monkeypatch.setattr(participant.os, 'getpid', lambda: 3)
    monkeypatch.setattr(participant, 'parent_map', lambda: {3: (2, 'python.exe'), 2: (1, 'unrelated.exe')})
    with pytest.raises(ValueError, match='git_transport_parent_not_found'):
        participant.credential(tmp_path)


def report_adder():
    report = BusinessScenarioReport(session_id='session', scenario='git', case='sensitive',
                                    stages=[ScenarioStage(stage_id=s.step_id, participant=s.participant)
                                            for s in default_steps('git')])

    def add(stage, provenance, process=None, **kwargs):
        row = ScenarioEvidence(evidence_id=f'e-{len(report.evidence)}', stage_id=stage,
                               provenance=provenance, process=process, **kwargs)
        report.evidence.append(row)
        next(s for s in report.stages if s.stage_id == stage).evidence_ids.append(row.evidence_id)
        return row

    return report, add


def git_receipt(attempt='attempt-1', **kwargs):
    return {'attempt_id': attempt, 'new_objects': [{'object_type': 'blob', 'object_id': 'a' * 40}],
            'inspection_complete': True, 'quarantine_observed': True, 'limitations': [], **kwargs}


def git_blob(attempt='attempt-1'):
    return {'attempt_id': attempt, 'object_id': 'a' * 40, 'object_bytes': 20,
            'content_sha256': 'b' * 64, 'inspected': True, 'findings': [],
            'raw_body': 'SYNTHETIC_DO_NOT_PERSIST_BLOB'}


def test_receiver_git_scan_keeps_equal_content_attempts_separate():
    report, add = report_adder()
    runtime.integrate_git(report, [git_receipt('attempt-1'), git_receipt('attempt-2')],
                          [git_blob('attempt-1'), git_blob('attempt-2')], add, {'transformer': {'success': True}})
    assert [row.attempt_id for row in report.git_scans] == ['attempt-1', 'attempt-2']
    assert len(report.git_objects) == 2
    assert report.git_objects[0].object_id == report.git_objects[1].object_id
    assert all(row.received_blob_count == 1 for row in report.git_scans)
    assert 'SYNTHETIC_DO_NOT_PERSIST_BLOB' not in report.model_dump_json()


def test_git_scan_counts_receiver_truth_not_successful_detector_callbacks():
    report, add = report_adder()
    runtime.integrate_git(report, [git_receipt()], [], add, {})
    assert report.git_scans[0].received_blob_count == 1
    assert report.git_objects == []
    # The later assessor will reject the missing blob inspection; a collector
    # callback failure must not turn one received object into a zero-object delta.


@pytest.mark.parametrize('change', [
    {'inspection_complete': False}, {'quarantine_observed': False},
    {'limitations': ['git_quarantine_inspection_failed']},
])
def test_git_scan_unknown_health_or_boundary_is_not_complete(change):
    report, add = report_adder()
    runtime.integrate_git(report, [git_receipt(**change)], [git_blob()], add, {})
    assert report.git_scans[0].complete is False


def test_git_unsupported_object_body_cannot_be_no_match():
    report, add = report_adder()
    blob = git_blob()
    blob['inspected'] = False
    runtime.integrate_git(report, [git_receipt()], [blob], add, {})
    assert report.git_objects[0].detection_status == 'incomplete'
    assert next(e for e in report.evidence if e.object_id).complete is False


def link_report():
    left_process = ScenarioProcess(role='exporter', pid=10, creation_filetime=100, image_sha256='a' * 64)
    right_process = ScenarioProcess(role='transformer', pid=11, creation_filetime=101, image_sha256='a' * 64)
    left = ScenarioEvidence(evidence_id='write', stage_id='export', provenance='native_io', process=left_process,
                            body_sha256='b' * 64, body_bytes=40, complete=True, file_identity='volume:file',
                            io_operation='write', io_offset=0, io_started_qpc=1, io_completed_qpc=2, qpc_frequency=1000,
                            event_ids=['native:1'])
    right = ScenarioEvidence(evidence_id='read', stage_id='transform', provenance='native_io', process=right_process,
                             body_sha256='b' * 64, body_bytes=40, complete=True, file_identity='volume:file',
                             io_operation='read', io_offset=0, io_started_qpc=3, io_completed_qpc=4, qpc_frequency=1000,
                             event_ids=['native:2'])
    return BusinessScenarioReport(session_id='session', scenario='webhook', case='plain',
                                   participants=[left_process, right_process], evidence=[left, right])


def test_content_link_builder_preserves_independent_same_body_attempts():
    report = link_report()
    for index in range(2):
        report.evidence.append(ScenarioEvidence(evidence_id=f'capture-{index}', stage_id='upload', provenance='ecapture',
                                                process=report.participants[1], attempt_id=f'attempt-{index}',
                                                body_sha256='b' * 64, body_bytes=40, complete=True))
    runtime.link_content(report)
    assert len([r for r in report.relations if r.method == 'observed_file_handoff']) == 1
    linked = [r.right_id for r in report.relations if r.left_id == 'read' and r.method == 'content_candidate']
    assert linked == ['capture-0', 'capture-1']


def test_content_link_builder_does_not_use_incomplete_source_or_capture():
    report = link_report()
    report.evidence[0].complete = False
    report.evidence.append(ScenarioEvidence(evidence_id='partial', stage_id='upload', provenance='ecapture',
                                            process=report.participants[1], body_sha256='b' * 64, body_bytes=40, complete=False))
    runtime.link_content(report)
    assert report.relations == []


def test_same_content_different_file_is_not_file_handoff():
    report = link_report()
    report.evidence[1].file_identity = 'different:file'
    runtime.link_content(report)
    assert not any(r.method == 'observed_file_handoff' for r in report.relations)


@pytest.mark.parametrize('released,expected', [(False, 'unavailable'), (True, 'partial')])
def test_late_runtime_failure_persists_uncertified_status_without_error_secret(tmp_path, monkeypatch, released, expected):
    output = tmp_path / 'audit'
    monkeypatch.setattr(runtime, 'load', lambda path: (None, {}, output))

    def operation(_):
        output.mkdir()
        runtime.dump(output / 'runtime.json', {'schema_version': 'transpect.business.runtime/1.0',
                     'session_id': 'session', 'scenario': 'webhook', 'state': 'observing',
                     'data_released': released, 'certified': True, 'can_enforce': False, 'gaps': ['prior_gap']})
        raise KeyError('SYNTHETIC_EXCEPTION_SECRET')

    monkeypatch.setattr(runtime, '_run', operation)
    result = runtime.run(tmp_path / 'manifest.json')
    saved = (output / 'runtime.json').read_text()
    assert result['state'] == expected and result['certified'] is False
    assert result == json.loads(saved)
    assert result['gaps'] == ['prior_gap', 'runtime_or_report_failed_KeyError']
    assert 'SYNTHETIC_EXCEPTION_SECRET' not in saved


@pytest.mark.parametrize('release_already_present', [False, True])
def test_worker_abort_precedes_task_release(tmp_path, monkeypatch, release_already_present):
    release = tmp_path / 'transformer.release'
    if release_already_present:
        release.touch()
    (tmp_path / 'abort').touch()
    monkeypatch.setattr(participant.time, 'sleep', lambda delay: pytest.fail('cancelled worker should not wait'))
    with pytest.raises(RuntimeError, match='fixture_cancelled'):
        participant.wait(release)
