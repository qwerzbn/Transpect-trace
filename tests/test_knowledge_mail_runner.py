"""A worker statement is not proof that Native authorized or rejected mail."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from types import SimpleNamespace

import pytest

from transpect_trace.flow.knowledge_mail import runner
from transpect_trace.flow.knowledge_mail.tools import LIMIT, NATIVE_OWNER, ToolError, encode_draft
from transpect_trace.protect.detection import ContentIndex


def draft():
    return {'From': {'Email': 'codex@transpect.test'},
            'To': [{'Email': 'partner@example.test'}],
            'Subject': 'FAKE_ONLY component subject', 'Text': 'Only public component data.'}


def evidence(deny=False):
    raw = encode_draft(draft())
    digest = hashlib.sha256(raw).hexdigest()
    subject = {'pid': 1201, 'creation_filetime': 555, 'image_sha256': 'a' * 64}
    capture = {'pid': 1201, 'creation_filetime': 555, 'attempt_id': 'actual-attempt',
               'body_sha256': digest, 'body_bytes': len(raw), 'completeness': 'complete',
               'source': NATIVE_OWNER, 'decision': 'BLOCK' if deny else 'ALLOW'}
    execution = {'pid': 1201, 'attempt_id': 'actual-attempt',
                 'action': 'block_request' if deny else 'none',
                 'result': 'native_rejection' if deny else 'transport_authorized'}
    result = {'kind': 'mail_blocked' if deny else 'mail_sent',
              'tool_attempt_id': 'b' * 32, 'body_sha256': digest, 'body_bytes': len(raw)}
    if deny:
        result['reason'] = 'NATIVE_PERMISSION_DENIED'
    else:
        result.update(status_code=200, delivery_scope='local_mailpit_acceptance')
    return subject, raw, [capture], [execution], result


@pytest.mark.parametrize('deny', [False, True])
def test_exact_native_attempt_and_body_can_verify_execution_only(deny):
    value = evidence(deny)
    original = deepcopy(value)
    assert runner.verify_execution(*value)
    assert value == original


@pytest.mark.parametrize('group,index,key,value', [
    ('capture', 0, 'pid', 1202), ('capture', 0, 'creation_filetime', 556),
    ('capture', 0, 'attempt_id', 'unrelated'), ('capture', 0, 'body_sha256', 'c' * 64),
    ('capture', 0, 'body_bytes', 1), ('capture', 0, 'completeness', 'partial'),
    ('capture', 0, 'source', 'observer'), ('capture', 0, 'decision', 'UNRECOGNIZED'),
    ('execution', 0, 'pid', 1202), ('execution', 0, 'attempt_id', 'unrelated'),
    ('execution', 0, 'action', 'terminate_process'),
    ('execution', 0, 'result', 'native_rejection'),
    ('result', 0, 'body_sha256', 'c' * 64), ('result', 0, 'body_bytes', 1),
    ('result', 0, 'kind', 'tool_failed'),
])
def test_mismatched_native_or_worker_evidence_is_not_verified(group, index, key, value):
    subject, raw, captures, executions, result = evidence()
    selected = {'capture': captures[0], 'execution': executions[0], 'result': result}[group]
    selected[key] = value
    assert not runner.verify_execution(subject, raw, captures, executions, result)


@pytest.mark.parametrize('deny', [False, True])
def test_missing_duplicate_attempts_or_executions_do_not_verify(deny):
    subject, raw, captures, executions, result = evidence(deny)
    for c, e in [([], executions), (captures, []), (captures * 2, executions),
                 (captures, executions * 2)]:
        assert not runner.verify_execution(subject, raw, c, e, result)


@pytest.mark.parametrize('decision', ['BLOCK', 'REVIEW', 'UNKNOWN'])
def test_refusal_needs_native_rejection_and_block_request(decision):
    subject, raw, captures, executions, result = evidence(True)
    captures[0]['decision'] = decision
    assert runner.verify_execution(subject, raw, captures, executions, result)
    executions[0]['action'] = 'none'
    assert not runner.verify_execution(subject, raw, captures, executions, result)


def test_worker_output_discards_unrecognized_fields_and_cannot_claim_receipt():
    result = evidence()[-1]
    result.update(Text='FAKE_ONLY_SECRET', Authorization='Bearer FAKE_ONLY_TOKEN',
                  Cookie='FAKE_ONLY_COOKIE', receipt_verified=True)
    public = runner.public_worker_result(result)
    encoded = json.dumps(public)
    assert 'FAKE_ONLY_SECRET' not in encoded and 'Bearer' not in encoded and 'COOKIE' not in encoded
    assert public['receipt_verified'] is False


@pytest.mark.parametrize('value', [None, [], {'kind': 'other'},
    {'kind': 'mail_blocked', 'reason': 'private exception body'},
    {'kind': 'mail_blocked', 'body_sha256': 'secret'},
    {'kind': 'mail_sent', 'status_code': 503, 'delivery_scope': 'local_mailpit_acceptance'},
    {'kind': 'mail_sent', 'status_code': 200, 'delivery_scope': 'external_smtp_delivery'},
    {'kind': 'mail_blocked', 'body_bytes': True}])
def test_malformed_control_output_is_rejected(value):
    with pytest.raises(ValueError, match='mail_worker_result_invalid'):
        runner.public_worker_result(value)


def test_oversized_draft_is_rejected_before_unbounded_read(tmp_path):
    path = tmp_path / 'oversized.json'
    path.write_bytes(b' ' * (LIMIT + 10))
    with pytest.raises(ToolError, match='JSON_SIZE_UNSUPPORTED'):
        runner.bounded_json(path)


@pytest.fixture
def controlled_worker(tmp_path, monkeypatch):
    from transpect_trace.observe import windows
    from transpect_trace.protect import pipe
    subject, raw, captures, executions, result = evidence()
    index = tmp_path / 'index.json'
    index.write_text(ContentIndex.register('component/1', []).model_dump_json())
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'content_index': str(index), 'gate_audit_directory': str(tmp_path / 'audit'),
                                  'gate_dll': 'fixed-test.pyd', 'gate_manifest': 'fixed-test.json',
                                  'run_id': 'component'}))
    body = tmp_path / 'draft.json'
    body.write_bytes(raw)
    state = {'subject': subject, 'captures': captures, 'executions': executions, 'result': result,
             'ready': {'kind': 'protect.ready', 'pid': subject['pid'], 'gate_ready': True,
                       'adapter_id': NATIVE_OWNER, 'mode': 'outbound-json'},
             'gate_errors': [], 'returncode': 0, 'capture_result': None}

    class Process:
        pid = subject['pid']
        returncode = None

        def __init__(self, *args, **kwargs):
            self.stdin = io.BytesIO()
            state['process'] = self

        def wait(self, timeout):
            self.returncode = state['returncode']
            return self.returncode

    class Gate:
        def __init__(self, supplied_subject, engine, audit):
            assert supplied_subject == subject
            self.engine = engine
            self.errors = state['gate_errors']
            self.execution_records = []
            state['gate'] = self

        def start(self):
            state['started'] = True

        def close(self):
            state['closed'] = True

    class Output:
        def __init__(self, process):
            self.count = 0

        def get(self, timeout):
            self.count += 1
            if self.count == 1:
                return state['ready']
            assert state.get('started')
            assert b'RUN\n' in state['process'].stdin.getvalue()
            gate = state['gate']
            gate.engine.captures[:] = state['captures']
            gate.execution_records[:] = state['executions']
            return state['result']

    counter = iter(range(0, 1000, 10))
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda: next(counter), sleep=lambda _: None))
    monkeypatch.setattr(runner.subprocess, 'Popen', Process)
    monkeypatch.setattr(runner, 'ControlOutput', Output)
    monkeypatch.setattr(windows, 'identity', lambda pid: {**subject})
    monkeypatch.setattr(pipe, 'ProtectionServer', Gate)
    return state, config, body


def test_controlled_worker_is_released_after_ready_and_native_proof_is_required(controlled_worker):
    state, config, body = controlled_worker
    result = runner.send_protected(config, body)
    assert result['kind'] == 'mail_sent' and result['execution_verified']
    report = json.loads((__import__('pathlib').Path(result['audit_directory']) / 'summary.json').read_text())
    assert report['receiver_verified'] is False
    assert state['closed']


@pytest.mark.parametrize('fault', ['missing_execution', 'duplicate_execution', 'gate_error', 'worker_exit',
                                   'changed_body', 'missing_capture'])
def test_worker_success_with_broken_evidence_becomes_failure(controlled_worker, fault):
    state, config, body = controlled_worker
    if fault == 'missing_execution':
        state['executions'] = []
    elif fault == 'duplicate_execution':
        state['executions'] *= 2
    elif fault == 'gate_error':
        state['gate_errors'].append('request_or_transport_invalid')
    elif fault == 'worker_exit':
        state['returncode'] = 2
    elif fault == 'changed_body':
        state['captures'][0]['body_sha256'] = 'c' * 64
    else:
        state['captures'] = []
    result = runner.send_protected(config, body)
    assert result['kind'] == 'tool_failed' and not result['execution_verified']
    assert result['reason'] == 'MAIL_EXECUTION_UNVERIFIED'


@pytest.mark.parametrize('field,value', [('adapter_id', 'unregistered'), ('mode', 'llm'),
                                       ('pid', True), ('gate_ready', False)])
def test_bad_ready_never_releases_worker(controlled_worker, field, value):
    state, config, body = controlled_worker
    state['ready'][field] = value
    result = runner.send_protected(config, body)
    assert result['kind'] == 'tool_failed' and not result['execution_verified']
    assert 'started' not in state


def test_non_object_control_record_is_invalid():
    output = runner.ControlOutput(SimpleNamespace(stdout=io.BytesIO(b'[]\n')))
    assert output.get(2)['kind'] == 'invalid_control'
