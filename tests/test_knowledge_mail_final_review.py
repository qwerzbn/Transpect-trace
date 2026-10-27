"""Independent review counterexamples for the real knowledge/mail claims."""
from __future__ import annotations

import hashlib
import io
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from transpect_trace.flow.knowledge_mail import experiment, mcp
from transpect_trace.flow.knowledge_mail.models import KnowledgeMailReport
from transpect_trace.flow.knowledge_mail.tools import NATIVE_OWNER, encode_draft


def case_input():
    public = 'The project has completed its documentation milestone.'
    draft = {'From': {'Email': 'codex@transpect.test'}, 'To': [{'Email': 'partner@example.test'}],
             'Subject': 'KM-review', 'Text': public}
    raw = encode_draft(draft)
    digest = hashlib.sha256(raw).hexdigest()
    subject = {'pid': 123, 'creation_filetime': 456, 'image_sha256': 'a' * 64}
    capture = {'attempt_id': 'native-attempt', 'pid': 123, 'creation_filetime': 456,
               'body_sha256': digest, 'body_bytes': len(raw), 'completeness': 'complete',
               'source': NATIVE_OWNER, 'decision': 'ALLOW'}
    execution = {'attempt_id': 'native-attempt', 'pid': 123, 'action': 'none',
                 'result': 'transport_authorized'}
    return dict(case='ordinary', public_text=public, marker='FAKE_ONLY_NOT_PRESENT', draft=draft,
                reads=[{'kind': 'knowledge_page_read', 'page_id': 1}],
                submissions=[{'execution_verified': True, 'native_ready': True, 'worker_exit_code': 0,
                              'errors': [], 'cleanup_kill': False, 'subject': subject,
                              'captures': [capture], 'executions': [execution],
                              'client_result': {'kind': 'mail_sent', 'body_sha256': digest,
                                                'body_bytes': len(raw)}}],
                new_messages=[{'message_id': 'received-1',
                               'normalized_text_sha256': experiment.mail_text_hash(public)}],
                codex={'exit_code': 0, 'timed_out': False, 'errors': [], 'autonomous_model': True,
                       'preprogrammed_model_service': False,
                       'events': [{'type': 'item.completed', 'item_type': 'mcp_tool_call',
                                   'mcp_server': 'knowledge_mail', 'mcp_tool': 'read_page',
                                   'tool_status': 'completed', 'mcp_error_present': False,
                                   'mcp_result_failed': False}, {'type': 'turn.completed'}]})


def test_reference_evidence_is_accepted_before_mutation():
    assert experiment.assess_case(**case_input())['passed']


@pytest.mark.parametrize('field,value', [('autonomous_model', False),
                                       ('preprogrammed_model_service', True)])
def test_ordinary_success_cannot_be_certified_as_real_autonomy_when_declared_otherwise(field, value):
    data = case_input()
    data['codex'][field] = value
    assert not experiment.assess_case(**data)['passed']


@pytest.mark.parametrize('change', [
    {'type': 'item.started', 'tool_status': 'in_progress'},
    {'tool_status': 'failed', 'mcp_error_present': True},
    {'tool_status': 'completed', 'mcp_result_failed': True},
])
def test_pending_or_failed_mcp_call_is_not_successful_tool_execution(change):
    data = case_input()
    data['codex']['events'][0].update(change)
    result = experiment.assess_case(**data)
    assert not result['checks']['real_tool_execution']
    assert not result['passed']


def complete_report():
    cases = []
    for name in ('ordinary', 'sensitive', 'redacted'):
        cases.append({'case': name, 'passed': True, 'checks': {'required_evidence': True}})
    return {'schema_version': 'transpect.knowledge-mail.report/1.0', 'state': 'complete',
            'passed': True, 'cases': cases, 'expected_cases': 3,
            'controller': {'pid': 777, 'creation_filetime': 888, 'image_sha256': 'a' * 64},
            'real_codex_autonomy': True, 'codex_sha256': experiment.BINARY_SHA256,
            'codex_tool_host_sha256': experiment.CODEX_TOOL_HOST_SHA256,
            'model': 'component-only', 'mail_control': 'component-only',
            'service_transport': 'loopback HTTP', 'scope': 'component-only',
            'service_cleanup_confirmed': True}


@pytest.mark.parametrize('fault', ['failed_check', 'no_checks', 'no_autonomy', 'wrong_cli', 'wrong_host'])
def test_complete_public_report_cannot_contradict_evidence_or_baseline(fault):
    value = complete_report()
    if fault == 'failed_check':
        value['cases'][0]['checks']['required_evidence'] = False
    elif fault == 'no_checks':
        value['cases'][0].pop('checks')
    elif fault == 'no_autonomy':
        value['real_codex_autonomy'] = False
    elif fault == 'wrong_cli':
        value['codex_sha256'] = 'b' * 64
    else:
        value['codex_tool_host_sha256'] = 'c' * 64
    with pytest.raises(ValueError):
        KnowledgeMailReport.model_validate(value)


def test_codex_default_audit_does_not_persist_unknown_metadata_or_usage_text(tmp_path):
    marker = 'FAKE_ONLY_SECRET_METADATA_MUST_NOT_PERSIST'
    rows = [{'type': 'item.completed', 'item': {'id': 'item_1', 'type': 'mcp_tool_call',
             'server': marker, 'tool': marker, 'status': marker, 'arguments': {'draft': marker},
             'result': {'Text': marker}}},
            {'type': 'turn.completed', 'usage': {'input_tokens': 1, 'output_tokens': 2,
                                               'unrecognized_private_context': marker}}]
    encoded = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
    process = SimpleNamespace(stdout=io.BytesIO(encoded), returncode=0, wait=lambda timeout: 0)
    progress = tmp_path / 'codex-events.jsonl'
    result = experiment.collect_codex(process, progress_path=progress)
    assert marker not in json.dumps(result)
    assert marker.encode() not in progress.read_bytes()


def test_initialized_notification_accepts_standard_metadata_without_executing_work(tmp_path, monkeypatch):
    path = tmp_path / 'tools.json'
    path.write_text(json.dumps({'page_id': 7,
                               'draft_path': str((tmp_path / 'explicit-fake-fixtures/mail.json').resolve())}))
    monkeypatch.setattr(mcp, 'KnowledgeMailTools', lambda _: SimpleNamespace())
    server = mcp.MCPServer(path)
    response = server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                              'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                                         'clientInfo': {'name': 'review-client', 'version': '1'}}})
    assert 'result' in response
    assert server.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized',
                          'params': {'_meta': {'review_token': 'not_persisted'}}}) is None
    assert server.ready
    assert 'result' in server.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})


def test_formal_preparation_and_mcp_files_are_in_source_allowlist():
    root = Path(__file__).resolve().parents[1]
    files = set(json.loads((root / 'release-files.json').read_text(encoding='utf-8'))['files'])
    assert {'scripts/prepare_codex_tools.py', 'tests/test_prepare_codex_tools.py',
            'src/transpect_trace/flow/knowledge_mail/mcp.py', 'tests/test_knowledge_mail_mcp.py'} <= files
