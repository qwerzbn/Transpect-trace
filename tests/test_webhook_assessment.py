"""Evidence assessment tests, not Windows capture or enforcement certification."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from transpect_trace.flow.models import CollectorHealth
from transpect_trace.flow.scenarios.models import ScenarioProcess
from transpect_trace.flow.scenarios.runtime import webhook_control_assessment


def fixture(action='block'):
    exporter = ScenarioProcess(role='exporter', pid=100, creation_filetime=1000, image_sha256='a' * 64)
    powershell = ScenarioProcess(role='transformer', pid=200, creation_filetime=2000, image_sha256='b' * 64)
    healthy = lambda: CollectorHealth(ready=True, terminal=True, identity_verified=True)
    report = SimpleNamespace(participants=[exporter, powershell], health={
        name: healthy() for name in ('native_io', 'etw', 'ecapture', 'native_request')})
    base = dict(success=True, capture_gap=False, data_bytes=80, completed_length=80,
                data_sha256='c' * 64, file_identity='volume:file', offset=0, qpc_frequency=1000)
    io = [dict(base, pid=100, creation_filetime=1000, kind='write', path_role='source', qpc=1, completed_qpc=2),
          dict(base, pid=200, creation_filetime=2000, kind='read', path_role='source', qpc=3, completed_qpc=4),
          dict(base, pid=200, creation_filetime=2000, kind='write', path_role='transfer', qpc=5, completed_qpc=6,
               registration_ids=['fake-confidential'])]
    decision = dict(kind='connection.decision', run_id='run-1', pid=200, creation_filetime=2000,
                    attempt_id=7, destination_address='127.0.0.1', destination_port=19443,
                    protocol='tcp', decision=action, execution='pending')
    reject = dict(kind='connection.rejected', run_id='run-1', pid=200, creation_filetime=2000,
                  attempt_id=7, native_result=-1, winsock_error=10013,
                  evidence='native_failure_return_before_original_connect')
    clients = {'codex': {'exit_code': 0, 'tool_results': [{'status': 'completed', 'exit_code': 0}]},
               'transformer': {'success': action == 'allow', 'transform_success': True,
                               'attempts': [{'success': action == 'allow'}]}}
    tls = [] if action == 'block' else [dict(complete=True, inspected=True, body_sha256='c' * 64,
                                           body_bytes=80, findings=[{'registration_id': 'fake-confidential'}])]
    receipts = [] if action == 'block' else [dict(route='webhook', completeness='complete',
                                                 body_sha256='c' * 64, body_bytes=80)]
    return dict(report=report, clients=clients, io_rows=io, tls_rows=tls, receipts=receipts,
                egress_records=[decision, reject] if action == 'block' else [decision],
                egress_errors=[], action=action, port=19443, egress_ready=True, tool_ready=True,
                active_before_close=True, origin_errors=[], runtime_gaps=[],
                scope_control=dict(not_enrolled=True, controller_active=True, exit_code=0, exact_body_received=True))


def assess(value):
    return webhook_control_assessment(**value)


def test_denial_requires_native_execution_and_receiver_evidence():
    result = assess(fixture())
    assert result['passed'] is True and all(result['checks'].values())
    assert result['source_body_bytes'] == 0
    assert result['content_based_blocking'] is False
    assert result['protection_active_now'] is False
    assert result['business_transport'] == 'regular_file_and_https_not_experimental_business_pipe'


@pytest.mark.parametrize('field,value', [('run_id', 'other-run'), ('pid', 201),
                                       ('creation_filetime', 2001), ('attempt_id', 8)])
def test_native_rejection_must_match_exact_decision_identity(field, value):
    data = fixture()
    data['egress_records'][1][field] = value
    result = assess(data)
    assert result['passed'] is False
    assert result['checks']['native_block_return_paired'] is False


@pytest.mark.parametrize('field,value', [('native_result', 0), ('winsock_error', 10061),
                                       ('evidence', 'process_terminated_after_connect')])
def test_wrong_failure_or_termination_is_not_request_rejection(field, value):
    data = fixture()
    data['egress_records'][1][field] = value
    assert assess(data)['passed'] is False


def test_zero_source_or_client_failure_alone_cannot_prove_block():
    data = fixture()
    data['egress_records'] = []
    data['clients']['transformer']['attempts'] = [{'success': False, 'exit_code': 2}]
    assert assess(data)['passed'] is False


def test_every_target_decision_needs_its_own_denial_result():
    data = fixture()
    second = dict(data['egress_records'][0], attempt_id=8)
    data['egress_records'].append(second)
    result = assess(data)
    assert result['passed'] is False
    data['egress_records'].append(dict(data['egress_records'][1], attempt_id=8))
    assert assess(data)['passed'] is True


@pytest.mark.parametrize('size,state', [(1, 'complete'), (1, 'partial'), (0, 'partial')])
def test_any_received_body_or_incomplete_webhook_attempt_prevents_denial_certification(size, state):
    data = fixture()
    data['receipts'] = [dict(route='webhook', body_bytes=size, completeness=state, body_sha256='e' * 64)]
    result = assess(data)
    assert result['passed'] is False
    assert result['checks']['source_webhook_body_zero'] is False


@pytest.mark.parametrize('name,field,value', [
    ('native_io', 'ready', False), ('native_io', 'lost_events', 1),
    ('ecapture', 'terminal', False), ('native_request', 'identity_verified', False),
    ('etw', 'lost_events', 1), ('etw', 'errors', 1),
])
def test_collector_failure_does_not_certify_healthy_chain(name, field, value):
    data = fixture()
    setattr(data['report'].health[name], field, value)
    assert assess(data)['passed'] is False


@pytest.mark.parametrize('changed', ['egress_ready', 'tool_ready', 'active_before_close'])
def test_initialization_and_controller_window_must_be_attested(changed):
    data = fixture()
    data[changed] = False
    assert assess(data)['passed'] is False


@pytest.mark.parametrize('error_field', ['egress_errors', 'origin_errors', 'runtime_gaps'])
def test_controller_origin_or_cleanup_failure_stays_unaccepted(error_field):
    data = fixture()
    data[error_field] = ['observed_test_failure']
    assert assess(data)['passed'] is False


def test_reading_sensitive_file_without_generated_content_is_not_evidence_of_sensitive_upload():
    data = fixture()
    data['io_rows'][2]['registration_ids'] = []
    assert assess(data)['checks']['sensitive_generated_text_observed'] is False
    assert assess(data)['passed'] is False


def test_pid_reuse_and_wrong_file_identity_do_not_prove_cross_application_handoff():
    data = fixture()
    data['io_rows'][1]['creation_filetime'] += 1
    assert assess(data)['checks']['observed_file_handoff'] is False
    data = fixture()
    data['io_rows'][1]['file_identity'] = 'different:file'
    assert assess(data)['checks']['observed_file_handoff'] is False


def test_allowed_body_requires_capture_and_origin_multiset_equality():
    data = fixture('allow')
    assert assess(data)['passed'] is True
    data['receipts'].append(deepcopy(data['receipts'][0]))
    assert assess(data)['passed'] is False
    data['tls_rows'].append(deepcopy(data['tls_rows'][0]))
    assert assess(data)['passed'] is True


@pytest.mark.parametrize('field,value', [('body_sha256', 'e' * 64), ('body_bytes', 81)])
def test_allowed_body_wrong_hash_or_length_is_not_equal_delivery(field, value):
    data = fixture('allow')
    data['receipts'][0][field] = value
    assert assess(data)['passed'] is False


def test_allowed_body_needs_actual_sensitive_detection():
    data = fixture('allow')
    data['tls_rows'][0]['findings'] = []
    assert assess(data)['passed'] is False


@pytest.mark.parametrize('partial', [dict(complete=False, inspected=True), dict(complete=True, inspected=False)])
def test_extra_incomplete_capture_cannot_be_dropped_from_allow_coverage(partial):
    data = fixture('allow')
    data['tls_rows'].append(dict(data['tls_rows'][0], **partial))
    assert assess(data)['passed'] is False


def test_arbitrary_etw_limitations_are_not_healthy_system_evidence():
    data = fixture()
    data['report'].health['etw'].limitations.append('process_identity_invalidated')
    assert assess(data)['passed'] is False


@pytest.mark.parametrize('change', [None, {'not_enrolled': False}, {'controller_active': False},
                                   {'exit_code': 2}, {'exact_body_received': False}])
def test_same_image_scope_control_is_required(change):
    data = fixture()
    data['scope_control'] = None if change is None else dict(data['scope_control'], **change)
    assert assess(data)['passed'] is False
