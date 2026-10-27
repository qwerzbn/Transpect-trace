"""Evidence failures cannot become a cross-application protection claim."""
from copy import deepcopy
import json

import pytest

from transpect_trace.flow.file_upload_evidence import assess_file_upload


def experiment(block=True):
    a = dict(pid=101, creation_filetime=1001, parent_pid=90, image_sha256='a' * 64)
    b = dict(pid=102, creation_filetime=1002, parent_pid=90, image_sha256='b' * 64)

    def io(subject, kind, role, digest, size, start, identity, sequence):
        return dict(**{key: subject[key] for key in ('pid', 'creation_filetime')},
                    provider='native-io', capture_layer='win32-sync-io', kind=kind,
                    object_kind='file', path_role=role, success=True,
                    capture_gap=False, data_truncated=False, unsupported=[],
                    lost_events=0, win32_error=0, offset=0, data_sha256=digest,
                    data_bytes=size, length=size, completed_length=size,
                    requested_length=size, file_identity=identity, open_generation=1,
                    qpc=start, completed_qpc=start + 1, qpc_frequency=1000,
                    event_id=f"io:{subject['pid']}:{subject['creation_filetime']}:{sequence}")

    rows = [io(a, 'read', 'source', 'c' * 64, 91, 10, '00000001:0000000000000001', 1),
            io(a, 'write', 'transfer', 'd' * 64, 84, 20, '00000001:0000000000000002', 2),
            io(b, 'read', 'transfer', 'd' * 64, 84, 30, '00000001:0000000000000002', 1)]
    body = dict(attempt_id='attempt-1', pid=b['pid'], creation_filetime=b['creation_filetime'],
                completeness='complete', source='python-httpx-outbound-native/1',
                capture_layer='request-body', body_sha256='d' * 64, body_bytes=84,
                decision='BLOCK' if block else 'ALLOW',
                detection_status='matched' if block else 'no_match',
                findings=[dict(rule_id='registered-text')] if block else [])
    execution = dict(attempt_id='attempt-1', pid=b['pid'], qpc=40,
                     action='block_request' if block else 'none',
                     result='native_rejection' if block else 'transport_authorized')
    health = {role: dict(pid=subject['pid'], creation_filetime=subject['creation_filetime'],
                         ready=True, terminal=True, terminal_health=True, errors=[], lost_events=0)
              for role, subject in [('A', a), ('B', b)]}
    health.update(gate=dict(ready=True, identity_verified=True, execution_drained=True, errors=[]),
                  receiver=dict(ready=True, terminal=True, pending_requests=0, errors=[]))
    return dict(subjects={'A': a, 'B': b}, io_rows=rows,
                original_sha256='c' * 64, original_bytes=91,
                modified_sha256='d' * 64, modified_bytes=84,
                body_capture=[body], execution_records=[execution],
                receipts=[] if block else [dict(complete=True, body_sha256='d' * 64, body_bytes=84)],
                health=health, expected_block=block)


@pytest.mark.parametrize('block', [True, False])
def test_real_distinct_apps_modified_file_and_native_request_execution(block):
    value = experiment(block)
    original = deepcopy(value)
    result = assess_file_upload(**value)
    assert result['passed'] and all(result['checks'].values())
    assert result['business_transport'] == 'regular-file'
    assert result['capture_layer'] == 'request-body'
    assert result['propagation'] == dict(confidence='Medium', unique_source_proven=False,
                                        byte_level_taint_proof=False)
    assert value == original


def test_sensitive_source_sanitized_by_A_and_only_public_output_uploaded():
    value = experiment(False)
    # Source content is never used as proof of outbound content: only the
    # independently expected modified output is compared with the Gate body.
    value['io_rows'][0]['findings'] = [{'rule_id': 'fake-secret-in-input'}]
    assert assess_file_upload(**value)['passed']


@pytest.mark.parametrize('field,value', [('pid', 101), ('creation_filetime', 999),
                                        ('image_sha256', 'a' * 64), ('parent_pid', 101)])
def test_process_name_or_same_path_cannot_substitute_for_independent_identity(field, value):
    case = experiment()
    case['subjects']['B'][field] = value
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('index', [0, 1, 2])
def test_missing_actual_source_read_output_write_or_B_read_fails(index):
    case = experiment()
    case['io_rows'].pop(index)
    assert not assess_file_upload(**case)['passed']


def test_unchanged_output_is_not_a_file_modification():
    case = experiment()
    case['original_sha256'] = case['modified_sha256']
    case['io_rows'][0]['data_sha256'] = case['modified_sha256']
    result = assess_file_upload(**case)
    assert not result['passed']
    assert not result['checks']['independent_transformation_oracle']


@pytest.mark.parametrize('field,value', [('file_identity', None), ('file_identity', '00000001:0000000000000009'),
                                        ('offset', None), ('offset', 1), ('offset', False),
                                        ('open_generation', 0), ('success', False),
                                        ('capture_gap', True), ('data_truncated', True),
                                        ('unsupported', ['overlapped_io']), ('completed_length', 40),
                                        ('data_bytes', 40), ('data_sha256', 'e' * 64),
                                        ('creation_filetime', 999), ('qpc_frequency', 999)])
def test_B_read_requires_same_stable_file_complete_range_and_exact_process(field, value):
    case = experiment()
    case['io_rows'][2][field] = value
    assert not assess_file_upload(**case)['passed']


def test_single_chunk_digest_does_not_certify_whole_file():
    case = experiment()
    for key in ('length', 'completed_length', 'data_bytes'):
        case['io_rows'][2][key] = 42
    case['io_rows'].append({**case['io_rows'][2], 'offset': 42,
                            'event_id': 'io:102:1002:2'})
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('read_start', [18, 20])
def test_read_cannot_precede_completed_write(read_start):
    case = experiment()
    case['io_rows'][2].update(qpc=read_start, completed_qpc=read_start + 1)
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('changes', [dict(qpc=24, completed_qpc=25),
                                      dict(qpc=19, completed_qpc=32),
                                      dict(qpc=None, completed_qpc=None)])
def test_same_hash_rewrite_or_unknown_write_cannot_prove_original_file_version(changes):
    case = experiment()
    case['io_rows'].append({**case['io_rows'][1], **changes, 'event_id': 'io:101:1001:3'})
    assert not assess_file_upload(**case)['passed']


def test_previous_unrelated_file_version_does_not_invalidate_later_handoff():
    case = experiment()
    case['io_rows'].append({**case['io_rows'][1], 'qpc': 2, 'completed_qpc': 3,
                            'data_sha256': 'e' * 64, 'event_id': 'io:101:1001:3'})
    assert assess_file_upload(**case)['passed']


@pytest.mark.parametrize('identity', [None, '00000001:0000000000000009'])
def test_missing_identity_or_replacement_at_transfer_path_does_not_get_ignored(identity):
    case = experiment()
    case['io_rows'].append({**case['io_rows'][1], 'file_identity': identity,
                            'qpc': 24, 'completed_qpc': 25, 'event_id': 'io:101:1001:3'})
    assert not assess_file_upload(**case)['passed']


def test_duplicate_native_rows_are_not_independent_evidence():
    case = experiment()
    case['io_rows'].append(deepcopy(case['io_rows'][1]))
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('field,value', [('creation_filetime', 1003), ('pid', 101),
                                        ('body_sha256', 'c' * 64), ('body_bytes', 91),
                                        ('completeness', 'partial'),
                                        ('source', 'fixture_truth'), ('capture_layer', 'tls')])
def test_request_must_be_independently_captured_from_real_sender(field, value):
    case = experiment()
    case['body_capture'][0][field] = value
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('mutation', ['missing', 'wrong_attempt', 'authorized', 'kill', 'duplicate', 'extra'])
def test_zero_receiver_bytes_or_policy_denial_is_not_native_execution(mutation):
    case = experiment()
    if mutation == 'missing':
        case['execution_records'] = []
    elif mutation == 'wrong_attempt':
        case['execution_records'][0]['attempt_id'] = 'different-attempt'
    elif mutation == 'authorized':
        case['execution_records'][0].update(action='none', result='transport_authorized')
    elif mutation == 'kill':
        case['execution_records'][0].update(action='terminate_process', result='terminated')
    elif mutation == 'duplicate':
        case['execution_records'].append(deepcopy(case['execution_records'][0]))
    else:
        case['execution_records'].append({**case['execution_records'][0], 'attempt_id': 'extra'})
    result = assess_file_upload(**case)
    assert not result['passed']
    assert not result['checks']['native_execution_matches_every_attempt']


def test_repeated_identical_body_attempts_use_multiset_not_hash_set():
    case = experiment(False)
    case['body_capture'].append({**case['body_capture'][0], 'attempt_id': 'attempt-2'})
    case['execution_records'].append({**case['execution_records'][0], 'attempt_id': 'attempt-2'})
    assert not assess_file_upload(**case)['passed']
    case['receipts'].append(deepcopy(case['receipts'][0]))
    assert assess_file_upload(**case)['passed']


def test_native_execution_cannot_precede_B_file_read():
    case = experiment()
    case['execution_records'][0]['qpc'] = 1
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('receipt', [dict(complete=False, body_sha256='d' * 64, body_bytes=84),
                                    dict(complete=True, body_sha256='e' * 64, body_bytes=84),
                                    dict(complete=True, body_sha256='d' * 64, body_bytes=85)])
def test_allow_receipt_content_and_completion_are_independent(receipt):
    case = experiment(False)
    case['receipts'] = [receipt]
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('block', [True, False])
def test_unexpected_received_request_is_not_hidden(block):
    case = experiment(block)
    case['receipts'].append(dict(complete=True, body_sha256='e' * 64, body_bytes=11))
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('role', ['A', 'B', 'gate', 'receiver'])
def test_missing_health_is_not_certified(role):
    case = experiment()
    del case['health'][role]
    assert not assess_file_upload(**case)['passed']


@pytest.mark.parametrize('field,value', [('terminal_health', False), ('ready', False),
                                        ('terminal', False), ('lost_events', 1),
                                        ('errors', ['sensitive-error-detail']),
                                        ('creation_filetime', 999)])
def test_capture_loss_or_identity_gap_cannot_keep_complete_protection_claim(field, value):
    case = experiment()
    case['health']['B'][field] = value
    assert not assess_file_upload(**case)['passed']


def test_report_never_echoes_body_findings_paths_urls_or_error_details():
    secret = 'FAKE_SECRET_CONTENT_SHOULD_NOT_APPEAR'
    case = experiment()
    case['io_rows'][0].update(data=secret, path=secret)
    case['body_capture'][0].update(body=secret, findings=[{'value': secret}], url=secret)
    case['health']['gate']['errors'] = [secret]
    result = assess_file_upload(**case)
    assert secret not in json.dumps(result)


@pytest.mark.parametrize('key,value', [('subjects', None), ('subjects', {'A': None, 'B': []}),
                                      ('io_rows', None), ('original_bytes', 'malformed'),
                                      ('modified_bytes', None), ('body_capture', [None]),
                                      ('execution_records', [None]), ('receipts', [None]),
                                      ('health', None)])
def test_malformed_metadata_degrades_without_exception_or_success(key, value):
    case = experiment()
    case[key] = value
    assert not assess_file_upload(**case)['passed']


def test_nested_invalid_digest_is_not_used_as_a_hashable_multiset_key():
    case = experiment(False)
    case['modified_sha256'] = []
    case['body_capture'][0]['body_sha256'] = []
    assert not assess_file_upload(**case)['passed']
