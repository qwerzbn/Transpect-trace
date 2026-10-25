"""Independent negative evidence tests, without claiming Windows runtime proof."""
import base64
import hashlib
import json

import pytest
from pydantic import ValidationError
from transpect_trace.flow.evidence import FlowEvidence
from transpect_trace.flow.models import LIMIT, CrossApplicationSession
from transpect_trace.flow.report import report
from transpect_trace.observe.models import CaptureEvent
from transpect_trace.observe.protocol import Body
from transpect_trace.observe.pipeline import Pipeline
from transpect_trace.guard.policy import GuardPolicy
from transpect_trace.protect.detection import ContentIndex


SECRET = 'company-fixture-sensitive-source-' * 3
SUBJECTS = [{'role': 'A', 'pid': 101, 'creation_filetime': 1111, 'image_sha256': 'a' * 64},
            {'role': 'B', 'pid': 202, 'creation_filetime': 2222, 'image_sha256': 'b' * 64}]


def make(tmp_path=None, *, healthy=True):
    index = ContentIndex.register('fixture/1', [('fixture-code', SECRET, 'CONFIDENTIAL', ['source_code'])], chunk_size=32)
    flow = FlowEvidence('fixture-flow', SUBJECTS, index=index, directory=tmp_path)
    if healthy:
        for component in ('native-io:A', 'native-io:B', 'etw', 'ecapture'):
            flow.health(component, ready=True, terminal=True, identity_verified=True)
    return flow


class Native:
    def __init__(self, flow):
        self.flow = flow
        self.seq = {101: 0, 202: 0}
        self.qpc = 0
        self.gen = 0

    def event(self, role, kind, **kwargs):
        subject = SUBJECTS[role == 'B']
        pid = subject['pid']
        self.seq[pid] += 1
        self.qpc += 1
        event = dict(pid=pid, creation_filetime=subject['creation_filetime'], sequence=self.seq[pid], qpc=self.qpc,
                     qpc_frequency=1000, success=True, win32_error=0, handle_id='handle', open_generation=self.gen,
                     object_kind='file', file_identity='volume:stable-id', path_role='transfer', kind=kind)
        event.update(kwargs)
        self.flow.consume_native(event)

    def file(self, role, operation, data, *, file_id='volume:stable-id', chunks=None, offset=0):
        self.gen += 1
        path_role = 'source' if file_id == 'source' else 'transfer'
        self.event(role, 'open', file_identity=file_id, path_role=path_role)
        chunks = chunks or [data]
        for chunk in chunks:
            self.event(role, operation, data=chunk, requested_length=len(chunk), completed_length=len(chunk),
                       offset=offset, file_identity=file_id, path_role=path_role)
            offset += len(chunk)
        self.event(role, 'close', file_identity=file_id)

    def pipe(self, role, operation, data, *, generation=1, birth=None, parts=1, pipe_name='fixture-pipe'):
        self.gen += 1
        peer = SUBJECTS[role == 'A']
        common = dict(object_kind='pipe', path_role='pipe', file_identity=None, peer_pid=peer['pid'],
                      peer_creation_filetime=birth or peer['creation_filetime'], connection_generation=generation,
                      pipe_identity=pipe_name)
        self.event(role, 'open', **common)
        split = max(1, len(data) // parts)
        chunks = [data[i:i + split] for i in range(0, len(data), split)]
        for i, chunk in enumerate(chunks):
            last = i == len(chunks) - 1
            self.event(role, operation, data=chunk, requested_length=len(chunk), completed_length=len(chunk),
                       message_complete=last, success=last or operation == 'write',
                       win32_error=0 if last or operation == 'write' else 234, **common)
        self.event(role, 'close', **common)


def outbound(flow, data, *, n=1, **kwargs):
    event = CaptureEvent(provider='ecapture-windows', capture_point='tls', pid=202, creation_filetime=2222,
                         tid=1, connection_id='context-secret-id', direction='send', sequence=n, captured_qpc=1000,
                         qpc_frequency=1000, image_sha256='b' * 64, **kwargs)
    body = Body(data, {'host': 'localhost:1234', 'content-type': 'text/plain', ':method': 'POST',
                       ':path': '/upload?secret=DO-NOT-EXPORT', 'authorization': 'Bearer DO-NOT-EXPORT',
                       'cookie': 'DO-NOT-EXPORT'}, 'http/1.1')
    flow.consume_body(event, body, f'original-{n}')
    return event, body


def receipt(flow, data, rid='receipt'):
    flow.add_receipt(hashlib.sha256(data).hexdigest(), len(data), rid)


def test_file_handoff_has_direct_object_evidence_but_not_unique_causality(tmp_path):
    flow = make(tmp_path)
    native = Native(flow)
    native.file('A', 'read', SECRET.encode(), file_id='source')
    native.file('A', 'write', SECRET.encode())
    native.file('B', 'read', SECRET.encode())
    outbound(flow, SECRET.encode())
    receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'complete'
    relations = result['propagation']['relations']
    handoff = next(r for r in relations if r['relation_kind'] == 'file_handoff_candidate')
    assert handoff['confidence'] == 'High'
    assert not handoff['unique_source_proven'] and not handoff['byte_level_taint_proof']
    assert next(r for r in relations if r['relation_kind'] == 'outbound_content_candidate')['confidence'] == 'Medium'
    assert result['origin_receipts']['hash_multiset_matches']
    assert report(tmp_path) == result
    saved = (tmp_path / 'flow-evidence.json').read_text()
    assert SECRET not in saved and 'DO-NOT-EXPORT' not in saved and 'context-secret-id' not in saved
    assert all(not r['merged'] for r in relations)


def test_read_sensitive_but_send_public_does_not_claim_leak():
    flow = make(); native = Native(flow)
    native.file('A', 'read', SECRET.encode(), file_id='source')
    native.file('A', 'write', SECRET.encode())
    native.file('B', 'read', SECRET.encode())
    outbound(flow, b'ordinary summary'); receipt(flow, b'ordinary summary')
    result = flow.finish()
    assert result['session']['status'] == 'complete'
    assert result['content_detection']['outbound'][0]['detection_status'] == 'no_match'
    assert not any(r['relation_kind'] == 'outbound_content_candidate' for r in result['propagation']['relations'])


def test_healthy_collectors_and_origin_without_io_cannot_be_complete():
    flow = make()
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['origin_receipts']['hash_multiset_matches']
    assert all(h['ready'] and h['terminal'] for h in result['session']['health'].values())
    assert result['session']['status'] == 'partial'
    assert not result['collection_coverage']['complete']
    assert 'a_source_read_observed_missing' in result['coverage_gaps']
    assert 'handoff_object_range_supported_missing' in result['coverage_gaps']


@pytest.mark.parametrize('omitted', ['source', 'write', 'read'])
def test_each_handoff_stage_is_required(omitted):
    flow = make(); native = Native(flow)
    if omitted != 'source': native.file('A', 'read', SECRET.encode(), file_id='source')
    if omitted != 'write': native.file('A', 'write', SECRET.encode())
    if omitted != 'read': native.file('B', 'read', SECRET.encode())
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'partial'
    assert not result['collection_coverage']['complete']


def test_disjoint_handoff_file_identity_cannot_be_complete():
    flow = make(); native = Native(flow)
    native.file('A', 'read', SECRET.encode(), file_id='source')
    native.file('A', 'write', SECRET.encode(), file_id='file-one')
    native.file('B', 'read', SECRET.encode(), file_id='file-two')
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'partial'
    coverage = result['collection_coverage']
    assert coverage['a_source_read_observed'] and coverage['a_handoff_write_observed'] and coverage['b_handoff_read_observed']
    assert not coverage['handoff_object_range_supported']


def test_pipe_full_collection_does_not_require_outbound_sensitive_match():
    flow = make(); native = Native(flow)
    native.file('A', 'read', SECRET.encode(), file_id='source')
    native.pipe('A', 'write', SECRET.encode())
    native.pipe('B', 'read', SECRET.encode(), generation=2, parts=3)
    outbound(flow, b'ordinary public result'); receipt(flow, b'ordinary public result')
    result = flow.finish()
    assert result['session']['status'] == 'complete'
    assert result['collection_coverage']['complete']
    assert not any(r['relation_kind'] == 'outbound_content_candidate' for r in result['propagation']['relations'])


def test_equal_payload_on_different_pipe_names_never_certifies_handoff():
    flow = make(); native = Native(flow)
    native.file('A', 'read', SECRET.encode(), file_id='source')
    native.pipe('A', 'write', SECRET.encode(), pipe_name='pipe-one')
    native.pipe('B', 'read', SECRET.encode(), pipe_name='pipe-two')
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'partial'
    assert not result['collection_coverage']['handoff_object_range_supported']
    assert not any(r['relation_kind'] == 'pipe_handoff_candidate' for r in result['propagation']['relations'])
    serialized = json.dumps(result)
    assert 'pipe-one' not in serialized and 'pipe-two' not in serialized


def test_same_payload_after_pipe_reconnect_retains_candidates_without_certification():
    flow = make(); native = Native(flow)
    native.file('A', 'read', SECRET.encode(), file_id='source')
    native.pipe('A', 'write', SECRET.encode(), generation=1)
    native.pipe('B', 'read', SECRET.encode(), generation=90)
    native.pipe('A', 'write', SECRET.encode(), generation=2)
    native.pipe('B', 'read', SECRET.encode(), generation=91)
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'partial'
    assert not result['collection_coverage']['handoff_object_range_supported']
    relations = [r for r in result['propagation']['relations'] if r['relation_kind'] == 'pipe_handoff_candidate']
    assert relations
    assert all('pipe_connection_mapping_ambiguous' in r['limitations'] for r in relations)


def test_repeated_same_message_without_mapping_does_not_certify_multiple_reads():
    flow = make(); native = Native(flow)
    native.file('A', 'read', SECRET.encode(), file_id='source')
    native.pipe('A', 'write', SECRET.encode())
    native.pipe('B', 'read', SECRET.encode())
    native.pipe('B', 'read', SECRET.encode())
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'partial'
    assert 'pipe_message_mapping_ambiguous' in result['coverage_gaps']
    assert not result['collection_coverage']['handoff_object_range_supported']


def test_multiple_equal_content_sources_keep_complete_collection_and_candidates():
    flow = make(); native = Native(flow)
    native.file('A', 'read', SECRET.encode(), file_id='source')
    for file_id in ('candidate-one', 'candidate-two'):
        native.file('A', 'write', SECRET.encode(), file_id=file_id)
        native.file('B', 'read', SECRET.encode(), file_id=file_id)
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'complete'
    assert len(result['collection_coverage']['supported_relation_ids']) == 2
    outbound_relations = [r for r in result['propagation']['relations'] if r['relation_kind'] == 'outbound_content_candidate']
    assert len(outbound_relations) == 2 and all(not r['unique_source_proven'] for r in outbound_relations)


def test_source_read_after_handoff_does_not_complete_chain():
    flow = make(); native = Native(flow)
    native.file('A', 'write', SECRET.encode())
    native.file('B', 'read', SECRET.encode())
    native.file('A', 'read', SECRET.encode(), file_id='source')
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'partial'
    assert result['collection_coverage']['handoff_object_range_supported']
    assert not result['collection_coverage']['source_read_before_handoff_observed']


def test_report_links_etw_without_rewriting_saved_evidence(tmp_path):
    flow = make(tmp_path)
    saved = flow.finish()
    original = (tmp_path / 'flow-evidence.json').read_bytes()
    (tmp_path / 'etw').mkdir()
    (tmp_path / 'etw' / 'events.jsonl').write_text('')
    coverage = {'actual_event_count': 0, 'gaps': ['etw_no_real_events']}
    (tmp_path / 'runtime.json').write_text(json.dumps({'etw_coverage': coverage}))
    result = report(tmp_path)
    assert result['etw_evidence']['events_file'] == 'etw/events.jsonl'
    assert result['etw_evidence']['coverage'] == coverage
    assert result['session'] == saved['session']
    assert (tmp_path / 'flow-evidence.json').read_bytes() == original


@pytest.mark.parametrize('replacement_id', ['volume:stable-id', 'replacement-id'])
def test_overwrite_or_replacement_does_not_reuse_old_version(replacement_id):
    flow = make(); native = Native(flow)
    native.file('A', 'write', SECRET.encode())
    native.file('A', 'write', b'ordinary replacement', file_id=replacement_id)
    native.file('B', 'read', b'ordinary replacement', file_id=replacement_id)
    outbound(flow, b'ordinary replacement'); receipt(flow, b'ordinary replacement')
    result = flow.finish()
    old = result['system_behavior']['transfers'][0]['observation_id']
    assert not any(r['left_id'] == old and r['relation_kind'] == 'file_handoff_candidate' for r in result['propagation']['relations'])


def test_equal_content_in_distinct_files_retains_multiple_outbound_candidates():
    flow = make(); native = Native(flow)
    native.file('B', 'read', SECRET.encode(), file_id='one')
    native.file('B', 'read', SECRET.encode(), file_id='two')
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    relations = flow.finish()['propagation']['relations']
    assert len(relations) == 2
    assert all(not r['unique_source_proven'] for r in relations)


def test_same_hash_parallel_attempts_preserve_counts_and_ids():
    flow = make()
    outbound(flow, SECRET.encode(), n=1); outbound(flow, SECRET.encode(), n=2)
    receipt(flow, SECRET.encode(), 'one')
    result = flow.finish()
    rows = result['content_detection']['outbound']
    assert len({r['attempt_id'] for r in rows}) == 2
    assert result['origin_receipts']['captured_count'] == 2
    assert not result['origin_receipts']['hash_multiset_matches']
    assert result['session']['status'] == 'partial'


def test_pipe_messages_more_data_and_generation_not_conflated():
    flow = make(); native = Native(flow)
    native.pipe('A', 'write', SECRET.encode(), generation=4)
    native.pipe('B', 'read', SECRET.encode(), generation=90, parts=4)
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    relation = next(r for r in result['propagation']['relations'] if r['relation_kind'] == 'pipe_handoff_candidate')
    assert relation['confidence'] == 'Medium'
    assert 'cross_endpoint_generation_mapping_unverified' in relation['limitations']
    assert len(result['system_behavior']['transfers']) == 2
    assert all(t['completeness'] == 'complete' for t in result['system_behavior']['transfers'])


def test_pid_reuse_or_wrong_peer_birth_never_has_handoff_edge():
    flow = make(); native = Native(flow)
    native.pipe('A', 'write', SECRET.encode(), birth=9999)
    native.pipe('B', 'read', SECRET.encode())
    flow.consume_native({'pid': 202, 'creation_filetime': 9999, 'kind': 'read'})
    result = flow.finish()
    assert not any(r['relation_kind'] == 'pipe_handoff_candidate' for r in result['propagation']['relations'])
    assert 'unregistered_process_identity' in result['coverage_gaps']


def test_blocking_pipe_read_can_start_before_writer_and_complete_afterwards():
    flow = make(); native = Native(flow)
    common = dict(object_kind='pipe', path_role='pipe', file_identity=None, connection_generation=1, pipe_identity='fixture-pipe')
    native.event('A', 'open', peer_pid=202, peer_creation_filetime=2222, **common)
    native.event('B', 'open', peer_pid=101, peer_creation_filetime=1111, **common)
    native.event('B', 'read', qpc=5, completed_qpc=30, peer_pid=101, peer_creation_filetime=1111,
                 data=SECRET.encode(), requested_length=len(SECRET), completed_length=len(SECRET), message_complete=True, **common)
    native.event('A', 'write', qpc=10, completed_qpc=20, peer_pid=202, peer_creation_filetime=2222,
                 data=SECRET.encode(), requested_length=len(SECRET), completed_length=len(SECRET), message_complete=True, **common)
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert any(r['relation_kind'] == 'pipe_handoff_candidate' for r in result['propagation']['relations'])


def test_write_during_read_lowers_file_version_confidence():
    flow = make(); native = Native(flow)
    native.file('A', 'write', SECRET.encode())
    native.gen += 1
    read_gen = native.gen
    native.event('B', 'open')
    native.event('B', 'read', qpc=5, completed_qpc=25, data=SECRET.encode(),
                 requested_length=len(SECRET), completed_length=len(SECRET), offset=0)
    native.file('A', 'write', b'changed concurrently')
    native.event('B', 'close', open_generation=read_gen, qpc=30)
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    read = next(r for r in result['system_behavior']['transfers'] if r['process']['role'] == 'B')
    assert 'file_modified_during_read' in read['limitations']
    assert read['completeness'] == 'partial'
    assert all(r['confidence'] != 'High' for r in result['propagation']['relations'])


def test_reused_pid_with_wrong_capture_image_is_rejected():
    flow = make()
    event, body = outbound(flow, b'ordinary')
    flow.outbound.clear()
    event.image_sha256 = 'c' * 64
    flow.consume_body(event, body, 'bad-image')
    assert not flow.outbound
    assert 'outbound_image_identity_mismatch' in flow.finish()['coverage_gaps']


@pytest.mark.parametrize('failure', ['missing_terminal', 'loss', 'identity', 'sequence'])
def test_health_failure_prevents_high_confidence(failure):
    flow = make(healthy=False); native = Native(flow)
    for component in ('native-io:A', 'native-io:B', 'etw', 'ecapture'):
        flow.health(component, ready=True, terminal=not(component == 'ecapture' and failure == 'missing_terminal'),
                    identity_verified=not(component == 'etw' and failure == 'identity'),
                    lost_events=int(component == 'etw' and failure == 'loss'))
    native.file('A', 'write', SECRET.encode())
    if failure == 'sequence': native.seq[101] += 1
    native.file('A', 'read', SECRET.encode(), file_id='source')
    native.file('B', 'read', SECRET.encode())
    outbound(flow, SECRET.encode()); receipt(flow, SECRET.encode())
    result = flow.finish()
    assert result['session']['status'] == 'partial'
    assert all(r['confidence'] == 'Unknown' for r in result['propagation']['relations'])


def test_missing_close_and_noncontiguous_ranges_cannot_be_complete():
    flow = make(); native = Native(flow)
    native.event('A', 'open')
    native.event('A', 'write', data=b'bytes', requested_length=5, completed_length=5, offset=22)
    row = flow.finish()['system_behavior']['transfers'][0]
    assert row['completeness'] == 'partial'
    assert 'transfer_boundary_unknown' in row['limitations']
    assert 'file_range_noncontiguous' in row['limitations']


def test_registration_across_native_chunks_and_large_chinese_text():
    data = ('普通文本' * 12000 + SECRET).encode()
    flow = make(); native = Native(flow)
    cut = len(data) - len(SECRET.encode()) + 15
    native.file('B', 'read', data, chunks=[data[:cut], data[cut:]])
    outbound(flow, data); receipt(flow, data)
    result = flow.finish()
    assert result['system_behavior']['transfers'][0]['findings']
    assert result['content_detection']['outbound'][0]['detection_status'] == 'matched'


@pytest.mark.parametrize('size', [LIMIT, LIMIT + 1])
def test_size_boundary(size):
    data = b'x' * size
    flow = make(); native = Native(flow)
    native.file('B', 'read', data)
    outbound(flow, data); receipt(flow, data)
    result = flow.finish()
    assert result['system_behavior']['transfers'][0]['captured_bytes'] <= LIMIT
    assert result['content_detection']['outbound'][0]['completeness'] == ('complete' if size == LIMIT else 'partial')


@pytest.mark.parametrize('modification', ['compression', 'binary', 'invalid_json', 'missing_type', 'truncated'])
def test_unsupported_content_does_not_report_safe(modification):
    flow = make()
    event, body = outbound(flow, b'ordinary', truncated=modification == 'truncated')
    flow.outbound.clear()
    if modification == 'compression': body.headers['content-encoding'] = 'gzip'
    if modification == 'binary': body.data = b'\xff\xfe'
    if modification == 'invalid_json': body.headers['content-type'] = 'application/json'
    if modification == 'missing_type': body.headers.pop('content-type')
    flow.consume_body(event, body, 'unknown')
    result = flow.finish()['content_detection']['outbound'][0]
    assert result['completeness'] == ('partial' if modification == 'truncated' else 'complete')
    assert result['detection_status'] == 'incomplete'


def test_nested_json_upload_detected_without_llm_structure():
    flow = make()
    event, body = outbound(flow, b'')
    flow.outbound.clear()
    body.headers['content-type'] = 'application/json'
    body.data = json.dumps({'report': {'credentials': {'api_key': 'FakeSensitiveValue12345'}}}).encode()
    flow.consume_body(event, body, 'nested')
    row = flow.outbound[0]
    assert row.completeness == 'complete' and row.llm_classification == 'UNKNOWN'
    assert row.detection_status == 'matched'
    assert 'FakeSensitiveValue12345' not in row.model_dump_json()


def test_observe_body_sink_works_for_plain_upload_independent_of_llm_unknown(tmp_path):
    flow = make()
    pipeline = Pipeline(tmp_path, GuardPolicy(), body_sink=flow.consume_body)
    payload = b'POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello'
    event = CaptureEvent(provider='ecapture-windows', capture_point='tls', pid=202, creation_filetime=2222, tid=1,
                         connection_id='connection', direction='send', sequence=1, captured_qpc=55, qpc_frequency=1000,
                         data_b64=base64.b64encode(payload).decode())
    pipeline.consume(event)
    assert pipeline.rows[0]['completeness'] == 'unknown'
    assert flow.outbound[0].completeness == 'complete'
    assert flow.outbound[0].llm_classification == 'UNKNOWN'
    assert flow.outbound[0].original_observation_id == pipeline.rows[0]['observation_id']


def test_observe_sink_failure_records_gap_without_plaintext_exception(tmp_path):
    def fail(*args): raise RuntimeError('SECRET-MUST-NOT-BE-LOGGED')
    pipeline = Pipeline(tmp_path, GuardPolicy(), body_sink=fail)
    payload = b'POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello'
    pipeline.consume(CaptureEvent(provider='fixture', capture_point='tls', pid=202, creation_filetime=2222, tid=1,
        connection_id='c', direction='send', sequence=1, captured_qpc=1, qpc_frequency=1, data_b64=base64.b64encode(payload).decode()))
    assert pipeline.gaps[0]['reason'] == 'body_sink_failed'
    assert 'SECRET-MUST-NOT' not in (tmp_path / 'coverage-gaps.jsonl').read_text()


def test_contract_cannot_claim_enforcement():
    with pytest.raises(ValidationError):
        CrossApplicationSession(session_id='test', subjects=[], can_enforce=True)
