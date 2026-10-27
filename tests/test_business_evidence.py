from copy import deepcopy

import pytest

from transpect_trace.flow.scenarios.evidence import assess
from transpect_trace.flow.scenarios.models import BusinessScenarioReport, ScenarioProcess


def complete_report():
    process = ScenarioProcess(role='transformer', pid=40, creation_filetime=100, image_sha256='a' * 64).model_dump()
    exporter = ScenarioProcess(role='exporter', pid=41, creation_filetime=101, image_sha256='a' * 64).model_dump()
    evidence, stages = [], []
    requirements = {'export': ['native_io', 'etw', 'client_result'],
                    'tool': ['native_request', 'etw', 'client_result'],
                    'transform': ['native_io', 'etw', 'client_result'],
                    'upload': ['ecapture', 'source_receipt', 'client_result']}
    for stage, sources in requirements.items():
        ids = []
        for source in sources:
            eid = f'{stage}:{source}'
            ids.append(eid)
            row = dict(evidence_id=eid, stage_id=stage, provenance=source,
                       process=exporter if stage == 'export' else process,
                       complete=True, success=True, event_ids=[f'event:{eid}'])
            if source == 'native_io':
                row.update(body_sha256='c' * 64, body_bytes=40, file_identity='volume:file-id',
                           io_operation='write' if stage == 'export' else 'read', io_offset=0,
                           io_started_qpc=1 if stage == 'export' else 3,
                           io_completed_qpc=2 if stage == 'export' else 4, qpc_frequency=1000000,
                           content_registration_ids=['test-secret'])
            if stage == 'upload' and source in {'ecapture', 'source_receipt'}:
                row.update(attempt_id='attempt-1', body_sha256='b' * 64, body_bytes=80,
                           content_registration_ids=['test-secret'])
            evidence.append(row)
        stages.append(dict(stage_id=stage, participant='transformer', evidence_ids=ids))
    return dict(session_id='session', scenario='webhook', case='public',
                participants=[process, exporter], stages=stages, evidence=evidence,
                health={k: dict(ready=True, terminal=True, identity_verified=True)
                        for k in ('native_io', 'etw', 'ecapture', 'native_request')},
                outbound=[dict(attempt_id='attempt-1', process=process, capture_source='ecapture',
                               capture_layer='tls', completeness='complete', body_sha256='b' * 64,
                               body_bytes=80, capture_evidence_id='upload:ecapture',
                               receipt_evidence_id='upload:source_receipt', detection_status='no_match',
                               association_basis='ordered_body_multiset')],
                relations=[dict(relation_id='handoff', left_id='export:native_io', right_id='transform:native_io',
                                method='observed_file_handoff', evidence_ids=['export:native_io', 'transform:native_io']),
                           dict(relation_id='relation', left_id='transform:native_io', right_id='upload:ecapture',
                                method='content_candidate', evidence_ids=['transform:native_io', 'upload:ecapture'])])


def test_complete_controlled_observation_is_not_enforcement_or_causality():
    source = complete_report()
    result = assess(source)
    assert result.state == 'complete' and result.certified
    assert result.can_enforce is False and result.byte_level_taint_proof is False
    assert result.relations[0].confidence == 'Medium'
    assert not result.relations[0].unique_source_proven
    assert result.capabilities.control == 'not_applicable'
    assert source['relations'][0].get('confidence') is None


def test_fixture_self_report_cannot_certify_complete_stage():
    value = complete_report()
    for row in value['evidence']:
        row['provenance'] = 'fixture_truth'
        for key in ('file_identity', 'io_operation', 'io_offset', 'io_started_qpc', 'io_completed_qpc', 'qpc_frequency'):
            row.pop(key, None)
    value.update(state='complete', certified=True)
    result = assess(value)
    assert result.state == 'partial' and not result.certified
    assert all(s.state != 'complete' for s in result.stages)


@pytest.mark.parametrize('field,value', [('terminal', False), ('ready', False), ('identity_verified', False),
                                        ('lost_events', 1), ('errors', 1)])
def test_capture_health_gaps_invalidate_content_and_relations(field, value):
    report = complete_report()
    report['health']['ecapture'][field] = value
    result = assess(report)
    assert result.state == 'partial' and not result.certified
    assert result.outbound[0].source_received is True
    assert result.outbound[0].receipt_match is False
    assert result.relations[1].confidence == 'Unknown'


def test_pid_reuse_not_mistaken_for_same_registered_sender():
    value = complete_report()
    value['evidence'][-3]['process'] = {**value['evidence'][-3]['process'], 'creation_filetime': 101}
    result = assess(value)
    assert not result.certified and result.outbound[0].receipt_match is False


def test_source_receipt_is_not_inferred_from_capture_or_success_exit():
    value = complete_report()
    value['evidence'] = [r for r in value['evidence'] if r['provenance'] != 'source_receipt']
    value['outbound'][0].update(source_received=True, receipt_match=True)
    result = assess(value)
    assert result.outbound[0].source_received is None
    assert result.outbound[0].receipt_match is False


def test_equal_hash_two_actual_attempts_remain_separate():
    value = complete_report()
    second = {**deepcopy(value['outbound'][0]), 'attempt_id': 'attempt-2',
              'capture_evidence_id': 'capture-2', 'receipt_evidence_id': 'receipt-2'}
    value['outbound'].append(second)
    for source, key in [('ecapture', 'capture-2'), ('source_receipt', 'receipt-2')]:
        original = next(e for e in value['evidence'] if e['provenance'] == source)
        value['evidence'].append({**deepcopy(original), 'evidence_id': key, 'attempt_id': 'attempt-2'})
    result = assess(value)
    assert result.certified and len(result.outbound) == 2
    assert all(r.receipt_match is True for r in result.outbound)
    assert all(r.association_basis == 'ordered_body_multiset' for r in result.outbound)


@pytest.mark.parametrize('basis', ['unknown', 'exact_runtime_id'])
def test_unverified_receipt_identity_mapping_cannot_certify(basis):
    value = complete_report()
    value['outbound'][0]['association_basis'] = basis
    result = assess(value)
    assert not result.certified
    assert result.outbound[0].receipt_match is True  # equal bytes still remain a fact


def test_reused_receipt_cannot_cover_two_attempts():
    value = complete_report()
    value['outbound'].append({**deepcopy(value['outbound'][0]), 'attempt_id': 'attempt-2'})
    result = assess(value)
    assert not result.certified
    assert all('evidence_reused_across_attempts' in r.limitations for r in result.outbound)


@pytest.mark.parametrize('source', ['source_receipt', 'ecapture'])
def test_unassociated_extra_attempt_cannot_be_hidden_by_matching_hash_set(source):
    value = complete_report()
    row = deepcopy(next(e for e in value['evidence'] if e['provenance'] == source))
    row.update(evidence_id='unmatched-event', attempt_id='attempt-missing')
    value['evidence'].append(row)
    result = assess(value)
    assert not result.certified
    assert ('unassociated_source_receipt' if source == 'source_receipt'
            else 'unassociated_capture_attempt') in result.limitations


def test_duplicate_ids_cannot_hide_missing_events():
    value = complete_report()
    value['evidence'].append(deepcopy(value['evidence'][0]))
    result = assess(value)
    assert not result.certified and 'duplicate_evidence_identifier' in result.limitations


def test_same_length_different_body_not_received_match():
    value = complete_report()
    next(r for r in value['evidence'] if r['provenance'] == 'source_receipt')['body_sha256'] = 'c' * 64
    result = assess(value)
    assert not result.certified and result.outbound[0].source_received is True
    assert result.outbound[0].receipt_match is False


def test_saved_report_cannot_lower_required_stage_provenance():
    value = complete_report()
    value['evidence'] = [r for r in value['evidence'] if r['provenance'] != 'native_io']
    value['stages'][0]['required_provenance'] = []
    result = assess(value)
    assert not result.certified
    assert 'missing_native_io' in result.stages[0].limitations


def test_missing_stage_is_not_complete_despite_remaining_results():
    value = complete_report()
    value['stages'] = value['stages'][1:]
    result = assess(value)
    assert not result.certified and 'required_stage_graph_missing' in result.limitations


def test_high_claim_without_direct_mapping_is_downgraded():
    value = complete_report()
    value['relations'][0].update(confidence='High', method='observed_file_handoff')
    result = assess(value)
    assert result.relations[0].confidence == 'Medium'
    assert 'candidate_not_unique_source' in result.relations[0].limitations


def test_timing_only_chain_cannot_certify_business_propagation():
    value = complete_report()
    for row in value['relations']:
        row['method'] = 'timing_candidate'
    result = assess(value)
    assert result.state == 'partial' and result.capabilities.propagation == 'partial'
    assert all(row.confidence == 'Low' for row in result.relations)


def test_file_handoff_needs_actual_shared_object_range_and_completed_content():
    value = complete_report()
    next(r for r in value['evidence'] if r['evidence_id'] == 'transform:native_io')['file_identity'] = 'different:file'
    result = assess(value)
    assert not result.certified and result.relations[0].confidence == 'Unknown'


@pytest.mark.parametrize('change', [
    {'io_started_qpc': 5, 'io_completed_qpc': 6},
    {'io_started_qpc': None, 'io_completed_qpc': None, 'qpc_frequency': None},
    {'qpc_frequency': 2000000},
])
def test_file_handoff_rejects_reversed_or_missing_clock(change):
    value = complete_report()
    next(r for r in value['evidence'] if r['evidence_id'] == 'export:native_io').update(change)
    assert not assess(value).certified


def test_file_rewrite_in_handoff_window_downgrades_same_hash_candidate():
    value = complete_report()
    write = deepcopy(next(r for r in value['evidence'] if r['evidence_id'] == 'export:native_io'))
    write.update(evidence_id='competing-write', io_started_qpc=2, io_completed_qpc=3,
                 body_sha256='d' * 64, complete=False)
    value['evidence'].append(write)
    result = assess(value)
    assert not result.certified and result.relations[0].confidence == 'Unknown'


def git_report(blob_count=1):
    import json
    value = json.loads(json.dumps(complete_report()).replace('upload', 'push'))
    value.update(scenario='git', case='public')
    value['outbound'][0]['detection_status'] = 'unsupported'
    value['stages'].append(dict(stage_id='commit', participant='git-helper', evidence_ids=['commit-object', 'commit-client']))
    value['evidence'] += [
        dict(evidence_id='commit-object', stage_id='commit', provenance='git_object',
             complete=True, event_ids=['git:commit']),
        dict(evidence_id='commit-client', stage_id='commit', provenance='client_result', complete=True, success=True),
        dict(evidence_id='scan', stage_id='push', provenance='git_object', complete=True,
             attempt_id='attempt-1', object_location='origin', observed_blob_count=blob_count, event_ids=['git:scan']),
    ]
    next(s for s in value['stages'] if s['stage_id'] == 'push')['evidence_ids'].append('scan')
    value['git_scans'] = [dict(attempt_id='attempt-1', evidence_id='scan', received_blob_count=blob_count, complete=True)]
    value['git_objects'] = []
    for index in range(blob_count):
        key = str(index) * 40
        value['evidence'].append(dict(evidence_id='object-' + str(index), stage_id='push', provenance='git_object',
                                     complete=True, attempt_id='attempt-1', object_location='origin', object_id=key,
                                     body_sha256='c' * 64, body_bytes=40, event_ids=['git:blob:' + str(index)]))
        value['git_objects'].append(dict(attempt_id='attempt-1', evidence_id='object-' + str(index), object_id=key,
                                         body_sha256='c' * 64, body_bytes=40, detection_status='no_match'))
        value['relations'].append(dict(relation_id='object-relation-' + str(index),
                                        left_id='transform:native_io', right_id='object-' + str(index),
                                        method='content_candidate', evidence_ids=['transform:native_io', 'object-' + str(index)]))
    return value


def test_git_binary_transport_is_separate_from_received_blob_detection():
    result = assess(git_report())
    assert result.certified and result.capabilities.content_detection == 'complete'
    assert result.outbound[0].detection_status == 'unsupported'
    assert result.git_objects[0].detection_status == 'no_match'


def test_git_raw_pack_hash_without_object_inspection_does_not_certify_detection():
    value = git_report()
    value['git_objects'] = []
    assert not assess(value).certified
    value = git_report()
    value['outbound'][0]['detection_status'] = 'no_match'
    assert not assess(value).certified


def test_source_local_git_objects_do_not_replace_receiver_evidence():
    value = git_report()
    next(r for r in value['evidence'] if r.get('object_id'))['object_location'] = 'sender'
    assert not assess(value).certified


def test_git_zero_new_objects_requires_independent_receiver_scan():
    value = git_report(0)
    assert assess(value).certified
    value['evidence'] = [r for r in value['evidence'] if r['evidence_id'] != 'scan']
    assert not assess(value).certified


def test_git_history_blob_cannot_disappear_from_inspected_delta():
    value = git_report(2)
    assert assess(value).certified
    value['git_objects'] = value['git_objects'][:1]
    value['git_scans'][0]['received_blob_count'] = 1
    next(r for r in value['evidence'] if r['evidence_id'] == 'scan')['observed_blob_count'] = 1
    assert not assess(value).certified


def test_expected_ref_rejection_keeps_actual_failure_and_received_data_separate():
    value = git_report()
    value['case'] = 'reject_ref'
    next(r for r in value['evidence'] if r['evidence_id'] == 'push:client_result')['success'] = False
    result = assess(value)
    assert result.certified and result.outbound[0].source_received is True
    assert next(r for r in result.evidence if r.evidence_id == 'push:client_result').success is False
