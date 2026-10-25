"""Evidence-contract tests; simulated callbacks do not certify Windows capture."""
import hashlib
import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from transpect_trace.flow.agents.evidence import AgentEvidence
from transpect_trace.flow.agents.models import AgentFlowSession, AgentMessageObservation, AgentPropagationRelation
from transpect_trace.flow.agents.protocol import encode, make_message, make_outbound, transform_payload
from transpect_trace.flow.evidence import FlowEvidence
from transpect_trace.flow.models import LIMIT
from transpect_trace.observe.models import CaptureEvent
from transpect_trace.observe.protocol import Body
from transpect_trace.protect.detection import ContentIndex

SUBJECTS = [{'role': 'A', 'pid': 101, 'creation_filetime': 1111, 'image_sha256': 'a' * 64},
            {'role': 'B', 'pid': 202, 'creation_filetime': 2222, 'image_sha256': 'b' * 64}]
TASK = '146f3d57bd22481ab82f98475caeb202'
MESSAGE = '82f3dd3e635a478e87a67c82910c1912'
TOOL = '17f4f62e96bf4db297f087d1735102c1'
SECRET = 'flow_agent_fixture_credential_a821394f'
DOCUMENT = 'COMPANY_AGENT_FAKE_REGISTERED_DOCUMENT_DO_NOT_PERSIST_' * 2
PAYLOAD = {'public_text': '公开说明', 'api_key': SECRET, 'document': DOCUMENT}


class Experiment:
    def __init__(self):
        self.index = ContentIndex.register('agent-fixture-v1', [('fake-agent-document', DOCUMENT, 'CONFIDENTIAL', ['registered_text'])], chunk_size=32)
        self.agent = AgentEvidence('agent-fixture', SUBJECTS, TASK, self.index)
        self.flow = FlowEvidence('agent-fixture', SUBJECTS, self.index, transfer_sink=self.agent.consume_transfer)
        for component in ('native-io:A', 'native-io:B', 'etw', 'ecapture'):
            self.flow.health(component, ready=True, terminal=True, identity_verified=True)
        self.qpc = 0
        self.seq = {'A': 0, 'B': 0}
        self.gen = 0
        self.attempts = 0

    def event(self, role, kind, **changes):
        self.seq[role] += 1; self.qpc += 1
        subject = SUBJECTS[role == 'B']
        event = dict(kind=kind, pid=subject['pid'], creation_filetime=subject['creation_filetime'],
            sequence=self.seq[role], qpc=self.qpc, qpc_frequency=1000, success=True, win32_error=0,
            handle_id='fixture-handle', open_generation=self.gen, object_kind='file',
            file_identity='volume:source', path_role='source')
        event.update(changes)
        self.flow.consume_native(event)

    def source(self, data=None):
        data = encode(PAYLOAD) if data is None else data
        self.gen += 1
        self.event('A', 'open')
        self.event('A', 'read', data=data, offset=0, requested_length=len(data), completed_length=len(data))
        self.event('A', 'close')

    def pipe(self, role, operation, data, **changes):
        self.gen += 1
        peer = SUBJECTS[role == 'A']
        shared = dict(object_kind='pipe', file_identity=None, path_role='pipe', pipe_identity='local-agent-fixture',
                      peer_pid=peer['pid'], peer_creation_filetime=peer['creation_filetime'], connection_generation=1)
        shared.update(changes)
        self.event(role, 'open', **shared)
        self.event(role, operation, data=data, requested_length=len(data), completed_length=len(data), message_complete=True, **shared)
        self.event(role, 'close', **shared)

    def handoff(self, payload=None, message=None):
        message = message if message is not None else make_message(TASK, MESSAGE, PAYLOAD if payload is None else payload)
        self.pipe('A', 'write', message)
        self.pipe('B', 'read', message)

    def outbound(self, report=None, *, data=None, attempt=None, parent=MESSAGE):
        self.attempts += 1
        data = data if data is not None else make_outbound(TASK, parent, TOOL, attempt or uuid4().hex, PAYLOAD if report is None else report)
        event = CaptureEvent(provider='ecapture-windows', capture_point='tls', pid=202, creation_filetime=2222,
            tid=1, connection_id='not-for-audit-connection-id', direction='send', sequence=self.attempts,
            captured_qpc=1000+self.attempts, qpc_frequency=1000, image_sha256='b'*64)
        body = Body(data, {'host': 'localhost:443', 'content-type': 'application/json', ':method': 'POST',
                          ':path': '/upload?do-not-persist', 'authorization': 'Bearer SECRET-HEADER', 'cookie': 'SECRET-COOKIE'}, 'http/1.1')
        self.flow.consume_body(event, body, 'observe-'+str(self.attempts))
        self.agent.consume_outbound(self.flow.outbound[-1], data)
        self.flow.add_receipt(hashlib.sha256(data).hexdigest(), len(data), 'origin-'+str(self.attempts))
        return data

    def finish(self, truth=None):
        self.base = self.flow.finish()
        return self.agent.finish(self.base, fixture_truth=truth)


def by_stage(result, stage):
    return [row for row in result['observations'] if row['stage'] == stage]


@pytest.mark.parametrize('mode', ['copy', 'nested', 'extractive'])
def test_multistep_observations_keep_transformation_and_parent_claims_separate(mode):
    run = Experiment(); run.source(); run.handoff(); run.outbound(transform_payload(PAYLOAD, mode))
    result = run.finish()
    assert run.base['session']['status'] == result['session']['status'] == 'complete'
    assert result['stage_counts'] == dict(source_read=1, message_write=1, message_read=1, outbound=1)
    for row in result['observations']:
        assert row['detection_status'] == 'matched'
        assert {'SECRET', 'CONFIDENTIAL'} <= set(row['sensitivity_labels'])
    handoff = next(r for r in result['relations'] if r['relation_kind'] == 'agent_message_handoff')
    assert handoff['confidence'] == 'Medium' and handoff['base_relation_ids']
    parent = next(r for r in result['relations'] if r['relation_kind'] == 'protocol_parent_reference')
    assert parent['protocol_declaration_only'] and not parent['byte_level_taint_proof'] and not parent['merged']
    assert parent['content_evidence'] == ('exact_payload' if mode == 'copy' else 'registered_content_overlap')
    assert by_stage(result, 'outbound')[0]['llm_classification'] == 'UNKNOWN'
    assert not result['can_enforce'] and result['blocked_requests'] == 0


@pytest.mark.parametrize('public_handoff', [True, False])
def test_sensitive_read_does_not_taint_public_delegation_or_public_output(public_handoff):
    run = Experiment(); run.source()
    public = {'public_text': 'ordinary public report'}
    run.handoff(public if public_handoff else PAYLOAD); run.outbound(public)
    result = run.finish()
    assert result['session']['status'] == 'complete'
    assert by_stage(result, 'source_read')[0]['detection_status'] == 'matched'
    assert by_stage(result, 'message_read')[0]['detection_status'] == ('no_match' if public_handoff else 'matched')
    assert by_stage(result, 'outbound')[0]['detection_status'] == 'no_match'
    assert by_stage(result, 'outbound')[0]['sensitivity_labels'] == []
    assert not by_stage(result, 'outbound')[0]['findings']
    if public_handoff:
        assert not any(r['relation_kind'] == 'source_message_candidate' for r in result['relations'])
    else:
        assert next(r for r in result['relations'] if r['relation_kind'] == 'protocol_parent_reference')['content_evidence'] == 'none'


def test_fixture_truth_cannot_create_missing_external_observations_or_leak_payload():
    run = Experiment(); run.source(); run.handoff(); run.outbound()
    base = run.flow.finish()
    empty = AgentEvidence('agent-fixture', SUBJECTS, TASK, run.index)
    result = empty.finish(base, fixture_truth=[{'stage': 'message_read', 'payload': SECRET, 'message_id': MESSAGE, 'certified': True}])
    assert result['session']['status'] == 'partial' and not result['observations'] and not result['relations']
    assert 'source_read_not_observed' in result['coverage_gaps']
    assert result['fixture_truth']['entry_count'] == 1 and not result['fixture_truth']['used_for_certification']
    assert SECRET not in json.dumps(result) and MESSAGE not in json.dumps(result)


def test_audit_excludes_content_authentication_and_protocol_identifiers():
    run = Experiment(); run.source(); run.handoff(); raw = run.outbound()
    attempt = json.loads(raw)['attempt_id']
    result = run.finish([{'payload': SECRET, 'task_id': TASK, 'parent_message_id': MESSAGE}])
    saved = json.dumps(result, ensure_ascii=False)
    for secret in (SECRET, DOCUMENT, TASK, MESSAGE, TOOL, attempt, 'SECRET-HEADER', 'SECRET-COOKIE', 'not-for-audit-connection-id'):
        assert secret not in saved
    assert by_stage(result, 'message_read')[0]['message_id_sha256'] == hashlib.sha256(MESSAGE.encode()).hexdigest()
    assert all(not row['can_enforce'] for row in result['observations'] + result['relations'])


@pytest.mark.parametrize('fault', ['missing_id', 'wrong_task', 'wrong_actor', 'duplicate_key', 'non_json'])
def test_unverified_protocol_cannot_be_certified(fault):
    run = Experiment(); run.source()
    value = json.loads(make_message(TASK, MESSAGE, PAYLOAD))
    if fault == 'missing_id': value.pop('message_id')
    if fault == 'wrong_task': value['task_id'] = 'f'*32
    if fault == 'wrong_actor': value['sender_agent'] = 'agent-b'
    raw = encode(value)
    if fault == 'duplicate_key': raw = raw[:-1] + b',"message_id":"' + MESSAGE.encode() + b'"}'
    if fault == 'non_json': raw = b'api_key='+SECRET.encode()
    run.handoff(message=raw); run.outbound()
    result = run.finish()
    assert result['session']['status'] == 'partial'
    assert by_stage(result, 'message_read')[0]['protocol_status'] == 'invalid'
    assert not any(r['relation_kind'] == 'agent_message_handoff' and r['confidence'] != 'Unknown' for r in result['relations'])


def test_wrong_parent_keeps_real_outbound_detection_without_inventing_link():
    run = Experiment(); run.source(); run.handoff(); run.outbound(parent='f'*32)
    result = run.finish()
    assert result['session']['status'] == 'partial'
    assert by_stage(result, 'outbound')[0]['detection_status'] == 'matched'
    assert 'outbound_parent_not_observed' in result['coverage_gaps']
    assert not any(r['relation_kind'] == 'protocol_parent_reference' for r in result['relations'])


def test_same_message_id_different_payloads_do_not_establish_handoff():
    run = Experiment(); run.source()
    run.pipe('A', 'write', make_message(TASK, MESSAGE, PAYLOAD))
    run.pipe('B', 'read', make_message(TASK, MESSAGE, {'public_text':'different'}))
    run.outbound()
    result = run.finish()
    assert result['session']['status'] == 'partial'
    assert next(r for r in result['relations'] if r['relation_kind'] == 'agent_message_handoff')['confidence'] == 'Unknown'


def test_repeated_message_identifier_preserves_candidates_without_certification():
    run = Experiment(); run.source(); run.handoff(); run.handoff(); run.outbound()
    result = run.finish()
    assert result['session']['status'] == 'partial'
    assert result['stage_counts']['message_write'] == result['stage_counts']['message_read'] == 2
    assert 'message_identifier_missing_or_ambiguous' in result['coverage_gaps']
    assert all(r['confidence'] == 'Unknown' for r in result['relations'] if r['relation_kind'] != 'source_message_candidate')


def test_distinct_send_attempts_are_not_merged_by_report_content():
    run = Experiment(); run.source(); run.handoff(); run.outbound(); run.outbound()
    result = run.finish()
    assert result['session']['status'] == 'complete'
    outs = by_stage(result, 'outbound')
    assert len(outs) == 2 and outs[0]['payload_sha256'] == outs[1]['payload_sha256']
    assert outs[0]['local_attempt_id'] != outs[1]['local_attempt_id']
    assert outs[0]['protocol_attempt_id_sha256'] != outs[1]['protocol_attempt_id_sha256']
    assert run.base['origin_receipts']['captured_count'] == run.base['origin_receipts']['received_count'] == 2


def test_replayed_protocol_attempt_id_is_ambiguous_not_deduplicated():
    run = Experiment(); run.source(); run.handoff(); run.outbound(attempt='e'*32); run.outbound(attempt='e'*32)
    result = run.finish()
    assert result['session']['status'] == 'partial' and len(by_stage(result, 'outbound')) == 2
    assert 'duplicate_protocol_attempt_identifier' in result['coverage_gaps']
    assert all(r['confidence'] == 'Unknown' for r in result['relations'] if r['relation_kind'] == 'protocol_parent_reference')


@pytest.mark.parametrize('fault', ['missing_terminal', 'lost_event', 'base_identity', 'missing_native_relation', 'missing_base_observation', 'changed_base_timing', 'origin_mismatch'])
def test_incomplete_real_evidence_is_not_repaired_by_fixture_truth(fault):
    run = Experiment(); run.source(); run.handoff(); run.outbound(); base = run.flow.finish()
    if fault == 'missing_terminal': base['session']['health']['ecapture']['terminal'] = False
    if fault == 'lost_event': base['session']['health']['native-io:B']['lost_events'] = 1
    if fault == 'base_identity': base['session']['subjects'][1]['creation_filetime'] += 1
    if fault == 'missing_native_relation': base['propagation']['relations'] = []
    if fault == 'missing_base_observation': base['system_behavior']['transfers'] = []
    if fault == 'changed_base_timing': base['system_behavior']['transfers'][1]['last_qpc'] += 1
    if fault == 'origin_mismatch': base['origin_receipts']['hash_multiset_matches'] = False
    result = run.agent.finish(base, fixture_truth=[{'all_checks_passed':True}])
    assert result['session']['status'] == 'partial' and result['coverage_gaps']
    if fault in {'missing_terminal', 'lost_event', 'base_identity'}:
        assert all(r['confidence'] == 'Unknown' for r in result['relations'])


def test_registered_pid_reused_or_image_changed_cannot_supply_agent_message():
    run = Experiment(); run.source(); run.handoff(); row = run.flow.transfers[-1].model_copy(deep=True)
    row.observation_id = uuid4().hex; row.process.creation_filetime += 1
    run.agent.consume_transfer(row, make_message(TASK, MESSAGE, PAYLOAD)); run.outbound()
    result = run.finish()
    assert result['session']['status'] == 'partial'
    assert 'observation_identity_mismatch' in result['coverage_gaps']


def test_wrong_callback_bytes_and_repeated_callback_are_rejected():
    run = Experiment(); run.source(); run.handoff(); row = run.flow.transfers[-1]
    run.agent.consume_transfer(row, b'not the snapshot'); run.outbound()
    result = run.finish()
    assert 'duplicate_observation_callback' in result['coverage_gaps']
    assert len(by_stage(result, 'message_read')) == 1
    other = AgentEvidence('agent-fixture', SUBJECTS, TASK)
    other.consume_transfer(row, b'not the snapshot')
    assert not other.observations and 'agent_snapshot_identity_mismatch' in other.gaps


def test_transfer_sink_is_memory_only_immutable_and_failure_is_a_gap():
    run = Experiment(); seen=[]
    def sink(row, data):
        seen.append((row.content_sha256, len(data)))
        row.completeness='partial'
        raise RuntimeError(SECRET)
    run.flow.transfer_sink=sink; run.source()
    assert seen == [(hashlib.sha256(encode(PAYLOAD)).hexdigest(),len(encode(PAYLOAD)))]
    assert run.flow.transfers[0].completeness=='complete'
    assert not run.flow._states
    assert run.flow.gaps==['transfer_sink_failed']
    assert SECRET not in json.dumps(run.flow.finish())


def test_schemas_reject_enforcement_and_payload_storage():
    run = Experiment(); run.source(); run.handoff(); run.outbound(); result=run.finish()
    for cls,value in [(AgentFlowSession,result['session']), (AgentMessageObservation,result['observations'][0]),
                      (AgentPropagationRelation,result['relations'][0])]:
        cls.model_validate(value)
        with pytest.raises(ValidationError):cls.model_validate({**value,'can_enforce':True})
        with pytest.raises(ValidationError):cls.model_validate({**value,'payload':SECRET})


def test_large_unicode_message_keeps_full_snapshot_and_stage_digests():
    run=Experiment(); payload={**PAYLOAD,'padding':'报告数据。'*12000}
    run.source(encode(payload)); run.handoff(payload); run.outbound(transform_payload(payload,'nested'))
    result=run.finish()
    assert result['session']['status']=='complete'
    assert all(row['body_bytes']>65536 for row in result['observations'])
    assert all(row['detection_status']=='matched' for row in result['observations'])
    assert by_stage(result,'message_read')[0]['body_sha256']==by_stage(result,'message_write')[0]['body_sha256']
    assert by_stage(result,'outbound')[0]['body_sha256']!=by_stage(result,'message_read')[0]['body_sha256']


def test_snapshot_over_limit_does_not_get_parsed_or_stored():
    run=Experiment(); run.source(); row=run.flow.transfers[0].model_copy(deep=True)
    row.observation_id=uuid4().hex
    huge=b'x'*(LIMIT+1)
    run.agent.consume_transfer(row,huge)
    assert 'agent_snapshot_invalid_or_oversized' in run.agent.gaps
    assert len(run.agent.observations)==1


def test_duplicate_base_observation_id_cannot_be_certified():
    run=Experiment();run.source();run.handoff();run.outbound();base=run.flow.finish()
    base['system_behavior']['transfers'].append(dict(base['system_behavior']['transfers'][0]))
    result=run.agent.finish(base)
    assert result['session']['status']=='partial'
    assert 'duplicate_base_observation_identifier' in result['coverage_gaps']


def test_body_from_request_hook_cannot_replace_tls_capture_for_agent_scope():
    run=Experiment();run.source();run.handoff();data=run.outbound()
    row=run.flow.outbound[0].model_copy(deep=True)
    row.observation_id=uuid4().hex;row.capture_layer='request';row.provider='native'
    isolated=AgentEvidence('agent-fixture',SUBJECTS,TASK,run.index)
    isolated.consume_outbound(row,data)
    assert not isolated.observations and isolated.gaps==['agent_outbound_capture_unsupported']


def test_json_value_and_identical_text_encoding_do_not_claim_identical_semantics():
    run=Experiment();run.source();run.handoff({'public_text':'public'})
    run.outbound('{"public_text":"public"}')
    result=run.finish()
    assert result['session']['status']=='complete'
    parent=next(r for r in result['relations'] if r['relation_kind']=='protocol_parent_reference')
    assert parent['content_evidence']=='none'
    assert by_stage(result,'message_read')[0]['payload_representation']=='json'
    assert by_stage(result,'outbound')[0]['payload_representation']=='text'
