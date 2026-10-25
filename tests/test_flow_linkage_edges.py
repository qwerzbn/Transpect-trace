"""Adversarial linkage timelines, using simulated callbacks rather than OS proof."""
import json

import pytest

from test_flow_evidence import Native, make, outbound, receipt, SECRET
from test_agent_flow_evidence import Experiment, PAYLOAD, MESSAGE, TOOL, by_stage
from transpect_trace.flow.agents.protocol import make_outbound


def seed_file_chain(flow):
    native=Native(flow)
    native.file('A','read',SECRET.encode(),file_id='source')
    native.file('A','write',SECRET.encode())
    native.file('B','read',SECRET.encode())
    return native


def finish(flow):
    outbound(flow,SECRET.encode());receipt(flow,SECRET.encode())
    return flow.finish()


def assert_unknown(result):
    assert result['session']['status']=='partial'
    assert result['propagation']['relations']
    assert all(r['confidence']=='Unknown' for r in result['propagation']['relations'])
    assert all(not r['unique_source_proven'] and not r['byte_level_taint_proof'] for r in result['propagation']['relations'])


def test_late_pipe_ambiguity_retracts_earlier_complete_file_edge():
    flow=make();native=seed_file_chain(flow)
    native.pipe('A','write',SECRET.encode())
    native.pipe('B','read',SECRET.encode())
    native.pipe('B','read',SECRET.encode())
    result=finish(flow)
    assert 'pipe_message_mapping_ambiguous' in result['coverage_gaps']
    assert any(r['relation_kind']=='file_handoff_candidate' for r in result['propagation']['relations'])
    assert_unknown(result)


def test_empty_connection_then_reconnect_is_not_hidden_by_transfer_only_history():
    flow=make();native=Native(flow)
    native.file('A','read',SECRET.encode(),file_id='source')
    old=dict(object_kind='pipe',file_identity=None,path_role='pipe',pipe_identity='fixture-pipe',
             peer_pid=202,peer_creation_filetime=2222,connection_generation=1)
    native.gen+=1
    native.event('A','open',**old);native.event('A','pipe_connect',**old);native.event('A','close',**old)
    native.pipe('A','write',SECRET.encode(),generation=2)
    native.pipe('B','read',SECRET.encode(),generation=90)
    result=finish(flow)
    assert 'pipe_connection_mapping_ambiguous' in result['coverage_gaps']
    assert len([t for t in result['system_behavior']['transfers'] if t['object_kind']=='pipe'])==2
    assert not result['collection_coverage']['handoff_object_range_supported']
    assert_unknown(result)


def test_nonmatching_concurrent_write_still_invalidates_read_snapshot():
    flow=make();native=seed_file_chain(flow)
    native.gen+=1;reader=native.gen
    native.event('B','open',qpc=40,file_identity='second-file')
    native.event('B','read',qpc=50,completed_qpc=100,file_identity='second-file',offset=0,
                 data=SECRET.encode(),requested_length=len(SECRET),completed_length=len(SECRET))
    native.gen+=1
    native.event('A','open',qpc=55,file_identity='second-file')
    native.event('A','write',qpc=60,completed_qpc=65,file_identity='second-file',offset=0,
                 data=b'ordinary rewrite',requested_length=16,completed_length=16)
    native.event('A','close',qpc=70,file_identity='second-file')
    native.event('B','close',qpc=110,open_generation=reader,file_identity='second-file')
    result=finish(flow)
    reads=[t for t in result['system_behavior']['transfers'] if t['process']['role']=='B' and t['operation']=='read']
    assert len(reads)==2 and reads[-1]['completeness']=='partial'
    assert 'file_modified_during_read' in reads[-1]['limitations']
    assert_unknown(result)


def test_overlapping_write_intervals_cannot_certify_old_identical_version():
    flow=make();native=Native(flow)
    native.file('A','read',SECRET.encode(),file_id='source')
    native.gen+=1;first=native.gen
    native.event('A','open',qpc=5)
    native.gen+=1;second=native.gen
    native.event('A','open',qpc=6)
    native.event('A','write',qpc=10,completed_qpc=30,open_generation=first,offset=0,
                 data=SECRET.encode(),requested_length=len(SECRET),completed_length=len(SECRET))
    native.event('A','write',qpc=20,completed_qpc=40,open_generation=second,offset=0,
                 data=b'different',requested_length=9,completed_length=9)
    native.event('A','close',qpc=35,open_generation=first)
    native.event('A','close',qpc=45,open_generation=second)
    native.gen+=1
    native.event('B','open',qpc=49)
    native.event('B','read',qpc=50,completed_qpc=60,offset=0,data=SECRET.encode(),
                 requested_length=len(SECRET),completed_length=len(SECRET))
    native.event('B','close',qpc=65)
    result=finish(flow)
    writes=[t for t in result['system_behavior']['transfers'] if t['operation']=='write']
    assert len(writes)==2 and all(t['completeness']=='partial' for t in writes)
    assert 'file_write_order_ambiguous' in result['coverage_gaps']
    assert not result['collection_coverage']['handoff_object_range_supported']
    assert next(t for t in result['system_behavior']['transfers'] if t['process']['role']=='B')['file_version'] is None
    assert_unknown(result)


def test_sequential_identical_rewrite_uses_only_latest_closed_version():
    flow=make();native=Native(flow)
    native.file('A','read',SECRET.encode(),file_id='source')
    native.file('A','write',SECRET.encode());native.file('A','write',SECRET.encode())
    native.file('B','read',SECRET.encode())
    result=finish(flow)
    assert result['session']['status']=='complete'
    edges=[r for r in result['propagation']['relations'] if r['relation_kind']=='file_handoff_candidate']
    writes=[t for t in result['system_behavior']['transfers'] if t['operation']=='write']
    assert len(edges)==1 and edges[0]['left_id']==writes[-1]['observation_id']
    assert edges[0]['confidence']=='High' and not edges[0]['unique_source_proven']


@pytest.mark.parametrize('other_valid_handoff',[False,True])
def test_shared_registration_fragment_does_not_certify_mismatched_complete_ranges(other_valid_handoff):
    flow=make();native=Native(flow)
    native.file('A','read',SECRET.encode(),file_id='source')
    if other_valid_handoff:
        native.file('A','write',SECRET.encode(),file_id='other-good-file')
        native.file('B','read',SECRET.encode(),file_id='other-good-file')
    native.file('A','write',SECRET.encode()+b'first version')
    native.file('B','read',SECRET.encode()+b'other version with different length')
    result=finish(flow)
    assert all(t['completeness']=='complete' for t in result['system_behavior']['transfers'])
    assert 'handoff_object_range_unverified' in result['coverage_gaps']
    assert result['collection_coverage']['handoff_object_range_supported']==other_valid_handoff
    assert_unknown(result)


@pytest.mark.parametrize('fault',['health','origin_multiplicity','partial_snapshot'])
def test_final_collection_failure_downgrades_every_relation_without_erasing_findings(fault):
    flow=make();native=seed_file_chain(flow)
    if fault=='health':flow.health('ecapture',lost_events=1)
    if fault=='partial_snapshot':
        native.gen+=1
        native.event('B','open',file_identity='extra-file')
        native.event('B','read',file_identity='extra-file',offset=0,data=SECRET.encode(),
                     requested_length=len(SECRET),completed_length=len(SECRET))
        # No close: finish must retain a partial observation, not invent a boundary.
    if fault=='origin_multiplicity':outbound(flow,SECRET.encode(),n=2)
    result=finish(flow)
    assert_unknown(result)
    assert all(o['detection_status']=='matched' for o in result['content_detection']['outbound'])
    assert all(o['findings'] for o in result['content_detection']['outbound'])


def test_agent_late_unknown_parent_downgrades_earlier_parent_and_handoff_relations():
    run=Experiment();run.source();run.handoff();run.outbound();run.outbound(parent='f'*32)
    result=run.finish()
    assert result['session']['status']=='partial'
    assert 'outbound_parent_not_observed' in result['coverage_gaps']
    assert any(r['relation_kind']=='protocol_parent_reference' for r in result['relations'])
    assert all(r['confidence']=='Unknown' for r in result['relations'])
    assert all(o['detection_status']=='matched' for o in by_stage(result,'outbound'))


def test_agent_wrong_task_does_not_leave_earlier_edges_certified():
    run=Experiment();run.source();run.handoff();run.outbound()
    run.outbound(data=make_outbound('f'*32,MESSAGE,TOOL,'e'*32,PAYLOAD))
    result=run.finish()
    assert result['session']['status']=='partial'
    assert 'message_task_mismatch' in result['coverage_gaps']
    assert all(r['confidence']=='Unknown' for r in result['relations'])
    assert by_stage(result,'outbound')[-1]['findings']
    assert not result['can_enforce'] and result['blocked_requests']==0


def test_agent_public_report_is_not_safe_or_tainted_when_linkage_is_incomplete():
    run=Experiment();run.source();run.handoff();run.outbound({'public_text':'ordinary'},parent='f'*32)
    result=run.finish()
    row=by_stage(result,'outbound')[0]
    assert row['detection_status']=='no_match' and not row['sensitivity_labels']
    assert result['session']['status']=='partial'
    assert all(r['confidence']=='Unknown' for r in result['relations'])
    assert 'SAFE' not in json.dumps(result) and not result['can_enforce']
