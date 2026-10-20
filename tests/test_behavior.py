import json

import pytest

from transpect_trace.behavior.index import BehaviorIndex
from transpect_trace.behavior.models import ProcessIdentity, BehaviorEvent, EgressRule
from transpect_trace.behavior.report import evaluate_egress, build_report
from transpect_trace.behavior.collector import verify_collector, CodexBehaviorCollector
from transpect_trace.guard.etw import PROCESS, FILE, NETWORK


def index():
    value = BehaviorIndex(ProcessIdentity(pid=12, creation_filetime=100, image_sha256='a'*64), 'run-1')
    value.consume({'kind':'etw.ready','qpc_frequency':100,'clock_qpc':1,'clock_filetime':100})
    return value


def event(provider, pid, tick, *, task='', opcode=0, **props):
    return dict(kind='etw.event', provider=provider, header_pid=pid, timestamp_qpc=tick,
                task=task, opcode=opcode, properties=props)


def child(value, pid=13, birth=110, tick=10):
    return value.consume(event(PROCESS, pid, tick, task='Process', opcode=1, ParentProcessID=12, CreateTime=birth))


def test_lineage_requires_creation_time_and_never_pid_only():
    value=index()
    assert child(value, birth=0) is None
    assert value.consume(event(NETWORK,13,20,task='TcpIp',daddr='127.0.0.1',dport=1234)) is None
    assert 'child_creation_time_missing' in value.gaps
    assert child(value,birth=110,tick=30).subject.key=='13-110'
    assert value.lineage('13-110')==['12-100','13-110']


def test_pid_reuse_and_delayed_exit_cannot_retire_new_generation():
    value=index();child(value)
    child(value,birth=120,tick=30)
    assert value.consume(event(PROCESS,13,40,task='Process',opcode=2,CreateTime=110)) is None
    assert value.at(13,40)['subject'].key=='13-120'
    old=value.consume(event(NETWORK,13,20,task='TcpIp',PID=13))
    assert old.subject.key=='13-110'
    value.consume(event(PROCESS,13,50,task='Process',opcode=1,ParentProcessID=999,CreateTime=140))
    assert value.consume(event(NETWORK,13,60,task='TcpIp')) is None


@pytest.mark.parametrize("parent", [12, 999])
def test_missing_birth_invalidates_previous_pid_generation(parent):
    value = index()
    child(value)
    value.consume(event(PROCESS,13,30,task='Process',opcode=1,ParentProcessID=parent))
    assert value.consume(event(NETWORK,13,40,task='TcpIp')) is None
    assert value.at(13,20)['subject'].key == '13-110'
    assert 'process_identity_invalidated' in value.gaps


def test_network_pid_property_and_no_payload_claim_or_secret_properties():
    value=index();child(value)
    row=value.consume(event(NETWORK,0,20,task='TcpIp',PID=13,daddr='127.0.0.1',dport=99,size=42,
                            Cookie='TEST_COOKIE_SECRET',CommandLine='TEST_PROMPT_SECRET'))
    assert row.subject.key=='13-110' and row.destination_port==99
    assert row.payload_sent=='unknown'
    assert 'TEST_' not in row.model_dump_json()


def test_file_object_generation_scope_and_access_not_read_success():
    value=index();child(value)
    opened=value.consume(event(FILE,13,20,task='Create',FileObject='123',FileName=r'C:\fake.txt'))
    assert opened.kind=='file.access' and opened.read_success=='unknown'
    assert value.consume(event(FILE,13,21,task='Read',FileObject='123')).path==r'c:\fake.txt'
    child(value,birth=120,tick=30)
    assert value.consume(event(FILE,13,40,task='Read',FileObject='123')).path is None


def test_directory_listing_does_not_relabel_an_open_file():
    value=index();child(value)
    value.consume(event(FILE,13,20,task='Create',FileObject=123,FileName=r'C:\directory'))
    value.consume(event(FILE,13,21,task='DirEnum',FileObject=123,FileName='unrelated-secret.txt'))
    row=value.consume(event(FILE,13,22,task='Read',FileObject=123))
    assert row.path==r'c:\directory'


def test_reused_file_object_without_name_does_not_inherit_path():
    value=index();child(value)
    value.consume(event(FILE,13,20,task='Create',FileObject=123,FileName=r'C:\old-secret.txt'))
    value.consume(event(FILE,13,30,task='Create',FileObject=123))
    assert value.consume(event(FILE,13,31,task='Read',FileObject=123)).path is None


def test_process_capacity_is_explicit_gap():
    value=index();value.limit=1
    assert child(value) is None
    assert 'process_capacity_exceeded' in value.gaps


@pytest.mark.parametrize('failure', ['lost','eof','unavailable','malformed','unknown_counters'])
def test_health_failure_never_high_source_confidence(failure):
    value=index();child(value)
    value.consume(event(FILE,13,20,task='Read',FileName=r'C:\fake.txt',FileObject=123))
    if failure=='lost':value.consume(dict(kind='etw.stopped',status=0,events_lost=1,counters_verified=True))
    elif failure=='eof':value.eof(0)
    elif failure=='unavailable':value.consume(dict(kind='etw.unavailable'))
    elif failure=='malformed':value.gaps.add('malformed_collector_record')
    else:value.consume(dict(kind='etw.stopped',status=0))
    result=value.correlate(dict(request_id='q',captured_qpc=25,qpc_frequency=100,candidate_source_paths=[r'C:\fake.txt']))
    assert result['source_relation']['confidence']=='Unknown'


def test_match_and_read_candidate_is_not_causal_proof():
    value=index();child(value)
    value.consume(event(FILE,13,20,task='Read',FileName=r'C:\fake.txt',FileObject=123))
    decision=dict(request_id='q',captured_qpc=25,qpc_frequency=100,candidate_source_paths=[r'C:\fake.txt'])
    relation=value.correlate(decision)
    assert relation['source_relation']['confidence']=='High'
    assert not relation['source_relation']['byte_level_taint_proof']
    decision['candidate_source_paths']=[]
    assert value.correlate(decision)['source_relation']['confidence']!='High'


def test_egress_rule_is_explicit_destination_policy_not_file_taint():
    value=index()
    value.consume(event(FILE,12,10,task='Read',FileName='secret.env',FileObject=1))
    network=value.consume(event(NETWORK,12,20,task='TcpIp',daddr='127.0.0.1',dport=100))
    assert evaluate_egress(network,[])['decision']=='audit'
    rule=EgressRule(rule_id='test',image_sha256='a'*64,destination_address='127.0.0.1',destination_port=100,protocol='tcp',action='recommend_block')
    result=evaluate_egress(network,[rule])
    assert result['decision']=='recommend_block' and result['actual_action']=='none' and not result['can_enforce']
    rule.image_sha256='b'*64
    assert evaluate_egress(network,[rule])['decision']=='audit'


def test_events_bounded_and_unknown_protocol():
    value=index();value.limit=2
    assert value.consume(event(NETWORK,12,20,task='other',daddr='not-an-ip',dport='garbage')).protocol=='unknown'
    assert value.consume(event(NETWORK,12,30)) is None
    assert 'event_capacity_exceeded' in value.gaps


def test_manifest_mismatch_rejected(tmp_path):
    target=tmp_path/'etw.exe';target.write_bytes(b'changed')
    (tmp_path/'build-manifest.json').write_text(json.dumps({'artifacts_sha256':{'etw.exe':'a'*64}}))
    with pytest.raises(ValueError,match='hash mismatch'):verify_collector(target)


def test_wrong_codex_version_refused_before_launch(tmp_path):
    with pytest.raises(ValueError,match='fixed Codex baseline'):
        CodexBehaviorCollector(dict(pid=12,creation_filetime=100,baseline={'sha256':'a'*64,'supported':True}),tmp_path/'none',tmp_path/'out')


def test_report_rejects_wrong_run_and_never_copies_payload(tmp_path):
    value=index();root=tmp_path/'behavior';root.mkdir();guard=tmp_path/'guard';guard.mkdir()
    (root/'status.json').write_text(json.dumps(dict(root=value.root.model_dump(),run_id=value.run_id,health=value.health())))
    (root/'events.jsonl').write_text(value.events[0].model_dump_json()+'\n')
    subject=dict(pid=12,creation_filetime=999,baseline={'sha256':'a'*64})
    (guard/'status.json').write_text(json.dumps({'identity':subject}))
    (guard/'audit.jsonl').write_text(json.dumps(dict(kind='policy.decision',request_id='q',payload_utf8='TEST_SECRET'))+'\n')
    with pytest.raises(ValueError,match='identity mismatch'):build_report(root,guard_directory=guard)
    subject['creation_filetime']=100
    (guard/'status.json').write_text(json.dumps({'identity':subject}))
    report=build_report(root,guard_directory=guard)
    assert 'TEST_SECRET' not in json.dumps(report)
    assert report['health']['state']=='degraded'
    assert 'terminal_health_not_confirmed' in report['gaps']
