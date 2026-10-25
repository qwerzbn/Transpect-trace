"""Controlled agent orchestration doubles; these are not Windows capture proof."""
import io
import json
import queue
from types import SimpleNamespace

import pytest


SECRET = 'FAKE-AGENT-SECRET-MUST-NOT-BE-LOGGED'


def harness(tmp_path, monkeypatch, *, failure=None):
    from transpect_trace.flow.agents import runtime
    from transpect_trace.flow import native, etw, origin, ecapture_diagnostics
    from transpect_trace.observe import ecapture, windows
    from transpect_trace.protect.detection import ContentIndex

    paths = {name: tmp_path / name for name in ('python', 'participant', 'observer', 'etw', 'native_manifest',
             'ecapture', 'ecapture_manifest', 'source', 'content_index', 'certificate', 'private_key')}
    paths['content_index'].write_text(ContentIndex(version='fixture-empty').model_dump_json())
    manifest = SimpleNamespace(timeout_seconds=10, handoff_public=False, transform='nested',
        implementation={'agents/participant.py': SimpleNamespace(sha256='c'*64)},
        **{name: SimpleNamespace(sha256='a'*64 if name=='python' else 'b'*64) for name in paths})
    output = tmp_path/'audit'
    monkeypatch.setattr(runtime, 'load', lambda _: (manifest, paths, output))
    monkeypatch.setattr(runtime.sys, 'platform', 'win32')
    commands, timeline, fixtures, origins, native_collectors, etw_collectors, ecapture_collectors = [], [], [], [], [], [], []
    phase = {'during_workflow':False}

    class Process:
        def __init__(self, role):
            self.pid = 101 if role=='A' else 202
            self.code = None
        def poll(self): return self.code

    class AgentFixture:
        def __init__(self, command, directory, role):
            self.role, self.process, self.events = role, Process(role), []
            self.command = list(command)
            fixtures.append(self)
        def wait(self, kind, timeout=15, check=None):
            timeline.append((self.role,'wait:'+kind))
            if kind=='transfer_complete': phase['during_workflow']=True
            if check: check()
            if kind=='ready':
                return {'kind':kind,'pid':self.process.pid+int(failure=='ready_pid' and self.role=='B'),
                        'source_access_started':failure=='source_started' and self.role=='A'}
            if kind=='pipe_ready' and failure=='pipe_ready': raise TimeoutError(SECRET)
            return {'kind':kind,'bytes':1,'http_status':200}
        def send(self, command):
            commands.append((self.role,command));timeline.append((self.role,'send:'+command))
        def close(self):
            self.process.code = 0
            if failure=='fixture_close' and self.role=='A':raise RuntimeError(SECRET)

    class Origin:
        def __init__(self, *args):
            self.receipts, self.errors = [], []
            self.url, self.server = 'https://localhost:12345/upload', SimpleNamespace(server_port=12345)
            self.closed = False;origins.append(self)
        def start(self): return self
        def close(self):
            self.closed=True
            if failure=='origin_close':raise RuntimeError(SECRET)

    class Native:
        def __init__(self, subject, *args, **kwargs):
            self.subject=subject;self.started=self.terminal=False
            native_collectors.append(self)
        def start(self):
            if failure=='native_start':raise RuntimeError(SECRET)
            self.started=failure!='native_not_ready'
            self.terminal=failure=='native_early_terminal'
        def close(self):
            self.terminal=True
            if failure=='native_close':raise RuntimeError(SECRET)
        def status(self):
            if failure=='native_status' and self.terminal:raise RuntimeError(SECRET)
            loss = 1 if failure=='native_loss' else 0
            errors = ['mock_native_exit'] if failure=='native_during_workflow' and phase['during_workflow'] else []
            return {'ready':self.started,'terminal':self.terminal,'lost_events':loss,'errors':errors}

    class ETW:
        def __init__(self, members, *args, **kwargs):
            self.members=members;self.started=self.terminal=False
            self.process=SimpleNamespace(poll=lambda:0 if failure=='etw_process_exit' else None)
            self.index=SimpleNamespace(health=self.health,events=[])
            etw_collectors.append(self)
        def health(self):
            if failure=='etw_health' and self.terminal:raise RuntimeError(SECRET)
            stopped=self.terminal or failure=='etw_during_workflow' and phase['during_workflow']
            return {'state':'stopped' if stopped else 'ready' if self.started else 'unavailable',
                    'ready_observed':self.started,'terminal_observed':self.terminal,
                    'events_lost':int(failure=='etw_loss'),
                    'gaps':['mock_etw_gap'] if failure=='etw_gap' else []}
        def start(self):
            self.started=failure!='etw_start'
            return self.health()
        def stop(self):
            self.terminal=True
            if failure=='etw_stop':raise RuntimeError(SECRET)
            return self.health()

    class ECapture:
        def __init__(self, subject, *args, **kwargs):
            self.subject=subject;self.errors=[]
            self._verified_manifest={'artifacts_sha256':{'schannel_hook.dll':'d'*64}}
            self.structured=SimpleNamespace(ready=False,terminal=False,lost=0)
            ecapture_collectors.append(self)
        def start(self):
            if failure=='ecapture_start':raise RuntimeError(SECRET)
            self.structured.ready=failure!='ecapture_not_ready'
            self.structured.terminal=failure=='ecapture_early_terminal'
            self.structured.lost=int(failure=='ecapture_loss')
        def check_health(self):
            if failure=='ecapture_health' or failure=='ecapture_during_workflow' and phase['during_workflow']:
                raise RuntimeError(SECRET)
        def close(self):
            self.structured.terminal=True
            if failure=='ecapture_close':raise RuntimeError(SECRET)

    def identity(pid):
        if pid==runtime.os.getpid():
            return {'pid':pid,'creation_filetime':pid*10,'image_sha256':'d'*64,'image_path':str(tmp_path/'controller.exe')}
        if pid not in {101,202}:raise OSError(SECRET)
        return {'pid':pid,'creation_filetime':pid*10,'image_sha256':'c'*64 if failure=='identity' else 'a'*64,
                'image_path':str(tmp_path/'same-python.exe')}

    def verify(_):
        if failure=='build_identity':raise ValueError(SECRET)
        return {'variant':'upstream','protocol':'preview'} if failure=='build_stock' else {'variant':'enhanced','protocol':'ECW2'}

    def diagnostic(*args):
        if failure=='diagnostics':raise RuntimeError(SECRET)
        return {'state':'observed','counters':{'total':0},'can_enforce':False}

    monkeypatch.setattr(runtime,'AgentFixture',AgentFixture)
    monkeypatch.setattr(origin,'Origin',Origin)
    monkeypatch.setattr(native,'NativeIOCollector',Native)
    monkeypatch.setattr(etw,'MultiApplicationETWCollector',ETW)
    monkeypatch.setattr(etw,'summarize_coverage',lambda *a,**k:{'actual_event_count':0,'gaps':['etw_no_real_events']})
    monkeypatch.setattr(ecapture,'ECaptureCollector',ECapture)
    monkeypatch.setattr(ecapture,'verify_build',verify)
    monkeypatch.setattr(ecapture_diagnostics,'snapshot',diagnostic)
    monkeypatch.setattr(windows,'identity',identity)
    return SimpleNamespace(runtime=runtime,output=output,commands=commands,timeline=timeline,fixtures=fixtures,
                           origins=origins,native=native_collectors,etw=etw_collectors,ecapture=ecapture_collectors)


def safe_audit(folder):
    for path in folder.rglob('*'):
        if path.is_file():assert SECRET not in path.read_text(encoding='utf-8'),path.name


@pytest.mark.parametrize('failure',[
    'identity','ready_pid','source_started','native_start','native_not_ready','native_early_terminal','native_loss',
    'etw_start','etw_process_exit','etw_loss','etw_gap',
    'ecapture_start','ecapture_health','ecapture_not_ready','ecapture_early_terminal','ecapture_loss',
])
def test_prerelease_identity_or_collector_failure_keeps_both_agents_idle(tmp_path,monkeypatch,failure):
    h=harness(tmp_path,monkeypatch,failure=failure)
    result=h.runtime.run(tmp_path/'mock.manifest.json')
    assert result['state']=='unavailable' and not result['data_released'] and not result['certified']
    assert not any(command=='release' for _,command in h.commands)
    assert all(f.process.poll()==0 for f in h.fixtures)
    assert h.origins[0].closed
    safe_audit(h.output)


@pytest.mark.parametrize('failure',['build_identity','build_stock'])
def test_bad_ecapture_build_stops_before_origin_or_agent_launch(tmp_path,monkeypatch,failure):
    h=harness(tmp_path,monkeypatch,failure=failure);result=h.runtime.run(tmp_path/'mock.manifest.json')
    assert result['state']=='unavailable' and not result['data_released']
    assert not h.fixtures and not h.origins and not h.commands
    safe_audit(h.output)


def test_b_pipe_must_be_ready_before_a_can_read_or_delegate(tmp_path,monkeypatch):
    h=harness(tmp_path,monkeypatch);result=h.runtime.run(tmp_path/'mock.manifest.json')
    assert h.commands==[('B','release'),('A','release')]
    assert h.timeline.index(('B','wait:pipe_ready'))<h.timeline.index(('A','send:release'))
    assert result['data_released'] and result['state']=='partial' and not result['certified']
    assert 'etw_no_real_events' in json.dumps(json.loads((h.output/'flow-evidence.json').read_text()))
    agents=json.loads((h.output/'agent-evidence.json').read_text())
    assert agents['session']['status']=='partial' and not agents['observations']
    assert agents['stage_counts']==dict(source_read=0,message_write=0,message_read=0,outbound=0)
    assert not agents['can_enforce'] and agents['blocked_requests']==0


def test_pipe_readiness_failure_does_not_release_a(tmp_path,monkeypatch):
    h=harness(tmp_path,monkeypatch,failure='pipe_ready');result=h.runtime.run(tmp_path/'mock.manifest.json')
    assert h.commands==[('B','release')]
    assert result['state'] in {'partial','unavailable'} and not result['certified']
    assert not result.get('client_send_completed',False)
    safe_audit(h.output)


def test_same_interpreter_agents_are_bound_to_distinct_process_instances(tmp_path,monkeypatch):
    h=harness(tmp_path,monkeypatch);result=h.runtime.run(tmp_path/'mock.manifest.json')
    subjects=result['subjects']
    assert [s['pid'] for s in subjects]==[101,202]
    assert [s['creation_filetime'] for s in subjects]==[1010,2020]
    assert {s['image_sha256'] for s in subjects}=={'a'*64}
    assert {c.subject['pid'] for c in h.native}=={101,202}
    assert {s['pid'] for s in h.etw[0].members}=={101,202}
    assert h.ecapture[0].subject['pid']==202
    assert result['membership']=='explicit_independent_agents_not_parent_child'


@pytest.mark.parametrize('failure',['native_during_workflow','etw_during_workflow','ecapture_during_workflow'])
def test_collector_failure_after_release_is_partial_and_does_not_claim_completion(tmp_path,monkeypatch,failure):
    h=harness(tmp_path,monkeypatch,failure=failure);result=h.runtime.run(tmp_path/'mock.manifest.json')
    assert result['data_released'] and result['state']=='partial' and result['gaps']
    assert not result.get('client_send_completed',False) and not result['certified']
    assert h.origins[0].closed and all(f.process.poll()==0 for f in h.fixtures)
    safe_audit(h.output)


@pytest.mark.parametrize('failure',[
    'fixture_close','native_close','etw_stop','ecapture_close','origin_close','native_status','etw_health','diagnostics',
])
def test_cleanup_and_final_health_failures_still_persist_partial_redacted_evidence(tmp_path,monkeypatch,failure):
    h=harness(tmp_path,monkeypatch,failure=failure);result=h.runtime.run(tmp_path/'mock.manifest.json')
    assert result['state']=='partial' and result['gaps'] and not result['certified']
    assert (h.output/'flow-evidence.json').is_file() and (h.output/'agent-evidence.json').is_file()
    saved=json.loads((h.output/'runtime.json').read_text())
    assert saved['state']=='partial' and saved['ended_at_utc']
    assert h.origins[0].closed and all(f.process.poll()==0 for f in h.fixtures)
    safe_audit(h.output)


@pytest.mark.parametrize('kind',['ready','received','error','agent_step'])
def test_decode_truth_discards_original_body_tokens_and_identifiers(kind):
    from transpect_trace.flow.agents.runtime import decode_truth
    raw={'kind':kind,'role':'A','evidence_origin':'fixture_truth','text':SECRET,'token':SECRET,
         'message_id':SECRET,'task_id':SECRET,'error':SECRET,'headers':{'authorization':SECRET},'pid':101}
    if kind=='agent_step':raw.update(step='query',task_id_sha256='a'*64,message_id_sha256='b'*64)
    decoded=decode_truth(raw,'A')
    assert SECRET not in json.dumps(decoded)
    assert decoded['evidence_origin']=='fixture_truth' and decoded['kind']==kind
    assert set(decoded)<={'kind','role','evidence_origin','pid','step','task_id_sha256','message_id_sha256'}


@pytest.mark.parametrize('override',[
    {'role':'B'},{'evidence_origin':'native-io'},{'kind':SECRET},{'pid':SECRET},
    {'source_access_started':SECRET},{'step':SECRET},{'task_id_sha256':SECRET},{'task_id_sha256':None},
])
def test_malformed_truth_emits_only_generic_error_and_eof(override):
    from transpect_trace.flow.agents.runtime import AgentFixture
    value={'kind':'agent_step','role':'A','evidence_origin':'fixture_truth','step':'query','task_id_sha256':'a'*64}
    value.update(override)
    fixture=AgentFixture.__new__(AgentFixture)
    fixture.role,fixture.events,fixture.queue='A',[],queue.Queue(maxsize=128)
    fixture.process=SimpleNamespace(stdout=io.BytesIO((json.dumps(value)+'\n').encode()))
    fixture._read()
    assert not fixture.events
    assert fixture.queue.get_nowait()=={'kind':'error'}
    assert fixture.queue.get_nowait()=={'kind':'eof'}


def test_valid_fixture_reader_saves_only_sanitized_test_truth():
    from transpect_trace.flow.agents.runtime import AgentFixture
    value={'kind':'agent_step','role':'B','evidence_origin':'fixture_truth','step':'http_upload',
           'task_id_sha256':'a'*64,'attempt_id_sha256':'b'*64,'text':SECRET,'token':SECRET,'report':SECRET}
    fixture=AgentFixture.__new__(AgentFixture)
    fixture.role,fixture.events,fixture.queue='B',[],queue.Queue(maxsize=128)
    fixture.process=SimpleNamespace(stdout=io.BytesIO((json.dumps(value)+'\n').encode()))
    fixture._read()
    assert len(fixture.events)==1 and fixture.events[0]['evidence_origin']=='fixture_truth'
    assert SECRET not in json.dumps(fixture.events)
    assert fixture.queue.get_nowait()==fixture.events[0]
    assert fixture.queue.get_nowait()=={'kind':'eof'}


@pytest.mark.parametrize('component',['flow_finish','agent_finish','etw_coverage','observe_finish'])
def test_final_report_or_parser_failure_cannot_leave_observing_status(tmp_path,monkeypatch,component):
    from transpect_trace.flow import evidence, etw
    from transpect_trace.flow.agents.evidence import AgentEvidence
    from transpect_trace.observe.pipeline import Pipeline
    h=harness(tmp_path,monkeypatch)
    def fail(*args,**kwargs):raise RuntimeError(SECRET)
    if component=='flow_finish':monkeypatch.setattr(evidence.FlowEvidence,'finish',fail)
    if component=='agent_finish':monkeypatch.setattr(AgentEvidence,'finish',fail)
    if component=='etw_coverage':monkeypatch.setattr(etw,'summarize_coverage',fail)
    if component=='observe_finish':monkeypatch.setattr(Pipeline,'finish',fail)
    result=h.runtime.run(tmp_path/'mock.manifest.json')
    saved=json.loads((h.output/'runtime.json').read_text())
    assert result['state']==saved['state']=='partial'
    assert result['gaps'] and saved['ended_at_utc'] and not saved['certified']
    assert all(f.process.poll()==0 for f in h.fixtures) and h.origins[0].closed
    if component in {'flow_finish','agent_finish'}:assert 'evidence_finalize_failed' in result['gaps']
    safe_audit(h.output)
