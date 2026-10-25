"""Controlled agent workflow orchestrator using the existing Flow collectors."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import sys
import threading
import traceback
from uuid import uuid4

from ..runtime import Fixture
from .manifest import load


def decode_truth(value, role):
    if not isinstance(value, dict) or value.get('role') != role or value.get('evidence_origin') != 'fixture_truth':
        raise ValueError('invalid_fixture_enrollment')
    kind = value.get('kind')
    if kind not in {'ready','transfer_complete','pipe_ready','received','sent','finished','error','agent_step',
                    'source_read_part','attempt_failed','upload_paused'}:
        raise ValueError('invalid_fixture_kind')
    result = {'kind':kind, 'role':role, 'evidence_origin':'fixture_truth'}
    for field in ('pid','bytes','http_status','win32_error'):
        if field in value:
            item = value[field]
            if item is not None and (type(item) is not int or not 0 <= item <= 0xffffffff):
                raise ValueError('invalid_fixture_number')
            result[field] = item
    if 'source_access_started' in value:
        if type(value['source_access_started']) is not bool:
            raise ValueError('invalid_fixture_source_flag')
        result['source_access_started'] = value['source_access_started']
    if kind == 'agent_step':
        if value.get('step') not in {'query','delegate','transform','http_upload'}:
            raise ValueError('invalid_fixture_step')
        result['step'] = value['step']
        for field in ('task_id_sha256','message_id_sha256','tool_call_id_sha256','attempt_id_sha256'):
            if field in value:
                if not isinstance(value[field], str) or not re.fullmatch('[0-9a-f]{64}', value[field]):
                    raise ValueError('invalid_fixture_identifier')
                result[field] = value[field]
        if 'task_id_sha256' not in result:
            raise ValueError('missing_fixture_task')
    # Error payload/stage is not necessary to decide observation completeness.
    # Unknown fields, including original content or identifiers, are never saved.
    return result


class AgentFixture(Fixture):
    def _read(self):
        try:
            while line := self.process.stdout.readline(4097):
                if len(line) > 4096:
                    raise ValueError('fixture_record_limit')
                row = decode_truth(json.loads(line), self.role)
                self.events.append(row)
                self.queue.put_nowait(row)
        except (ValueError, OSError, queue.Full):
            try: self.queue.put_nowait({'kind':'error'})
            except queue.Full: pass
        finally:
            try: self.queue.put_nowait({'kind':'eof'})
            except queue.Full: pass


def run(manifest_path, *, experiment=None, _start_barrier=None):
    # Internal qualification entry: a closed set of fake-data variations.
    # Normal CLI / manifest semantics stay unchanged.
    if experiment is not None:
        from .linkage import LinkageExperiment
        experiment = LinkageExperiment(experiment)
    manifest, paths, output = load(manifest_path)
    output.mkdir(parents=True, exist_ok=False)
    session_id, task_id, message_id = uuid4().hex, uuid4().hex, uuid4().hex
    state = {'schema_version':'transpect.agent-flow.runtime/1.0', 'session_id':session_id,
             'task_id_sha256':hashlib.sha256(task_id.encode()).hexdigest(), 'state':'initializing',
             'agent_kind':'deterministic_test_agent', 'can_enforce':False, 'certified':False,
             'data_released':False, 'gaps':[], 'fixture_exit_codes':{},
             'started_at_utc':datetime.now(timezone.utc).isoformat(),
             'environment':{'os':platform.system(),'os_version':platform.version(),
                            'python':platform.python_version(),'architecture':platform.machine()},
             'baseline':{name:getattr(manifest,name).sha256 for name in paths},
             'implementation':{name:value.sha256 for name,value in manifest.implementation.items()}}
    def persist():
        temporary = output/'runtime.tmp'
        temporary.write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8')
        temporary.replace(output/'runtime.json')
    persist()
    if experiment:
        state['qualification'] = {'mode':experiment.mode,'rounds':experiment.rounds,
                                  'attempts_per_message':experiment.attempts,'can_enforce':False}
    if sys.platform != 'win32' or sys.maxsize <= 2**32:
        state.update(state='unavailable',gaps=['requires_windows_x64']);persist();return state

    from transpect_trace.observe.windows import identity, Profile
    from transpect_trace.observe.ecapture import ECaptureCollector, verify_build
    from transpect_trace.observe.pipeline import Pipeline
    from transpect_trace.observe.policy import ObservationPolicy
    from transpect_trace.protect.detection import ContentIndex
    from ..native import NativeIOCollector
    from ..etw import MultiApplicationETWCollector, summarize_coverage
    from ..origin import Origin
    from ..evidence import FlowEvidence
    from .evidence import AgentEvidence
    origin = etw = ecapture = pipeline = flow = agents = None
    fixtures, collectors, subjects = {}, {}, {}
    evidence_lock = threading.RLock()
    phase = 'baseline'
    def safely(reason, action, fallback=None):
        try:
            return action()
        except Exception:
            state['gaps'].append(reason)
            return fallback
    try:
        state['controller'] = {k:v for k,v in identity(os.getpid()).items() if k != 'image_path'}
        build = verify_build(paths['ecapture'])
        if build.get('variant') != 'enhanced' or build.get('protocol') != 'ECW2':
            raise ValueError('enhanced_ecapture_required')
        index = ContentIndex.model_validate_json(paths['content_index'].read_bytes())
        phase = 'origin'
        options = {'response_statuses':(503,200)} if experiment and experiment.mode == 'retry_after_503' else {}
        origin = Origin(paths['certificate'],paths['private_key'],**options).start()
        handoff = rf'\\.\pipe\TranspectFlowBusiness-{session_id}'
        phase = 'agents'
        common = [str(paths['python']),'-I','-S','-B',str(paths['participant']),'--task-id',task_id,'--handoff',handoff]
        fixtures['A'] = AgentFixture([*common,'--role','A','--source',str(paths['source']),
                                      '--message-id',message_id,*(['--handoff-public'] if manifest.handoff_public else []),
                                      *(experiment.arguments('A') if experiment else [])],output,'A')
        fixtures['B'] = AgentFixture([*common,'--role','B','--url',origin.url,'--transform',manifest.transform,
                                      *(experiment.arguments('B') if experiment else [])],output,'B')
        for role, fixture in fixtures.items():
            ready = fixture.wait('ready')
            if ready.get('pid') != fixture.process.pid or ready.get('source_access_started') is not False:
                raise ValueError('fixture_not_idle_or_identity_mismatch')
            subject = identity(fixture.process.pid)
            if subject['image_sha256'] != manifest.python.sha256:
                raise ValueError('actual_interpreter_mismatch')
            subjects[role] = subject
        state['subjects'] = [{k:v for k,v in s.items() if k != 'image_path'} | {'role':r} for r,s in subjects.items()]
        state['membership'] = 'explicit_independent_agents_not_parent_child'
        agents = AgentEvidence(session_id, state['subjects'], task_id, index=index)
        flow = FlowEvidence(session_id,state['subjects'],index=index,directory=output,transfer_sink=agents.consume_transfer)
        flow.session.scenario = 'pipe'
        flow.session.build_identities = state['baseline']
        flow.session.started_at_utc = state['started_at_utc']
        def native_event(row):
            with evidence_lock: flow.consume_native(row)
        def body_event(event, body, observation_id):
            with evidence_lock:
                count = len(flow.outbound)
                flow.consume_body(event,body,observation_id)
                if len(flow.outbound) == count+1:
                    agents.consume_outbound(flow.outbound[-1],body.data)
                else:
                    flow.gap('agent_outbound_snapshot_not_registered')
        scopes = [{'role':'source','path':str(paths['source'])},{'role':'pipe','path':handoff}]
        phase = 'native_io'
        for role, subject in subjects.items():
            collectors[role] = NativeIOCollector(subject,paths['observer'],paths['native_manifest'],native_event,scopes=scopes)
            collectors[role].start()
        phase = 'etw'
        members = [{k:v for k,v in subject.items() if k != 'image_path'} | {'image_name':Path(subject['image_path']).name}
                   for subject in subjects.values()]
        etw = MultiApplicationETWCollector(members,paths['etw'],output/'etw',run_id=session_id,
                                           duration=min(300,manifest.timeout_seconds+90),manifest=paths['native_manifest'])
        if etw.start()['state'] != 'ready': raise RuntimeError('etw_not_ready')
        phase = 'ecapture'
        pipeline = Pipeline(output/'observe',ObservationPolicy(),body_sink=body_event)
        ecapture = ECaptureCollector(subjects['B'],Profile(image_sha256=manifest.python.sha256,
                                       application='test-agent-b-winhttp',mode='schannel'),paths['ecapture'],pipeline)
        ecapture.start()
        def healthy():
            ecapture.check_health()
            eh = getattr(ecapture, 'structured', None)
            if not eh or not eh.ready or eh.terminal or eh.lost:
                raise RuntimeError('ecapture_incomplete')
            th = etw.index.health()
            if (etw.process.poll() is not None or th['state'] != 'ready'
                    or th['events_lost'] or th['gaps']):
                raise RuntimeError('etw_stopped')
            for collector in collectors.values():
                nh = collector.status()
                if not nh['ready'] or nh['terminal'] or nh['errors'] or nh['lost_events']:
                    raise RuntimeError('native_io_failed')
        healthy()
        if _start_barrier is not None:
            _start_barrier.wait(timeout=20)
            healthy()
        phase = 'workflow'
        state.update(state='observing',data_released=True,released_at_utc=datetime.now(timezone.utc).isoformat());persist()
        rounds = experiment.rounds if experiment else 1
        attempts = experiment.attempts if experiment else 1
        for turn in range(rounds):
            fixtures['B'].send('release' if turn == 0 else 'next')
            fixtures['B'].wait('pipe_ready',manifest.timeout_seconds,healthy)
            fixtures['A'].send('release' if turn == 0 else 'next')
            fixtures['A'].wait('transfer_complete',manifest.timeout_seconds,healthy)
            if experiment and experiment.mode in ('ecapture_exit','etw_exit','native_io_stop'):
                fixtures['B'].wait('upload_paused',manifest.timeout_seconds,healthy)
                # Stop the actual collector after a real HTTP prefix was sent.
                # This deliberately continues an observe-only fixture transfer.
                phase = 'fault_injection'
                if experiment.mode == 'ecapture_exit': ecapture.close()
                elif experiment.mode == 'etw_exit': state['etw_injected_stop'] = etw.stop()
                else: collectors['B'].close()
                state['gaps'].append('qualification_collector_stopped_during_upload')
                state['fault_injection'] = {'collector':experiment.mode,'phase':'http_body_prefix_sent',
                                            'action':'request_stop_and_wait','can_enforce':False}
                metadata = output/'observe'/'capture-metadata.jsonl'
                prefix = [json.loads(line) for line in metadata.read_text().splitlines()] if metadata.is_file() else []
                state['fault_injection']['observed_tls_send_bytes_at_stop'] = sum(
                    row.get('captured_bytes',0) for row in prefix if row.get('direction') == 'send')
                state['fault_injection']['origin_receipts_at_stop'] = len(origin.receipts)
                state['state'] = 'partial'; persist()
                fixtures['B'].send('continue_upload')
                fixtures['B'].wait('sent',manifest.timeout_seconds)
            else:
                for attempt in range(attempts):
                    expected = 'attempt_failed' if experiment and experiment.mode == 'retry_after_503' and attempt == 0 else 'sent'
                    fixtures['B'].wait(expected,manifest.timeout_seconds,healthy)
        state['client_send_completed'] = True
        state['workflow_completed_at_utc'] = datetime.now(timezone.utc).isoformat()
    except Exception as error:
        state['gaps'].append(f'{phase}_{type(error).__name__}')
        state['failure_phase'] = phase
        state['failure_frames'] = [{'file':Path(f.filename).name,'line':f.lineno,'function':f.name}
                                   for f in traceback.extract_tb(error.__traceback__)]
    finally:
        if ecapture:
            try: ecapture.close()
            except Exception: state['gaps'].append('ecapture_close_failed')
            from ..ecapture_diagnostics import snapshot
            build = getattr(ecapture,'_verified_manifest',{})
            state['ecapture_diagnostics'] = safely('ecapture_diagnostics_failed',
                lambda: snapshot(subjects['B'],paths['ecapture'].parent/'schannel_hook.dll',
                                 build.get('artifacts_sha256',{}).get('schannel_hook.dll')),
                {'state':'unavailable','can_enforce':False})
        for role, collector in collectors.items():
            try: collector.close()
            except Exception: state['gaps'].append(f'native_io_{role}_close_failed')
        for role, fixture in fixtures.items():
            try: fixture.close()
            except Exception: state['gaps'].append(f'fixture_{role}_cleanup_failed')
            state['fixture_exit_codes'][role] = safely(f'fixture_{role}_status_failed', fixture.process.poll)
            if state['data_released'] and state['fixture_exit_codes'][role] != 0: state['gaps'].append(f'fixture_{role}_nonzero_exit')
            safely(f'fixture_{role}_audit_failed', lambda:
                (output/f'fixture-{role}.json').write_text(json.dumps(fixture.events,indent=2)+'\n',encoding='utf-8'))
        if etw:
            try: state['etw_health'] = etw.stop()
            except Exception: state['gaps'].append('etw_stop_failed')
        if origin:
            try: origin.close()
            except Exception: state['gaps'].append('origin_close_failed')
        def finalize():
            for role, collector in collectors.items():
                h = safely(f'native_io_{role}_health_failed', collector.status,
                    {'ready':False,'terminal':False,'lost_events':0,'errors':['health_unavailable']})
                flow.health('native-io:'+role,ready=h['ready'],terminal=h['terminal'],identity_verified=h['ready'],
                            lost_events=h['lost_events'],errors=len(h['errors']),limitations=h['errors'])
            if etw:
                h = safely('etw_health_failed', etw.index.health,
                    {'ready_observed':False,'terminal_observed':False,'events_lost':0,'gaps':['health_unavailable']})
                flow.health('etw',ready=h['ready_observed'],terminal=h['terminal_observed'],identity_verified=h['ready_observed'],
                            lost_events=h['events_lost'],limitations=h['gaps'])
                coverage = safely('etw_coverage_failed', lambda: summarize_coverage(etw.index,subjects,'pipe',
                    destination_port=origin.server.server_port if origin else None),
                    {'actual_event_count':0,'gaps':['etw_coverage_unavailable']})
                state['etw_coverage'] = coverage
                state['etw_event_count'] = coverage['actual_event_count']
                for gap in coverage['gaps']: flow.gap(gap)
            if ecapture:
                h = getattr(ecapture,'structured',None)
                flow.health('ecapture',ready=bool(h and h.ready),terminal=bool(h and h.terminal),identity_verified=bool(h and h.ready),
                            lost_events=h.lost if h else 0,errors=len(ecapture.errors),limitations=ecapture.errors)
            if pipeline:
                try: pipeline.finish()
                except Exception: state['gaps'].append('observe_finalize_failed')
                for gap in pipeline.gaps: flow.gap(gap['reason'])
            if origin:
                for r in origin.receipts: flow.add_receipt(r['body_sha256'],r['body_bytes'],r['receipt_id'])
                for gap in origin.errors: flow.gap(gap)
                if experiment:
                    state['origin_response_statuses'] = [r.get('response_status',200) for r in origin.receipts]
            for gap in state['gaps']: flow.gap(gap)
            flow.session.ended_at_utc = datetime.now(timezone.utc).isoformat()
            result = flow.finish()
            agent_result = agents.finish(result,fixture_truth=[e for f in fixtures.values() for e in f.events])
            (output/'agent-evidence.json').write_text(json.dumps(agent_result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            state['flow_state'] = result['session']['status']
            state['state'] = agent_result['session']['status']
            state['coverage_gaps'] = agent_result.get('coverage_gaps',[])
            return True
        if flow:
            if not safely('evidence_finalize_failed', finalize, False):
                state['state'] = 'partial'
                state['coverage_gaps'] = [*state.get('coverage_gaps',[]),'evidence_finalize_failed']
        else:
            state['state'] = 'unavailable'
        if not state['data_released']: state['state'] = 'unavailable'
        state['ended_at_utc'] = datetime.now(timezone.utc).isoformat()
        persist()
    return state
