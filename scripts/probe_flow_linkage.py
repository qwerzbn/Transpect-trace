"""Complex controlled Flow qualification, including expected evidence degradation.

Run as administrator with fake inputs and a leased localhost test trust. No
protection is enabled. A partial flow can be the correct outcome of a case;
acceptance and collection completeness are deliberately separate.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import threading
import re

from _build_support import ROOT
from _local_test_trust import LocalTestTrust
from probe_cross_agent_flow import prepare_manifest, privacy_scan, MARKER, SECRET, REGISTRATION
from transpect_trace.flow.agents.linkage import LinkageExperiment, MODES, FAULTS
from transpect_trace.flow.agents.runtime import run
from transpect_trace.observe.elevation import is_elevated
from transpect_trace.protect.detection import ContentIndex


def load(path):
    return json.loads(path.read_bytes()) if path.is_file() else {}


def assess(mode, state, audit):
    flow, agent = load(audit/'flow-evidence.json'), load(audit/'agent-evidence.json')
    rows = agent.get('observations',[])
    groups = {k:[r for r in rows if r.get('stage')==k] for k in ('source_read','message_write','message_read','outbound')}
    tls = flow.get('content_detection',{}).get('outbound',[])
    receipts = flow.get('origin_receipts',{}).get('receipts',[])
    relations = [*agent.get('relations',[]),*flow.get('propagation',{}).get('relations',[])]
    spec = LinkageExperiment(mode) if mode in MODES else None
    rounds, attempts = (spec.rounds,spec.attempts) if spec else (1,1)
    expected = rounds*attempts
    verified_tls = [r for r in tls if r.get('completeness')=='complete' and r.get('provider')=='ecapture-windows'
                    and r.get('capture_layer')=='tls' and r.get('encoding_state')=='identity'
                    and r.get('send_evidence')=='encryption_input_observed']
    captured = Counter((r.get('decoded_body_sha256'),r.get('body_bytes')) for r in verified_tls)
    received = Counter((r.get('body_sha256'),r.get('body_bytes')) for r in receipts)
    fault = mode in FAULTS
    complete_expected = not spec or spec.expects_complete
    subjects = state.get('subjects',[])
    expected_public = mode in ('conflicting_message','concurrent_public')
    final = groups['outbound']
    health=flow.get('session',{}).get('health',{})
    healthy=all(h.get('ready') is True and h.get('terminal') is True and h.get('identity_verified') is True
                and h.get('lost_events')==0 and h.get('errors')==0 and not h.get('limitations')
                for name in ('native-io:A','native-io:B','etw','ecapture') for h in [health.get(name,{})])
    checks = {
        'workflow_completed':state.get('client_send_completed') is True and all(c==0 for c in state.get('fixture_exit_codes',{}).values())
            and len(state.get('fixture_exit_codes',{}))==2,
        'identities_distinct':len(subjects)==2 and len({(s['pid'],s['creation_filetime']) for s in subjects})==2,
        'observe_only':state.get('can_enforce') is False and agent.get('can_enforce') is False and flow.get('can_enforce') is False
            and agent.get('blocked_requests')==0 and flow.get('blocked_requests')==0,
        'origin_attempt_count':len(receipts)==expected,
        'receipts_well_formed':len(receipts)==expected and all(r.get('evidence_source')=='controlled_origin'
            and isinstance(r.get('body_sha256'),str) and re.fullmatch('[a-f0-9]{64}',r['body_sha256'])
            and type(r.get('body_bytes')) is int and 0<r['body_bytes']<=1024*1024 for r in receipts),
        'collector_health_accounted':healthy,
        'actual_etw_events':state.get('etw_event_count',0)>0 and bool(state.get('etw_coverage')) and not state.get('etw_coverage',{}).get('gaps'),
        'stages_retained':len(groups['source_read'])==1 and len(groups['message_write'])==rounds and len(groups['message_read'])==rounds,
        'no_request_deduplication':len(final)==(0 if mode=='ecapture_exit' else expected),
        'default_privacy':privacy_scan(audit)['passed'],
    }
    if complete_expected:
        checks['complete_evidence'] = state.get('state')=='complete' and agent.get('session',{}).get('status')=='complete'
        checks['counter_matches'] = captured==received and sum(captured.values())==expected
        checks['all_tls_rows_verified'] = len(verified_tls)==len(tls)==expected
        checks['no_coverage_gaps'] = not state.get('coverage_gaps') and not state.get('gaps')
    else:
        checks['expected_degradation'] = state.get('state')=='partial' and agent.get('session',{}).get('status')=='partial'
        checks['gaps_explicit'] = bool(agent.get('coverage_gaps'))
        agent_relations=agent.get('relations',[])
        checks['no_supported_relations_after_gap'] = bool(agent_relations) and all(r.get('confidence')=='Unknown' for r in agent_relations)
        if flow.get('session',{}).get('status')=='partial':
            base_relations=flow.get('propagation',{}).get('relations',[])
            checks['base_gap_relations_degraded'] = bool(base_relations) and all(r.get('confidence')=='Unknown' for r in base_relations)
        if mode!='ecapture_exit': checks['counter_matches'] = captured==received and sum(captured.values())==expected
    if mode=='ecapture_exit':
        checks['incomplete_tls_not_promoted'] = not tls and not flow.get('origin_receipts',{}).get('hash_multiset_matches')
    if fault:
        injection = state.get('fault_injection',{})
        path=audit/'observe/capture-metadata.jsonl'
        metadata=[json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.is_file() else []
        b=next((s for s in subjects if s.get('role')=='B'),{})
        actual_send_bytes=sum(r.get('captured_bytes',0) for r in metadata if r.get('direction')=='send'
            and r.get('provider')=='ecapture-windows' and r.get('capture_point')=='tls'
            and r.get('pid')==b.get('pid') and r.get('creation_filetime')==b.get('creation_filetime')
            and r.get('image_sha256')==b.get('image_sha256') and r.get('event')=='data'
            and r.get('truncated') is False and r.get('lost_events')==0
            and type(r.get('captured_bytes')) is int and r['captured_bytes']>0
            and isinstance(r.get('data_sha256'),str) and re.fullmatch('[a-f0-9]{64}',r['data_sha256']))
        checks['during_actual_upload'] = (injection.get('phase')=='http_body_prefix_sent'
            and 32768<injection.get('observed_tls_send_bytes_at_stop',0)<=actual_send_bytes
            and injection.get('origin_receipts_at_stop')==0 and all(r['body_bytes']>65536 for r in receipts))
    if mode=='retry_after_503': checks['real_503_then_200'] = state.get('origin_response_statuses')==[503,200]
    if expected_public:
        want_public = 1 if mode=='conflicting_message' else expected
        checks['no_sensitive_read_inheritance'] = sum(r.get('detection_status')=='no_match' and not r.get('findings') for r in final)==want_public
        if mode=='conflicting_message':
            checks['conflicting_sensitive_attempt_found'] = sum(r.get('detection_status')=='matched'
                and any(f.get('registration_id')==REGISTRATION for f in r.get('findings',[])) for r in final)==1
    elif mode!='ecapture_exit':
        checks['sensitive_content_found'] = all(any(f.get('registration_id')==REGISTRATION for f in r.get('findings',[])) for r in final)
    if mode=='duplicate_attempt':
        checks['duplicate_body_count_preserved'] = any(count>1 for count in received.values()) and len(final)==2
        checks['duplicate_attempt_gap'] = 'duplicate_protocol_attempt_identifier' in agent.get('coverage_gaps',[])
    if mode in ('duplicate_message','conflicting_message'):
        checks['ambiguous_message_id_gap'] = 'message_identifier_missing_or_ambiguous' in agent.get('coverage_gaps',[])
    if mode in ('reconnect_unique','duplicate_message','conflicting_message'):
        checks['actual_reconnect_gap'] = 'pipe_connection_mapping_ambiguous' in flow.get('coverage_gaps',[])
        checks['all_sends_present'] = len(verified_tls)==len(tls)==expected
    return {'mode':mode,'accepted':all(checks.values()),'collection_state':state.get('state'),'checks':checks,
        'gaps':agent.get('coverage_gaps',[]),'stage_counts':{k:len(v) for k,v in groups.items()},
        'origin_receipts':len(receipts),'tls_complete_requests':sum(captured.values()),
        'etw_actual_events':state.get('etw_event_count',0),'can_enforce':False}


def concurrent_isolation(states, results):
    # Runtime intervals overlap only after readiness and before teardown.
    intervals = [(datetime.fromisoformat(s['released_at_utc']),datetime.fromisoformat(s['workflow_completed_at_utc']))
                 for s in states if s.get('released_at_utc') and s.get('workflow_completed_at_utc')]
    ids = [s.get('task_id_sha256') for s in states]
    subjects = [(p['pid'],p['creation_filetime']) for s in states for p in s.get('subjects',[])]
    valid_ids=len(ids)==3 and all(isinstance(t,str) and re.fullmatch('[a-f0-9]{64}',t) for t in ids)
    return {'accepted':len(intervals)==3 and max(a for a,b in intervals)<min(b for a,b in intervals)
        and valid_ids and len(set(ids))==3 and len(subjects)==len(set(subjects))==6
        and len(results)==3 and all(r['accepted'] for r in results),
        'overlapping_observation_intervals':len(intervals)==3 and max(a for a,b in intervals)<min(b for a,b in intervals),
        'distinct_tasks':bool(valid_ids and len(set(ids))==3),'distinct_process_instances':len(subjects)==len(set(subjects))==6,
        'can_enforce':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--prepare-test-trust',action='store_true')
    parser.add_argument('--certificate',type=Path);parser.add_argument('--private-key',type=Path)
    parser.add_argument('--python',type=Path,default=Path(sys._base_executable))
    parser.add_argument('--ecapture-dir',type=Path,default=ROOT/'build/flow-ecapture-v2')
    parser.add_argument('--native-dir',type=Path,default=ROOT/'build/flow')
    parser.add_argument('--case',choices=[*MODES,'concurrent'])
    args=parser.parse_args(argv)
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    summary={'schema_version':'transpect.flow.linkage-qualification/1.0','state':'initializing','cases':[],
             'can_enforce':False,'certified':False,'started_at_utc':datetime.now(timezone.utc).isoformat()}
    def save():
        temp=output/'summary.tmp';temp.write_text(json.dumps(summary,indent=2)+'\n');temp.replace(output/'summary.json')
    save()
    if not is_elevated():
        summary.update(state='unavailable',reason='administrator_token_required');save();return 2
    lease=None
    try:
        if args.prepare_test_trust:
            def command(cmd):return subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,creationflags=0x08000000)
            lease=LocalTestTrust(output/'test-trust',command_runner=command).prepare()
            summary['state']='waiting_test_trust';save();lease.install()
            certificate,key=lease.certificate,lease.private_key
        else:
            if not args.certificate or not args.private_key:raise ValueError('trusted_test_certificate_required')
            certificate,key=args.certificate.resolve(),args.private_key.resolve()
        inputs=output/'explicit-fake-inputs';inputs.mkdir()
        index=inputs/'index.json'
        index.write_text(ContentIndex.register('linkage-v1',[(REGISTRATION,MARKER,'CONFIDENTIAL',['registered_text'])]).model_dump_json())
        def execute(name,mode,public=False):
            source=inputs/(name+'.json')
            source.write_text(json.dumps({'public_text':'普通文本'+('x'*131072 if mode in FAULTS else ''),'api_key':SECRET,'document':MARKER},ensure_ascii=False),encoding='utf-8')
            manifest=prepare_manifest(output,name,source=source,index=index,certificate=certificate,private_key=key,
                transform='public' if public else 'copy',handoff_public=False,python=args.python.resolve(),native_dir=args.native_dir.resolve(),ecapture_dir=args.ecapture_dir.resolve())
            state=run(manifest,experiment=mode if mode in MODES else None,_start_barrier=barrier if mode=='concurrent' else None)
            result=assess('concurrent_public' if public else mode,state,output/name/'audit')
            result['name']=name;result['evidence_path']=name+'/audit/agent-evidence.json'
            return state,result
        labels=[args.case] if args.case else ['concurrent',*MODES]
        for mode in labels:
            summary.update(state='running',active_case=mode);save()
            if mode=='concurrent':
                # Read-only content is shared; every session owns separate IPC,
                # ETW and eCapture targets. Equal content never merges sessions.
                barrier=threading.Barrier(3)
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures=[executor.submit(execute,f'concurrent-{i}','concurrent',i==2) for i in range(3)]
                    values=[f.result() for f in futures]
                states,results=zip(*values)
                summary['cases'].extend(results)
                summary['concurrency']=concurrent_isolation(states,results)
            else:
                _,result=execute(mode,mode);summary['cases'].append(result)
            save()
        summary['state']='accepted' if all(r['accepted'] for r in summary['cases']) and summary.get('concurrency',{'accepted':True})['accepted'] else 'partial'
    except Exception as error:
        summary.update(state='unavailable',error_type=type(error).__name__)
    finally:
        if lease:
            try:summary['test_trust_cleanup_confirmed']=bool(lease.cleanup()['cleanup_confirmed'])
            except Exception:summary['test_trust_cleanup_confirmed']=False
            if not summary['test_trust_cleanup_confirmed']:summary['state']='partial'
        summary.pop('active_case',None)
        summary['ended_at_utc']=datetime.now(timezone.utc).isoformat()
        summary['privacy']=privacy_scan(output,skip_fake_inputs=True)
        if not summary['privacy']['passed']:summary['state']='partial'
        summary['accepted_cases']=sum(r['accepted'] for r in summary['cases']);save()
    print(json.dumps({'state':summary['state'],'accepted_cases':summary['accepted_cases'],'can_enforce':False}))
    return 0 if summary['state']=='accepted' else 2


if __name__=='__main__':raise SystemExit(main())
