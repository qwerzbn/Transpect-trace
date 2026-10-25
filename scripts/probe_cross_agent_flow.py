"""Controlled two-test-Agent validation, not external LLM/framework certification.

Run in an administrator terminal. --prepare-test-trust explicitly leases a
localhost-only CurrentUser CA and removes that exact CA in finally. This script
does not elevate itself, build Native components or alter existing run folders.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT
from _local_test_trust import LocalTestTrust
from transpect_trace.flow.manifest import frozen
from transpect_trace.flow.agents.manifest import AgentFlowManifest, implementation_paths
from transpect_trace.flow.agents.runtime import run
from transpect_trace.observe.elevation import is_elevated
from transpect_trace.protect.detection import ContentIndex

MARKER = 'AGENT_FLOW_TEST_CONFIDENTIAL_DOCUMENT_2026_fake_registration_content_only'
SECRET = 'agent_validation_fake_credential_a81c954e'
REGISTRATION = 'fake-agent-document'
CASES = {
    'copy_sensitive': ('copy', False, True, True),
    'nested_sensitive': ('nested', False, True, True),
    'extractive_sensitive': ('extractive', False, True, True),
    'a_public': ('copy', True, False, False),
    'b_public': ('public', False, True, False),
}


def prepare_manifest(folder, name, *, source, index, certificate, private_key,
                     transform, handoff_public, python, native_dir, ecapture_dir):
    paths = dict(python=python, participant=implementation_paths()['agents/participant.py'],
                 observer=native_dir/'ttrace-flow-io.dll', etw=native_dir/'flow_etw.exe',
                 native_manifest=native_dir/'native-build.json', ecapture=ecapture_dir/'ecapture.exe',
                 ecapture_manifest=ecapture_dir/'ecapture-build.json', source=source, content_index=index,
                 certificate=certificate, private_key=private_key)
    manifest = AgentFlowManifest(fake_data_only=True, output=folder/name/'audit',
        transform=transform, handoff_public=handoff_public,
        implementation={name:frozen(path) for name,path in implementation_paths().items()},
        **{name:frozen(path) for name,path in paths.items()})
    manifest.resolve(folder)
    path = folder/(name+'.manifest.json')
    path.write_text(manifest.model_dump_json(indent=2)+'\n', encoding='utf-8')
    return path


def privacy_scan(directory, *, skip_fake_inputs=False):
    failures, unreadable, count = [], [], 0
    needles = [value.encode(encoding) for value in (SECRET, MARKER) for encoding in ('utf-8','utf-16-le','utf-16-be')]
    for path in directory.rglob('*'):
        relative = path.relative_to(directory)
        if skip_fake_inputs and relative.parts[0] == 'explicit-fake-inputs':
            continue
        if path.is_symlink():
            unreadable.append(relative.as_posix())
            continue
        if not path.is_file():
            continue
        count += 1
        try:
            data = path.read_bytes()
        except OSError:
            unreadable.append(relative.as_posix())
            continue
        if any(needle in data for needle in needles):
            failures.append(relative.as_posix())
    return {'passed': not (failures or unreadable), 'files_scanned':count,
            'files_with_test_secret':failures, 'unreadable_or_linked_files':unreadable,
            'excluded_fake_inputs':skip_fake_inputs}


def _findings_match(rows, sensitive):
    if len(rows) != 1:
        return False
    row, findings = rows[0], rows[0].get('findings', [])
    if not sensitive:
        return row.get('detection_status') == 'no_match' and not findings
    return (row.get('detection_status') == 'matched'
            and any(f.get('registration_id') == REGISTRATION for f in findings)
            and any('credential' in f.get('data_types', []) for f in findings))


def evaluate_case(name, result, audit, *, message_sensitive, outbound_sensitive):
    def read_json(filename):
        path = audit/filename
        return json.loads(path.read_bytes()) if path.is_file() else {}
    flow, agents = read_json('flow-evidence.json'), read_json('agent-evidence.json')
    observations = agents.get('observations', [])
    stages = {stage:[r for r in observations if r.get('stage') == stage]
              for stage in ('source_read','message_write','message_read','outbound')}
    outbound = flow.get('content_detection', {}).get('outbound', [])
    receipts = flow.get('origin_receipts', {}).get('receipts', [])
    actual_tls = [r for r in outbound if r.get('provider') == 'ecapture-windows'
                  and r.get('capture_layer') == 'tls' and r.get('completeness') == 'complete'
                  and r.get('encoding_state') == 'identity' and r.get('send_evidence') == 'encryption_input_observed']
    captured = Counter((r.get('decoded_body_sha256'),r.get('body_bytes')) for r in actual_tls)
    received = Counter((r.get('body_sha256'),r.get('body_bytes')) for r in receipts
                       if r.get('evidence_source') == 'controlled_origin')
    semantic = Counter((r.get('body_sha256'),r.get('body_bytes')) for r in stages['outbound'])
    subjects = agents.get('session', {}).get('subjects', [])
    health = flow.get('session', {}).get('health', {})
    collector_names = ('native-io:A','native-io:B','etw','ecapture')
    healthy = all(h.get('ready') is True and h.get('terminal') is True and h.get('identity_verified') is True
                  and h.get('lost_events') == 0 and h.get('errors') == 0 and not h.get('limitations')
                  for key in collector_names for h in [health.get(key,{})])
    relations = agents.get('relations', [])
    privacy = privacy_scan(audit)
    checks = {
        'runtime_complete':result.get('state') == 'complete' and result.get('client_send_completed') is True,
        'agent_session_complete':agents.get('session', {}).get('status') == 'complete' and not agents.get('coverage_gaps'),
        'base_flow_complete':flow.get('session', {}).get('status') == 'complete' and flow.get('collection_coverage', {}).get('complete') is True,
        'same_interpreter_distinct_processes':len(subjects) == 2 and {s.get('role') for s in subjects} == {'A','B'}
            and len({s.get('pid') for s in subjects}) == 2 and all(s.get('creation_filetime',0) > 0 for s in subjects)
            and len({s.get('image_sha256') for s in subjects}) == 1
            and all(s.get('image_sha256') == result.get('baseline', {}).get('python') for s in subjects),
        'collectors_healthy':healthy,
        'real_etw_coverage':result.get('etw_event_count',0) > 0 and bool(result.get('etw_coverage'))
            and not result.get('etw_coverage', {}).get('gaps'),
        'exact_stage_counts':all(len(rows) == 1 for rows in stages.values()),
        'actual_tls_origin_count_and_hash':sum(captured.values()) == sum(received.values()) == 1
            and len(actual_tls) == len(outbound) == len(receipts) == 1 and captured == received == semantic,
        'source_sensitive':_findings_match(stages['source_read'],True),
        'message_write_expected':_findings_match(stages['message_write'],message_sensitive),
        'message_read_expected':_findings_match(stages['message_read'],message_sensitive),
        'outbound_expected':_findings_match(stages['outbound'],outbound_sensitive)
            and _findings_match(outbound,outbound_sensitive),
        'observed_handoff':any(r.get('relation_kind') == 'agent_message_handoff'
                              and r.get('confidence') in {'High','Medium'} for r in relations),
        'parent_reference_observed':any(r.get('relation_kind') == 'protocol_parent_reference'
                                and r.get('confidence') in {'High','Medium'} for r in relations),
        'observe_only':result.get('can_enforce') is False and agents.get('can_enforce') is False
            and flow.get('can_enforce') is False and agents.get('blocked_requests') == flow.get('blocked_requests') == 0,
        'privacy':privacy['passed'],
    }
    gaps = sorted(set([*result.get('gaps',[]), *result.get('coverage_gaps',[]),
                       *flow.get('coverage_gaps',[]), *agents.get('coverage_gaps',[]),
                       *('probe_check_failed:'+key for key,ok in checks.items() if not ok)]))
    return {'case':name, 'state':result.get('state','unavailable'), 'passed':all(checks.values()),
            'expectations':{'source_sensitive':True,'message_sensitive':message_sensitive,'outbound_sensitive':outbound_sensitive},
            'checks':checks,'gaps':gaps,'privacy':privacy,'collector_health':health,
            'stage_counts':{stage:len(rows) for stage,rows in stages.items()},
            'etw_event_count':result.get('etw_event_count',0),
            'tls_request_count':sum(captured.values()),'origin_receipt_count':sum(received.values()),
            'final_findings':[f for row in stages['outbound'] for f in row.get('findings',[])],
            'relation_counts':dict(Counter(r.get('relation_kind') for r in relations)),
            'evidence_path':name+'/audit/agent-evidence.json','base_evidence_path':name+'/audit/flow-evidence.json',
            'can_enforce':False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--prepare-test-trust', action='store_true')
    parser.add_argument('--certificate', type=Path)
    parser.add_argument('--private-key', type=Path)
    parser.add_argument('--python', type=Path, default=Path(sys._base_executable))
    parser.add_argument('--native-dir', type=Path, default=ROOT/'build/flow')
    parser.add_argument('--ecapture-dir', type=Path, default=ROOT/'build/flow-ecapture-v2')
    parser.add_argument('--repeat', type=int, choices=range(1,11), default=3)
    parser.add_argument('--case', choices=list(CASES))
    args = parser.parse_args(argv)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    labels = [args.case] if args.case else list(CASES)
    summary = {'schema_version':'transpect.agent-flow.probe/1.0','state':'initializing',
        'agent_kind':'deterministic_test_agent','can_enforce':False,'certified':False,'cases':[],
        'expected_case_count':len(labels)*args.repeat,'repeat':args.repeat,
        'started_at_utc':datetime.now(timezone.utc).isoformat(),
        'certificate_cleanup':{'owned':False,'required':False,'confirmed':None}}
    def save():
        temporary = output/'summary.tmp'
        temporary.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        temporary.replace(output/'summary.json')
    save()
    if not is_elevated():
        summary.update(state='unavailable',reason='administrator_token_required')
        save()
        return 2
    lease = None
    try:
        if args.prepare_test_trust and (args.certificate or args.private_key):
            raise ValueError('conflicting_certificate_modes')
        if args.prepare_test_trust:
            def command(arguments):
                return subprocess.run(arguments,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    timeout=180,creationflags=0x08000000,check=False)
            lease = LocalTestTrust(output/'test-trust',command_runner=command).prepare()
            summary.update(state='waiting_test_trust',certificate_cleanup={'owned':True,'required':True,'confirmed':False})
            save()
            lease.install()
            certificate, private_key = lease.certificate,lease.private_key
        else:
            if not args.certificate or not args.private_key:
                raise ValueError('pretrusted_localhost_certificate_required')
            certificate,private_key = args.certificate.resolve(),args.private_key.resolve()
        inputs = output/'explicit-fake-inputs'
        inputs.mkdir()
        index = ContentIndex.register('agent-fixtures-v1',[(REGISTRATION,MARKER,'CONFIDENTIAL',['registered_text'])])
        index_path = inputs/'content-index.json'
        index_path.write_text(index.model_dump_json(indent=2)+'\n',encoding='utf-8')
        for trial in range(1,args.repeat+1):
            for label in labels:
                transform,handoff_public,message_sensitive,outbound_sensitive = CASES[label]
                name = f'{label}-r{trial:02d}'
                source = inputs/(name+'.json')
                source.write_text(json.dumps({'public_text':'普通的受控测试报告','api_key':SECRET,'document':MARKER,
                                              'irrelevant':'背景字段不属于查询结果'},ensure_ascii=False)+'\n',encoding='utf-8')
                summary.update(state='running',active_case=name);save()
                try:
                    manifest = prepare_manifest(output,name,source=source,index=index_path,certificate=certificate,
                        private_key=private_key,transform=transform,handoff_public=handoff_public,
                        python=args.python.resolve(),native_dir=args.native_dir.resolve(),ecapture_dir=args.ecapture_dir.resolve())
                    result = run(manifest)
                    case = evaluate_case(name,result,output/name/'audit',message_sensitive=message_sensitive,
                                         outbound_sensitive=outbound_sensitive)
                except Exception as error:
                    case = {'case':name,'state':'unavailable','passed':False,'error_type':type(error).__name__,
                            'gaps':['probe_case_did_not_complete'],'can_enforce':False}
                summary['cases'].append(case)
                save()
        summary['state'] = 'passed' if (len(summary['cases']) == summary['expected_case_count']
            and all(case['passed'] for case in summary['cases'])) else 'partial'
    except Exception as error:
        summary.update(state='unavailable',error_type=type(error).__name__)
    finally:
        if lease:
            try:
                confirmed = bool(lease.cleanup()['cleanup_confirmed'])
            except Exception:
                confirmed = False
            summary['certificate_cleanup'].update(owned=True,required=True,confirmed=confirmed)
            summary['test_trust_cleanup_confirmed'] = confirmed
            if not confirmed:
                summary.update(state='partial',cleanup_gap='test_trust_cleanup_unconfirmed')
        summary.pop('active_case',None)
        summary['passed_case_count'] = sum(case.get('passed',False) for case in summary['cases'])
        summary['ended_at_utc'] = datetime.now(timezone.utc).isoformat()
        summary['privacy'] = privacy_scan(output,skip_fake_inputs=True)
        if not summary['privacy']['passed']:
            summary.update(state='partial',privacy_gap='default_artifacts_failed_secret_scan')
        save()
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return 0 if summary['state'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
