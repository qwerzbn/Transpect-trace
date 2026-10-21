"""Run isolated business suites and export independent capability matrices."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT,enter_repository
from transpect_trace.guard import BINARY_SHA256


def read(path):return json.loads(path.read_text(encoding='utf-8'))


def capture_complete(directory,row):
    health=row.get('capture',{})
    capture_root=directory if (directory/'capture').is_dir() else directory/'guard'
    metadata=capture_root/'capture/request-snapshots.jsonl'
    audit=capture_root/'audit.jsonl'
    if (health.get('state')!='stopped' or not health.get('terminal_health') or
            health.get('dropped_snapshots',1) or health.get('errors') or not metadata.is_file()):return False
    try:
        frames=[json.loads(line) for line in metadata.read_text(encoding='utf-8').splitlines()]
        decisions=[json.loads(line) for line in audit.read_text(encoding='utf-8').splitlines()]
    except (ValueError,OSError):return False
    if not frames or any(r.get('completeness')!='complete' or r.get('boundary_evidence')!='versioned_immutable_request_snapshot' for r in frames):return False
    decisions=[r for r in decisions if r.get('kind')=='policy.decision']
    if not decisions or len(frames)!=health.get('observed_requests') or len({r.get('request_id') for r in frames})!=len(frames):return False
    expected={(r.get('request_id'),r.get('content_sha256'),r.get('content_bytes')) for r in decisions}
    captured={(r.get('request_id'),r.get('payload_sha256'),r.get('payload_bytes')) for r in frames}
    if expected!=captured or any(not request or not digest or not size for request,digest,size in expected):return False
    receipts=row.get('source_receipts',[])
    # Existing exec fixture metadata remains readable without rewriting it.
    if not receipts and (directory/'summary.json').is_file():
        try:receipts=read(directory/'summary.json').get('origin_connections',[])
        except (ValueError,OSError):return False
    source_hashes={r.get('payload_sha256') for r in receipts if r.get('payload_bytes',0)>0}
    allowed_hashes={r.get('content_sha256') for r in decisions if r.get('decision')=='allow'}
    return bool(source_hashes) and None not in source_hashes and source_hashes<=allowed_hashes


def report(root,evidence_directories=None):
    from probe_codex_business_content import CASES
    visibility=[];detection=[];control=[];sources=[];gaps=[]
    evidence_directories=evidence_directories or {}
    def case_rows(name):
        directories=evidence_directories.get(name,root/name)
        if not isinstance(directories,list):directories=[directories]
        result=[]
        for directory in directories:
            path=Path(directory)/'summary.json'
            if not path.is_file():gaps.append({'stage':name,'reason':'summary_unavailable'});continue
            result.extend((row,path) for row in read(path).get('cases',[]))
        return result
    for name in ('exec','tui'):
        rows=case_rows(name)
        expected={(case,protocol) for case in ([*CASES] if name=='exec' else ['ordinary_prompt',*CASES]) for protocol in ('http','wss')}
        observed=[(r['case'],r['protocol']) for r,_ in rows]
        if set(observed)!=expected or len(observed)!=len(expected):gaps.append({'stage':name,'reason':'required_cases_missing_or_duplicated'})
        for row,path in rows:
            case,protocol=row['case'],row['protocol']
            passed=row.get('passed',row.get('experiment_valid',False) and row.get('expected_outcome_met',False))
            complete=capture_complete(path.parent/f'{case}-{protocol}',row)
            expected_action,expected_rule=CASES.get(case,('allow','negative_control'))
            rule_ids=sorted(set(row.get('policy_hits',row.get('policy_rule_ids',[]))))
            visibility.append({'mode':name,'case':case,'protocol':protocol,'status':'complete' if complete else 'unknown',
                'capture_layer':'request-body','tls_plaintext_certified':False})
            detection.append({'mode':name,'case':case,'protocol':protocol,
                'result':'confirmed_match' if rule_ids else 'no_match' if passed else 'unknown',
                'matched_rule_ids':rule_ids,'expected_action':expected_action,
                'passed':bool(passed and (expected_rule in rule_ids if expected_action=='deny' else not rule_ids)),
                'no_match_means_safe':False,'evidence':str(path.resolve())})
            control.append({'mode':name,'case':case,'protocol':protocol,'passed':bool(passed),
                'actual_blocked':bool(row.get('actual_blocked')),'expected_action':expected_action,
                'evidence':str(path.resolve())})
            sources.append({'mode':name,'case':case,'confidence':'Unknown','reason':'content_test_does_not_certify_ETW_provenance'})
    for action in ('allow','block'):
        rows=case_rows(f'tools-{action}')
        if {r['case'] for r,_ in rows}!={'git','curl','python','scp'} or len(rows)!=4:gaps.append({'stage':f'tools-{action}','reason':'required_cases_missing_or_duplicated'})
        for row,path in rows:
            control.append({'mode':'exec-tools','case':row['case'],'target_action':action,
                'passed':bool(row.get('experiment_valid') and (row.get('tool_egress_blocked') if action=='block' else row.get('received_exact_file'))),
                'actual_blocked':bool(row.get('tool_egress_blocked')),'executor':'native-descendant-gate',
                'wfp_pid_isolation':False,'evidence':str(path.resolve())})
    return {'schema':'transpect.codex.scenario-suite/1.0','content_visibility':visibility,'content_detection':detection,'control':control,'source_evidence':sources,
        'gaps':gaps,'required_control_cases_passed':bool(control) and not gaps and all(r['passed'] for r in control),
        'required_visibility_cases_passed':len(visibility)==4*len(CASES)+2 and all(r['status']=='complete' for r in visibility),
        'required_detection_cases_passed':len(detection)==4*len(CASES)+2 and all(r['passed'] for r in detection),
        'whole_stage_complete':False,'completion_limitations':['Default-trust TLS requires separate authenticated capture evidence',
            'ETW and WFP runtime health require separate elevated experiments','Request-layer adapters are not TLS backend certification']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--codex',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--sftp-python',type=Path)
    p.add_argument('--manifest',type=Path,help='Report-only mapping to preserved evidence directories, relative to this JSON file.')
    p.add_argument('--report-only',action='store_true');args=p.parse_args();enter_repository()
    binary=args.codex.resolve();root=args.output.resolve()
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=BINARY_SHA256:p.error('fixed official baseline mismatch')
    evidence=None
    if args.manifest:
        if not args.report_only:p.error('--manifest requires --report-only')
        manifest=args.manifest.resolve();raw=read(manifest)
        if not isinstance(raw,dict) or set(raw)-{'exec','tui','tools-allow','tools-block'}:p.error('Invalid scenario evidence manifest')
        evidence={}
        for key,value in raw.items():
            values=value if isinstance(value,list) else [value]
            if not values or not all(isinstance(v,str) and v for v in values):p.error('Invalid evidence paths')
            evidence[key]=[(manifest.parent/v).resolve() for v in values]
    if not args.report_only:
        if args.sftp_python is None:p.error('--sftp-python requires an isolated test-source interpreter')
        root.mkdir(parents=True,exist_ok=False)
        jobs=[('exec','probe_codex_business_content.py',[]),('tui','probe_codex_tui.py',[]),
              ('tools-allow','probe_codex_business_uploads.py',['--egress-action','allow']),
              ('tools-block','probe_codex_business_uploads.py',['--egress-action','block'])]
        for name,script,extra in jobs:
            command=[sys.executable,str(ROOT/'scripts'/script),'--codex',str(binary),'--output',str(root/name),*extra]
            if name.startswith('tools-'):command+=['--sftp-python',str(args.sftp_python.resolve())]
            with (root/f'{name}.log').open('wb') as log:
                result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,cwd=ROOT)
            print(json.dumps({'suite':name,'exit_code':result.returncode}),flush=True)
    result=report(root,evidence);root.mkdir(parents=True,exist_ok=True)
    with (root/'capabilities.json').open('x',encoding='utf-8') as stream:stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'control_cases':len(result['control']),'required_control_cases_passed':result['required_control_cases_passed'],
        'whole_stage_complete':result['whole_stage_complete']}))
    if not all(result[k] for k in ('required_control_cases_passed','required_visibility_cases_passed','required_detection_cases_passed')) or result['gaps']:raise SystemExit(1)

if __name__=='__main__':main()
