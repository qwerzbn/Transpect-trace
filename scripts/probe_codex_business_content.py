"""Business leakage fixtures against the unchanged fixed Native Guard and detector.

Only fake data. Negative detection results are coverage gaps, not passing protection.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from uuid import uuid4

from _build_support import ROOT
from probe_guard_native import experiment
from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.policy import GuardPolicy, PolicyEngine


def quote(value):
    return "'"+str(value).replace("'","''")+"'"


class EvidenceEngine(PolicyEngine):
    """Observe evidence in memory; delegate every decision to the original engine."""
    def __init__(self, policy, marker):
        super().__init__(policy)
        self.marker=marker
        self.observations=[]

    def evaluate(self, request):
        decision,audit=super().evaluate(request)
        if request.kind=='model.request':
            payload=json.loads(request.payload_utf8)
            tools=[x for x in payload.get('input',[]) if isinstance(x,dict) and x.get('type')=='function_call_output']
            self.observations.append(dict(request_id=request.request_id,protocol=request.protocol,
                content_sha256=hashlib.sha256(request.payload_utf8.encode()).hexdigest(),
                marker_in_request=self.marker in request.payload_utf8,
                marker_in_tool_result=any(self.marker in str(x.get('output','')) for x in tools),
                decision=decision.decision,action=decision.action,hits=audit.get('matched_rule_ids',[])))
        return decision,audit


class InternalAPI:
    def __init__(self, data):
        self.receipts=[];receipts=self.receipts
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path!='/fixture':
                    self.send_error(404);return
                body=json.dumps(data).encode()
                receipts.append(dict(response_bytes=len(body),response_sha256=hashlib.sha256(body).hexdigest()))
                self.send_response(200);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*_):pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3)


CASES = {
    'clean_log': ('allow', 'negative_control'),
    'log_password': ('deny', 'CONFIG_CREDENTIAL'),
    'log_bearer': ('allow', 'unrecognized_bearer_token'),
    'log_pii': ('allow', 'unregistered_personal_information'),
    'environment_secret': ('deny', 'CONFIG_CREDENTIAL'),
    'connection_uri': ('allow', 'unrecognized_connection_uri'),
    'registered_source': ('deny', 'REGISTERED_CONTENT'),
    'registered_document': ('deny', 'REGISTERED_CONTENT'),
    'registered_source_exact': ('deny', 'REGISTERED_CONTENT'),
    'registered_document_exact': ('deny', 'REGISTERED_CONTENT'),
    'unregistered_source': ('allow', 'registration_required'),
    'api_formatted_secret': ('deny', 'CONFIG_CREDENTIAL'),
    'api_json_secret': ('allow', 'json_encoded_tool_output'),
    'api_pii': ('allow', 'unregistered_personal_information'),
}


def fixture(case, holders):
    def make(workspace):
        marker='FAKE_ONLY_'+uuid4().hex
        policy=GuardPolicy(credential_rules=True)
        environment={}
        source=workspace/'fixture.txt'
        prompt='Inspect the isolated fake fixture with the supplied tool and explain the result.'
        command=f'Get-Content -LiteralPath {quote(source)}'
        if case=='clean_log':text=f'INFO synthetic test completed. request_id={marker}\n'
        elif case=='log_password':text=f'ERROR synthetic login failed: mysql_password={marker}\n'
        elif case=='log_bearer':text=f'ERROR fixture Authorization: Bearer {marker}\n'
        elif case=='log_pii':text=f'SYNTHETIC customer_id={marker} phone=13800000000 email=fixture@example.invalid\n'
        elif case=='environment_secret':
            text='';environment['TTRACE_FAKE_API_SECRET']=marker
            command="Write-Output ('api_secret=' + $env:TTRACE_FAKE_API_SECRET)"
        elif case=='connection_uri':text=f'database_url=postgresql://fixture:{marker}@127.0.0.1:5432/fixture\n'
        elif case in ('registered_source','registered_source_exact','unregistered_source'):
            text=f'# Synthetic proprietary module {marker}\ndef internal_discount(amount):\n    return amount * 0.731\n'
        elif case in ('registered_document','registered_document_exact'):text=f'企业内部假数据实验文档。登记编号：{marker}。\n本段用于验证已登记内容，不代表真实业务信息。\n'
        else:
            data={'api_secret':marker} if case!='api_pii' else {'customer_id':marker,'phone':'13800000000','email':'fixture@example.invalid'}
            api=InternalAPI(data);holders['api']=api
            url=f'http://127.0.0.1:{api.server.server_port}/fixture'
            code='import urllib.request,json; data=json.loads(urllib.request.urlopen('+repr(url)+',timeout=5).read()); '
            code += "print('api_secret='+data['api_secret'])" if case=='api_formatted_secret' else 'print(json.dumps(data))'
            command=f'& {quote(Path(sys.base_prefix)/"python.exe")} -I -c {quote(code)}'
            text=''
        if text:
            source.write_text(text,encoding='utf-8')
        if case in ('registered_source','registered_document','registered_source_exact','registered_document_exact'):
            policy.registered_files=[source]
        if case in ('registered_source_exact','registered_document_exact'):
            code='import pathlib,sys; sys.stdout.buffer.write(pathlib.Path('+repr(str(source))+').read_text(encoding="utf-8").encode("utf-8"))'
            command=f'& {quote(Path(sys.base_prefix)/"python.exe")} -I -c {quote(code)}'
        engine=EvidenceEngine(policy,marker);holders.update(engine=engine,marker=marker)
        return dict(marker=marker,command=command,prompt=prompt,environment=environment,policy=policy,engine=engine)
    return make


def assess(result,observations,case,protocol,receipts,marker_hash):
    sensitive=[r for r in observations if r['marker_in_tool_result']]
    expected,reason=CASES[case]
    actual_blocked=bool(sensitive and all(r['decision']=='deny' for r in sensitive) and
        result['blocked_sensitive_body_zero_at_oracle'] and result['native_error_displayed'])
    arrived=any(r.get('marker_in_origin_payload') for r in result['origin_connections'])
    policy_hits=[hit for row in result['policy_events'] for hit in row.get('matched_rule_ids',[])]
    # Evidence of inspection is required even for negative controls and coverage gaps.
    valid=bool(sensitive and result['native_ready'] and result['disk_unchanged'] and not result['fixture_cleanup_terminated_child'])
    valid=valid and ((actual_blocked and not arrived and result['returncode']==1) or
                     (arrived and not actual_blocked and result['returncode']==0))
    expected_met=(actual_blocked and reason in policy_hits) if expected=='deny' else (arrived and not actual_blocked)
    status='blocked' if actual_blocked else 'allowed_negative_control' if case in ('clean_log','unregistered_source') and arrived else 'coverage_gap' if arrived else 'inconclusive'
    summary=dict(case=case,protocol=protocol,experiment_valid=bool(valid),protection_status=status,
        expected_current_behavior=expected,expected_outcome_met=bool(expected_met),explanation=reason,actual_blocked=actual_blocked,
        marker_reached_model_origin=arrived,marker_in_tool_result_observed=bool(sensitive),
        observations=observations,policy_hits=policy_hits,client_exit_code=result['returncode'],
        api_receipts=receipts,fake_content_sha256=marker_hash,
        source_attribution='not_attested_no_etw_in_this_case',detector_modified=False)
    return summary


def run_case(binary,root,case,protocol):
    holders={}
    try:
        result=experiment(binary,ROOT/'build/guard/ttrace-guard.dll',root,protocol,'block_request',
            scenario='tool_network',fixture_factory=fixture(case,holders))
    finally:
        if holders.get('api'):holders['api'].close()
    summary=assess(result,holders['engine'].observations,case,protocol,
        holders['api'].receipts if holders.get('api') else [],hashlib.sha256(holders['marker'].encode()).hexdigest())
    (root/'business-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    return summary


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--codex',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--assess-existing',action='store_true',help='Write separate reassessment; preserve original fixture and audit records')
    p.add_argument('--case',choices=list(CASES),action='append')
    p.add_argument('--transport',choices=['http','wss','both'],default='both')
    args=p.parse_args();root=args.output.resolve()
    if args.assess_existing:
        rows=[]
        for path in sorted(root.glob('*/business-summary.json')):
            old=json.loads(path.read_text());raw=json.loads((path.parent/'summary.json').read_text())
            hits={r['request_id']:r.get('matched_rule_ids',[]) for r in raw['policy_events'] if r.get('kind')=='policy.decision'}
            observations=[r|dict(hits=hits.get(r['request_id'],[])) for r in old['observations']]
            row=assess(raw,observations,old['case'],old['protocol'],old['api_receipts'],old['fake_content_sha256'])
            row['reassessment_reason']='Use existing matched_rule_ids; separate experiment validity from protection success'
            with (path.parent/'reassessment.json').open('x',encoding='utf-8') as out:json.dump(row,out,indent=2)
            rows.append(row)
        with (root/'reassessment.json').open('x',encoding='utf-8') as out:
            json.dump(dict(cases=rows,experiment_valid=bool(rows) and all(r['experiment_valid'] for r in rows),all_cases_protected=False),out,indent=2)
        print(json.dumps(dict(cases=len(rows),experiment_valid=bool(rows) and all(r['experiment_valid'] for r in rows))))
        return
    if not args.codex:p.error('--codex is required for live experiments')
    binary=args.codex.resolve()
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=BINARY_SHA256:p.error('fixed baseline mismatch')
    root.mkdir(parents=True,exist_ok=False);rows=[]
    for case in args.case or CASES:
        for protocol in ('http','wss') if args.transport=='both' else [args.transport]:
            row=run_case(binary,root/f'{case}-{protocol}',case,protocol);rows.append(row)
            print(json.dumps({k:row[k] for k in ('case','protocol','experiment_valid','protection_status','policy_hits')}),flush=True)
            (root/'summary.json').write_text(json.dumps(dict(cases=rows,experiment_valid=all(r['experiment_valid'] for r in rows),
                all_cases_protected=False,scope='explicit_fake_business_fixtures'),indent=2)+'\n')
    if not all(r['experiment_valid'] for r in rows):raise SystemExit(2)


if __name__=='__main__':main()
