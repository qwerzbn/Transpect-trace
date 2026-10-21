"""Fixed official TUI + owned terminal + original Native Gate, fake local data."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import time

from _build_support import ROOT
from probe_codex_tls import Origin,certificate,events
from probe_codex_business_content import CASES,fixture
from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.manager import attach_guard,close_components
from transpect_trace.guard.policy import GuardPolicy
from transpect_trace.guard.terminal import TerminalProcess


def wait_for(predicate,seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if predicate():return True
        time.sleep(.1)
    return False


def run(binary,root,case,transport,recovery=False,synthetic_terminal=False):
    root.mkdir(parents=True,exist_ok=False);home=root/'home';work=root/'workspace';home.mkdir();work.mkdir()
    holders={};f=fixture(case,holders)(work) if case!='ordinary_prompt' else {}
    marker=f.get('marker','FAKE_TUI_ORDINARY_PROMPT');recovering=False
    def reply(payload):
        body=json.loads(payload)
        if recovering or case=='ordinary_prompt' or body.get('generate') is False or any(
                isinstance(x,dict) and x.get('type')=='function_call_output' for x in body.get('input',[])):
            return events()
        call={'type':'function_call','id':'fc-tui-fixture','call_id':'call-tui-fixture','name':'exec_command',
              'arguments':json.dumps({'cmd':f['command'],'workdir':str(work),'login':False}), 'status':'completed'}
        response={'id':'resp-tui-fixture','object':'response','model':'gpt-probe','status':'completed','output':[call],
                  'usage':{'input_tokens':1,'output_tokens':1,'total_tokens':2}}
        return [{'type':'response.created','response':{**response,'output':[],'status':'in_progress'}},
                {'type':'response.output_item.added','output_index':0,'item':{**call,'arguments':'','status':'in_progress'}},
                {'type':'response.function_call_arguments.delta','output_index':0,'item_id':call['id'],'delta':call['arguments']},
                {'type':'response.function_call_arguments.done','output_index':0,'item_id':call['id'],'arguments':call['arguments'],'name':call['name']},
                {'type':'response.output_item.done','output_index':0,'item':call},
                {'type':'response.completed','response':response}]
    cert,key,ca=certificate(root);origin=Origin(root,cert,key,marker.encode(),reply);origin.thread.start()
    config=('model_provider="fixture"\napproval_policy="never"\nsandbox_mode="read-only"\n'
        '[features]\nplugins=false\napps=false\n[model_providers.fixture]\nname="Isolated fixture"\n'
        f'base_url="https://localhost:{origin.port}"\nwire_api="responses"\nrequires_openai_auth=false\n'
        f'request_max_retries=0\nstream_max_retries=0\nsupports_websockets={str(transport=="wss").lower()}\n'
        '[windows]\nsandbox="unelevated"\n')
    (home/'config.toml').write_text(config,encoding='utf-8')
    names={'CODEX_HOME','CODEX_CA_CERTIFICATE','SSL_CERT_FILE','SSLKEYLOGFILE','OPENAI_API_KEY','CODEX_API_KEY','API_KEY','RUST_LOG'}
    env={k:v for k,v in os.environ.items() if k.upper() not in names and 'PROXY' not in k.upper()}
    env.update(CODEX_HOME=str(home),CODEX_CA_CERTIFICATE=str(ca),NO_PROXY='*',TERM='xterm-256color',RUST_LOG='warn')
    env.update(f.get('environment',{}))
    policy=root/'policy.json';policy.write_text(f.get('policy',GuardPolicy()).model_dump_json(by_alias=True),encoding='utf-8')
    screen=bytearray()
    def output(data):
        screen.extend(data)
        if len(screen)>1024*1024:del screen[:len(screen)-1024*1024]
    terminal=TerminalProcess([str(binary),'--no-daemon','--no-alt-screen','--model','gpt-probe'],cwd=work,env=env,output=output)
    server=None;row={'case':case,'protocol':transport,'mode':'tui_no_daemon','passed':False}
    try:
        server,state,status=attach_guard(terminal.pid,ROOT/'build/guard/ttrace-guard.dll',policy,root/'guard',
            launched_cli=True,engine_factory=(lambda identity:f['engine']) if f else None)
        pre_ready=len(origin.records);terminal.mark_gate_ready()
        if not wait_for(lambda:b'Trust and continue' in screen or b'gpt-probe' in screen,15):
            raise RuntimeError('TUI initial input boundary unavailable')
        if b'Trust and continue' in screen:terminal.write(b'\r')
        if not wait_for(lambda:b'gpt-probe' in screen,15):
            raise RuntimeError('TUI model prompt did not become ready')
        time.sleep(.5)
        terminal.write('FAKE_TUI_ORDINARY_PROMPT reply OK' if not f else f['prompt'])
        time.sleep(.3);terminal.write(b'\r')
        expected='allow' if case=='ordinary_prompt' else CASES[case][0]
        if expected=='deny':
            done=wait_for(lambda:any(r.get('decision')=='deny' for r in server.records),35)
        else:
            done=wait_for(lambda:b'TLS probe received.' in screen,35)
        time.sleep(.3)
        decisions=[r for r in server.records if r.get('kind')=='policy.decision']
        denied=any(r.get('decision')=='deny' for r in decisions)
        sensitive_seen=case=='ordinary_prompt' or any(r['marker_in_tool_result'] for r in holders['engine'].observations)
        delivered=any(r.get('marker_in_origin_payload') for r in origin.records)
        zero=all(not r.get('marker_in_origin_payload') for r in origin.records)
        native_error=any(r.get('kind')=='native.outcome' and r.get('action')=='block_request' for r in server.records)
        hashes={r.get('content_sha256') for r in decisions}
        source_hashes={r.get('payload_sha256') for r in origin.records if r.get('payload_bytes',0)>0}
        outcome=(denied and zero and native_error) if expected=='deny' else (not denied and delivered and bool(source_hashes & hashes))
        if case=='sensitive_read_discard':
            row['discarded_sensitive_content_absent_from_request']=not any(r.get('discarded_source_content_in_request') for r in holders['engine'].observations)
            outcome=outcome and row['discarded_sensitive_content_absent_from_request']
        row.update(passed=bool(done and pre_ready==0 and sensitive_seen and outcome),native_ready=True,
            pre_ready_source_connections=pre_ready,input_released_after_gate_ready=True,
            sensitive_tool_result_observed=sensitive_seen,actual_blocked=denied,native_refusal_confirmed=native_error,
            sensitive_marker_reached_source=delivered,source_rejected_body_zero=zero if expected=='deny' else None,
            source_same_layer_hash_match=bool(source_hashes & hashes),
            source_receipts=[{k:r[k] for k in ('payload_bytes','payload_sha256') if k in r}
                for r in origin.records if r.get('payload_bytes',0)>0],
            policy_rule_ids=sorted({h for r in decisions for h in r.get('matched_rule_ids',[])}),
            response_completed=b'TLS probe received.' in screen,
            disk_unchanged=hashlib.sha256(binary.read_bytes()).hexdigest()==BINARY_SHA256,
            tls_test_configuration='custom_ca',external_service_tested=False)
        if recovery and expected=='deny':
            before=len(server.records);recovering=True
            terminal.write(b'\x1b');time.sleep(1);terminal.write(b'\x15')
            new_screen=len(screen)
            terminal.write('/new');time.sleep(.2);terminal.write(b'\r');time.sleep(1)
            # The fixed official build asks which Git worktree the new chat
            # should use. Keep the isolated current worktree before typing a
            # second prompt; typing into that menu would invalidate recovery.
            if wait_for(lambda:b'Where should the new conversation run?' in screen[new_screen:],3):
                terminal.write(b'\r');time.sleep(2)
            terminal.write('FAKE_CLEAN_RECOVERY_PROMPT Reply OK');time.sleep(.2);terminal.write(b'\r')
            recovered=wait_for(lambda:b'TLS probe received.' in screen,20)
            later=[r for r in server.records[before:] if r.get('kind')=='policy.decision']
            row['request_refusal_recovery']={'same_pid':terminal.pid,'new_session_response_completed':recovered,
                'later_request_allowed':any(r.get('decision')=='allow' for r in later),
                'original_sensitive_marker_still_zero':all(not r.get('marker_in_origin_payload') for r in origin.records)}
            row['passed']=row['passed'] and recovered and row['request_refusal_recovery']['later_request_allowed'] and row['request_refusal_recovery']['original_sensitive_marker_still_zero']
        terminal.write(b'\x03');time.sleep(.4);terminal.write(b'\x03')
        wait_for(lambda:terminal.poll() is not None,5)
        row['natural_terminal_exit']=terminal.poll() is not None
    except (OSError,RuntimeError,ValueError) as error:
        row.update(error_type=type(error).__name__)
    finally:
        if server:
            close_components(server,state,status);row['capture']=state['capture']
        terminal.close();origin.stop.set();origin.listener.close();origin.thread.join(3)
        if holders.get('api'):holders['api'].close()
        if synthetic_terminal:(root/'synthetic-terminal.log').write_bytes(screen)
        row['terminal_closed_by_harness']=not row.get('natural_terminal_exit',False)
        (root/'summary.json').write_text(json.dumps(row,indent=2)+'\n',encoding='utf-8')
    return row


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--codex',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--case',choices=['ordinary_prompt',*CASES],action='append')
    p.add_argument('--transport',choices=['http','wss','both'],default='both');p.add_argument('--recovery',action='store_true')
    p.add_argument('--synthetic-terminal',action='store_true',help='Explicit opt-in to save fake-data-only terminal output.');args=p.parse_args()
    binary=args.codex.resolve();root=args.output.resolve()
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=BINARY_SHA256:p.error('fixed baseline mismatch')
    root.mkdir(parents=True,exist_ok=False);rows=[]
    for case in args.case or ['ordinary_prompt',*CASES]:
        for protocol in ['http','wss'] if args.transport=='both' else [args.transport]:
            row=run(binary,root/f'{case}-{protocol}',case,protocol,args.recovery,args.synthetic_terminal);rows.append(row)
            print(json.dumps({k:row[k] for k in ['case','protocol','passed']}),flush=True)
            (root/'summary.json').write_text(json.dumps({'cases':rows,'passed':all(r['passed'] for r in rows)},indent=2)+'\n')
    if not all(r['passed'] for r in rows):raise SystemExit(1)

if __name__=='__main__':main()
