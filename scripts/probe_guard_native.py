"""Real official CLI + native DLL + local TLS oracle; no Frida in the runtime."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

from probe_codex_tls import Origin, certificate, decrypt_control, events
from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.native import inject, resume
from transpect_trace.guard.pipe import PipeServer
from transpect_trace.guard.policy import GuardPolicy, Marker, PolicyEngine
from transpect_trace.guard.external import ExternalEngine


class SlowEngine(PolicyEngine):
    def evaluate(self,request):
        if request.kind=="model.request":time.sleep(2.5)
        return super().evaluate(request)


class BadReplyServer(PipeServer):
    def decision_frame(self,decision):
        from transpect_trace.guard.wire import encode_frame
        value=decision.model_dump(by_alias=True)
        if decision.reason!="CONTROL_ACK":value["request_id"]="stale-request-id"
        return encode_frame(value)


class MalformedReplyServer(PipeServer):
    def decision_frame(self,decision):
        from transpect_trace.guard.wire import encode_frame
        if decision.reason=="CONTROL_ACK":return super().decision_frame(decision)
        # A plausible allow followed by a second JSON root must fail closed.
        value=decision.model_dump(by_alias=True)
        value.update(decision="allow",action="none")
        frame=encode_frame(value)
        raw=frame[4:]+b' {}'
        import struct
        return struct.pack("<I",len(raw))+raw


def experiment(binary:Path,dll:Path,root:Path,transport:str,action:str,engine_language:str="reference",fault:str="none",scenario:str="prompt",launcher:bool=False,coexist:bool=False,protect_bridge:bool=False,ecapture_compare:bool=False,elevate_ecapture:bool=False,behavior_compare:bool=False,elevate_behavior:bool=False,tool_command:str|None=None,on_ready=None,behavior_collector:Path|None=None,fixture_factory=None,capture_requests=False,egress_policy_file:Path|None=None):
    if fixture_factory and (launcher or engine_language!='reference' or fault!='none'):
        raise ValueError('Business fixtures require the reference direct research harness without fault injection')
    if egress_policy_file and not launcher:raise ValueError('Public egress policy requires launcher mode')
    root.mkdir(parents=True,exist_ok=False)
    home,workspace=root/"codex-home",root/"workspace";home.mkdir();workspace.mkdir()
    marker=f"TRANSPECT_NATIVE_PROBE_{uuid4().hex}"
    if scenario=='credential':marker=f'mysql_password=FAKE_ONLY_{uuid4().hex}'
    fixture=fixture_factory(workspace) if fixture_factory else {}
    if fixture:
        marker=fixture['marker']
        tool_command=fixture['command']
    source=workspace/"fake_secret.txt"
    if scenario in ("tool_read", "tool_read_discard"):source.write_text(marker+"\nOnly synthetic fixture data.\n")
    def reply(payload):
        parsed=json.loads(payload)
        if scenario not in ("tool_read", "tool_read_discard", "tool_network") or parsed.get("generate") is False:return events()
        inputs=parsed.get("input",[])
        if any(isinstance(x,dict) and x.get("type")=="function_call_output" for x in inputs):return events()
        command = tool_command or f"Get-Content -LiteralPath '{source}'"
        if scenario == 'tool_read_discard': command += " | Out-Null; Write-Output 'synthetic read completed'"
        tool_arguments={"cmd":command,"workdir":str(workspace),"login":False}
        if fixture.get('yield_time_ms'):tool_arguments['yield_time_ms']=fixture['yield_time_ms']
        item={"id":"fc_probe","type":"function_call","status":"completed","call_id":"call_probe",
              "name":"exec_command","arguments":json.dumps(tool_arguments)}
        response={"id":"resp_probe","object":"response","status":"completed","model":"gpt-probe","output":[item],
                  "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}
        return [{"type":"response.created","response":{**response,"status":"in_progress","output":[]}},
                {"type":"response.output_item.added","output_index":0,"item":{**item,"status":"in_progress","arguments":""}},
                {"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_probe","delta":item["arguments"]},
                {"type":"response.function_call_arguments.done","output_index":0,"item_id":"fc_probe","name":"exec_command","arguments":item["arguments"]},
                {"type":"response.output_item.done","output_index":0,"item":item},
                {"type":"response.completed","response":response}]
    cert,key,ca=certificate(root);origin=Origin(root,cert,key,marker.encode(),reply);origin.thread.start()
    (home/"config.toml").write_text(
        'model_provider = "native_probe"\napproval_policy = "never"\nsandbox_mode = "read-only"\n'
        '[features]\nplugins = false\napps = false\n'
        '[model_providers.native_probe]\nname = "Native test origin"\n'
        f'base_url = "https://localhost:{origin.port}"\nwire_api = "responses"\n'
        'requires_openai_auth = false\nrequest_max_retries = 0\nstream_max_retries = 0\n'
        f'supports_websockets = {str(transport=="wss").lower()}\n'
        '[windows]\nsandbox = "unelevated"\n')
    secret_names={"CODEX_HOME","CODEX_CA_CERTIFICATE","SSL_CERT_FILE","SSLKEYLOGFILE","RUST_LOG",
                  "OPENAI_API_KEY","API_KEY","DEEPSEEK_API_KEY","ANTHROPIC_API_KEY","OPENAI_BASE_URL",
                  "CODEX_API_KEY","CHATGPT_BASE_URL","TRANSPECT_MODEL_API_KEY"}
    env={k:v for k,v in os.environ.items() if k.upper() not in secret_names and "PROXY" not in k.upper()}
    env.update(CODEX_HOME=str(home),CODEX_CA_CERTIFICATE=str(ca),NO_PROXY="*",HTTP_PROXY="",HTTPS_PROXY="",ALL_PROXY="",RUST_LOG="warn")
    env.update(fixture.get('environment',{}))
    policy=GuardPolicy(credential_rules=scenario=='credential' and action!='observe',deny_action="block_request" if action=="observe" else action,
                       content_markers=[] if action=="observe" or scenario=='credential' else [Marker(marker_id="fake-secret",value=marker,source_path=str(source) if scenario in ("tool_read", "tool_read_discard") else "fixture")])
    prompt=f"Do not run tools. Reply OK. Synthetic marker: {marker}" if scenario in ("prompt","credential") else "Read fake_secret.txt with exec_command and explain its contents."
    if fixture:
        policy=fixture['policy']
        prompt=fixture['prompt']
    command=[str(binary),"exec","--json","--ephemeral","--skip-git-repo-check","--model","gpt-probe",
             "--cd",str(workspace),prompt]
    if launcher:
        policy_file=root/"policy.json"
        policy_file.write_text(policy.model_dump_json(by_alias=True),encoding="utf-8")
        cli=[sys.executable,"-m","transpect_trace.cli","guard","codex","--codex",str(binary),
             "--dll",str(dll.resolve()),"--policy-file",str(policy_file),"--runs-dir",str(root/"managed")]
        if protect_bridge:
            from transpect_trace.protect.policy import ProtectionPolicy
            from transpect_trace.protect.detection import ContentIndex
            policy_file.write_text(ProtectionPolicy(deny_action='block_request' if action=='observe' else action).model_dump_json())
            index=root/'content-index.json';index.write_text(ContentIndex.register('fixture/1',[] if action=='observe' else [('fixture',marker,'SECRET',['registered_text'])]).model_dump_json())
            cli=[sys.executable,'-m','transpect_trace.cli','protect','run','--channel','cli','--binary',str(binary),
                '--dll',str(dll.resolve()),'--policy-file',str(policy_file),'--index-file',str(index),'--runs-dir',str(root/'managed')]
        if engine_language=="c":
            argv_file=root/"engine-argv.json"
            argv_file.write_text(json.dumps([str((dll.parent/"policy_fixture.exe").resolve()),"{pid}",
                                  marker if action!="observe" else "NEVER_MATCH_NATIVE_FIXTURE",
                                  "block_request" if action=="observe" else action]))
            cli.extend(["--engine-command-file",str(argv_file)])
        if egress_policy_file:cli.extend(['--egress-policy-file',str(egress_policy_file.resolve())])
        command=[*cli,"--",*command[1:]]
    with (root/"client.stdout.jsonl").open("wb") as out,(root/"client.stderr.log").open("wb") as err:
        # `exec` waits for additional stdin before issuing the model request.
        # Hold EOF until native.ready; do not rely on loader injection into an
        # uninitialized suspended process whose module list is unavailable.
        client=subprocess.Popen(command,env=env,cwd=Path(__file__).resolve().parents[1] if launcher else workspace,stdin=subprocess.PIPE,
                                stdout=out,stderr=err)
        if launcher:
            server=SimpleNamespace(records=[],errors=[],ready=threading.Event(),close=lambda:None)
        elif engine_language=="c":
            server=ExternalEngine(client.pid,[str(dll.parent/"policy_fixture.exe"),str(client.pid),
                                  marker if action!="observe" else "NEVER_MATCH_NATIVE_FIXTURE",
                                  "block_request" if action=="observe" else action],root/"audit.jsonl")
        else:
            server_type={"stale_reply":BadReplyServer,"malformed_reply":MalformedReplyServer}.get(fault,PipeServer)
            engine_type=SlowEngine if fault=="timeout" else PolicyEngine
            server=server_type(client.pid,fixture.get('engine') or engine_type(policy),root/"audit.jsonl")
        cleanup=False;comparison=None;behavior=None;request_capture=None
        observer_conflict_refused=None
        try:
            if not launcher:
                server.start();identity=inject(client.pid,dll,launched_cli=True)
                if not server.ready.wait(15):raise RuntimeError(f"Native hooks not ready: {server.errors}")
                if behavior_compare:
                    from _behavior_probe import BehaviorComparison
                    (root/'status.json').write_text(json.dumps({'identity':identity, 'state':'research_fixture'}))
                    behavior=BehaviorComparison(client.pid,root/'behavior',elevate=elevate_behavior,collector=behavior_collector)
                    behavior.start()
                if ecapture_compare:
                    from _capture_comparison import PassiveComparison
                    comparison=PassiveComparison(client.pid,'codex-cli',root/'ecapture',elevate=elevate_ecapture)
                    comparison.start()
                if coexist:
                    from transpect_trace.observe.windows import discover_profile
                    from transpect_trace.observe.native import NativeCollector
                    from transpect_trace.observe.pipeline import Pipeline
                    subject,profile=discover_profile(client.pid,'codex-cli')
                    observer=NativeCollector(subject,profile,Path('build/observe/ttrace-observe.dll'),Pipeline(root/'observer',policy))
                    try:observer.start();observer_conflict_refused=False
                    except RuntimeError:observer_conflict_refused=True
                    finally:observer.close()
                if fault=="disconnect":server.close()
                # Fixtures can opt into the production single-Hook snapshot tap.
                server.request_tap=fixture.get('request_tap')
                if capture_requests:
                    if server.request_tap:raise ValueError('Only one request tap may own this fixture')
                    from transpect_trace.observe.request_capture import GuardRequestTap
                    request_capture=GuardRequestTap(root/'capture',dict(identity,image_sha256=BINARY_SHA256),policy=policy)
                    server.request_tap=request_capture
                if on_ready:on_ready(identity)
            client.stdin.close()
            try:code=client.wait(timeout=35)
            except subprocess.TimeoutExpired:
                cleanup=True;client.kill();code=client.wait(timeout=10)
        finally:
            if behavior:behavior.close()
            if comparison:comparison.close()
            if client.poll() is None:cleanup=True;client.kill();client.wait(timeout=10)
            server.close()
            if request_capture:request_capture.close()
            origin.stop.set();origin.thread.join(timeout=15);origin.listener.close()
    managed_state=None
    actual_pid=client.pid
    module_base=identity.get("module_base") if not launcher else None
    if launcher:
        status_files=list((root/"managed").glob("*/status.json"))
        if len(status_files)==1:
            status_file=status_files[0]
            managed_state=json.loads(status_file.read_text())
            actual_pid=managed_state["identity"]["pid"]
            module_base=managed_state["identity"].get("module_base")
            if managed_state.get("protected_since_unix_ns"):server.ready.set()
            audit_file=status_file.parent/"audit.jsonl"
            if audit_file.is_file():server.records=[json.loads(x) for x in audit_file.read_text(encoding="utf-8").splitlines()]
    current=hashlib.sha256(binary.read_bytes()).hexdigest()
    for connection in origin.records:
        if connection.get("cipher"):
            connection["offline_oracle"]=decrypt_control((root/connection["wire_file"]).read_bytes(),
                      root/"origin-session.keys",connection["cipher"],marker.encode())
    if (action!="observe" and scenario!='tool_read_discard') or fault!="none":
        zero_body=all(not r.get("marker_in_origin_payload") and
                      (r.get("payload_bytes") is not None or (r.get("offline_oracle",{}).get("decoded_payload_bytes")==0
                                                             and r.get("offline_oracle",{}).get("unparsed_payload_bytes")==0))
                      for r in origin.records)
    else:zero_body=None
    result={"transport":transport,"action":action,"runtime":"native","frida_used":False,"engine_language":engine_language,"fault":fault,"scenario":scenario,
            "pid":actual_pid,"returncode":code,"native_ready":server.ready.is_set(),
            "via_public_launcher":launcher,"manager_state":managed_state,
            "module_base":module_base,
            "observer_conflict_refused":observer_conflict_refused,
            "binary_sha256_before":BINARY_SHA256,"binary_sha256_after":current,
            "disk_unchanged":current==BINARY_SHA256,"proxy_used":False,"tls_replaced":False,
            "synthetic_only":True,"fixture_cleanup_terminated_child":cleanup,
            "blocked_sensitive_body_zero_at_oracle":zero_body,
            "policy_events":server.records,"pipe_errors":server.errors,
            "native_error_displayed":any(b"request denied by local policy" in (root/name).read_bytes()
                                         for name in ("client.stdout.jsonl","client.stderr.log")),
            "origin_connections":origin.records,"wss_streaming_coverage":"not_claimed"}
    if comparison:result['ecapture_comparison']=comparison.report(origin.records)
    if request_capture:result['request_capture']=request_capture.status()
    if behavior:
        result['behavior_comparison']=behavior.report()
        if (root/'behavior/events.jsonl').exists():
            from transpect_trace.behavior.report import build_report
            (root/'behavior/report.json').write_text(json.dumps(build_report(root/'behavior',guard_directory=root),indent=2)+'\n')
    (root/"summary.json").write_text(json.dumps(result,indent=2)+"\n")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex",type=Path,default=shutil.which("codex"))
    parser.add_argument("--dll",type=Path,default=Path("build/guard/ttrace-guard.dll"))
    parser.add_argument("--action",choices=["observe","block_request","block_session","terminate_process"],default="observe")
    parser.add_argument("--output",type=Path,default=Path("runs/guard-native")/uuid4().hex)
    parser.add_argument("--engine",choices=["reference","c"],default="reference")
    parser.add_argument("--fault",choices=["none","disconnect","timeout","stale_reply","malformed_reply"],default="none")
    parser.add_argument("--scenario",choices=["prompt","credential","tool_read","tool_read_discard"],default="prompt")
    parser.add_argument("--launcher",action="store_true",help="Exercise public ttrace guard codex entry point.")
    parser.add_argument('--protect-bridge',action='store_true',help='Use public Protect policy bridge through the original Native Guard v1 contract.')
    parser.add_argument("--copy-baseline",action="store_true",help="Run byte-identical EXE copy to exercise independent image layout.")
    parser.add_argument("--coexist-observer",action="store_true",help="Verify observer refuses an already guarded semantic entry.")
    parser.add_argument('--ecapture-compare',action='store_true',help='Try enhanced Schannel observation independently of the Native Gate.')
    parser.add_argument('--elevate-ecapture',action='store_true',help='Request UAC for the optional eCapture collector.')
    parser.add_argument('--behavior-compare',action='store_true',help='Collect Codex-scoped system evidence independently of Native Gate.')
    parser.add_argument('--elevate-behavior',action='store_true',help='UAC for the finite-duration evidence worker, not Codex.')
    parser.add_argument('--behavior-collector',type=Path,help='Manifest-checked isolated Behavior build; existing default is unchanged.')
    parser.add_argument('--egress-policy-file',type=Path,help='Explicit descendant TCP policy for the public launcher.')
    parser.add_argument('--transport',choices=['http','wss','both'],default='both')
    args=parser.parse_args()
    if args.launcher and args.fault!="none":parser.error("fault injection uses the direct research fixture")
    if args.launcher and args.coexist_observer:parser.error('coexistence uses direct injection fixture')
    if args.protect_bridge and (not args.launcher or args.engine!='reference'):parser.error('protect-bridge requires launcher and reference engine')
    if args.ecapture_compare and (args.launcher or args.coexist_observer):parser.error('eCapture comparison uses the direct fixture without another observer')
    if args.elevate_ecapture and not args.ecapture_compare:parser.error('elevation requires --ecapture-compare')
    if args.behavior_compare and args.launcher:parser.error('behavior comparison uses the direct fixture')
    if args.elevate_behavior and not args.behavior_compare:parser.error('elevation requires --behavior-compare')
    if hashlib.sha256(args.codex.read_bytes()).hexdigest()!=BINARY_SHA256:parser.error("baseline mismatch")
    root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    binary=args.codex
    if args.copy_baseline:
        folder=root/"official-copy";folder.mkdir()
        binary=folder/"codex.exe";shutil.copyfile(args.codex,binary)
        if hashlib.sha256(binary.read_bytes()).hexdigest()!=BINARY_SHA256:raise RuntimeError("copy integrity failure")
    transports=['http','wss'] if args.transport=='both' else [args.transport]
    results=[experiment(binary,args.dll,root/t,t,args.action,args.engine,args.fault,args.scenario,args.launcher,args.coexist_observer,args.protect_bridge,args.ecapture_compare,args.elevate_ecapture,args.behavior_compare,args.elevate_behavior,behavior_collector=args.behavior_collector,egress_policy_file=args.egress_policy_file) for t in transports]
    (root/"summary.json").write_text(json.dumps({"experiments":results},indent=2)+"\n")
    print(json.dumps({"output":str(root),"results":[{k:v for k,v in r.items() if k not in {"policy_events","origin_connections","manager_state"}} for r in results]},indent=2))
    for result in results:
        denied=(args.action!="observe" and args.scenario!='tool_read_discard') or args.fault!="none"
        expected=76 if args.action=="terminate_process" and args.fault=="none" else 1 if denied else 0
        valid=(result["native_ready"] and result["disk_unchanged"] and not result["fixture_cleanup_terminated_child"]
               and result["returncode"]==expected)
        if denied: valid=valid and result["blocked_sensitive_body_zero_at_oracle"]
        elif args.scenario=='tool_read_discard':
            valid=valid and any(r.get("payload_bytes",0)>0 for r in result["origin_connections"])
        else: valid=valid and any(r.get("marker_in_origin_payload") for r in result["origin_connections"])
        if not valid:raise SystemExit(1)


if __name__=="__main__":main()
