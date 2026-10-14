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


def experiment(binary:Path,dll:Path,root:Path,transport:str,action:str,engine_language:str="reference",fault:str="none",scenario:str="prompt",launcher:bool=False):
    root.mkdir(parents=True,exist_ok=False)
    home,workspace=root/"codex-home",root/"workspace";home.mkdir();workspace.mkdir()
    marker=f"TRANSPECT_NATIVE_PROBE_{uuid4().hex}"
    source=workspace/"fake_secret.txt"
    if scenario=="tool_read":source.write_text(marker+"\nOnly synthetic fixture data.\n")
    def reply(payload):
        parsed=json.loads(payload)
        if scenario!="tool_read" or parsed.get("generate") is False:return events()
        inputs=parsed.get("input",[])
        if any(isinstance(x,dict) and x.get("type")=="function_call_output" for x in inputs):return events()
        item={"id":"fc_probe","type":"function_call","status":"completed","call_id":"call_probe",
              "name":"exec_command","arguments":json.dumps({"cmd":f"Get-Content -LiteralPath '{source}'","workdir":str(workspace),"login":False})}
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
    policy=GuardPolicy(credential_rules=False,deny_action="block_request" if action=="observe" else action,
                       content_markers=[] if action=="observe" else [Marker(marker_id="fake-secret",value=marker,source_path=str(source) if scenario=="tool_read" else "fixture")])
    prompt=f"Do not run tools. Reply OK. Synthetic marker: {marker}" if scenario=="prompt" else "Read fake_secret.txt with exec_command and explain its contents."
    command=[str(binary),"exec","--json","--ephemeral","--skip-git-repo-check","--model","gpt-probe",
             "--cd",str(workspace),prompt]
    if launcher:
        policy_file=root/"policy.json"
        policy_file.write_text(policy.model_dump_json(by_alias=True),encoding="utf-8")
        cli=[sys.executable,"-m","transpect_trace.cli","guard","codex","--codex",str(binary),
             "--dll",str(dll.resolve()),"--policy-file",str(policy_file),"--runs-dir",str(root/"managed")]
        if engine_language=="c":
            argv_file=root/"engine-argv.json"
            argv_file.write_text(json.dumps([str((dll.parent/"policy_fixture.exe").resolve()),"{pid}",
                                  marker if action!="observe" else "NEVER_MATCH_NATIVE_FIXTURE",
                                  "block_request" if action=="observe" else action]))
            cli.extend(["--engine-command-file",str(argv_file)])
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
            server=server_type(client.pid,engine_type(policy),root/"audit.jsonl")
        cleanup=False
        try:
            if not launcher:
                server.start();identity=inject(client.pid,dll,launched_cli=True)
                if not server.ready.wait(15):raise RuntimeError(f"Native hooks not ready: {server.errors}")
                if fault=="disconnect":server.close()
            client.stdin.close()
            try:code=client.wait(timeout=35)
            except subprocess.TimeoutExpired:
                cleanup=True;client.kill();code=client.wait(timeout=10)
        finally:
            if client.poll() is None:cleanup=True;client.kill();client.wait(timeout=10)
            server.close();origin.stop.set();origin.thread.join(timeout=15);origin.listener.close()
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
    if action!="observe" or fault!="none":
        zero_body=all(not r.get("marker_in_origin_payload") and
                      (r.get("payload_bytes") is not None or (r.get("offline_oracle",{}).get("decoded_payload_bytes")==0
                                                             and r.get("offline_oracle",{}).get("unparsed_payload_bytes")==0))
                      for r in origin.records)
    else:zero_body=None
    result={"transport":transport,"action":action,"runtime":"native","frida_used":False,"engine_language":engine_language,"fault":fault,"scenario":scenario,
            "pid":actual_pid,"returncode":code,"native_ready":server.ready.is_set(),
            "via_public_launcher":launcher,"manager_state":managed_state,
            "module_base":module_base,
            "binary_sha256_before":BINARY_SHA256,"binary_sha256_after":current,
            "disk_unchanged":current==BINARY_SHA256,"proxy_used":False,"tls_replaced":False,
            "synthetic_only":True,"fixture_cleanup_terminated_child":cleanup,
            "blocked_sensitive_body_zero_at_oracle":zero_body,
            "policy_events":server.records,"pipe_errors":server.errors,
            "native_error_displayed":any(b"request denied by local policy" in (root/name).read_bytes()
                                         for name in ("client.stdout.jsonl","client.stderr.log")),
            "origin_connections":origin.records,"wss_streaming_coverage":"not_claimed"}
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
    parser.add_argument("--scenario",choices=["prompt","tool_read"],default="prompt")
    parser.add_argument("--launcher",action="store_true",help="Exercise public ttrace guard codex entry point.")
    parser.add_argument("--copy-baseline",action="store_true",help="Run byte-identical EXE copy to exercise independent image layout.")
    args=parser.parse_args()
    if args.launcher and args.fault!="none":parser.error("fault injection uses the direct research fixture")
    if hashlib.sha256(args.codex.read_bytes()).hexdigest()!=BINARY_SHA256:parser.error("baseline mismatch")
    root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    binary=args.codex
    if args.copy_baseline:
        folder=root/"official-copy";folder.mkdir()
        binary=folder/"codex.exe";shutil.copyfile(args.codex,binary)
        if hashlib.sha256(binary.read_bytes()).hexdigest()!=BINARY_SHA256:raise RuntimeError("copy integrity failure")
    results=[experiment(binary,args.dll,root/t,t,args.action,args.engine,args.fault,args.scenario,args.launcher) for t in ["http","wss"]]
    (root/"summary.json").write_text(json.dumps({"experiments":results},indent=2)+"\n")
    print(json.dumps({"output":str(root),"results":[{k:v for k,v in r.items() if k not in {"policy_events","origin_connections","manager_state"}} for r in results]},indent=2))
    for result in results:
        denied=args.action!="observe" or args.fault!="none"
        expected=76 if args.action=="terminate_process" and args.fault=="none" else 1 if denied else 0
        valid=(result["native_ready"] and result["disk_unchanged"] and not result["fixture_cleanup_terminated_child"]
               and result["returncode"]==expected)
        valid=valid and (result["blocked_sensitive_body_zero_at_oracle"] if denied else
                        any(r.get("marker_in_origin_payload") for r in result["origin_connections"]))
        if not valid:raise SystemExit(1)


if __name__=="__main__":main()
