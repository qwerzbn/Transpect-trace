"""Verify refusal and a later benign turn in ONE official CLI process (ConPTY)."""
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
from uuid import uuid4

from winpty import PtyProcess
from probe_codex_tls import Origin,certificate
from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.native import inject,api
from probe_codex_tls import decrypt_control
from transpect_trace.guard.pipe import PipeServer
from transpect_trace.guard.policy import GuardPolicy,Marker,PolicyEngine


def wait_for(predicate,timeout=25):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        if predicate():return True
        time.sleep(0.05)
    return False


def terminate_synthetic_fixture(pid,creation_filetime):
    # ConPTY children do not necessarily accept os.kill(SIGTERM). Hold and
    # verify the known fake-data process handle before explicit test cleanup.
    import ctypes
    from ctypes import wintypes
    k=api();handle=k.OpenProcess(0x100001|0x1000,False,pid)
    if not handle:
        if ctypes.get_last_error()==87:return
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if k.WaitForSingleObject(handle,0)==0:return
        times=[wintypes.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle,*(ctypes.byref(x) for x in times)):raise ctypes.WinError(ctypes.get_last_error())
        created=times[0].dwLowDateTime+(times[0].dwHighDateTime<<32)
        if creation_filetime is not None and created!=creation_filetime:raise RuntimeError("Fixture PID reused; refuse cleanup")
        k.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT];k.TerminateProcess.restype=wintypes.BOOL
        if not k.TerminateProcess(handle,90):raise ctypes.WinError(ctypes.get_last_error())
        k.WaitForSingleObject(handle,5000)
    finally:k.CloseHandle(handle)


class ControllerObserver:
    """Read metadata written by the real public attach controller."""
    def __init__(self,pid,dll,root,policy):
        self.pid,self.dll,self.root,self.policy=pid,dll,root,policy
        self.ready=threading.Event();self.errors=[];self.process=None;self.log=None
        self.run=None;self.identity={}

    @property
    def records(self):
        if self.run is None:return []
        path=self.run/"audit.jsonl"
        if not path.is_file():return []
        rows=[]
        for line in path.read_text(encoding="utf-8").splitlines():
            try:rows.append(json.loads(line))
            except ValueError:pass
        return rows

    def start(self):
        policy_file=self.root/"policy.json"
        policy_file.write_text(self.policy.model_dump_json(by_alias=True),encoding="utf-8")
        self.log=(self.root/"controller.log").open("wb")
        self.process=subprocess.Popen([sys.executable,"-m","transpect_trace.cli","guard","attach",
              "--pid",str(self.pid),"--dll",str(self.dll.resolve()),"--policy-file",str(policy_file),
              "--runs-dir",str(self.root/"managed")],cwd=Path(__file__).resolve().parents[1],
              stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log)
        def active():
            paths=list((self.root/"managed").glob("*/status.json"))
            if len(paths)!=1:return False
            try:state=json.loads(paths[0].read_text())
            except ValueError:return False
            if not state.get("protected_since_unix_ns"):return False
            self.run=paths[0].parent;self.identity=state["identity"];return True
        if not wait_for(active,45):raise RuntimeError("Public attach controller did not become ready")
        self.ready.set()

    def close(self):
        if self.process:
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:self.process.terminate();self.process.wait(timeout=5)
        if self.log:self.log.close()


def experiment(binary,dll,root,transport,action,controller=False):
    root.mkdir(parents=True,exist_ok=False)
    home,workspace=root/"codex-home",root/"workspace";home.mkdir();workspace.mkdir()
    marker=f"TRANSPECT_TUI_SECRET_{uuid4().hex}"
    cert,key,ca=certificate(root);origin=Origin(root,cert,key,marker.encode());origin.thread.start()
    config=('model_provider = "tui_probe"\napproval_policy = "never"\nsandbox_mode = "read-only"\n'
            'check_for_update_on_startup = false\n'
            '[features]\nplugins = false\napps = false\n'
            '[model_providers.tui_probe]\nname = "TUI test origin"\n'
            f'base_url = "https://localhost:{origin.port}"\nwire_api = "responses"\n'
            'requires_openai_auth = false\nrequest_max_retries = 0\nstream_max_retries = 0\n'
            f'supports_websockets = {str(transport=="wss").lower()}\n'
            f'[projects.{json.dumps(str(workspace))}]\ntrust_level = "trusted"\n')
    (home/"config.toml").write_text(config)
    excluded={"CODEX_HOME","CODEX_CA_CERTIFICATE","SSL_CERT_FILE","SSLKEYLOGFILE","RUST_LOG",
              "OPENAI_API_KEY","API_KEY","DEEPSEEK_API_KEY","ANTHROPIC_API_KEY","OPENAI_BASE_URL",
              "CODEX_API_KEY","CHATGPT_BASE_URL","TRANSPECT_MODEL_API_KEY"}
    env={k:v for k,v in os.environ.items() if k.upper() not in excluded and "PROXY" not in k.upper()}
    env.update(CODEX_HOME=str(home),CODEX_CA_CERTIFICATE=str(ca),NO_PROXY="*",HTTP_PROXY="",HTTPS_PROXY="",ALL_PROXY="",RUST_LOG="warn",TERM="xterm-256color")
    client=PtyProcess.spawn([str(binary),"--no-daemon","--no-alt-screen","--model","gpt-probe","--cd",str(workspace)],
                            cwd=str(workspace),env=env,dimensions=(40,140),backend=0)
    output=[]
    def read():
        try:
            while client.isalive():
                value=client.read(4096)
                output.append(value)
        except (EOFError,OSError):pass
    reader=threading.Thread(target=read,daemon=True);reader.start()
    policy=GuardPolicy(credential_rules=False,deny_action=action,
                       content_markers=[Marker(marker_id="fake-secret",value=marker,source_path="fixture")])
    server=ControllerObserver(client.pid,dll,root,policy) if controller else PipeServer(client.pid,PolicyEngine(policy),root/"audit.jsonl")
    identity={}
    result={"transport":transport,"action":action,"runtime":"native","frida_used":False,
            "proxy_used":False,"tls_replaced":False,"synthetic_only":True,
            "binary_sha256_before":BINARY_SHA256,"native_ready":False,"via_public_attach":controller}
    try:
        server.start();identity=server.identity if controller else inject(client.pid,dll)
        if not server.ready.wait(15):raise RuntimeError("Native hooks not ready")
        result.update(native_ready=True,module_base=identity.get("module_base"))
        boot=wait_for(lambda:"gpt-probe" in "".join(output) and ("context" in "".join(output) or "OpenAI" in "".join(output)))
        result["ui_ready"]=boot
        time.sleep(0.5)
        client.write(f"Do not use tools. Reply OK. Synthetic secret: {marker}")
        time.sleep(0.7);client.write("\r")
        denied=wait_for(lambda:any(r.get("decision")=="deny" for r in server.records),45)
        error_displayed=wait_for(lambda:"request denied by local policy" in "".join(output),15)
        alive_after_denial=client.isalive()
        # A denied prompt remains in Codex's conversation. Start a fresh
        # conversation to make the later request actually unrelated/benign.
        client.write("/new");time.sleep(0.7);client.write("\r")
        if wait_for(lambda:"Where should the new conversation run?" in "".join(output),5):
            client.write("\r")  # Select current worktree in the synthetic session only.
        time.sleep(1.2)
        before=len(server.records)
        benign_sent=time.perf_counter_ns()
        client.write("Do not use tools. Reply OK. This is a benign second turn.")
        time.sleep(0.7);client.write("\r")
        def new_evidence():
            for row in server.records[before:]:
                tick=row.get("captured_qpc") or 0;freq=row.get("qpc_frequency") or 1
                if tick*1_000_000_000//freq>=benign_sent:return True
            return False
        subsequent=wait_for(new_evidence,20)
        after=server.records[before:]
        if action=="block_request":
            wait_for(lambda:any(r.get("kind")=="policy.decision" and r.get("decision")=="allow"
                               and (r.get("captured_qpc",0)*1_000_000_000//(r.get("qpc_frequency") or 1))>=benign_sent
                               for r in server.records[before:]),15)
            after=server.records[before:]
        result.update(pid=client.pid,denied=denied,error_displayed=error_displayed,
                      same_process_alive_after_denial=alive_after_denial,
                      subsequent_observed=subsequent,subsequent_policy_events=after,
                      subsequent_request_allowed=any(r.get("kind")=="policy.decision" and r.get("decision")=="allow" for r in after),
                      subsequent_session_rejection=any(r.get("kind")=="native.outcome" and r.get("action")=="block_session"
                            and (r.get("captured_qpc",0)*1_000_000_000//(r.get("qpc_frequency") or 1))>=benign_sent for r in after),
                      no_secret_at_origin=not any(r.get("marker_in_origin_payload") for r in origin.records),
                      origin_connections=origin.records,policy_events=server.records,
                      disk_unchanged=hashlib.sha256(binary.read_bytes()).hexdigest()==BINARY_SHA256,
                      pipe_errors=server.errors,wss_streaming_coverage="not_claimed")
    finally:
        # End only the synthetic test CLI after observations; not a guard action.
        terminate_synthetic_fixture(client.pid,identity.get("creation_filetime"))
        reader.join(timeout=3);server.close();origin.stop.set();origin.thread.join(timeout=15);origin.listener.close()
        (root/"synthetic-terminal.log").write_text("".join(output),encoding="utf-8")
    for connection in origin.records:
        if connection.get("cipher"):
            connection["offline_oracle"]=decrypt_control((root/connection["wire_file"]).read_bytes(),
                    root/"origin-session.keys",connection["cipher"],marker.encode())
    result["blocked_sensitive_body_zero_at_oracle"]=all(
        not r.get("marker_in_origin_payload") and
        (r.get("payload_bytes") is not None or (r.get("offline_oracle",{}).get("decoded_payload_bytes")==0
         and r.get("offline_oracle",{}).get("unparsed_payload_bytes")==0)) for r in origin.records)
    result["fixture_cleanup_terminated_child"]=True
    result["binary_sha256_after"]=hashlib.sha256(binary.read_bytes()).hexdigest()
    (root/"summary.json").write_text(json.dumps(result,indent=2)+"\n")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex",type=Path,default=shutil.which("codex"))
    parser.add_argument("--dll",type=Path,default=Path("build/guard/ttrace-guard.dll"))
    parser.add_argument("--action",choices=["block_request","block_session"],default="block_request")
    parser.add_argument("--transport",choices=["http","wss"],default="http")
    parser.add_argument("--output",type=Path,default=Path("runs/guard-tui")/uuid4().hex)
    parser.add_argument("--controller",action="store_true",help="Use public ttrace guard attach controller.")
    args=parser.parse_args()
    if hashlib.sha256(args.codex.read_bytes()).hexdigest()!=BINARY_SHA256:parser.error("baseline mismatch")
    result=experiment(args.codex,args.dll,args.output.resolve(),args.transport,args.action,args.controller)
    print(json.dumps({k:v for k,v in result.items() if k not in {"policy_events","origin_connections","subsequent_policy_events"}},indent=2))
    valid=(result["native_ready"] and result["denied"] and result["error_displayed"] and result["disk_unchanged"]
           and result["same_process_alive_after_denial"] and result["blocked_sensitive_body_zero_at_oracle"])
    valid=valid and (result["subsequent_request_allowed"] if args.action=="block_request" else result["subsequent_session_rejection"])
    if not valid:raise SystemExit(1)


if __name__=="__main__":main()
