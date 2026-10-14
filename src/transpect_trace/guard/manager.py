from __future__ import annotations

import ctypes as c
import json
from pathlib import Path
import subprocess
import sys
import time

from .baseline import inspect_binary
from .native import api,inject,process_identity,wait_ready
from .pipe import PipeServer
from .policy import GuardPolicy,PolicyEngine
from .etw import EtwSession
from .external import ExternalEngine


def attach_guard(pid:int,dll:Path,policy_file:Path,run_dir:Path,*,launched_cli=False,engine_command=None):
    identity=process_identity(pid,launched_cli=launched_cli)
    run_dir.mkdir(parents=True,exist_ok=False)
    if engine_command:
        replacements={"{pid}":str(pid),"{pipe}":rf"\\.\pipe\ttrace-guard-{pid}","{policy_file}":str(policy_file.resolve())}
        command=[]
        for arg in engine_command:
            for key,value in replacements.items():arg=arg.replace(key,value)
            command.append(arg)
        server=ExternalEngine(pid,command,run_dir/"audit.jsonl")
    else:server=PipeServer(pid,PolicyEngine(GuardPolicy.load(policy_file)),run_dir/"audit.jsonl")
    state={"schema":"transpect.guard.status/1.0","identity":identity,"state":"initializing",
           "started_at_unix_ns":time.time_ns(),"disk_mutation":False,"runtime":"native",
           "frida_runtime_dependency":False,"wss_streaming_coverage":"not_claimed",
           "content_scope":["HTTP EncodedJsonBody","WSS response.create serialized JSON"],
           "uncovered":["raw/multipart uploads","other WSS messages/streaming","daemon/app-server","non-Codex child egress"],
           "etw":{"state":"not_started","confidence":"Unknown"}}
    status=run_dir/"status.json"
    status.write_text(json.dumps(state,indent=2)+"\n")
    try:
        server.etw=EtwSession(dll.parent/"etw.exe",identity,run_dir/"etw.jsonl")
        server.etw.start();state["etw"]=server.etw.state
        server.start();loaded=inject(pid,dll,identity,launched_cli=launched_cli)
        identity["module_base"]=loaded.get("module_base")
        if not wait_ready(identity):raise RuntimeError("Native hooks did not attest readiness")
        state.update(state="active_limited",protected_since_unix_ns=time.time_ns())
        status.write_text(json.dumps(state,indent=2)+"\n")
        return server,state,status
    except Exception:
        state["state"]="initialization_failed"
        status.write_text(json.dumps(state,indent=2)+"\n")
        server.close()
        if hasattr(server,"etw"):server.etw.close(server.records,run_dir/"source-relations.jsonl")
        raise


def suspend(pid):
    k=api();handle=k.OpenProcess(0x800,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    try:
        n=c.WinDLL("ntdll");n.NtSuspendProcess.argtypes=[c.c_void_p];n.NtSuspendProcess.restype=c.c_long
        if n.NtSuspendProcess(handle):raise RuntimeError("Could not hold failed startup")
    finally:k.CloseHandle(handle)


def launch(binary:Path,args:list[str],dll:Path,policy:Path,run_dir:Path,engine_command=None):
    if not inspect_binary(binary)["supported"]:raise ValueError("fixed baseline mismatch")
    if not args or args[0]!="exec":
        raise ValueError("Native launcher currently validates 'codex exec'; use explicit PID attach for --no-daemon TUI")
    # Hold stdin EOF at the already-tested exec boundary. No account/provider/TLS edits.
    client=subprocess.Popen([str(binary),*args],stdin=subprocess.PIPE)
    try:
        server,state,status=attach_guard(client.pid,dll,policy,run_dir,launched_cli=True,engine_command=engine_command)
    except Exception:
        # Do not close stdin and accidentally release an unguarded request.
        suspend(client.pid)
        if client.stdin:client.stdin.close()
        raise RuntimeError(f"Guard startup failed; CLI PID {client.pid} is held suspended, not terminated")
    try:
        if "-" in args:
            data=sys.stdin.buffer.read(16*1024*1024+1)
            if len(data)>16*1024*1024:
                suspend(client.pid);state["state"]="held_suspended"
                raise ValueError("stdin exceeds v1 inspection limit; CLI is held suspended")
            client.stdin.write(data)
        client.stdin.close()
        try:code=client.wait()
        except KeyboardInterrupt:code=client.wait(timeout=10)
    finally:
        if client.stdin and not client.stdin.closed:client.stdin.close()
        server.close();server.etw.close(server.records,status.parent/"source-relations.jsonl")
        if state["state"]!="held_suspended":
            state["state"]="stopped" if client.poll() is not None else "controller_stopped_fail_closed"
        state["ended_at_unix_ns"]=time.time_ns()
        status.write_text(json.dumps(state,indent=2)+"\n")
    return code,state


def monitor(pid:int,server:PipeServer,state:dict,status:Path):
    k=api();handle=k.OpenProcess(0x100000,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    try:
        while k.WaitForSingleObject(handle,500)==258:pass
    except KeyboardInterrupt:
        state["state"]="controller_stopped_fail_closed"
    else:state["state"]="stopped"
    finally:
        k.CloseHandle(handle);server.close();server.etw.close(server.records,status.parent/"source-relations.jsonl")
        state["ended_at_unix_ns"]=time.time_ns()
        status.write_text(json.dumps(state,indent=2)+"\n")
