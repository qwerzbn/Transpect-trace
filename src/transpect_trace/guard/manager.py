from __future__ import annotations

import ctypes as c
import json
import os
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


def attach_guard(pid:int,dll:Path,policy_file:Path,run_dir:Path,*,launched_cli=False,engine_command=None,engine_factory=None,
                 capture_requests=True,egress_policy=None,egress_dll=None):
    identity=process_identity(pid,launched_cli=launched_cli)
    run_dir.mkdir(parents=True,exist_ok=False)
    if engine_command:
        replacements={"{pid}":str(pid),"{pipe}":rf"\\.\pipe\ttrace-guard-{pid}","{policy_file}":str(policy_file.resolve())}
        command=[]
        for arg in engine_command:
            for key,value in replacements.items():arg=arg.replace(key,value)
            command.append(arg)
        server=ExternalEngine(pid,command,run_dir/"audit.jsonl")
    else:server=PipeServer(pid,engine_factory(identity) if engine_factory else PolicyEngine(GuardPolicy.load(policy_file)),run_dir/"audit.jsonl")
    server.request_capture=None;server.egress=None
    if capture_requests and not engine_command:
        from transpect_trace.observe.request_capture import GuardRequestTap
        subject={**identity,'image_sha256':identity['baseline']['sha256']}
        content_policy=server.engine.policy if isinstance(server.engine.policy,GuardPolicy) else None
        server.request_capture=GuardRequestTap(run_dir/'capture',subject,policy=content_policy)
        server.request_tap=server.request_capture
    state={"schema":"transpect.guard.status/1.0","identity":identity,"state":"initializing",
           "started_at_unix_ns":time.time_ns(),"disk_mutation":False,"runtime":"native",
           "frida_runtime_dependency":False,"wss_streaming_coverage":"not_claimed",
           "content_scope":["HTTP EncodedJsonBody","WSS response.create serialized JSON"],
           "uncovered":["raw/multipart uploads","other WSS messages/streaming","daemon/app-server","non-Codex child egress"],
           "etw":{"state":"not_started","confidence":"Unknown"}}
    from transpect_trace.observe.windows import identity as controller_identity
    state['controller_identity']=controller_identity(os.getpid())
    state['capture']={'adapter':'codex-request','capture_layer':'request-body','hook_owner':'native-guard',
        'tls_plaintext_capture':False,'state':'initializing' if server.request_capture else 'not_enabled'}
    state['tool_egress']={'state':'not_enabled','can_enforce':False}
    status=run_dir/"status.json"
    status.write_text(json.dumps(state,indent=2)+"\n")
    try:
        server.etw=EtwSession(dll.parent/"etw.exe",identity,run_dir/"etw.jsonl")
        server.etw.start();state["etw"]=server.etw.state
        server.start();loaded=inject(pid,dll,identity,launched_cli=launched_cli)
        identity["module_base"]=loaded.get("module_base")
        if not wait_ready(identity):raise RuntimeError("Native hooks did not attest readiness")
        if egress_policy is not None:
            from transpect_trace.behavior.native_egress import EgressController
            server.egress=EgressController(identity,egress_dll or Path('build/egress/ttrace-egress.dll'),egress_policy,run_dir/'egress')
            server.egress.start();state['tool_egress']=dict(server.egress.state)
        if server.request_capture:state['capture']=server.request_capture.status()
        state.update(state="active_limited",protected_since_unix_ns=time.time_ns())
        status.write_text(json.dumps(state,indent=2)+"\n")
        return server,state,status
    except Exception:
        state["state"]="initialization_failed"
        close_components(server,state,status)
        status.write_text(json.dumps(state,indent=2)+"\n")
        raise


def suspend(pid):
    k=api();handle=k.OpenProcess(0x800,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    try:
        n=c.WinDLL("ntdll");n.NtSuspendProcess.argtypes=[c.c_void_p];n.NtSuspendProcess.restype=c.c_long
        if n.NtSuspendProcess(handle):raise RuntimeError("Could not hold failed startup")
    finally:k.CloseHandle(handle)


def close_components(server,state,status):
    failures=[]
    def finish(name,callback):
        try:callback()
        except Exception as error:failures.append({'component':name,'error_type':type(error).__name__})
    finish('policy_service',server.close)
    capture=getattr(server,'request_capture',None)
    if capture:
        finish('request_capture',capture.close)
        finish('request_capture_status',lambda:state.update(capture=capture.status()))
    egress=getattr(server,'egress',None)
    if egress:
        finish('tool_egress',egress.close)
        state['tool_egress']=dict(egress.state)
    etw=getattr(server,'etw',None)
    if etw:
        finish('etw',lambda:etw.close(server.records,status.parent/'source-relations.jsonl'))
        state['etw']=dict(etw.state)
        if any(e['component']=='etw' for e in failures):state['etw']['finalization']='unavailable'
    state['cleanup']={'complete':not failures,'errors':failures}


def update_health(server,state,status,terminal=None):
    previous=json.dumps(state,sort_keys=True)
    if hasattr(server,'threads'):
        alive=sum(thread.is_alive() for thread in server.threads)
    else:
        process=getattr(server,'process',None)
        alive=int(process is not None and process.poll() is None and getattr(server,'thread',None) is not None and server.thread.is_alive())
    service_ok=alive>0 and not server.errors
    state['policy_service']={'state':'ready' if service_ok else 'degraded_fail_closed','live_workers':alive,
        'error_count':len(server.errors)}
    if not service_ok:state['state']='degraded_policy_service_fail_closed'
    if getattr(server,'request_capture',None):state['capture']=server.request_capture.status()
    if getattr(server,'egress',None):
        state['tool_egress']=dict(server.egress.state)
        if not server.egress.state.get('can_enforce') or server.egress.errors:
            state['state']='degraded_tool_egress' if service_ok else 'degraded_policy_and_tool_egress'
    if terminal is not None:
        output_alive=terminal.thread.is_alive()
        terminal_ok=not terminal.errors and (output_alive or terminal.poll() is not None)
        state['terminal']={'state':'ready' if terminal_ok else 'degraded_io',
            'output_worker_alive':output_alive,'errors':sorted(set(terminal.errors)),
            'user_input_released':terminal.input_ready.is_set()}
        if not terminal_ok:state['state']='degraded_terminal_io'
    state['etw']=dict(server.etw.state)
    if previous!=json.dumps(state,sort_keys=True):status.write_text(json.dumps(state,indent=2)+'\n')


def launch(binary:Path,args:list[str],dll:Path,policy:Path,run_dir:Path,engine_command=None,engine_factory=None,
           capture_requests=True,egress_policy=None,egress_dll=None):
    if not inspect_binary(binary)["supported"]:raise ValueError("fixed baseline mismatch")
    if not args or args[0]!="exec":
        from .native import cli_mode
        if cli_mode([str(binary),*args])!='tui_no_daemon':
            raise ValueError('Use exec or controlled --no-daemon TUI without an initial prompt')
        return launch_tui(binary,args,dll,policy,run_dir,engine_command=engine_command,engine_factory=engine_factory,
            capture_requests=capture_requests,egress_policy=egress_policy,egress_dll=egress_dll)
    # Hold stdin EOF at the already-tested exec boundary. No account/provider/TLS edits.
    client=subprocess.Popen([str(binary),*args],stdin=subprocess.PIPE)
    try:
        server,state,status=attach_guard(client.pid,dll,policy,run_dir,launched_cli=True,engine_command=engine_command,engine_factory=engine_factory,
            capture_requests=capture_requests,egress_policy=egress_policy,egress_dll=egress_dll)
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
        try:
            while client.poll() is None:
                update_health(server,state,status);time.sleep(.2)
            code=client.returncode
        except KeyboardInterrupt:code=client.wait(timeout=10)
    finally:
        if client.stdin and not client.stdin.closed:client.stdin.close()
        close_components(server,state,status)
        if state["state"]!="held_suspended":
            state["state"]="stopped" if client.poll() is not None else "controller_stopped_fail_closed"
        state["ended_at_unix_ns"]=time.time_ns()
        status.write_text(json.dumps(state,indent=2)+"\n")
    return code,state


def launch_tui(binary,args,dll,policy,run_dir,**options):
    from .terminal import TerminalProcess
    import threading
    def output(data):
        stream=getattr(sys.stdout,'buffer',None)
        if stream:stream.write(data);stream.flush()
        else:sys.stdout.write(data.decode('utf-8',errors='replace'));sys.stdout.flush()
    terminal=TerminalProcess([str(binary),*args],output=output)
    try:
        server,state,status=attach_guard(terminal.pid,dll,policy,run_dir,launched_cli=True,**options)
    except Exception:
        if terminal.poll() is None:suspend(terminal.pid)
        # Retain the owned console: closing it could terminate the held client.
        _held_terminals.append(terminal)
        raise RuntimeError(f'TUI initialization failed; PID {terminal.pid} held with user input unreleased')
    state['startup']={'mode':'tui_no_daemon','input_released_after_gate_ready':True,
        'pre_ready_guard_requests':sum(r.get('kind')=='policy.decision' for r in server.records),
        'pre_hook_network_observation':'not_attested'}
    terminal.mark_gate_ready()
    threading.Thread(target=terminal.forward_input,daemon=True).start()
    try:
        while terminal.poll() is None:
            update_health(server,state,status,terminal=terminal);time.sleep(.2)
        code=terminal.poll()
    except KeyboardInterrupt:
        terminal.write(b'\x03');code=terminal.wait(10)
    finally:
        close_components(server,state,status)
        state['state']='stopped' if terminal.poll() is not None else 'controller_stopped_fail_closed'
        state['ended_at_unix_ns']=time.time_ns();status.write_text(json.dumps(state,indent=2)+'\n')
        if terminal.poll() is not None:terminal.close()
    return code,state


_held_terminals=[]


def monitor(pid:int,server:PipeServer,state:dict,status:Path):
    k=api();handle=k.OpenProcess(0x100000,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    try:
        while k.WaitForSingleObject(handle,500)==258:update_health(server,state,status)
    except KeyboardInterrupt:
        state["state"]="controller_stopped_fail_closed"
    else:state["state"]="stopped"
    finally:
        k.CloseHandle(handle);close_components(server,state,status)
        state["ended_at_unix_ns"]=time.time_ns()
        status.write_text(json.dumps(state,indent=2)+"\n")
