"""Preinstalled path-scoped WFP lease against a synthetic Codex tool descendant."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import socket
import subprocess
import threading
import time

from _build_support import ROOT
from _behavior_probe import ElevatedProcess
from probe_guard_native import experiment
from transpect_trace.behavior.collector import verify_collector
from transpect_trace.observe.windows import identity
from transpect_trace.guard import BINARY_SHA256


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--elevate',action='store_true')
    parser.add_argument('--native-dir',type=Path,default=ROOT/'build/behavior')
    args=parser.parse_args();root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    binary=args.codex.resolve()
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=BINARY_SHA256:parser.error('fixed baseline mismatch')
    client_exe=args.native_dir.resolve()/'egress_client.exe';helper=args.native_dir.resolve()/'wfp_lease.exe'
    for p in (client_exe,helper):verify_collector(p)
    source=socket.socket();source.bind(('127.0.0.1',0));source.listen();source.settimeout(.2)
    received=[];stop=threading.Event()
    def serve():
        while not stop.is_set():
            try:conn,_=source.accept()
            except socket.timeout:continue
            except OSError:break
            with conn:
                conn.settimeout(3);total=0
                try:
                    while data:=conn.recv(4096):total+=len(data)
                except OSError:pass
                received.append(total)
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    # This canary proves/restricts the app identity before the Codex child exists.
    # WFP will match both instances by path; this is explicitly not PID filtering.
    canary=subprocess.Popen([str(client_exe),str(source.getsockname()[1])],stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    replies=queue.Queue()
    def read():
        for line in canary.stdout:replies.put(json.loads(line))
    threading.Thread(target=read,daemon=True).start()
    lease=None;summary=dict(passed=False,pid_exact_filter=False,scope='preinstalled_synthetic_image_path_loopback_tcp',
        can_enforce_arbitrary_descendants=False,helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest())
    def request():
        before=sum(received)
        canary.stdin.write('send\n');canary.stdin.flush();reply=replies.get(timeout=5);time.sleep(.2)
        reply['source_bytes_delta']=sum(received)-before
        return reply
    try:
        subject=identity(canary.pid);summary['canary']=subject
        summary['before']=request();before_bytes=sum(received)
        def ready(owner):
            nonlocal lease
            argv=[str(canary.pid),str(subject['creation_filetime']),subject['image_sha256'],str(source.getsockname()[1]),'20',str(root/'filter.jsonl')]
            argv += ['--owner',str(owner['pid']),str(owner['creation_filetime']),BINARY_SHA256]
            lease=ElevatedProcess(helper,argv,ROOT) if args.elevate else subprocess.Popen([str(helper),*argv],creationflags=0x08000000)
            until=time.monotonic()+6
            while time.monotonic()<until:
                p=root/'filter.jsonl'
                if p.exists() and any(json.loads(x).get('kind')=='filter.installed' for x in p.read_text().splitlines()):return
                if lease.poll() is not None:break
                time.sleep(.05)
            raise RuntimeError('Filter was not installed before releasing the fake Codex task')
        command=f"& '{client_exe}' {source.getsockname()[1]} --once"
        result=experiment(binary,ROOT/'build/guard/ttrace-guard.dll',root/'http','http','observe',scenario='tool_network',
                          tool_command=command,behavior_compare=True,elevate_behavior=args.elevate,on_ready=ready,
                          behavior_collector=args.native_dir.resolve()/'etw.exe')
        summary['source_bytes_during']=sum(received)-before_bytes
        summary['lease_exit_code']=lease.wait(timeout=25)
        transcript=(root/'http/client.stdout.jsonl').read_text(encoding='utf-8')
        # Inspect only fake-data execution output; persist booleans, never full output.
        tool_replies=[]
        for line in transcript.splitlines():
            try: item=json.loads(line).get('item',{})
            except ValueError: continue
            if item.get('type')!='command_execution' or item.get('status')!='completed':continue
            for output_line in item.get('aggregated_output','').splitlines():
                try: reply=json.loads(output_line)
                except ValueError: continue
                if isinstance(reply,dict):tool_replies.append(reply)
        summary['tool_reported_access_denied']=any(r.get('connect_error')==10013 and r.get('sent_bytes')==0
            and r.get('failure_stage')=='connect' for r in tool_replies)
        report=json.loads((root/'http/behavior/report.json').read_text())
        starts=[json.loads(x) for x in (root/'http/behavior/events.jsonl').read_text().splitlines()]
        children=[r for r in starts if r['kind']=='process.start' and r['subject'].get('image_sha256')==subject['image_sha256']]
        summary['child_process_events']=[dict(event_id=r['event_id'],subject=r['subject'],parent_identity=r['parent_identity']) for r in children]
        summary['behavior_health']=report['health']
        summary['native_ready']=result['native_ready'];summary['client_returncode']=result['returncode']
        summary['after']=request()
        summary['filter_records']=[json.loads(x) for x in (root/'filter.jsonl').read_text().splitlines()]
        summary['passed']=bool(summary['before']['sent_bytes']==summary['before']['source_bytes_delta']>0 and
            summary['after']['sent_bytes']==summary['after']['source_bytes_delta']>0 and
            summary['source_bytes_during']==0 and summary['tool_reported_access_denied'] and children and
            summary['lease_exit_code']==0 and result['returncode']==0 and report['health']['state']=='stopped')
    except (OSError,RuntimeError,queue.Empty,subprocess.TimeoutExpired) as error:
        summary.update(error_type=type(error).__name__,win32_error=getattr(error,'winerror',None))
    finally:
        if lease and isinstance(lease,ElevatedProcess):lease.wait(timeout=25);lease.close()
        canary.stdin.write('quit\n');canary.stdin.flush();canary.wait(timeout=5)
        stop.set();source.close();thread.join(3)
        (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    if not summary['passed']:raise SystemExit(2)


if __name__=='__main__':main()
