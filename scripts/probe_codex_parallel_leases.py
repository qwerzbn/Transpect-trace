"""Two fixed Codex owners, independent local destinations; no PID filtering claim."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import queue
import sys
import threading

from _build_support import ROOT
from _behavior_probe import ElevatedProcess
from probe_guard_native import experiment
from probe_wfp_lifecycle import Client, Source, Lease, blocked, delivered
from transpect_trace.behavior.collector import verify_collector
from transpect_trace.guard.native import process_identity, api
from transpect_trace.observe.windows import identity


def worker(args):
    owners=[]
    for pid,birth in [(args.pid_a,args.birth_a),(args.pid_b,args.birth_b)]:
        value=process_identity(pid)
        if value['creation_filetime']!=birth:
            raise ValueError('owner lifetime changed')
        owners.append(identity(pid))
    for name in ('wfp_lease.exe','egress_client.exe'):
        verify_collector(args.native_dir/name)
    args.output.mkdir(parents=True,exist_ok=False)
    sources=[];clients=[];leases=[];result=dict(passed=False,owners=owners,pid_filtering=False)
    try:
        for owner in owners:
            source=Source();sources.append(source)
            client=Client(args.native_dir/'egress_client.exe',source);clients.append(client)
            leases.append(Lease(args.native_dir/'wfp_lease.exe',client,args.output/f'filter-{len(leases)}.jsonl',owner=owner))
        result['both_blocked']=[client.request() for client in clients]
        # Abnormal termination of ONLY the first owned fixture, not network refusal.
        handle=api().OpenProcess(0x0001|0x1000|0x100000,False,owners[0]['pid'])
        if not handle:
            raise OSError('fixture owner handle unavailable')
        try:
            if process_identity(owners[0]['pid'])['creation_filetime']!=owners[0]['creation_filetime']:
                raise ValueError('owner generation changed')
            if not api().TerminateProcess(handle,77):
                raise OSError('fixture owner terminate failed')
            api().WaitForSingleObject(handle,5000)
        finally:
            api().CloseHandle(handle)
        leases[0].process.wait(5)
        result['owner_a_cleanup']=leases[0].finish()
        result['after_a_exit']=[client.request() for client in clients]
        result['owner_b_ready']=leases[1].state()
        result['owner_b_cleanup']=leases[1].finish()
        result['after_b_revoke']=clients[1].request()
        result['passed']=(all(map(blocked,result['both_blocked'])) and
            result['owner_a_cleanup']['state']['cleanup_confirmed'] and
            delivered(result['after_a_exit'][0]) and blocked(result['after_a_exit'][1]) and
            result['owner_b_ready']['protected'] and delivered(result['after_b_revoke']))
    finally:
        result['cleanup']=[lease.finish() for lease in leases]
        for client in clients:client.close()
        for source in sources:source.close()
        (args.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--native-dir',type=Path,required=True)
    p.add_argument('--codex',type=Path);p.add_argument('--worker',action='store_true')
    for name in ('pid-a','birth-a','pid-b','birth-b'):p.add_argument('--'+name,type=int)
    args=p.parse_args();args.output=args.output.resolve();args.native_dir=args.native_dir.resolve()
    if args.worker:
        result=worker(args)
    else:
        args.output.mkdir(parents=True,exist_ok=False)
        ready=queue.Queue();release=threading.Event()
        def run(name):
            def callback(subject):
                ready.put((name,subject))
                if not release.wait(60):raise RuntimeError('parallel fixture coordination timeout')
            return experiment(args.codex.resolve(),ROOT/'build/guard/ttrace-guard.dll',args.output/name,
                              'http','observe',on_ready=callback)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures={name:pool.submit(run,name) for name in ('a','b')}
            try:
                subjects=dict(ready.get(timeout=25) for _ in range(2))
                command=[str(Path(__file__).resolve()),'--worker','--output',str(args.output/'leases'),
                         '--native-dir',str(args.native_dir)]
                for name,subject in sorted(subjects.items()):
                    command += ['--pid-'+name,str(subject['pid']),'--birth-'+name,str(subject['creation_filetime'])]
                child=ElevatedProcess(sys.executable,command,ROOT)
                try:code=child.wait(35)
                finally:child.close()
                if code!=0:raise RuntimeError('parallel lease worker failed')
            finally:
                release.set()
            runs={name:future.result() for name,future in futures.items()}
        result=json.loads((args.output/'leases/summary.json').read_text())
        result['owner_exit_codes']={name:probe['returncode'] for name,probe in runs.items()}
        result['passed']=result['passed'] and result['owner_exit_codes']=={'a':77,'b':0}
        (args.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(dict(passed=result['passed'],owner_exit_codes=result['owner_exit_codes'])))
    if not result['passed']:raise SystemExit(2)


if __name__=='__main__':main()
