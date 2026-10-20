"""Fixed Codex owner abnormal exit: lease cleanup, never a request-rejection demonstration."""
import argparse
import json
from pathlib import Path
import sys

from _build_support import ROOT
from _behavior_probe import ElevatedProcess
from probe_guard_native import experiment
from probe_wfp_lifecycle import Source, Client, Lease, blocked, delivered
from transpect_trace.behavior.collector import verify_collector
from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.native import api, process_identity
from transpect_trace.observe.windows import identity


def worker(args):
    subject = process_identity(args.pid)
    if subject['creation_filetime'] != args.birth or subject['baseline']['sha256'] != BINARY_SHA256:
        raise ValueError('fixed owner identity mismatch')
    for name in ('wfp_lease.exe','egress_client.exe'):
        verify_collector(args.native_dir/name)
    args.output.mkdir(parents=True,exist_ok=False)
    source=Source();client=Client(args.native_dir/'egress_client.exe',source);lease=None
    result=dict(passed=False, deliberate_fixture_owner_termination=True,
                demonstrates_request_refusal=False, pid_filtering=False)
    try:
        result['before']=client.request()
        lease=Lease(args.native_dir/'wfp_lease.exe',client,args.output/'filter.jsonl',owner=identity(args.pid))
        result['ready']=lease.state();result['during']=client.request()
        # Recheck lifetime before terminating only the fixed, held-stdin fixture.
        if process_identity(args.pid)['creation_filetime'] != args.birth:
            raise ValueError('owner generation changed')
        handle=api().OpenProcess(0x0001|0x1000|0x100000,False,args.pid)
        if not handle:
            raise OSError('cannot open fixture owner')
        try:
            if not api().TerminateProcess(handle,77):
                raise OSError('fixture termination failed')
            api().WaitForSingleObject(handle,5000)
        finally:
            api().CloseHandle(handle)
        # Wait for owner-exit cleanup; no revoke command until after this wait.
        result['owner_exit_lease_returncode']=lease.process.wait(5)
        result['finish']=lease.finish();result['after']=client.request()
        result['passed']=(delivered(result['before']) and result['ready']['protected'] and
            blocked(result['during']) and delivered(result['after']) and
            result['finish']['state']['cleanup_confirmed'] and any(
                r.get('reason')=='owner_exit' for r in result['finish']['records']))
    finally:
        if lease:
            result['cleanup']=lease.finish()
        client.close();source.close()
        (args.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--native-dir',type=Path,required=True)
    parser.add_argument('--codex',type=Path)
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--pid',type=int)
    parser.add_argument('--birth',type=int)
    args=parser.parse_args();args.output=args.output.resolve();args.native_dir=args.native_dir.resolve()
    if args.worker:
        result=worker(args)
    else:
        args.output.mkdir(parents=True,exist_ok=False)
        def ready(subject):
            process=ElevatedProcess(sys.executable,[str(Path(__file__).resolve()),'--worker',
                '--output',str(args.output/'lease'),'--native-dir',str(args.native_dir),
                '--pid',str(subject['pid']),'--birth',str(subject['creation_filetime'])],ROOT)
            try:
                code=process.wait(30)
            finally:
                process.close()
            if code!=0:
                raise RuntimeError('owner exit experiment failed')
        probe=experiment(args.codex.resolve(),ROOT/'build/guard/ttrace-guard.dll',args.output/'codex',
                         'http','observe',on_ready=ready)
        result=json.loads((args.output/'lease/summary.json').read_text())
        result['fixture_owner_exit_code']=probe['returncode']
        result['passed']=result['passed'] and probe['returncode']==77
        (args.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(dict(passed=result['passed'],fixture_owner_exit_code=probe['returncode'])))
    if not result['passed']:
        raise SystemExit(2)


if __name__=='__main__':main()
