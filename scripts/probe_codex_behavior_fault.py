"""Kill only this experiment's ETW collector; verify degraded evidence and independent Guard."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import sys
import time

from _build_support import ROOT
from _behavior_probe import ElevatedProcess
from probe_guard_native import experiment
from transpect_trace.behavior.collector import CodexBehaviorCollector
from transpect_trace.guard.native import process_identity


class Wnode(c.Structure):
    _fields_ = [('BufferSize',w.ULONG),('ProviderId',w.ULONG),('HistoricalContext',c.c_ulonglong),
                ('TimeStamp',c.c_longlong),('Guid',c.c_byte*16),('ClientContext',w.ULONG),('Flags',w.ULONG)]


class Properties(c.Structure):
    _fields_ = [('Wnode',Wnode), *[(name,w.ULONG) for name in (
        'BufferSize','MinimumBuffers','MaximumBuffers','MaximumFileSize','LogFileMode','FlushTimer',
        'EnableFlags','AgeLimit','NumberOfBuffers','FreeBuffers','EventsLost','BuffersWritten',
        'LogBuffersLost','RealTimeBuffersLost')], ('LoggerThreadId',w.HANDLE),
        ('LogFileNameOffset',w.ULONG),('LoggerNameOffset',w.ULONG)]


def trace_control(collector_pid, operation):
    # Only called with the Popen PID whose process handle this worker owns.
    storage = c.create_string_buffer(c.sizeof(Properties)+4096)
    properties = Properties.from_buffer(storage)
    properties.Wnode.BufferSize = len(storage)
    properties.LoggerNameOffset = c.sizeof(Properties)
    properties.LogFileNameOffset = c.sizeof(Properties)+2048
    api = c.WinDLL('advapi32').ControlTraceW
    api.argtypes = [c.c_ulonglong,w.LPCWSTR,c.POINTER(Properties),w.ULONG]
    api.restype = w.ULONG
    return api(0,f'TranspectBehavior-{collector_pid}',c.byref(properties),operation)


def worker(args):
    subject = process_identity(args.pid)
    if subject['creation_filetime'] != args.birth:
        raise ValueError('process generation changed')
    collector = CodexBehaviorCollector(subject,args.collector,args.output,duration=10)
    value = dict(passed=False)
    try:
        value['before'] = collector.start()
        if value['before']['state'] != 'ready':
            raise RuntimeError('ETW not ready; fault injection not executed')
        value['session_query_before'] = trace_control(collector.process.pid,0)
        time.sleep(.3)
        collector.process.terminate()
        collector.process.wait(5)
        value['after'] = collector.wait()
        # A killed native timer cannot stop its ETW session. Recover only our own.
        value['session_query_after_crash'] = trace_control(collector.process.pid,0)
        value['cleanup_stop_error'] = trace_control(collector.process.pid,1)
        value['session_query_after_cleanup'] = trace_control(collector.process.pid,0)
        value['passed'] = (value['after']['state'] == 'degraded' and
            'collector_exit_without_terminal' in value['after']['gaps'] and
            value['session_query_after_cleanup'] == 4201)
    finally:
        if collector.process and collector.process.poll() is None:
            collector.wait()
        (args.output/'fault-summary.json').write_text(json.dumps(value,indent=2)+'\n')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--collector',type=Path,required=True)
    parser.add_argument('--codex',type=Path)
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--pid',type=int)
    parser.add_argument('--birth',type=int)
    args=parser.parse_args();args.output=args.output.resolve();args.collector=args.collector.resolve()
    if args.worker:
        result=worker(args)
    else:
        args.output.mkdir(parents=True,exist_ok=False)
        rows=[]
        for name,action in [('allow','observe'),('deny','block_request')]:
            output=args.output/name
            def ready(subject):
                elevated=ElevatedProcess(sys.executable,[str(Path(__file__).resolve()),'--worker',
                    '--output',str(output/'behavior'),'--collector',str(args.collector),
                    '--pid',str(subject['pid']),'--birth',str(subject['creation_filetime'])],ROOT)
                try:
                    code=elevated.wait(25)
                finally:
                    elevated.close()
                if code != 0:
                    raise RuntimeError('ETW fault worker failed; inspect fault-summary')
            probe=experiment(args.codex.resolve(),ROOT/'build/guard/ttrace-guard.dll',output,
                             'http',action,on_ready=ready)
            fault=json.loads((output/'behavior/fault-summary.json').read_text())
            rows.append(dict(case=name,etw=fault,native_ready=probe['native_ready'],
                source_denied_body_zero=probe['blocked_sensitive_body_zero_at_oracle'],
                passed=fault['passed'] and not probe['fixture_cleanup_terminated_child'] and
                    probe['returncode']==(0 if name=='allow' else 1) and
                    (probe['blocked_sensitive_body_zero_at_oracle'] if name=='deny' else
                     any(r.get('payload_bytes',0)>0 for r in probe['origin_connections']))))
        result=dict(cases=rows,passed=all(r['passed'] for r in rows))
        (args.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
    if not result['passed']:
        raise SystemExit(2)


if __name__=='__main__':main()
