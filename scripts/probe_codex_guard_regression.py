"""Small fake-data regression matrix, original Native DLL and policy contracts."""
import argparse
import hashlib
import json
from pathlib import Path

from _build_support import ROOT
from probe_guard_native import experiment
from transpect_trace.guard import BINARY_SHA256


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args(); binary=args.codex.resolve(); root=args.output.resolve()
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=BINARY_SHA256:parser.error('fixed baseline mismatch')
    root.mkdir(parents=True, exist_ok=False); rows=[]
    cases=[('allow','observe','none','prompt'),('deny','block_request','none','prompt'),
           ('credential','block_request','none','credential'),
           ('disconnect','observe','disconnect','prompt'),('timeout','observe','timeout','prompt'),
           ('malformed','observe','malformed_reply','prompt'),('read_discard','block_request','none','tool_read_discard')]
    for name,action,fault,scenario in cases:
        for protocol in ('http','wss'):
            result=experiment(binary,ROOT/'build/guard/ttrace-guard.dll',root/f'{name}-{protocol}',protocol,
                              action,fault=fault,scenario=scenario)
            denied=name not in ('allow','read_discard')
            passed=(result['native_ready'] and result['disk_unchanged'] and not result['fixture_cleanup_terminated_child']
                    and result['returncode']==(1 if denied else 0))
            if denied:passed=passed and result['blocked_sensitive_body_zero_at_oracle']
            else:passed=passed and any(r.get('payload_bytes',0)>0 for r in result['origin_connections'])
            rows.append(dict(case=name,protocol=protocol,passed=bool(passed),source_denied_body_zero=result['blocked_sensitive_body_zero_at_oracle'],
                             client_exit_code=result['returncode'],evidence=f'{name}-{protocol}/summary.json'))
            print(json.dumps(rows[-1]),flush=True)
    (root/'summary.json').write_text(json.dumps(dict(cases=rows,passed=all(r['passed'] for r in rows)),indent=2)+'\n')
    if not all(r['passed'] for r in rows):raise SystemExit(1)


if __name__=='__main__':main()
