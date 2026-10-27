"""Real PowerShell A modifies JSON; independent HTTPX B uploads its raw bytes.

Explicit fake-data experiment. Regular file handoff, no business Named Pipe.
Native I/O observes both applications; the restored fixed Python Native Gate
checks B before HTTPX delegates to its original transport. No proxy, TLS
replacement, Windows trust installation, execution-policy changes or UAC.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from uuid import uuid4

from _build_support import ROOT
from probe_codex_tls import certificate
from transpect_trace.behavior.native_egress import inspect_process
from transpect_trace.flow.native import NativeIOCollector
from transpect_trace.flow.file_upload_policy import FileUploadPolicyEngine
from transpect_trace.flow.scenarios.sources import BusinessOrigin
from transpect_trace.observe.windows import identity
from transpect_trace.protect.detection import ContentIndex
from transpect_trace.protect.pipe import ProtectionServer

PS_SCRIPT = r'''
param([string]$Config)
$ErrorActionPreference='Stop'
$c=Get-Content -Raw -LiteralPath $Config | ConvertFrom-Json
Write-Output ('{"kind":"application-a.ready","pid":'+$PID+'}')
if ([Console]::ReadLine() -ne 'RUN') { exit 2 }
try {
  $d=[IO.File]::ReadAllText($c.source,[Text.Encoding]::UTF8) | ConvertFrom-Json
  $out=[ordered]@{ticket=$d.ticket;summary=$d.report.ToUpperInvariant();revision=([int]$d.revision+1)}
  if ($c.preserve) { $out['api_key']=$d.api_key; $out['private_note']=$d.private_note }
  $bytes=[Text.Encoding]::UTF8.GetBytes(($out | ConvertTo-Json -Depth 4 -Compress))
  [IO.File]::WriteAllBytes($c.modified,$bytes)
  Write-Output '{"kind":"application-a.done","ok":true}'
} catch { Write-Output '{"kind":"application-a.done","ok":false}'; }
$null=[Console]::ReadLine()
'''

B_SCRIPT = r'''
import json,ssl,sys
from pathlib import Path
import httpx
c=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
try:
    body=Path(c['modified']).read_bytes()
    with httpx.Client(verify=ssl.create_default_context(cafile=c['ca']),trust_env=False) as client:
        response=client.post(c['url'],content=body,headers={'Content-Type':'application/json'})
    result={'kind':'application-b.done','outcome':'response','status':response.status_code}
except PermissionError:
    result={'kind':'application-b.done','outcome':'native_denied'}
except Exception as error:
    result={'kind':'application-b.done','outcome':'failed','error_type':type(error).__name__}
print(json.dumps(result),flush=True)
sys.stdin.readline()
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class Output:
    """Bounded public control records, never raw application output in logs."""
    def __init__(self, process):
        self.queue = queue.Queue(maxsize=16)
        def read():
            try:
                while True:
                    line = process.stdout.readline(4097)
                    if not line:
                        return
                    if len(line) > 4096:
                        self.queue.put_nowait({'kind':'invalid'})
                        return
                    self.queue.put_nowait(json.loads(line))
            except Exception:
                try:
                    self.queue.put_nowait({'kind':'invalid'})
                except queue.Full:
                    pass
        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()

    def get(self, kind, seconds=20):
        value = self.queue.get(timeout=seconds)
        if value.get('kind') != kind:
            raise RuntimeError('unexpected_control_record')
        return value


def release(process, text):
    # Runner's handshake is deliberately byte-exact LF. Windows TextIOWrapper
    # would translate to CRLF and fail the ready->RUN boundary.
    process.stdin.buffer.write((text+'\n').encode('utf-8'))
    process.stdin.buffer.flush()


def transformed(source, preserve):
    result = {'ticket':source['ticket'], 'summary':source['report'].upper(), 'revision':source['revision']+1}
    if preserve:
        result.update(api_key=source['api_key'], private_note=source['private_note'])
    return json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def run_case(root, name, args):
    from transpect_trace.flow.file_upload_evidence import assess_file_upload
    root.mkdir(parents=True, exist_ok=False)
    fixtures = root/'explicit-fake-fixtures'
    fixtures.mkdir()
    secret = 'FAKE_ONLY_REGISTERED_PRIVATE_NOTE_'+uuid4().hex
    source = {'ticket':'FAKE-ONLY', 'report':'alpha incident', 'revision':0}
    sensitive = name != 'ordinary'
    preserve = name == 'sensitive'
    if sensitive:
        source.update(api_key='FAKE_ONLY_KEY_'+uuid4().hex, private_note=secret)
    original = json.dumps(source, separators=(',', ':')).encode()
    modified = transformed(source, preserve)
    source_path, modified_path = fixtures/'original.json', fixtures/'modified.json'
    source_path.write_bytes(original)
    a_script, b_script = fixtures/'modify.ps1', fixtures/'upload.py'
    a_script.write_text(PS_SCRIPT, encoding='ascii')
    b_script.write_text(B_SCRIPT, encoding='ascii')
    a_config, b_config = fixtures/'a.json', fixtures/'b.json'
    save(a_config, {'source':str(source_path), 'modified':str(modified_path), 'preserve':preserve})
    cert, key, ca = certificate(fixtures)
    origin = BusinessOrigin(cert, key).start()
    save(b_config, {'modified':str(modified_path), 'ca':str(ca), 'url':origin.webhook_url})
    index = ContentIndex.register('file-modify-upload/1', [("fixture-private-note", secret, 'CONFIDENTIAL', ['registered_text'])])
    save(root/'content-index.json', index.model_dump())
    engine = FileUploadPolicyEngine(index)
    rows, subjects, observers, processes = [], {}, {}, []
    gate = None
    cleanup_kill = False
    outcome_a = outcome_b = None
    errors = []
    try:
        # Ordinary -Command execution, without loading a .ps1 under a changed
        # execution policy. The saved script is a reproducibility artifact.
        command = '& { '+PS_SCRIPT+' } -Config \''+str(a_config).replace("'", "''")+"'"
        a = subprocess.Popen([str(args.powershell), '-NoLogo', '-NoProfile', '-NonInteractive',
                              '-Command', command],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, encoding='utf-8', creationflags=0x08000000)
        processes.append(a)
        a_output = Output(a)
        a_ready = a_output.get('application-a.ready')
        if a_ready['pid'] != a.pid:
            raise RuntimeError('powershell_identity_mismatch')
        a_identity = identity(a_ready['pid'])
        subjects['A'] = {**a_identity, 'parent_pid':inspect_process(a_ready['pid'])['parent_pid']}
        b = subprocess.Popen([sys.executable, '-m', 'transpect_trace.protect.python_runner'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, encoding='utf-8', creationflags=0x08000000)
        processes.append(b)
        b_output = Output(b)
        release(b, json.dumps({'dll':str(args.gate_dll.resolve()), 'manifest':str(args.gate_manifest.resolve()),
                              'server_pid':os.getpid(), 'run_id':root.name,
                              'script':str(b_script), 'arguments':[str(b_config)], 'mode':'outbound-json'}))
        b_ready = b_output.get('protect.ready')
        if not b_ready.get('gate_ready'):
            raise RuntimeError('native_gate_not_ready')
        b_identity = identity(b_ready['pid'])
        b_details = inspect_process(b_ready['pid'])
        # CPython venv's launcher can be the immediate parent. Bind the actual
        # ready PID to that child, not to an arbitrary same-image interpreter.
        if b_ready['pid'] != b.pid and b_details['parent_pid'] != b.pid:
            raise RuntimeError('python_start_identity_mismatch')
        subjects['B'] = {**b_identity, 'parent_pid':b_details['parent_pid']}
        gate = ProtectionServer(b_identity, engine, root/'policy.jsonl')
        gate.start()
        lock = threading.Lock()
        def capture(row):
            public = {k:v for k,v in row.items() if k != 'data'}
            public.update(data_sha256=sha(row['data']), data_bytes=len(row['data']))
            with lock:
                rows.append(public)
        for role, subject, scopes in (
                ('A', a_identity, [{'role':'source','path':source_path}, {'role':'transfer','path':modified_path}]),
                ('B', b_identity, [{'role':'transfer','path':modified_path}])):
            observers[role] = NativeIOCollector(subject, args.io_dll, args.io_manifest, capture, scopes=scopes)
            observers[role].start()
        # B stays idle; ordinary application A reads, edits and closes the file.
        release(a, 'RUN')
        outcome_a = a_output.get('application-a.done')
        if outcome_a.get('ok') is not True:
            raise RuntimeError('powershell_transform_failed')
        # Expected bytes are from the independent transformation oracle; reading
        # the output here is only an extra fixture check, not I/O evidence.
        if modified_path.read_bytes() != modified:
            raise RuntimeError('powershell_transform_oracle_mismatch')
        release(b, 'RUN')
        outcome_b = b_output.get('application-b.done', 30)
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            expected = {row['attempt_id'] for row in engine.captures}
            executed = {row['attempt_id'] for row in gate.execution_records}
            if expected and expected <= executed:
                break
            time.sleep(.02)
    except Exception as error:
        errors.append(type(error).__name__)
        # Only a fixed local diagnostic code may be persisted, never arbitrary
        # exception messages from potentially sensitive application content.
        if isinstance(error, RuntimeError) and error.args and error.args[0] in {
                'powershell_identity_mismatch','native_gate_not_ready','python_start_identity_mismatch',
                'powershell_transform_failed','powershell_transform_oracle_mismatch','unexpected_control_record'}:
            errors.append(error.args[0])
    finally:
        for observer in observers.values():
            observer.close()
        for process in processes:
            try:
                release(process, 'FINISH')
            except (OSError, ValueError):
                pass
        for process in processes:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                cleanup_kill = True
                process.terminate()
                process.wait(timeout=5)
        if gate:
            gate.close()
        origin.close()
    health = {role:observer.status() for role,observer in observers.items()}
    health['gate'] = {'ready':bool(gate and gate.listening.is_set()),
                      'identity_verified':bool(gate and subjects.get('B')),
                      'execution_drained':bool(engine.captures) and
                        {r['attempt_id'] for r in engine.captures} <= {r['attempt_id'] for r in gate.execution_records} if gate else False,
                      'errors':gate.errors if gate else ['not_started']}
    health['receiver'] = {'ready':True, 'terminal':not origin.thread.is_alive(),
                          'pending_requests':len(origin._active), 'errors':list(origin.errors)}
    receipt_rows = [{**row, 'complete':row.get('completeness') == 'complete' and 'error' not in row}
                    for row in origin.receipts]
    executions = gate.execution_records if gate else []
    result = assess_file_upload(subjects=subjects, io_rows=rows,
        original_sha256=sha(original), original_bytes=len(original),
        modified_sha256=sha(modified), modified_bytes=len(modified),
        body_capture=engine.captures, execution_records=executions,
        receipts=receipt_rows, health=health, expected_block=preserve)
    result['checks'].update(client_a_completed=outcome_a is not None and outcome_a.get('ok') is True,
        client_b_expected_result=outcome_b is not None and
           (outcome_b.get('outcome') == 'native_denied' if preserve else outcome_b.get('outcome') == 'response' and outcome_b.get('status') == 200),
        no_cleanup_kill=not cleanup_kill, no_orchestration_errors=not errors,
        normal_process_exit=bool(processes) and all(p.returncode == 0 for p in processes))
    result['passed'] = all(result['checks'].values())
    result.update(case=name, application_a='Windows PowerShell 5.1', application_b='CPython 3.12 + HTTPX 0.28.1',
        business_transport='regular_file', business_named_pipe_used=False,
        content_control='Python Native Gate before HTTPX transport',
        observation_can_enforce=False, default_persistent_protection=False,
        etw_rerun=False, ecapture_rerun=False, windows_trust_changed=False,
        proxy_used=False, tls_replaced=False, errors=errors,
        subjects=subjects, native_health=health, client_a=outcome_a, client_b=outcome_b,
        captures=engine.captures, execution_records=executions, receipts=receipt_rows,
        fixture_inputs_explicitly_fake=True,
        evidence_scope='registered_sync_Win32_IO_and_controlled_HTTPX_raw_JSON_upload')
    save(root/'io-evidence.json', rows)
    save(root/'summary.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fake-data-only', action='store_true', required=True)
    parser.add_argument('--powershell', type=Path, default=Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
    parser.add_argument('--io-dll', type=Path, default=ROOT/'build/flow-linkage/ttrace-flow-io.dll')
    parser.add_argument('--io-manifest', type=Path, default=ROOT/'build/flow-linkage/native-build.json')
    parser.add_argument('--gate-dll', type=Path, default=ROOT/'build/python-outbound-20261026/_ttrace_native_gate.pyd')
    parser.add_argument('--gate-manifest', type=Path, default=ROOT/'build/python-outbound-20261026/native-build.json')
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    cases = []
    for name in ('ordinary','sensitive','redacted'):
        result = run_case(root/name, name, args)
        cases.append(result)
        summary = {'passed':len(cases) == 3 and all(r['passed'] for r in cases), 'cases':cases,
                   'chain':'PowerShell reads and modifies file -> independent Python reads and uploads exact modified file bytes',
                   'business_named_pipe_used':False, 'can_enforce_scope':'controlled Python HTTPX adapter only'}
        save(root/'summary.json', summary)
        print(json.dumps({'case':name,'passed':result['passed'],'checks':result['checks'],'errors':result['errors']}),flush=True)
    return 0 if summary['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
