"""One fake-data Webhook scenario: allow, reject, then allow in a new session.

Live runs require an administrator token for ETW/eCapture. Explicit --elevate
also elevates the fixture clients. Preparation neither installs trust nor starts
clients. Recovery uses a new allow-policy session, never Hook removal.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from _build_support import ROOT
from _local_test_trust import LocalTestTrust
from probe_business_scenarios import MARKER, SECRET, REGISTRATION, dump, read, privacy_scan, prepare_manifest
from transpect_trace.flow.manifest import frozen, FrozenFile
from transpect_trace.observe.elevation import is_elevated
from transpect_trace.protect.detection import ContentIndex

PHASES = (('allow-before', 'allow'), ('block', 'block'), ('allow-after', 'allow'))


def verify_egress(inputs, base):
    paths = {name: FrozenFile.model_validate(value).verify(base) for name, value in inputs.items()}
    if set(paths) != {'egress_dll', 'egress_manifest'} or paths['egress_manifest'] != paths['egress_dll'].parent/'build-manifest.json':
        raise ValueError('egress_manifest_location_mismatch')
    manifest = json.loads(paths['egress_manifest'].read_bytes())
    if (manifest.get('schema') != 'transpect.native.egress.build/1.0' or
            manifest.get('artifacts_sha256', {}).get(paths['egress_dll'].name) != inputs['egress_dll']['sha256']):
        raise ValueError('egress_artifact_manifest_mismatch')
    return paths['egress_dll']


def assess_control(audit, action):
    report = read(audit/'webhook-control.json')
    checks = report.get('checks', {})
    valid_shape = isinstance(checks, dict) and bool(checks) and all(
        isinstance(k,str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',k) and type(v) is bool
        for k,v in checks.items())
    valid_checks = valid_shape and all(checks.values())
    privacy = privacy_scan(audit)
    accepted = bool(report.get('action') == action and report.get('passed') is True and valid_checks and privacy['passed'])
    return {'action': action, 'accepted': accepted, 'control_report_present': bool(report),
            'reported_passed': report.get('passed') is True, 'checks_valid': bool(valid_checks),
            'privacy': privacy, 'checks': checks if valid_shape else {},
            'recovery_scope': 'new_session_with_allow_policy'}


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument('--output', type=Path, required=True)
    value.add_argument('--codex', type=Path, required=True)
    value.add_argument('--fake-data-only', required=True, action='store_true')
    value.add_argument('--prepare-only', action='store_true')
    value.add_argument('--elevate', action='store_true', help='Explicit UAC for the whole fake-data experiment including clients')
    value.add_argument('--prepare-test-trust', action='store_true')
    value.add_argument('--certificate', type=Path)
    value.add_argument('--private-key', type=Path)
    value.add_argument('--python', type=Path, default=Path(sys._base_executable))
    value.add_argument('--powershell', type=Path, default=Path(shutil.which('powershell.exe') or 'powershell.exe'))
    value.add_argument('--native-dir', type=Path, default=ROOT/'build/flow-linkage')
    value.add_argument('--ecapture-dir', type=Path, default=ROOT/'build/flow-ecapture-v2')
    value.add_argument('--guard-dll', type=Path, default=ROOT/'build/guard/ttrace-guard.dll')
    value.add_argument('--behavior-etw', type=Path, default=ROOT/'build/behavior/etw.exe')
    value.add_argument('--egress-dll', type=Path, default=ROOT/'build/webhook-control-20261026-v2/egress/ttrace-egress.dll')
    value.add_argument('--timeout', type=int, default=180)
    return value


def _elevate(arguments):
    from _behavior_probe import ElevatedProcess
    child = ElevatedProcess(sys.executable, [str(Path(__file__).resolve()), *[v for v in arguments if v != '--elevate']], ROOT)
    try:
        result = child.wait(timeout=30*60)
        return result if result is not None else 2
    finally:
        child.close()


def run_control(manifest, dll, action):
    from transpect_trace.flow.scenarios.runtime import run_webhook_control
    return run_webhook_control(manifest, dll, action=action)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    p = parser(); args = p.parse_args(arguments)
    if args.prepare_test_trust == bool(args.certificate or args.private_key):
        p.error('choose --prepare-test-trust or both --certificate and --private-key')
    if not args.prepare_test_trust and not (args.certificate and args.private_key):
        p.error('both certificate and private key are required')
    if not 30 <= args.timeout <= 180: p.error('--timeout must be 30-180 seconds')
    if args.prepare_only and args.elevate: p.error('--prepare-only does not require elevation')
    elevated = is_elevated()
    if args.elevate and not elevated:
        try: return _elevate(arguments)
        except OSError as error:
            print(json.dumps({'state':'unavailable', 'error_type':type(error).__name__, 'passed':False}))
            return 2
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    summary = {'schema_version':'transpect.webhook.control.qualification/1.0', 'state':'initializing', 'passed':False,
        'phases':[], 'manifests':[], 'recovery_scope':'new_session_with_allow_policy',
        'environment':{'administrator_token':elevated, 'fixture_clients_elevated':elevated},
        'started_at_utc':datetime.now(timezone.utc).isoformat(), 'privacy_scope':'audit_outputs_only',
        'excluded_fixture_material':['explicit-fake-inputs', 'test-trust', '<phase>/fake-work-*']}
    lease = None
    save = lambda: dump(output/'summary.json', summary)
    save()
    try:
        if not args.prepare_only and (sys.platform != 'win32' or not elevated):
            summary.update(state='unavailable', reason='windows_administrator_token_required'); return 2
        executables = {name:frozen(path) for name,path in {'codex':args.codex, 'python':args.python, 'powershell':args.powershell}.items()}
        build_inputs = {name:frozen(path) for name,path in {
            'guard_dll':args.guard_dll, 'io_observer':args.native_dir/'ttrace-flow-io.dll',
            'native_manifest':args.native_dir/'native-build.json', 'etw':args.native_dir/'flow_etw.exe',
            'ecapture':args.ecapture_dir/'ecapture.exe', 'ecapture_manifest':args.ecapture_dir/'ecapture-build.json',
            'behavior_etw':args.behavior_etw}.items()}
        egress = {name:frozen(path) for name,path in
                  {'egress_dll':args.egress_dll, 'egress_manifest':args.egress_dll.parent/'build-manifest.json'}.items()}
        verify_egress(egress, output); summary['egress_inputs'] = egress
        if args.prepare_test_trust:
            def command(cmd):
                return subprocess.run(cmd, capture_output=True, timeout=180, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            lease = LocalTestTrust(output/'test-trust', command_runner=command).prepare()
            certificate, key = lease.certificate, lease.private_key
            summary['trust_state'] = 'prepared_not_installed'
        else:
            certificate, key = args.certificate.resolve(), args.private_key.resolve()
            summary['trust_state'] = 'caller_supplied_pretrusted_certificate'
        inputs = output/'explicit-fake-inputs'; inputs.mkdir()
        source, index = inputs/'ticket.json', inputs/'content-index.json'
        source.write_text(json.dumps({'ticket_id':'FAKE-INCIDENT-ONLY','public_text':'普通假数据统计','secret':MARKER,'api_key':SECRET},ensure_ascii=False),encoding='utf-8')
        index.write_text(ContentIndex.register('business-fixture-v1',[(REGISTRATION,MARKER,'CONFIDENTIAL',['registered_text'])]).model_dump_json(),encoding='utf-8')
        prepared = []
        for name, action in PHASES:
            manifest = prepare_manifest(output, name, scenario='webhook', case='plain', executables=executables,
                build_inputs=build_inputs, source=source, index=index, certificate=certificate, private_key=key, timeout=args.timeout)
            prepared.append((name,action,manifest)); summary['manifests'].append({'phase':name,'action':action,'path':manifest.name})
        save()
        if args.prepare_only:
            summary['state']='prepared'; return 0
        if lease:
            summary['state']='waiting_test_trust'; save(); lease.install(); summary['trust_state']='installed_for_owned_run'
        for name,action,manifest in prepared:
            summary.update(state='running', active_phase=name); save()
            try:
                dll = verify_egress(egress, output)
                state = run_control(manifest, dll, action)
                assessment = assess_control(output/name/'audit', action)
                assessment['observation_state'] = state.get('state','unknown')
            except Exception as error:
                assessment = {'action':action,'accepted':False,'error_type':type(error).__name__}
            summary['phases'].append({'phase':name, **assessment, 'evidence_path':name+'/audit/webhook-control.json'}); save()
            if not assessment['accepted']:
                summary['not_executed_phases']=[row[0] for row in prepared[len(summary['phases']):]]
                break
        summary['passed'] = len(summary['phases'])==3 and all(row['accepted'] for row in summary['phases'])
        summary['state']='passed' if summary['passed'] else 'partial'
    except Exception as error:
        summary.update(state='unavailable', error_type=type(error).__name__, passed=False)
    finally:
        if lease and lease.manifest and lease.manifest.get('import_attempted'):
            try: summary['test_trust_cleanup_confirmed']=bool(lease.cleanup()['cleanup_confirmed'])
            except Exception: summary['test_trust_cleanup_confirmed']=False
            if not summary['test_trust_cleanup_confirmed']: summary.update(state='partial',passed=False)
        summary.pop('active_phase',None); summary['ended_at_utc']=datetime.now(timezone.utc).isoformat(); save()
    return 0 if summary['state'] in ('prepared','passed') else 2


if __name__=='__main__':
    raise SystemExit(main())
