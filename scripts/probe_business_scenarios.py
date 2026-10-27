"""Frozen fake-data Webhook/Git qualification with independent evidence checks.

Live runs require a Windows administrator token. --prepare-only creates inputs
and manifests without collectors or trust installation. --elevate is an explicit
one-shot UAC request for this experiment; it also elevates fixture descendants.
No existing run folder, baseline, trust root, or user configuration is replaced.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys

from _build_support import ROOT
from _local_test_trust import LocalTestTrust
from transpect_trace.flow.manifest import frozen
from transpect_trace.flow.scenarios.manifest import BusinessScenarioManifest, CASES
from transpect_trace.flow.scenarios.runtime import run
from transpect_trace.observe.elevation import is_elevated
from transpect_trace.protect.detection import ContentIndex

MARKER = 'BUSINESS_FAKE_ONLY_CONFIDENTIAL_TICKET_DOCUMENT_2026_registered_test_content'
SECRET = 'business_validation_fake_credential_94a2d9cd'
REGISTRATION = 'fake-business-confidential'
NEGATIVE = {('webhook', 'public'), ('git', 'public'), ('git', 'untracked'), ('git', 'old_commit')}
CASE_NAMES = tuple(f'{scenario}:{case}' for scenario, cases in CASES.items() for case in sorted(cases))


def dump(path, value):
    temporary = path.with_suffix(path.suffix + '.pending')
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def read(path):
    return json.loads(path.read_bytes()) if path.is_file() else {}


def privacy_scan(audit):
    failures, unreadable, count = [], [], 0
    needles = [value.encode(encoding) for value in (MARKER, SECRET)
               for encoding in ('utf-8', 'utf-16-le', 'utf-16-be')]
    if not audit.is_dir():
        return {'passed': False, 'files_scanned': 0, 'scope': 'audit_outputs_only',
                'files_with_test_secret': [], 'unreadable_or_linked_files': ['audit_missing']}
    for path in audit.rglob('*'):
        if path.is_symlink():
            unreadable.append(path.relative_to(audit).as_posix())
            continue
        if not path.is_file():
            continue
        count += 1
        try:
            data = path.read_bytes()
        except OSError:
            unreadable.append(path.relative_to(audit).as_posix())
            continue
        if any(needle in data for needle in needles):
            failures.append(path.relative_to(audit).as_posix())
    return {'passed': not (failures or unreadable), 'files_scanned': count,
            'scope': 'audit_outputs_only', 'files_with_test_secret': failures,
            'unreadable_or_linked_files': unreadable}


def prepare_manifest(folder, name, *, scenario, case, executables, build_inputs,
                     source, index, certificate, private_key, backend='default', timeout=90):
    manifest = BusinessScenarioManifest(scenario=scenario, case=case, fake_data_only=True,
        executables={k: v for k, v in executables.items() if scenario == 'git' or k != 'git'},
        build_inputs=build_inputs, source=frozen(source), content_index=frozen(index),
        certificate=frozen(certificate), private_key=frozen(private_key), output=folder/name/'audit',
        timeout_seconds=timeout, git_tls_backend=backend)
    manifest.resolve(folder)
    path = folder/(name + '.manifest.json')
    path.write_text(manifest.model_dump_json(indent=2) + '\n', encoding='utf-8')
    return path


def assess_case(scenario, case, state, audit):
    """Do not turn source-only success or a saved certified flag into acceptance."""
    report, captured = read(audit/'business-report.json'), read(audit/'capture-summary.json')
    requests = captured.get('requests', [])
    receipts = [row for row in captured.get('receipts', [])
                if row.get('route') == ('webhook' if scenario == 'webhook' else 'git_receive')]
    tls = [row for row in requests if row.get('provider') == 'ecapture' and row.get('capture_layer') == 'tls'
           and row.get('complete') is True and not row.get('limitations')]
    expected = 2 if (scenario, case) == ('webhook', 'retry') else 1
    pairs = lambda rows: Counter((r.get('body_sha256'), r.get('body_bytes')) for r in rows)
    health = report.get('health', {})
    subjects = report.get('participants', [])
    findings = [finding for row in (captured.get('git_objects', []) if scenario == 'git' else tls)
                for finding in row.get('findings', [])]
    expected_sensitive = (scenario, case) not in NEGATIVE
    registered = any(row.get('registration_id') == REGISTRATION for row in findings)
    stages = report.get('stages', [])
    checks = {
        'runtime_complete': state.get('state') == 'complete' and state.get('certified') is True,
        'report_complete': report.get('state') == 'complete' and report.get('certified') is True,
        'observe_only': state.get('can_enforce') is False and report.get('can_enforce') is False,
        'stages_complete': bool(stages) and all(s.get('state') == 'complete' for s in stages),
        'distinct_process_instances': len(subjects) >= 3 and len(subjects) == len({(p.get('pid'), p.get('creation_filetime')) for p in subjects}),
        'collector_health': all(h.get('ready') is True and h.get('terminal') is True and h.get('identity_verified') is True
            and h.get('lost_events') == 0 and h.get('errors') == 0 and not h.get('limitations')
            for key in ('native_io', 'etw', 'ecapture', 'native_request') for h in [health.get(key, {})]),
        'real_etw_evidence': any(row.get('provenance') == 'etw' and row.get('event_ids')
            and row.get('complete') is True for row in report.get('evidence', [])),
        'request_count': len(tls) == len(requests) == len(receipts) == expected,
        'source_complete': len(receipts) == expected and all(r.get('completeness') == 'complete' and r.get('body_bytes', 0) > 0 for r in receipts),
        'source_hash_length_counts': pairs(tls) == pairs(receipts) and len(tls) == expected,
        'sensitive_expectation': registered if expected_sensitive else not findings,
        'privacy': privacy_scan(audit)['passed'],
    }
    if scenario == 'webhook':
        checks['text_checks_complete'] = bool(tls) and all(row.get('inspected') is True for row in tls)
        if case == 'retry':
            checks['actual_503_then_200'] = [r.get('response_status') for r in receipts] == [503, 200]
    else:
        git = captured.get('git_receipts', [])
        objects = captured.get('git_objects', [])
        checks['quarantine_inspected'] = len(git) == expected and all(r.get('quarantine_observed') is True
            and r.get('inspection_complete') is True and not r.get('limitations') for r in git)
        checks['all_received_blobs_inspected'] = bool(objects) and all(o.get('inspected') is True for o in objects)
        checks['refs_result'] = bool(git) and all(r.get('ref_update_observed') is (case != 'reject_ref') for r in git)
        if case == 'deleted_history':
            checks['history_contains_multiple_commits'] = any(sum(o.get('object_type') == 'commit' for o in r.get('new_objects', [])) >= 2 for r in git)
        if case == 'repeat':
            checks['no_fake_repeated_push_body'] = len(git) == 1
    return {'scenario': scenario, 'case': case, 'accepted': all(checks.values()),
            'collection_state': state.get('state', 'unknown'), 'checks': checks,
            'source_attempts': len(receipts), 'complete_tls_requests': len(tls),
            'coverage_gaps': sorted(set(state.get('gaps', []) + report.get('limitations', []))),
            'privacy': privacy_scan(audit), 'can_enforce': False}


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument('--output', required=True, type=Path)
    value.add_argument('--codex', required=True, type=Path, help='Exact saved official 0.162.0-alpha.17.2 executable')
    value.add_argument('--fake-data-only', required=True, action='store_true')
    value.add_argument('--case', choices=CASE_NAMES, action='append', help='Repeat for multiple cases; default all cases')
    value.add_argument('--repeat', type=int, choices=range(1, 6), default=3)
    value.add_argument('--git-tls-backend', choices=('default', 'schannel', 'both'), default='both')
    value.add_argument('--prepare-only', action='store_true', help='Freeze inputs without installing trust or running clients')
    value.add_argument('--elevate', action='store_true', help='Explicit UAC for the full fake-data experiment, including its fixture clients')
    value.add_argument('--prepare-test-trust', action='store_true', help='Create a new localhost-only trust lease; install only during live runs')
    value.add_argument('--certificate', type=Path)
    value.add_argument('--private-key', type=Path)
    value.add_argument('--python', type=Path, default=Path(sys._base_executable))
    value.add_argument('--powershell', type=Path, default=Path(shutil.which('powershell.exe') or 'powershell.exe'))
    value.add_argument('--git', type=Path, default=Path(shutil.which('git.exe') or shutil.which('git') or 'git.exe'))
    value.add_argument('--native-dir', type=Path, default=ROOT/'build/flow-linkage')
    value.add_argument('--ecapture-dir', type=Path, default=ROOT/'build/flow-ecapture-v2')
    value.add_argument('--guard-dll', type=Path, default=ROOT/'build/guard/ttrace-guard.dll')
    value.add_argument('--behavior-etw', type=Path, default=ROOT/'build/behavior/etw.exe')
    value.add_argument('--timeout', type=int, default=90, metavar='SECONDS', help='Per-scenario bounded timeout, 30-180 seconds')
    return value


def _elevate(arguments):
    from _behavior_probe import ElevatedProcess
    child = ElevatedProcess(sys.executable, [str(Path(__file__).resolve()), *[a for a in arguments if a != '--elevate']], Path.cwd())
    try:
        result = child.wait(timeout=4 * 60 * 60)
        return result if result is not None else 2
    finally:
        child.close()


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    p = parser(); args = p.parse_args(arguments)
    if args.prepare_test_trust == bool(args.certificate or args.private_key):
        p.error('choose --prepare-test-trust or both --certificate and --private-key')
    if not args.prepare_test_trust and not (args.certificate and args.private_key):
        p.error('both certificate and private key are required')
    if args.elevate and args.prepare_only:
        p.error('--prepare-only does not require elevation')
    if args.case and len(set(args.case)) != len(args.case):
        p.error('duplicate --case')
    if not 30 <= args.timeout <= 180:
        p.error('--timeout must be between 30 and 180 seconds')
    elevated = is_elevated()
    if args.elevate and not elevated:
        try:
            return _elevate(arguments)
        except OSError as error:
            print(json.dumps({'state': 'unavailable', 'error_type': type(error).__name__,
                              'reason': 'explicit_elevation_failed', 'can_enforce': False}))
            return 2
    output = args.output.resolve()
    # Intentionally outside the catch: never overwrite an existing run summary.
    output.mkdir(parents=True, exist_ok=False)
    summary = {'schema_version': 'transpect.business.qualification/1.0', 'state': 'initializing',
               'cases': [], 'manifests': [], 'can_enforce': False, 'certified': False,
               'environment': {'platform': sys.platform, 'administrator_token': elevated,
                               'fixture_clients_elevated': elevated, 'python_version': sys.version.split()[0]},
               'started_at_utc': datetime.now(timezone.utc).isoformat(),
               'excluded_fixture_material': ['explicit-fake-inputs', 'test-trust', '<case>/fake-work-*'],
               'privacy_scope': 'audit_outputs_only'}
    lease = None
    save = lambda: dump(output/'summary.json', summary)
    save()
    try:
        selected = args.case or list(CASE_NAMES)
        if not args.prepare_only and (sys.platform != 'win32' or not elevated):
            summary.update(state='unavailable', reason='windows_administrator_token_required')
            return 2
        executables = {name: frozen(path) for name, path in {'codex': args.codex, 'python': args.python,
                       'powershell': args.powershell, **({'git': args.git} if any(c.startswith('git:') for c in selected) else {})}.items()}
        build_inputs = {name: frozen(path) for name, path in {
            'guard_dll': args.guard_dll, 'io_observer': args.native_dir/'ttrace-flow-io.dll',
            'native_manifest': args.native_dir/'native-build.json', 'etw': args.native_dir/'flow_etw.exe',
            'ecapture': args.ecapture_dir/'ecapture.exe', 'ecapture_manifest': args.ecapture_dir/'ecapture-build.json',
            'behavior_etw': args.behavior_etw}.items()}
        if args.prepare_test_trust:
            def command(cmd):
                return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
                                      creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            lease = LocalTestTrust(output/'test-trust', command_runner=command).prepare()
            certificate, private_key = lease.certificate, lease.private_key
            summary['trust_state'] = 'prepared_not_installed'
        else:
            certificate, private_key = args.certificate.resolve(), args.private_key.resolve()
            summary['trust_state'] = 'caller_supplied_pretrusted_certificate'
        inputs = output/'explicit-fake-inputs'; inputs.mkdir()
        source, index = inputs/'ticket.json', inputs/'content-index.json'
        source.write_text(json.dumps({'ticket_id': 'FAKE-INCIDENT-ONLY', 'public_text': '普通排障统计，无业务记录',
                                      'secret': MARKER, 'api_key': SECRET}, ensure_ascii=False), encoding='utf-8')
        index.write_text(ContentIndex.register('business-fixture-v1', [(REGISTRATION, MARKER, 'CONFIDENTIAL',
                                                                      ['registered_text'])]).model_dump_json(), encoding='utf-8')
        prepared = []
        for selection in selected:
            scenario, case = selection.split(':')
            backends = ['default', 'schannel'] if scenario == 'git' and args.git_tls_backend == 'both' else [
                args.git_tls_backend if scenario == 'git' else 'default']
            for backend in backends:
                for repetition in range(1, args.repeat + 1):
                    name = f'{scenario}-{case}-{backend}-{repetition:02d}'
                    manifest = prepare_manifest(output, name, scenario=scenario, case=case, executables=executables,
                        build_inputs=build_inputs, source=source, index=index, certificate=certificate,
                        private_key=private_key, backend=backend, timeout=args.timeout)
                    prepared.append((name, scenario, case, backend, manifest))
                    summary['manifests'].append({'name': name, 'path': manifest.relative_to(output).as_posix(),
                                                 'scenario': scenario, 'case': case, 'git_tls_backend': backend})
        save()
        if args.prepare_only:
            summary['state'] = 'prepared'
            return 0
        if lease:
            summary['state'] = 'waiting_test_trust'; save()
            lease.install(); summary['trust_state'] = 'installed_for_owned_run'
        for name, scenario, case, backend, manifest in prepared:
            summary.update(state='running', active_case=name); save()
            try:
                state = run(manifest)
                result = assess_case(scenario, case, state, output/name/'audit')
            except Exception as error:
                result = {'scenario': scenario, 'case': case, 'accepted': False,
                          'collection_state': 'unavailable', 'error_type': type(error).__name__, 'can_enforce': False}
            summary['cases'].append({**result, 'name': name, 'git_tls_backend': backend,
                                     'evidence_path': name+'/audit/business-report.json'})
            save()
        summary['state'] = 'accepted' if summary['cases'] and all(case['accepted'] for case in summary['cases']) else 'partial'
    except Exception as error:
        summary.update(state='unavailable', error_type=type(error).__name__)
    finally:
        if lease and lease.manifest and lease.manifest.get('import_attempted'):
            try:
                summary['test_trust_cleanup_confirmed'] = bool(lease.cleanup()['cleanup_confirmed'])
            except Exception:
                summary['test_trust_cleanup_confirmed'] = False
            if not summary['test_trust_cleanup_confirmed']:
                summary['state'] = 'partial'
        summary.pop('active_case', None)
        summary['ended_at_utc'] = datetime.now(timezone.utc).isoformat()
        summary['accepted_cases'] = sum(case['accepted'] for case in summary['cases'])
        save()
    return 0 if summary['state'] in ('prepared', 'accepted') else 2


if __name__ == '__main__':
    raise SystemExit(main())
