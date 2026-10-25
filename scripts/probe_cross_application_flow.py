"""Reproduce controlled file/pipe experiments, using fake inputs only.

Run from an administrator terminal. --prepare-test-trust explicitly leases a
localhost-only CurrentUser test CA and removes that exact CA in finally.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT
from _local_test_trust import LocalTestTrust
from transpect_trace.flow.manifest import frozen
from transpect_trace.flow.runtime import run
from transpect_trace.observe.elevation import is_elevated
from transpect_trace.protect.detection import ContentIndex

MARKER = 'FLOW_TEST_CONFIDENTIAL_DOCUMENT_2026_fake_registration_content_only'
SECRET = 'flow_validation_fake_credential_a81c954e'


def prepare_manifest(folder, name, *, scenario, source, index, certificate, private_key, ordinary=False, content_type='text', ecapture_dir=None):
    native = ROOT/'build/flow'
    ecapture = ecapture_dir or ROOT/'build/observe/ecapture-enhanced'
    fields = dict(python=Path(sys._base_executable), participant=ROOT/'src/transpect_trace/flow/participant.py',
                  uploader=native/'flow_uploader.exe', observer=native/'ttrace-flow-io.dll', etw=native/'flow_etw.exe',
                  native_manifest=native/'native-build.json', ecapture=ecapture/'ecapture.exe',
                  ecapture_manifest=ecapture/'ecapture-build.json', source=source, content_index=index,
                  certificate=certificate, private_key=private_key)
    manifest = {'schema_version': 'transpect.flow.manifest/1.0', 'scenario': scenario,
                'fake_data_only': True, 'can_enforce': False, 'output': str(folder/name/'audit'),
                'ordinary_body': ordinary, 'content_type': content_type, **{k: frozen(p) for k, p in fields.items()}}
    path = folder/(name+'.manifest.json')
    path.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    return path


def privacy_scan(directory):
    failures = []
    for path in directory.rglob('*'):
        if path.is_file():
            data = path.read_bytes()
            if SECRET.encode() in data or MARKER.encode() in data:
                failures.append(path.relative_to(directory).as_posix())
    return {'passed': not failures, 'files_with_test_secret': failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--prepare-test-trust', action='store_true')
    parser.add_argument('--certificate', type=Path)
    parser.add_argument('--private-key', type=Path)
    parser.add_argument('--scenario', choices=['file','pipe','both'], default='both')
    parser.add_argument('--extended', action='store_true', help='Add >64KiB JSON and exactly 1MiB text cases')
    parser.add_argument('--case', choices=['sensitive','ordinary-upload','large-json','one-mib'])
    parser.add_argument('--repeat', type=int, choices=range(1,11), default=1)
    parser.add_argument('--ecapture-dir', type=Path, default=ROOT/'build/observe/ecapture-enhanced')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    summary = {'can_enforce': False, 'cases': [], 'state': 'initializing', 'certified': False}
    def save():
        (output/'summary.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
    save()
    if not is_elevated():
        summary.update(state='unavailable', reason='administrator_token_required')
        save()
        return 2
    lease = None
    try:
        if args.prepare_test_trust:
            def command(arguments):
                # The Windows certificate dialog may need human confirmation.
                return subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=180, creationflags=0x08000000, check=False)
            lease = LocalTestTrust(output/'test-trust', command_runner=command).prepare()
            summary['state'] = 'waiting_test_trust'; save()
            lease.install()
            certificate, key = lease.certificate, lease.private_key
        else:
            if not args.certificate or not args.private_key:
                raise ValueError('pretrusted_localhost_certificate_required')
            certificate, key = args.certificate.resolve(), args.private_key.resolve()
        inputs = output/'explicit-fake-inputs'
        inputs.mkdir()
        index = ContentIndex.register('flow-fixtures-v1', [("fake-document", MARKER, 'CONFIDENTIAL', ['registered_text'])])
        index_file = inputs/'content-index.json'
        index_file.write_text(index.model_dump_json(indent=2)+'\n', encoding='utf-8')
        base = f'测试资料\n{MARKER}\napi_key={SECRET}\n'
        payloads = [('sensitive', base.encode(), 'text', False), ('ordinary-upload', base.encode(), 'text', True)]
        if args.extended:
            payloads += [('large-json', json.dumps({'report': base + '长内容' * 12000}, ensure_ascii=False).encode(), 'json', False)]
            prefix = base.encode()
            payloads += [('one-mib', prefix + b'x'*(1024*1024-len(prefix)), 'text', False)]
        for scenario in (['file','pipe'] if args.scenario == 'both' else [args.scenario]):
            cases = [(label, data, ctype, ordinary, trial) for label, data, ctype, ordinary in payloads for trial in range(args.repeat)]
            for label, data, ctype, ordinary, trial in cases:
                if args.case and label != args.case: continue
                name = scenario+'-'+label + (f'-r{trial+1:02d}' if args.repeat > 1 else '')
                source = inputs/(name+'.txt')
                source.write_bytes(data)
                manifest = prepare_manifest(output, name, scenario=scenario, source=source, index=index_file,
                                            certificate=certificate, private_key=key, ordinary=ordinary, content_type=ctype,
                                            ecapture_dir=args.ecapture_dir.resolve())
                summary.update(state='running', active_case=name); save()
                result = run(manifest)
                audit = output/name/'audit'
                evidence_file = audit/'flow-evidence.json'
                evidence = json.loads(evidence_file.read_text()) if evidence_file.exists() else {}
                outbound = evidence.get('content_detection', {}).get('outbound', [])
                transfers = evidence.get('system_behavior', {}).get('transfers', [])
                relations = evidence.get('propagation', {}).get('relations', [])
                privacy = privacy_scan(audit)
                content_expected = len(outbound)==1 and outbound[0]['detection_status']==('no_match' if ordinary else 'matched')
                outbound_relations = [r for r in relations if r['relation_kind']=='outbound_content_candidate']
                handoff_relations = [r for r in relations if r['relation_kind']==scenario+'_handoff_candidate']
                passed = (result['state']=='complete' and content_expected and privacy['passed']
                          and bool(handoff_relations) and any(t['process']['role']=='B' and t['operation']=='read' for t in transfers)
                          and (not outbound_relations if ordinary else bool(outbound_relations)))
                summary['cases'].append({'case': name, 'state': result['state'], 'passed': passed,
                                         'content_expected': content_expected, 'privacy': privacy,
                                         'collector_health': evidence.get('session', {}).get('health', {}),
                                         'coverage_gaps': result.get('coverage_gaps', []),
                                         'etw_event_count': result.get('etw_event_count', 0),
                                         'gaps': result['gaps'], 'evidence_path': name+'/audit/flow-evidence.json',
                                         'can_enforce': False})
                save()
        summary['state'] = 'passed' if summary['cases'] and all(c['passed'] for c in summary['cases']) else 'partial'
    except Exception as error:
        summary.update(state='unavailable', error_type=type(error).__name__)
    finally:
        if lease:
            try:
                summary['test_trust_cleanup_confirmed'] = bool(lease.cleanup()['cleanup_confirmed'])
                if not summary['test_trust_cleanup_confirmed']:
                    summary['state'] = 'partial'
                    summary['cleanup_gap'] = 'test_trust_cleanup_unconfirmed'
            except Exception:
                summary['test_trust_cleanup_confirmed'] = False
                summary['state'] = 'partial'
        summary.pop('active_case', None)
        save()
    print(json.dumps(summary, indent=2))
    return 0 if summary['state']=='passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
