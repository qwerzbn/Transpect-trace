"""Controlled file mutation, with optional real ETW/Schannel upload evidence.

Default: fixed FIO1 component check without administrator privileges.
--full-chain requires an administrator terminal and a trusted localhost origin.
Inputs and intermediate data are confined to explicit-fake-inputs; audit output
contains metadata/hashes only. Both participants are controlled Python fixtures.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
from uuid import uuid4

from _build_support import ROOT
from transpect_trace.flow import mutation_participant as participant
from transpect_trace.flow.evidence import FlowEvidence
from transpect_trace.flow.manifest import frozen
from transpect_trace.flow.native import NativeIOCollector, validate_build
from transpect_trace.flow.runtime import Fixture
from transpect_trace.protect.detection import ContentIndex

MARKER = 'FLOW_MUTATION_FAKE_REGISTERED_CONTENT_2026_COMPONENT_ONLY'


def fake_source():
    return json.dumps({'document': MARKER, 'padding': 'A' * (2 * participant.CUT)}, separators=(',', ':')).encode()


def metadata(event):
    keep = ('event_id', 'kind', 'pid', 'creation_filetime', 'sequence', 'qpc', 'completed_qpc',
            'qpc_frequency', 'object_kind', 'path_role', 'open_generation', 'offset',
            'requested_length', 'completed_length', 'success', 'win32_error', 'capture_gap', 'lost_events')
    row = {key: event.get(key) for key in keep}
    row['file_identity_sha256'] = hashlib.sha256(event['file_identity'].encode()).hexdigest() if event.get('file_identity') else None
    row['snapshot_sha256'] = hashlib.sha256(event.get('data', b'')).hexdigest()
    row['snapshot_bytes'] = len(event.get('data', b''))
    row['can_enforce'] = False
    return row


class MutationFixture(Fixture):
    def _read(self):
        try:
            while line := self.process.stdout.readline(4097):
                if len(line) > 4096:
                    raise ValueError('fixture_record_limit')
                value = json.loads(line)
                if (not isinstance(value, dict) or value.get('role') != self.role
                        or value.get('evidence_origin') != 'fixture_truth'
                        or value.get('kind') not in {'ready', 'initial_written', 'rewritten', 'read_paused', 'read_complete', 'sent', 'finished', 'error'}):
                    raise ValueError('invalid_fixture_truth')
                row = {key: value[key] for key in ('kind', 'role', 'evidence_origin')}
                for key in ('pid', 'bytes', 'win32_error', 'http_status'):
                    if key in value:
                        number = value[key]
                        if number is not None and (type(number) is not int or not 0 <= number <= 0xffffffff):
                            raise ValueError('invalid_fixture_number')
                        row[key] = number
                for key in ('source_access_started', 'json_valid'):
                    if key in value:
                        if type(value[key]) is not bool:
                            raise ValueError('invalid_fixture_boolean')
                        row[key] = value[key]
                if 'body_sha256' in value:
                    digest = value['body_sha256']
                    if not isinstance(digest, str) or len(digest) != 64 or set(digest) - set('0123456789abcdef'):
                        raise ValueError('invalid_fixture_hash')
                    row['body_sha256'] = digest
                self.events.append(row)
                self.queue.put_nowait(row)
        except (ValueError, OSError, queue.Full):
            try: self.queue.put_nowait({'kind': 'error'})
            except queue.Full: pass
        finally:
            try: self.queue.put_nowait({'kind': 'eof'})
            except queue.Full: pass


def evaluate(scenario, result, raw, snapshots, truth, health, *, original, changed, failures,
             full_chain=False, etw_coverage=None, sent=False):
    transfers = result['system_behavior']['transfers']
    reads = [r for r in transfers if r['process']['role'] == 'B' and r['operation'] == 'read' and r['resource_role'] == 'transfer']
    writes = [r for r in transfers if r['process']['role'] == 'A' and r['operation'] == 'write' and r['resource_role'] == 'transfer']
    b_events = [r for r in raw if r['kind'] == 'read' and r['path_role'] == 'transfer']
    a_events = [r for r in raw if r['kind'] == 'write' and r['path_role'] == 'transfer']
    expected = changed if scenario == 'overwrite_suffix' else original
    expected_hash = hashlib.sha256(expected).hexdigest()
    read = reads[0] if len(reads) == 1 else {}
    actual_snapshot = snapshots.get(read.get('observation_id'), {})
    healthy = set(health) == {'A', 'B'} and all(h['ready'] and h['terminal'] and not h['errors'] and h['lost_events'] == 0 for h in health.values())
    nonzero = [r for r in b_events if r['completed_length']]
    offset = 0
    contiguous = bool(nonzero)
    for r in nonzero:
        contiguous &= r['offset'] == offset and r['requested_length'] >= r['completed_length'] == r['snapshot_bytes'] and r['success']
        offset += r['completed_length']
    identities = {r['file_identity_sha256'] for r in [*a_events, *b_events]}
    changes = [r for r in a_events if r['offset'] == participant.CUT]
    overlap = bool(changes and nonzero and nonzero[0]['completed_qpc'] <= changes[0]['qpc']
                   and changes[0]['completed_qpc'] <= nonzero[1]['qpc']) if len(nonzero) > 1 else False
    checks = {
        'component_no_runtime_errors': not failures,
        'native_ready_terminal_lossless': healthy,
        'b_read_one_observation': len(reads) == 1,
        'actual_offsets_and_completed_lengths': contiguous and offset == len(expected),
        'same_file_identity_observed': len(identities) == 1 and None not in identities,
        'actual_snapshot_hash': read.get('content_sha256') == expected_hash,
        'actual_snapshot_json_valid': actual_snapshot.get('json_valid') is True,
        'fixture_hash_is_separate_truth': truth.get('body_sha256') == expected_hash and truth.get('evidence_origin') == 'fixture_truth',
    }
    if full_chain:
        outbound = result['content_detection']['outbound']
        receipts = result['origin_receipts']['receipts']
        captured = Counter((o['decoded_body_sha256'], o['body_bytes']) for o in outbound
                           if o['provider'] == 'ecapture-windows' and o['capture_layer'] == 'tls'
                           and o['completeness'] == 'complete' and o['encoding_state'] == 'identity'
                           and o['parsing_state'] == 'json' and o['protocol'] == 'http/1.1'
                           and o['send_evidence'] == 'encryption_input_observed')
        received = Counter((o['body_sha256'], o['body_bytes']) for o in receipts)
        checks.update(
            client_send_completed=sent,
            actual_tls_origin_body=bool(captured) and len(outbound) == len(receipts) == 1
                and captured == received == Counter({(expected_hash, len(expected)): 1}),
            outbound_sensitive_detected=len(outbound) == 1 and outbound[0]['detection_status'] == 'matched'
                and any(f.get('registration_id') == 'fake-mutation-document' for f in outbound[0]['findings']),
            origin_mapping_not_overclaimed=result['origin_receipts']['request_identity_mapping'] == 'unverified',
            real_etw_coverage=bool(etw_coverage and etw_coverage.get('actual_event_count', 0) > 0 and not etw_coverage.get('gaps')),
            all_collectors_healthy=set(result['session']['health']) == {'native-io:A', 'native-io:B', 'etw', 'ecapture'}
                and all(h['ready'] and h['terminal'] and h['identity_verified'] and h['lost_events'] == h['errors'] == 0
                        and not h['limitations'] for h in result['session']['health'].values()))
        if scenario == 'stable':
            checks['full_chain_stable_complete'] = result['session']['status'] == 'complete' and not result['coverage_gaps']
        else:
            checks['full_chain_mutation_stays_partial'] = result['session']['status'] == 'partial'
            checks['uncertain_relations_not_certified'] = bool(result['propagation']['relations']) and all(
                r['confidence'] == 'Unknown' for r in result['propagation']['relations'])
    else:
        checks['full_chain_not_certified'] = result['session']['status'] == 'partial' and not result['content_detection']['outbound'] \
            and {'etw_health_incomplete', 'ecapture_health_incomplete', 'no_outbound_body_observed'} <= set(result['coverage_gaps'])
    if scenario == 'overwrite_suffix':
        checks.update(observed_interleaved_write=overlap and len(writes) == 2,
                      reopened_write_generation=len({r['open_generation'] for r in a_events}) == 2,
                      changed_read_hash=expected_hash != hashlib.sha256(original).hexdigest(),
                      modified_read_degraded=read.get('completeness') == 'partial' and 'file_modified_during_read' in read.get('limitations', []),
                      no_full_read_coverage=not result['collection_coverage']['b_handoff_read_observed'])
    else:
        checks.update(no_mutating_write=not changes and len(writes) == 1,
                      stable_read_complete=read.get('completeness') == 'complete' and not read.get('limitations'),
                      stable_file_handoff_coverage=result['collection_coverage']['complete'])
    return {'scenario': scenario, 'component_passed': all(checks.values()), 'checks': checks,
            'flow_status': result['session']['status'], 'flow_coverage_gaps': result['coverage_gaps'],
            'read_observation_id': read.get('observation_id'), 'read_completeness': read.get('completeness'),
            'read_limitations': read.get('limitations', []), 'can_enforce': False,
            'network_observation_performed': full_chain, 'full_chain_exercised': full_chain,
            'full_chain_certified': full_chain and result['session']['status'] == 'complete' and all(checks.values())}


def implementation_paths():
    package = Path(participant.__file__).resolve().parents[1]
    return {'participant': Path(participant.__file__).resolve(), 'probe': Path(__file__).resolve(),
            'winhttp': package/'flow/agents/winhttp.py', 'package_init': package/'__init__.py',
            'flow_init': package/'flow/__init__.py', 'agents_init': package/'flow/agents/__init__.py'}


def run_case(output, scenario, python, native_dir, *, full_chain=False, ecapture_dir=None,
             certificate=None, private_key=None):
    from transpect_trace.observe.windows import identity
    folder, inputs = output/scenario/'audit', output/'explicit-fake-inputs'/scenario
    folder.mkdir(parents=True); inputs.mkdir(parents=True)
    source, handoff = inputs/'source.json', inputs/'transfer.json'
    original = fake_source(); changed = participant.replacement(original)
    source.write_bytes(original)
    dll, manifest = native_dir/'ttrace-flow-io.dll', native_dir/'native-build.json'
    validate_build(dll, manifest)
    baseline_paths = {'python': python, **implementation_paths(), 'observer': dll,
                      'native_manifest': manifest, 'source': source}
    if full_chain:
        baseline_paths.update(etw=native_dir/'flow_etw.exe', ecapture=ecapture_dir/'ecapture.exe',
                              ecapture_manifest=ecapture_dir/'ecapture-build.json',
                              certificate=certificate, private_key=private_key)
    baseline = {name: frozen(path)['sha256'] for name, path in baseline_paths.items()}
    raw, snapshots, fixtures, collectors, subjects, failures, health = [], {}, {}, {}, {}, [], {}
    lock = threading.RLock()
    evidence = origin = pipeline = ecapture = etw = None
    etw_coverage, diagnostics = None, None
    sent = False
    read_truth = {}
    def sink(row, data):
        try: json.loads(data); valid = True
        except (ValueError, UnicodeError): valid = False
        snapshots[row.observation_id] = {'body_sha256': hashlib.sha256(data).hexdigest(), 'body_bytes': len(data), 'json_valid': valid}
    try:
        if full_chain:
            from transpect_trace.flow.origin import Origin
            from transpect_trace.observe.ecapture import verify_build
            build = verify_build(ecapture_dir/'ecapture.exe')
            if build.get('variant') != 'enhanced' or build.get('protocol') != 'ECW2':
                raise ValueError('enhanced_ecapture_required')
            origin = Origin(certificate, private_key).start()
        common = [str(python), '-I', '-S', '-B', str(Path(participant.__file__).resolve()), '--fake-data-only',
                  '--scenario', scenario, '--source', str(source), '--handoff', str(handoff)]
        for role in ('A', 'B'):
            fixtures[role] = MutationFixture([*common, '--role', role,
                *(['--url', origin.url] if full_chain and role == 'B' else [])], folder, role)
            ready = fixtures[role].wait('ready')
            subject = identity(fixtures[role].process.pid)
            if ready.get('pid') != subject['pid'] or ready.get('source_access_started') is not False or subject['image_sha256'] != baseline['python']:
                raise ValueError('fixture_identity_or_idle_mismatch')
            subjects[role] = subject
        members = [{k: v for k, v in s.items() if k != 'image_path'} | {'role': role} for role, s in subjects.items()]
        index = ContentIndex.register('file-mutation-v1', [('fake-mutation-document', MARKER, 'CONFIDENTIAL', ['registered_text'])])
        evidence = FlowEvidence(uuid4().hex, members, index=index, directory=folder, transfer_sink=sink)
        evidence.session.scenario = 'file'
        evidence.session.build_identities = baseline
        def event(row):
            with lock:
                raw.append(metadata(row))
                evidence.consume_native(row)
        scopes = [{'role': 'source', 'path': str(source)}, {'role': 'transfer', 'path': str(handoff)}]
        for role, subject in subjects.items():
            collectors[role] = NativeIOCollector(subject, dll, manifest, event, scopes=scopes)
            collectors[role].start()
        if full_chain:
            from transpect_trace.flow.etw import MultiApplicationETWCollector
            from transpect_trace.observe.windows import Profile
            from transpect_trace.observe.ecapture import ECaptureCollector
            from transpect_trace.observe.pipeline import Pipeline
            from transpect_trace.observe.policy import ObservationPolicy
            etw_members = [{k: v for k, v in subject.items() if k != 'image_path'}
                          | {'image_name': Path(subject['image_path']).name} for subject in subjects.values()]
            etw = MultiApplicationETWCollector(etw_members, native_dir/'flow_etw.exe', folder/'etw',
                                               run_id=evidence.session.session_id, duration=120, manifest=manifest)
            if etw.start()['state'] != 'ready':
                raise RuntimeError('etw_not_ready')
            def body_event(event, body, observation_id):
                with lock:
                    evidence.consume_body(event, body, observation_id)
            pipeline = Pipeline(folder/'observe', ObservationPolicy(), body_sink=body_event)
            ecapture = ECaptureCollector(subjects['B'], Profile(image_sha256=baseline['python'],
                application='file-mutation-winhttp-fixture', mode='schannel'), ecapture_dir/'ecapture.exe', pipeline)
            ecapture.start()
        def healthy():
            for collector in collectors.values():
                h = collector.status()
                if not h['ready'] or h['terminal'] or h['errors'] or h['lost_events']:
                    raise RuntimeError('native_io_not_active')
            if full_chain:
                ecapture.check_health()
                h = getattr(ecapture, 'structured', None)
                if not h or not h.ready or h.terminal or h.lost:
                    raise RuntimeError('ecapture_not_active')
                h = etw.index.health()
                if etw.process.poll() is not None or h['state'] != 'ready' or h['events_lost'] or h['gaps']:
                    raise RuntimeError('etw_not_active')
        healthy()
        fixtures['A'].send('release'); fixtures['A'].wait('initial_written', 15, healthy)
        fixtures['B'].send('release'); fixtures['B'].wait('read_paused', 15, healthy)
        if scenario == 'overwrite_suffix':
            fixtures['A'].send('rewrite'); fixtures['A'].wait('rewritten', 15, healthy)
        fixtures['B'].send('continue'); read_truth = fixtures['B'].wait('read_complete', 15, healthy)
        if full_chain:
            fixtures['B'].wait('sent', 30, healthy)
            sent = True
    except Exception as error:
        failures.append(type(error).__name__)
    finally:
        if ecapture:
            try: ecapture.close()
            except Exception: failures.append('ecapture_close_failed')
            try:
                from transpect_trace.flow.ecapture_diagnostics import snapshot
                build = getattr(ecapture, '_verified_manifest', {})
                diagnostics = snapshot(subjects['B'], ecapture_dir/'schannel_hook.dll',
                                       build.get('artifacts_sha256', {}).get('schannel_hook.dll'))
            except Exception:
                failures.append('ecapture_diagnostics_failed')
        for role, collector in collectors.items():
            try: collector.close()
            except Exception: failures.append('native_close_failed:'+role)
            health[role] = collector.status()
        for role, fixture in fixtures.items():
            try: fixture.close()
            except Exception: failures.append('fixture_close_failed:'+role)
            if fixture.process.poll() != 0: failures.append('fixture_nonzero_exit:'+role)
        if etw:
            try: etw.stop()
            except Exception: failures.append('etw_stop_failed')
        if origin:
            try: origin.close()
            except Exception: failures.append('origin_close_failed')
        # A failed audit write must not interrupt collector/origin teardown.
        for role, fixture in fixtures.items():
            try: (folder/f'fixture-{role}.json').write_text(json.dumps(fixture.events, indent=2)+'\n', encoding='utf-8')
            except OSError: failures.append('fixture_audit_failed:'+role)
    if evidence:
        for role, h in health.items():
            evidence.health('native-io:'+role, ready=h['ready'], terminal=h['terminal'], identity_verified=h['ready'],
                            lost_events=h['lost_events'], errors=len(h['errors']), limitations=h['errors'])
        if etw:
            from transpect_trace.flow.etw import summarize_coverage
            h = etw.index.health()
            evidence.health('etw', ready=h['ready_observed'], terminal=h['terminal_observed'],
                            identity_verified=h['ready_observed'], lost_events=h['events_lost'], limitations=h['gaps'])
            etw_coverage = summarize_coverage(etw.index, subjects, 'file', destination_port=origin.server.server_port if origin else None)
            for gap in etw_coverage['gaps']: evidence.gap(gap)
        if ecapture:
            h = getattr(ecapture, 'structured', None)
            evidence.health('ecapture', ready=bool(h and h.ready), terminal=bool(h and h.terminal),
                identity_verified=bool(h and h.ready), lost_events=h.lost if h else 0,
                errors=len(ecapture.errors), limitations=ecapture.errors)
        if pipeline:
            try: pipeline.finish()
            except Exception: failures.append('observe_finalize_failed')
            for gap in pipeline.gaps: evidence.gap(gap['reason'])
        if origin:
            for receipt in origin.receipts:
                evidence.add_receipt(receipt['body_sha256'], receipt['body_bytes'], receipt['receipt_id'])
            for gap in origin.errors: evidence.gap(gap)
        for failure in failures: evidence.gap(failure.replace(':', '_'))
        result = evidence.finish()
        report = evaluate(scenario, result, raw, snapshots, read_truth, health,
                          original=original, changed=changed, failures=failures, full_chain=full_chain,
                          etw_coverage=etw_coverage, sent=sent)
    else:
        report = {'scenario': scenario, 'component_passed': False, 'can_enforce': False, 'full_chain_certified': False}
    report.update(baseline=baseline, failures=failures, native_health=health, etw_coverage=etw_coverage,
                  ecapture_diagnostics=diagnostics,
                  fixture_exit_codes={r:f.process.poll() for r,f in fixtures.items()})
    (folder/'native-metadata.json').write_text(json.dumps(raw, indent=2)+'\n', encoding='utf-8')
    (folder/'snapshot-metadata.json').write_text(json.dumps(snapshots, indent=2)+'\n', encoding='utf-8')
    secrets = [MARKER.encode(encoding) for encoding in ('utf-8', 'utf-16-le', 'utf-16-be')]
    report['default_audit_secret_scan_passed'] = not any(needle in p.read_bytes() for p in folder.rglob('*') if p.is_file() for needle in secrets)
    report['component_passed'] &= report['default_audit_secret_scan_passed']
    report['full_chain_certified'] &= report['default_audit_secret_scan_passed']
    report['client_send_completed'] = sent
    (folder/'component-result.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return report


def administrator():
    from transpect_trace.observe.elevation import is_elevated
    return is_elevated()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fake-data-only', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--python', type=Path, default=Path(r'D:\devtools\python312\python.exe'))
    parser.add_argument('--native-dir', type=Path, default=ROOT/'build/flow')
    parser.add_argument('--full-chain', action='store_true')
    parser.add_argument('--ecapture-dir', type=Path, default=ROOT/'build/flow-ecapture-v2')
    parser.add_argument('--prepare-test-trust', action='store_true')
    parser.add_argument('--certificate', type=Path)
    parser.add_argument('--private-key', type=Path)
    args = parser.parse_args(argv)
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    summary = {'schema_version': 'transpect.flow.file-mutation-probe/1.0', 'started_at_utc': datetime.now(timezone.utc).isoformat(),
               'state': 'initializing', 'scope': 'native_etw_ecapture_origin' if args.full_chain else 'native_io_component_only',
               'fake_data_only': True, 'can_enforce': False, 'full_chain_certified': False,
               'cases': [], 'not_executed': ['same_path_file_replacement'] if args.full_chain else
                   ['ETW', 'eCapture', 'TLS', 'network_upload', 'same_path_file_replacement'],
               'certificate_cleanup': {'owned': False, 'required': False, 'confirmed': None}}
    def save():
        temporary = output/'summary.tmp'
        temporary.write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
        temporary.replace(output/'summary.json')
    save()
    lease = None
    try:
        if sys.platform != 'win32' or sys.maxsize <= 2**32:
            summary.update(state='unavailable', reason='requires_windows_x64')
        elif args.full_chain and not administrator():
            summary.update(state='unavailable', reason='administrator_token_required')
        else:
            certificate, private_key = None, None
            if not args.full_chain and (args.prepare_test_trust or args.certificate or args.private_key):
                raise ValueError('trust_options_require_full_chain')
            if args.full_chain:
                if args.prepare_test_trust:
                    if args.certificate or args.private_key:
                        raise ValueError('conflicting_trust_modes')
                    from _local_test_trust import LocalTestTrust
                    def command(arguments):
                        return subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              timeout=180, creationflags=0x08000000, check=False)
                    lease = LocalTestTrust(output/'test-trust', command_runner=command).prepare()
                    summary.update(state='waiting_test_trust', certificate_cleanup={'owned': True, 'required': True, 'confirmed': False})
                    save(); lease.install()
                    certificate, private_key = lease.certificate, lease.private_key
                else:
                    if not args.certificate or not args.private_key:
                        raise ValueError('pretrusted_localhost_certificate_required')
                    certificate, private_key = args.certificate.resolve(), args.private_key.resolve()
            for scenario in ('stable', 'overwrite_suffix'):
                summary.update(state='running', active_case=scenario); save()
                try:
                    result = run_case(output, scenario, args.python.resolve(), args.native_dir.resolve(),
                        full_chain=args.full_chain, ecapture_dir=args.ecapture_dir.resolve(),
                        certificate=certificate, private_key=private_key)
                except Exception as error:
                    # No exception strings: input paths/content can be sensitive.
                    result = {'scenario': scenario, 'component_passed': False, 'state': 'unavailable',
                              'failure_type': type(error).__name__, 'can_enforce': False, 'full_chain_certified': False}
                summary['cases'].append(result); save()
            passed = len(summary['cases']) == 2 and all(r['component_passed'] for r in summary['cases'])
            summary['state'] = ('full_chain_expectations_passed' if args.full_chain else 'component_passed') if passed else 'component_failed'
    except Exception as error:
        summary.update(state='unavailable', failure_type=type(error).__name__)
    finally:
        if lease:
            try: confirmed = bool(lease.cleanup()['cleanup_confirmed'])
            except Exception: confirmed = False
            summary['certificate_cleanup'].update(owned=True, required=True, confirmed=confirmed)
            if not confirmed:
                summary.update(state='component_failed', cleanup_gap='test_trust_cleanup_unconfirmed')
        summary.pop('active_case', None)
        summary['ended_at_utc'] = datetime.now(timezone.utc).isoformat()
        save()
    print(json.dumps({'state': summary['state'], 'cases': [(r['scenario'], r['component_passed']) for r in summary['cases']], 'full_chain_certified': False}))
    return 0 if summary['state'] in ('component_passed', 'full_chain_expectations_passed') else 2


if __name__ == '__main__':
    raise SystemExit(main())
