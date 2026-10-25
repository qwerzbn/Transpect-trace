"""Probe controls and redaction; integration evidence is produced separately."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from transpect_trace.flow import mutation_participant as participant


@pytest.fixture
def probe(monkeypatch):
    scripts = Path(__file__).resolve().parents[1]/'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location('probe_flow_file_mutation', scripts/'probe_flow_file_mutation.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_mutated_fixture_is_still_json_but_is_not_the_original_snapshot(probe):
    original = probe.fake_source()
    changed = participant.replacement(original)
    assert len(original) == len(changed) > participant.CUT
    assert original[:participant.CUT] == changed[:participant.CUT]
    assert original[participant.CUT:] != changed[participant.CUT:]
    assert json.loads(original)['document'] == json.loads(changed)['document'] == probe.MARKER
    assert hashlib.sha256(original).digest() != hashlib.sha256(changed).digest()


def test_native_metadata_never_exports_bytes_or_paths(probe):
    row = probe.metadata({'data': b'private-body', 'path': 'private-path', 'file_identity': 'volume:file',
                          'requested_length': 12, 'completed_length': 12, 'offset': 65536})
    text = json.dumps(row)
    assert 'private-body' not in text and 'private-path' not in text and 'volume:file' not in text
    assert row['snapshot_bytes'] == 12 and row['offset'] == 65536
    assert row['snapshot_sha256'] == hashlib.sha256(b'private-body').hexdigest()
    assert row['can_enforce'] is False


@pytest.mark.parametrize('value', [b'{}', b'bad' * 50000, b'X' * (participant.LIMIT + 1)],
                         ids=['short', 'invalid-json', 'over-limit'])
def test_replacement_rejects_invalid_or_out_of_scope_data(value):
    with pytest.raises(ValueError): participant.replacement(value)


def test_explicit_fake_data_flag_is_required(probe, tmp_path):
    with pytest.raises(SystemExit): probe.main(['--output', str(tmp_path/'not-created')])
    assert not (tmp_path/'not-created').exists()


def test_invalid_fixture_arguments_never_echo_input(capsys):
    assert participant.main(['--secret-argument', 'do-not-echo-secret']) == 2
    text = capsys.readouterr().out
    assert 'do-not-echo-secret' not in text
    assert json.loads(text)['kind'] == 'error'


def test_missing_native_input_records_failure_without_exception_contents(probe, tmp_path, monkeypatch):
    def unavailable(*_, **__):
        raise OSError('secret-path-or-body-must-not-be-exported')
    monkeypatch.setattr(probe, 'run_case', unavailable)
    monkeypatch.setattr(probe.sys, 'platform', 'win32')
    output = tmp_path/'failed'
    assert probe.main(['--fake-data-only', '--output', str(output)]) == 2
    text = (output/'summary.json').read_text()
    result = json.loads(text)
    assert result['state'] == 'component_failed' and len(result['cases']) == 2
    assert not any(row['component_passed'] for row in result['cases'])
    assert 'secret-path-or-body' not in text and result['full_chain_certified'] is False


def test_full_chain_requires_admin_before_trust_or_any_case(probe, tmp_path, monkeypatch):
    monkeypatch.setattr(probe.sys, 'platform', 'win32')
    monkeypatch.setattr(probe, 'administrator', lambda: False)
    def forbidden(*_, **__): raise AssertionError('must not start a case')
    monkeypatch.setattr(probe, 'run_case', forbidden)
    output = tmp_path/'unavailable'
    assert probe.main(['--fake-data-only', '--full-chain', '--prepare-test-trust', '--output', str(output)]) == 2
    result = json.loads((output/'summary.json').read_text())
    assert result['state'] == 'unavailable' and result['reason'] == 'administrator_token_required'
    assert not result['cases'] and not (output/'test-trust').exists()


def test_fixture_imports_are_recorded_and_resolve_under_package(probe):
    paths = probe.implementation_paths()
    assert all(p.is_file() for p in paths.values())
    assert {'participant', 'probe', 'winhttp', 'package_init', 'flow_init', 'agents_init'} == set(paths)
    assert paths['winhttp'].name == 'winhttp.py'


def sample_evaluation(probe, mutation):
    """Exercise acceptance failures without pretending this is live evidence."""
    original = probe.fake_source(); changed = participant.replacement(original)
    expected = changed if mutation else original
    digest = hashlib.sha256(expected).hexdigest()
    read = {'observation_id': 'read', 'process': {'role': 'B'}, 'operation': 'read', 'resource_role': 'transfer',
            'content_sha256': digest, 'completeness': 'partial' if mutation else 'complete',
            'limitations': ['file_modified_during_read'] if mutation else []}
    writes = [{'process': {'role': 'A'}, 'operation': 'write', 'resource_role': 'transfer'} for _ in range(2 if mutation else 1)]
    def raw(kind, offset, count, qpc, end, generation=1):
        return dict(kind=kind, path_role='transfer', offset=offset, completed_length=count,
                    requested_length=count, snapshot_bytes=count, qpc=qpc, completed_qpc=end,
                    open_generation=generation, file_identity_sha256='f'*64, success=True)
    events = [raw('write', 0, len(original), 1, 2), raw('read', 0, participant.CUT, 3, 4)]
    if mutation: events.append(raw('write', participant.CUT, len(expected)-participant.CUT, 5, 6, 2))
    events.append(raw('read', participant.CUT, len(expected)-participant.CUT, 7, 8))
    h = dict(ready=True, terminal=True, identity_verified=True, lost_events=0, errors=0, limitations=[])
    outbound = dict(provider='ecapture-windows', capture_layer='tls', completeness='complete', encoding_state='identity',
                    parsing_state='json', protocol='http/1.1', send_evidence='encryption_input_observed',
                    decoded_body_sha256=digest, body_bytes=len(expected), detection_status='matched',
                    findings=[{'registration_id': 'fake-mutation-document'}])
    result = {'system_behavior': {'transfers': [read, *writes]}, 'session': {'status': 'partial' if mutation else 'complete',
              'health': {name: dict(h) for name in ('native-io:A', 'native-io:B', 'etw', 'ecapture')}},
              'content_detection': {'outbound': [outbound]}, 'coverage_gaps': [],
              'origin_receipts': {'receipts': [{'body_sha256': digest, 'body_bytes': len(expected)}], 'request_identity_mapping': 'unverified'},
              'collection_coverage': {'complete': not mutation, 'b_handoff_read_observed': not mutation},
              'propagation': {'relations': [{'confidence': 'Unknown' if mutation else 'High'}]}}
    arguments = dict(original=original, changed=changed, failures=[], full_chain=True,
                     etw_coverage={'actual_event_count': 1, 'gaps': []}, sent=True)
    positional = ['overwrite_suffix' if mutation else 'stable', result, events, {'read': {'json_valid': True}},
                  {'body_sha256': digest, 'evidence_origin': 'fixture_truth'}, {'A': dict(h), 'B': dict(h)}]
    return positional, arguments


@pytest.mark.parametrize('mutation', [False, True], ids=['stable', 'mutated'])
def test_full_chain_expected_outcomes_require_tls_and_origin(probe, mutation):
    positional, arguments = sample_evaluation(probe, mutation)
    assert probe.evaluate(*positional, **arguments)['component_passed']
    positional[1]['origin_receipts']['receipts'].clear()
    report = probe.evaluate(*positional, **arguments)
    assert not report['component_passed'] and not report['checks']['actual_tls_origin_body']


def test_valid_json_mutation_cannot_pass_without_read_and_relation_downgrade(probe):
    positional, arguments = sample_evaluation(probe, True)
    positional[1]['system_behavior']['transfers'][0]['completeness'] = 'complete'
    positional[1]['propagation']['relations'][0]['confidence'] = 'Medium'
    report = probe.evaluate(*positional, **arguments)
    assert report['checks']['actual_snapshot_json_valid']
    assert not report['checks']['modified_read_degraded']
    assert not report['checks']['uncertain_relations_not_certified']
    assert not report['component_passed'] and not report['full_chain_certified']
