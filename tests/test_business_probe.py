"""Probe preparation/acceptance checks; no simulated Windows capture claims."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


@pytest.fixture
def probe(monkeypatch):
    scripts = Path(__file__).resolve().parents[1]/'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location('business_probe_tests', scripts/'probe_business_scenarios.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def files(tmp_path, monkeypatch):
    from transpect_trace.flow.scenarios import manifest
    root = tmp_path/'components'; root.mkdir()
    names = ['codex.exe', 'python.exe', 'powershell.exe', 'git.exe', 'ttrace-flow-io.dll',
             'flow_etw.exe', 'ecapture.exe', 'ttrace-guard.dll', 'etw.exe', 'certificate.pem', 'key.pem']
    values = {}
    for name in names:
        values[name] = root/name
        values[name].write_bytes(('inert-test-component:'+name).encode())
    # Tests use inert files; production's exact Codex hash validation is unchanged.
    monkeypatch.setattr(manifest, 'CODEX_SHA256', hashlib.sha256(values['codex.exe'].read_bytes()).hexdigest())
    (root/'native-build.json').write_text(json.dumps({'protocol': 'FIO1', 'can_enforce': False,
        'artifacts': {name: {'sha256': hashlib.sha256(values[name].read_bytes()).hexdigest()}
                      for name in ('ttrace-flow-io.dll', 'flow_etw.exe')}}), encoding='utf-8')
    (root/'ecapture-build.json').write_text('{}', encoding='utf-8')
    return root, values


def arguments(root, values, output):
    return ['--output', str(output), '--codex', str(values['codex.exe']), '--fake-data-only',
            '--python', str(values['python.exe']), '--powershell', str(values['powershell.exe']),
            '--git', str(values['git.exe']), '--native-dir', str(root), '--ecapture-dir', str(root),
            '--guard-dll', str(values['ttrace-guard.dll']), '--behavior-etw', str(values['etw.exe']),
            '--certificate', str(values['certificate.pem']), '--private-key', str(values['key.pem'])]


def test_prepare_freezes_cases_repeats_backends_without_clients_or_elevation(probe, tmp_path, monkeypatch):
    root, values = files(tmp_path, monkeypatch)
    output = tmp_path/'prepared'
    monkeypatch.setattr(probe, 'is_elevated', lambda: False)
    monkeypatch.setattr(probe, 'run', lambda *_: pytest.fail('prepare started a client'))
    monkeypatch.setattr(probe, '_elevate', lambda *_: pytest.fail('prepare requested UAC'))
    args = arguments(root, values, output) + ['--prepare-only', '--case', 'webhook:plain', '--case', 'git:untracked', '--repeat', '2']
    assert probe.main(args) == 0
    summary = json.loads((output/'summary.json').read_bytes())
    assert summary['state'] == 'prepared' and not summary['cases'] and not summary['certified']
    assert len(summary['manifests']) == 6
    for entry in summary['manifests']:
        data = json.loads((output/entry['path']).read_bytes())
        assert data['fake_data_only'] is True and data['can_enforce'] is False
        assert data['executables']['codex']['sha256'] == hashlib.sha256(values['codex.exe'].read_bytes()).hexdigest()
        assert not Path(data['output']).exists()
    assert probe.SECRET not in (output/'summary.json').read_text()
    before = (output/'summary.json').read_bytes()
    with pytest.raises(FileExistsError):
        probe.main(args)
    assert (output/'summary.json').read_bytes() == before


def test_ordinary_permission_live_run_records_unavailable_without_trust_or_client(probe, tmp_path, monkeypatch):
    root, values = files(tmp_path, monkeypatch)
    output = tmp_path/'unavailable'
    monkeypatch.setattr(probe, 'is_elevated', lambda: False)
    monkeypatch.setattr(probe, 'run', lambda *_: pytest.fail('client ran without administrator token'))
    assert probe.main(arguments(root, values, output) + ['--case', 'webhook:public', '--repeat', '1']) == 2
    summary = json.loads((output/'summary.json').read_bytes())
    assert summary['state'] == 'unavailable'
    assert summary['reason'] == 'windows_administrator_token_required'
    assert not summary['manifests'] and not summary['cases']
    assert not (output/'test-trust').exists()


def test_preparation_generates_but_never_installs_test_root(probe, tmp_path, monkeypatch):
    root, values = files(tmp_path, monkeypatch)
    output = tmp_path/'prepared-trust'
    monkeypatch.setattr(probe, 'is_elevated', lambda: False)
    monkeypatch.setattr(probe.LocalTestTrust, 'install', lambda *_: pytest.fail('prepare installed trust'))
    monkeypatch.setattr(probe.LocalTestTrust, 'cleanup', lambda *_: pytest.fail('prepare attempted trust deletion'))
    args = arguments(root, values, output)
    args = args[:args.index('--certificate')] + ['--prepare-test-trust', '--prepare-only', '--case', 'webhook:extract', '--repeat', '1']
    assert probe.main(args) == 0
    summary = json.loads((output/'summary.json').read_bytes())
    trust = json.loads((output/'test-trust/test-trust.json').read_bytes())
    assert summary['trust_state'] == 'prepared_not_installed'
    assert trust['import_attempted'] is False and trust['cleanup_attempted'] is False


def test_runtime_failure_redacted_and_owned_trust_cleanup_still_runs(probe, tmp_path, monkeypatch):
    root, values = files(tmp_path, monkeypatch)
    output = tmp_path/'failed'
    monkeypatch.setattr(probe, 'is_elevated', lambda: True)
    monkeypatch.setattr(probe.sys, 'platform', 'win32')
    leases = []
    class Lease:
        def __init__(self, directory, **_):
            self.certificate, self.private_key = values['certificate.pem'], values['key.pem']
            self.manifest = {'import_attempted': False}
            self.cleaned = False
            leases.append(self)
        def prepare(self): return self
        def install(self): self.manifest['import_attempted'] = True; return self
        def cleanup(self): self.cleaned = True; return {'cleanup_confirmed': True}
    monkeypatch.setattr(probe, 'LocalTestTrust', Lease)
    def fail(_): raise OSError(probe.SECRET)
    monkeypatch.setattr(probe, 'run', fail)
    args = arguments(root, values, output)
    args = args[:args.index('--certificate')] + ['--prepare-test-trust', '--case', 'webhook:plain', '--repeat', '1']
    assert probe.main(args) == 2
    summary = json.loads((output/'summary.json').read_bytes())
    assert leases[0].cleaned and summary['test_trust_cleanup_confirmed']
    assert summary['cases'][0]['error_type'] == 'OSError'
    assert probe.SECRET not in (output/'summary.json').read_text()


def test_source_receipt_and_saved_success_do_not_certify_missing_capture(probe, tmp_path):
    audit = tmp_path/'audit'; audit.mkdir()
    source = {'route': 'webhook', 'body_sha256': 'a'*64, 'body_bytes': 20, 'completeness': 'complete'}
    (audit/'capture-summary.json').write_text(json.dumps({'requests': [], 'receipts': [source]}))
    (audit/'business-report.json').write_text(json.dumps({'state': 'complete', 'certified': True,
                                                        'can_enforce': False}))
    value = probe.assess_case('webhook', 'plain', {'state': 'complete', 'certified': True, 'can_enforce': False}, audit)
    assert not value['accepted']
    assert not value['checks']['request_count'] and not value['checks']['collector_health']
    assert not value['checks']['sensitive_expectation']


def test_privacy_scan_fails_without_printing_secret_and_retains_scope(probe, tmp_path):
    audit = tmp_path/'audit'; audit.mkdir()
    (audit/'bad.json').write_text(json.dumps({'unexpected': probe.SECRET}))
    result = probe.privacy_scan(audit)
    assert not result['passed'] and result['files_with_test_secret'] == ['bad.json']
    assert result['scope'] == 'audit_outputs_only'
    assert probe.SECRET not in json.dumps(result)
