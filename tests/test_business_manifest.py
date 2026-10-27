import hashlib
import json

import pytest
from pydantic import ValidationError

from transpect_trace.flow.manifest import frozen
from transpect_trace.flow.scenarios import manifest as module


def inputs(tmp_path, monkeypatch, scenario='webhook'):
    def file(name, data=None):
        path = tmp_path / name
        path.write_bytes(data if data is not None else name.encode())
        return frozen(path)
    executables = {k: file(k + '.exe') for k in ('codex', 'python', 'powershell')}
    if scenario == 'git':
        executables['git'] = file('git.exe')
    monkeypatch.setattr(module, 'CODEX_SHA256', executables['codex']['sha256'])
    builds = {k: file(k + '.bin') for k in module.BUILD_KEYS - {'native_manifest', 'ecapture_manifest'}}
    builds['ecapture_manifest'] = file('ecapture-build.json', b'{}')
    native = {'protocol': 'FIO1', 'can_enforce': False,
              'artifacts': {k + '.bin': {'sha256': builds[k]['sha256']} for k in ('io_observer', 'etw')}}
    builds['native_manifest'] = file('native-build.json', json.dumps(native).encode())
    value = {'scenario': scenario, 'case': 'plain' if scenario == 'webhook' else 'sensitive',
             'fake_data_only': True, 'executables': executables, 'build_inputs': builds,
             'source': file('source.json', b'{"ticket":"FAKE_ONLY"}'),
             'content_index': file('index.json', b'{}'), 'certificate': file('localhost.pem'),
             'private_key': file('localhost.key'), 'output': 'new-audit'}
    return value


def test_inputs_are_resolved_from_manifest_and_hash_checked(tmp_path, monkeypatch):
    value = inputs(tmp_path, monkeypatch)
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(value), encoding='utf-8')
    monkeypatch.chdir(tmp_path.parent)
    manifest, paths, output = module.load(path)
    assert output == tmp_path / 'new-audit'
    assert [s.step_id for s in manifest.steps] == ['export', 'tool', 'transform', 'upload']
    paths['source'].write_bytes(b'changed')
    with pytest.raises(ValueError, match='hash_mismatch'):
        module.load(path)
    assert not output.exists()


@pytest.mark.parametrize('change', [
    {'command': 'arbitrary.exe'}, {'fake_data_only': False}, {'can_enforce': True},
    {'case': 'arbitrary'}, {'scenario': 'browser'}, {'git_tls_backend': 'schannel'},
    {'timeout_seconds': 181},
])
def test_manifest_rejects_expanded_execution_surface(tmp_path, monkeypatch, change):
    with pytest.raises(ValidationError):
        module.BusinessScenarioManifest.model_validate({**inputs(tmp_path, monkeypatch), **change})


def test_existing_evidence_never_overwritten(tmp_path, monkeypatch):
    value = module.BusinessScenarioManifest.model_validate(inputs(tmp_path, monkeypatch))
    (tmp_path / 'new-audit').mkdir()
    (tmp_path / 'new-audit' / 'unique.txt').write_text('keep')
    with pytest.raises(ValueError, match='output_must_be_new'):
        value.resolve(tmp_path)
    assert (tmp_path / 'new-audit' / 'unique.txt').read_text() == 'keep'


def test_codex_and_native_artifact_identity_remain_strict(tmp_path, monkeypatch):
    raw = inputs(tmp_path, monkeypatch)
    raw['executables']['codex']['sha256'] = 'f' * 64
    with pytest.raises(ValidationError, match='unsupported_codex_baseline'):
        module.BusinessScenarioManifest.model_validate(raw)
    raw = inputs(tmp_path, monkeypatch)
    native = tmp_path / 'native-build.json'
    native.write_text(json.dumps({'protocol': 'FIO1', 'can_enforce': False, 'artifacts': {}}))
    raw['build_inputs']['native_manifest'] = frozen(native)
    with pytest.raises(ValueError, match='native_artifact_manifest_mismatch'):
        module.BusinessScenarioManifest.model_validate(raw).resolve(tmp_path)


def test_manifest_does_not_allow_arbitrary_graph_or_tool(tmp_path, monkeypatch):
    raw = inputs(tmp_path, monkeypatch)
    raw['participants'] = [{'role': 'attacker', 'kind': 'real_application', 'executable_key': 'python'}]
    with pytest.raises(ValidationError, match='unsupported_scenario_graph'):
        module.BusinessScenarioManifest.model_validate(raw)
    raw = inputs(tmp_path, monkeypatch)
    raw['executables']['other'] = raw['executables']['python']
    with pytest.raises(ValidationError, match='executable_keys_mismatch'):
        module.BusinessScenarioManifest.model_validate(raw)


def test_git_graph_and_explicit_tls_selection(tmp_path, monkeypatch):
    raw = inputs(tmp_path, monkeypatch, 'git')
    raw['git_tls_backend'] = 'schannel'
    manifest = module.BusinessScenarioManifest.model_validate(raw)
    assert [s.step_id for s in manifest.steps][-2:] == ['commit', 'push']
    assert manifest.git_tls_backend == 'schannel'


@pytest.mark.parametrize('data', [b'not json', b'[]', b'\xff', b'x' * (1024 * 1024 + 1)],
                         ids=['invalid-json', 'not-object', 'invalid-utf8', 'oversize'])
def test_source_encoding_shape_and_size_are_bounded(tmp_path, monkeypatch, data):
    raw = inputs(tmp_path, monkeypatch)
    source = tmp_path / 'source.json'
    source.write_bytes(data)
    raw['source'] = frozen(source)
    with pytest.raises(ValueError):
        module.BusinessScenarioManifest.model_validate(raw).resolve(tmp_path)
