import json
from pathlib import Path
import pytest

from transpect_trace.flow.manifest import FlowManifest, frozen, load


def make_manifest(tmp_path):
    from transpect_trace.flow import participant
    paths = {}
    for field, name in [('python','python.exe'),('uploader','flow_uploader.exe'),('observer','ttrace-flow-io.dll'),
                        ('etw','flow_etw.exe'),('ecapture','ecapture.exe'),('ecapture_manifest','ecapture-build.json'),
                        ('source','input.txt'),('content_index','index.json'),('certificate','localhost.pem'),('private_key','localhost.key')]:
        path = tmp_path/name
        path.write_bytes(field.encode())
        paths[field] = frozen(path)
    native = tmp_path/'native-build.json'
    native.write_text(json.dumps({'protocol':'FIO1','can_enforce':False,
        'artifacts':{Path(paths[k]['path']).name: {'sha256':paths[k]['sha256']} for k in ('uploader','observer','etw')}}))
    paths['native_manifest'] = frozen(native)
    paths['participant'] = frozen(Path(participant.__file__))
    manifest = {'scenario':'file','fake_data_only':True,'output':'audit',**paths}
    target = tmp_path/'experiment.json'
    target.write_text(json.dumps(manifest))
    return target, manifest


def test_manifest_resolves_relative_output_and_freezes_all_inputs(tmp_path, monkeypatch):
    path, _ = make_manifest(tmp_path)
    monkeypatch.chdir(tmp_path.parent)
    manifest, paths, output = load(path)
    assert output == tmp_path/'audit'
    assert manifest.can_enforce is False
    paths['source'].write_bytes(b'modified')
    with pytest.raises(ValueError, match='hash_mismatch'): load(path)
    assert not output.exists()


def test_manifest_does_not_overwrite_evidence_or_accept_other_script(tmp_path):
    path, value = make_manifest(tmp_path)
    (tmp_path/'audit').mkdir()
    (tmp_path/'audit'/'unique.txt').write_text('preserve')
    with pytest.raises(ValueError, match='must_be_new'): load(path)
    assert (tmp_path/'audit'/'unique.txt').read_text() == 'preserve'
    value['output'] = 'new-audit'
    value['participant'] = value['source']
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='unsupported_participant'): load(path)


def test_manifest_rejects_unpinned_artifact_and_enforcement(tmp_path):
    path, value = make_manifest(tmp_path)
    value['can_enforce'] = True
    with pytest.raises(ValueError): FlowManifest.model_validate(value)
    value['can_enforce'] = False
    data = json.loads((tmp_path/'native-build.json').read_text())
    data['artifacts']['flow_etw.exe']['sha256'] = '0'*64
    (tmp_path/'native-build.json').write_text(json.dumps(data))
    value['native_manifest'] = frozen(tmp_path/'native-build.json')
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='artifact_manifest'): load(path)


def test_flow_cli_keeps_existing_groups_and_reads_unavailable(tmp_path):
    from typer.testing import CliRunner
    from typer.main import get_command
    from transpect_trace.cli import app
    assert set(get_command(app).commands) == {'guard','observe','protect','behavior','flow'}
    assert set(get_command(app).commands['flow'].commands) == {'run','status','report','agents','scenarios','knowledge-mail'}
    (tmp_path/'runtime.json').write_text('{"state":"unavailable","can_enforce":false}')
    result = CliRunner().invoke(app, ['flow','status',str(tmp_path)])
    assert result.exit_code == 0 and 'unavailable' in result.output
    result = CliRunner().invoke(app, ['flow','report',str(tmp_path)])
    assert result.exit_code == 0 and 'flow_evidence_not_available' in result.output


def test_runtime_non_windows_never_starts_or_releases(tmp_path, monkeypatch):
    from transpect_trace.flow import runtime
    path, _ = make_manifest(tmp_path)
    monkeypatch.setattr(runtime.sys, 'platform', 'linux')
    result = runtime.run(path)
    assert result['state']=='unavailable' and not result['data_released']
    assert not result['certified']


@pytest.mark.parametrize('encoding_errors', [None, 'strict', 'replace'])
def test_ecapture_native_popen_encoding_option_is_not_collector_error(encoding_errors):
    from types import SimpleNamespace
    from transpect_trace.observe.ecapture import ECaptureCollector
    collector = ECaptureCollector({}, None, Path('unused'), None)
    collector.process = SimpleNamespace(errors=encoding_errors, poll=lambda: None)
    collector.check_health()
    assert collector.errors == []
    collector.process.errors = ['collector_fault']
    with pytest.raises(RuntimeError): collector.check_health()
    assert collector.errors == ['collector_fault']


def test_status_rejects_stale_controller_without_rewriting_evidence(tmp_path, monkeypatch):
    from transpect_trace.flow.cli import read_status
    import transpect_trace.observe.windows as windows
    row={'state':'observing','controller':{'pid':5,'creation_filetime':10,'image_sha256':'a'*64}}
    path=tmp_path/'runtime.json';path.write_text(json.dumps(row))
    monkeypatch.setattr(windows, 'identity', lambda pid: {'pid':5,'creation_filetime':11,'image_sha256':'a'*64})
    result=read_status(tmp_path)
    assert result['state']=='unavailable' and result['recorded_state']=='observing'
    assert json.loads(path.read_text())==row
