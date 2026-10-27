import json
from pathlib import Path

import pytest

from transpect_trace.flow.agents.manifest import AgentFlowManifest, implementation_paths, load
from transpect_trace.flow.manifest import frozen


def make_manifest(tmp_path):
    from transpect_trace.flow.agents import participant
    fields = {}
    for name, filename in [('python','python.exe'),('observer','ttrace-flow-io.dll'),('etw','flow_etw.exe'),
                           ('ecapture','ecapture.exe'),('ecapture_manifest','ecapture-build.json'),
                           ('source','input.json'),('content_index','index.json'),('certificate','localhost.pem'),
                           ('private_key','localhost.key')]:
        path = tmp_path/filename
        path.write_bytes(name.encode())
        fields[name] = frozen(path)
    native = tmp_path/'native-build.json'
    native.write_text(json.dumps({'protocol':'FIO1','can_enforce':False,
                                 'artifacts':{Path(fields[k]['path']).name:{'sha256':fields[k]['sha256']} for k in ('observer','etw')}}))
    fields['native_manifest'] = frozen(native)
    fields['participant'] = frozen(Path(participant.__file__))
    result = {'fake_data_only':True, 'output':'audit', **fields,
              'implementation':{k:frozen(v) for k,v in implementation_paths().items()}}
    path = tmp_path/'manifest.json'
    path.write_text(json.dumps(result))
    return path,result


def test_agent_manifest_is_independent_and_freezes_imported_fixture_code(tmp_path,monkeypatch):
    path,value = make_manifest(tmp_path)
    monkeypatch.chdir(tmp_path.parent)
    manifest,paths,output = load(path)
    assert output == tmp_path/'audit' and not manifest.can_enforce
    assert 'uploader' not in paths and manifest.agent_kind == 'deterministic_test_agent'
    value['implementation']['agents/protocol.py']['sha256'] = '0'*64
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='hash_mismatch'): load(path)


def test_missing_or_substituted_helper_and_unknown_fields_rejected(tmp_path):
    path,value = make_manifest(tmp_path)
    value['implementation'].pop('agents/winhttp.py')
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='implementation_pin'): load(path)
    value['implementation'] = {k:frozen(v) for k,v in implementation_paths().items()}
    value['implementation']['agents/winhttp.py'] = value['source']
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='unsupported_agent_implementation'): load(path)
    with pytest.raises(ValueError): AgentFlowManifest.model_validate({**value,'can_enforce':True})
    with pytest.raises(ValueError): AgentFlowManifest.model_validate({**value,'scenario':'pipe'})


def test_new_output_required_and_artifact_manifest_still_enforced(tmp_path):
    path,value = make_manifest(tmp_path)
    output = tmp_path/'audit'
    output.mkdir()
    (output/'evidence.txt').write_text('unique')
    with pytest.raises(ValueError,match='must_be_new'): load(path)
    assert (output/'evidence.txt').read_text() == 'unique'
    value['output']='new-audit'
    native = Path(value['native_manifest']['path'])
    native.write_text('{"protocol":"FIO1","can_enforce":false,"artifacts":{}}')
    value['native_manifest'] = frozen(native)
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='artifact_manifest'): load(path)


def test_agent_commands_preserve_flow_commands_and_report_is_read_only(tmp_path):
    from typer.testing import CliRunner
    from typer.main import get_command
    from transpect_trace.cli import app
    from transpect_trace.flow.agents.cli import read_report
    flow = get_command(app).commands['flow']
    assert set(flow.commands) == {'run','report','status','agents','scenarios','knowledge-mail'}
    assert set(flow.commands['agents'].commands) == {'run','report','status'}
    value = {'schema_version':'transpect.agent.report/1.0','can_enforce':False,'session':{'status':'partial'}}
    original = json.dumps(value)
    (tmp_path/'agent-evidence.json').write_text(original)
    (tmp_path/'flow-evidence.json').write_text('{}')
    assert read_report(tmp_path)['independent_evidence_files'] == ['flow-evidence.json']
    assert (tmp_path/'agent-evidence.json').read_text() == original
    result = CliRunner().invoke(app,['flow','agents','report',str(tmp_path)])
    assert result.exit_code == 0 and 'partial' in result.output
