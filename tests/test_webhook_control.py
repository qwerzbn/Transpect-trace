"""Qualification failures cannot be replaced by saved observation success."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def probe(monkeypatch):
    scripts=Path(__file__).resolve().parents[1]/'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    spec=importlib.util.spec_from_file_location('webhook_control_tests',scripts/'probe_webhook_control.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def files(tmp_path, monkeypatch):
    from transpect_trace.flow.scenarios import manifest
    root=tmp_path/'components'; root.mkdir()
    names=['codex.exe','python.exe','powershell.exe','ttrace-flow-io.dll','flow_etw.exe','ecapture.exe','ttrace-guard.dll','etw.exe','certificate.pem','key.pem','ttrace-egress.dll']
    values={name:root/name for name in names}
    for name,path in values.items():path.write_bytes(('inert:'+name).encode())
    sha=lambda name:hashlib.sha256(values[name].read_bytes()).hexdigest()
    monkeypatch.setattr(manifest,'CODEX_SHA256',sha('codex.exe'))
    (root/'native-build.json').write_text(json.dumps({'protocol':'FIO1','can_enforce':False,'artifacts':{name:{'sha256':sha(name)} for name in ('ttrace-flow-io.dll','flow_etw.exe')}}))
    (root/'ecapture-build.json').write_text('{}')
    (root/'build-manifest.json').write_text(json.dumps({'schema':'transpect.native.egress.build/1.0','artifacts_sha256':{'ttrace-egress.dll':sha('ttrace-egress.dll')}}))
    return root,values


def arguments(root,values,output):
    return ['--output',str(output),'--codex',str(values['codex.exe']),'--fake-data-only',
        '--python',str(values['python.exe']),'--powershell',str(values['powershell.exe']),
        '--native-dir',str(root),'--ecapture-dir',str(root),'--guard-dll',str(values['ttrace-guard.dll']),
        '--behavior-etw',str(values['etw.exe']),'--egress-dll',str(values['ttrace-egress.dll']),
        '--certificate',str(values['certificate.pem']),'--private-key',str(values['key.pem'])]


def test_prepare_freezes_three_sessions_without_uac_or_clients(probe,tmp_path,monkeypatch):
    root,values=files(tmp_path,monkeypatch); output=tmp_path/'prepared'
    monkeypatch.setattr(probe,'is_elevated',lambda:False)
    monkeypatch.setattr(probe,'run_control',lambda *_:pytest.fail('prepare launched client'))
    monkeypatch.setattr(probe,'_elevate',lambda *_:pytest.fail('prepare requested UAC'))
    assert probe.main(arguments(root,values,output)+['--prepare-only'])==0
    summary=json.loads((output/'summary.json').read_bytes())
    assert summary['state']=='prepared' and not summary['passed'] and not summary['phases']
    assert [row['action'] for row in summary['manifests']]==['allow','block','allow']
    assert summary['recovery_scope']=='new_session_with_allow_policy'
    for row in summary['manifests']:
        manifest=json.loads((output/row['path']).read_bytes())
        assert manifest['scenario']=='webhook' and manifest['can_enforce'] is False and manifest['fake_data_only'] is True
        assert not Path(manifest['output']).exists()
    before=(output/'summary.json').read_bytes()
    with pytest.raises(FileExistsError):probe.main(arguments(root,values,output)+['--prepare-only'])
    assert (output/'summary.json').read_bytes()==before


def test_non_admin_does_not_create_trust_or_run_control(probe,tmp_path,monkeypatch):
    root,values=files(tmp_path,monkeypatch); output=tmp_path/'ordinary'
    monkeypatch.setattr(probe,'is_elevated',lambda:False)
    monkeypatch.setattr(probe,'run_control',lambda *_:pytest.fail('client started'))
    assert probe.main(arguments(root,values,output))==2
    summary=json.loads((output/'summary.json').read_bytes())
    assert summary['state']=='unavailable' and summary['reason']=='windows_administrator_token_required'
    assert not summary['manifests'] and not (output/'test-trust').exists()


@pytest.mark.parametrize('report',[
    {}, {'action':'block','passed':True,'checks':{}},
    {'action':'block','passed':True,'checks':{'rejected':1}},
    {'action':'block','passed':True,'checks':{'rejected':False}},
    {'action':'allow','passed':True,'checks':{'received':True}},
])
def test_missing_or_empty_or_wrong_control_evidence_is_not_pass(probe,tmp_path,report):
    audit=tmp_path/'audit'; audit.mkdir()
    (audit/'webhook-control.json').write_text(json.dumps(report))
    result=probe.assess_control(audit,'block')
    assert not result['accepted']


def test_observation_partial_can_coexist_with_verified_rejection(probe,tmp_path):
    audit=tmp_path/'audit'; audit.mkdir()
    (audit/'business-report.json').write_text('{"state":"partial","can_enforce":false}')
    (audit/'webhook-control.json').write_text(json.dumps({'action':'block','passed':True,'checks':{'native_rejection':True,'source_zero':True}}))
    assert probe.assess_control(audit,'block')['accepted']
    (audit/'unexpected.json').write_text(json.dumps({'secret':probe.SECRET}))
    result=probe.assess_control(audit,'block')
    assert not result['accepted'] and probe.SECRET not in json.dumps(result)


def test_modified_egress_build_is_rejected_before_control(probe,tmp_path,monkeypatch):
    root,values=files(tmp_path,monkeypatch)
    frozen={name:probe.frozen(path) for name,path in {'egress_dll':values['ttrace-egress.dll'],'egress_manifest':root/'build-manifest.json'}.items()}
    assert probe.verify_egress(frozen,tmp_path)==values['ttrace-egress.dll']
    values['ttrace-egress.dll'].write_bytes(b'changed')
    with pytest.raises(ValueError,match='frozen_file_hash_mismatch'):probe.verify_egress(frozen,tmp_path)


def test_live_three_sessions_require_each_control_report_and_cleanup(probe,tmp_path,monkeypatch):
    root,values=files(tmp_path,monkeypatch);output=tmp_path/'live'
    monkeypatch.setattr(probe,'is_elevated',lambda:True);monkeypatch.setattr(probe.sys,'platform','win32')
    actions=[]
    def run(path,dll,action):
        value=json.loads(path.read_bytes());audit=Path(value['output']);audit.mkdir(parents=True)
        actions.append(action)
        (audit/'webhook-control.json').write_text(json.dumps({'action':action,'passed':True,'checks':{'scope_verified':True,'source_or_rejection':True}}))
        return {'state':'partial'}
    monkeypatch.setattr(probe,'run_control',run)
    assert probe.main(arguments(root,values,output))==0
    summary=json.loads((output/'summary.json').read_bytes())
    assert summary['passed'] and actions==['allow','block','allow']
    assert all(row['observation_state']=='partial' for row in summary['phases'])


def test_bad_check_values_are_redacted_not_copied_to_summary(probe,tmp_path):
    audit=tmp_path/'audit';audit.mkdir()
    (audit/'webhook-control.json').write_text(json.dumps({'action':'block','passed':True,'checks':{'injected':probe.SECRET}}))
    result=probe.assess_control(audit,'block')
    assert not result['accepted'] and result['checks']=={} and probe.SECRET not in json.dumps(result)


def test_prepare_creates_owned_root_without_install_or_cleanup(probe,tmp_path,monkeypatch):
    root,values=files(tmp_path,monkeypatch);output=tmp_path/'trust-prepared'
    monkeypatch.setattr(probe,'is_elevated',lambda:False)
    monkeypatch.setattr(probe.LocalTestTrust,'install',lambda *_:pytest.fail('prepare installed root'))
    monkeypatch.setattr(probe.LocalTestTrust,'cleanup',lambda *_:pytest.fail('prepare removed root'))
    args=arguments(root,values,output);args=args[:args.index('--certificate')]+['--prepare-test-trust','--prepare-only']
    assert probe.main(args)==0
    lease=json.loads((output/'test-trust/test-trust.json').read_bytes())
    assert not lease['import_attempted'] and not lease['cleanup_attempted']


def test_runtime_failure_still_cleans_owned_root_and_redacts_error(probe,tmp_path,monkeypatch):
    root,values=files(tmp_path,monkeypatch);output=tmp_path/'failed-live';leases=[]
    monkeypatch.setattr(probe,'is_elevated',lambda:True);monkeypatch.setattr(probe.sys,'platform','win32')
    class Lease:
        def __init__(self,directory,**_):
            self.certificate,self.private_key=values['certificate.pem'],values['key.pem']
            self.manifest={'import_attempted':False};self.cleaned=False;leases.append(self)
        def prepare(self):return self
        def install(self):self.manifest['import_attempted']=True;return self
        def cleanup(self):self.cleaned=True;return {'cleanup_confirmed':True}
    monkeypatch.setattr(probe,'LocalTestTrust',Lease)
    def fail(*_):raise OSError(probe.SECRET)
    monkeypatch.setattr(probe,'run_control',fail)
    args=arguments(root,values,output);args=args[:args.index('--certificate')]+['--prepare-test-trust']
    assert probe.main(args)==2
    result=json.loads((output/'summary.json').read_bytes())
    assert leases[0].cleaned and result['test_trust_cleanup_confirmed'] and not result['passed']
    assert len(result['phases'])==1 and probe.SECRET not in json.dumps(result)
    assert result['not_executed_phases']==['block','allow-after']


def test_each_stage_rechecks_frozen_egress_build(probe,tmp_path,monkeypatch):
    root,values=files(tmp_path,monkeypatch);output=tmp_path/'changed-live';calls=[]
    monkeypatch.setattr(probe,'is_elevated',lambda:True);monkeypatch.setattr(probe.sys,'platform','win32')
    def run(path,dll,action):
        audit=Path(json.loads(path.read_bytes())['output']);audit.mkdir(parents=True)
        (audit/'webhook-control.json').write_text(json.dumps({'action':action,'passed':True,'checks':{'received':True}}))
        calls.append(action);dll.write_bytes(b'changed-after-first-stage')
        return {'state':'complete'}
    monkeypatch.setattr(probe,'run_control',run)
    assert probe.main(arguments(root,values,output))==2
    summary=json.loads((output/'summary.json').read_bytes())
    assert calls==['allow'] and not summary['passed']
    assert [r['accepted'] for r in summary['phases']]==[True,False]
    assert summary['not_executed_phases']==['allow-after']
