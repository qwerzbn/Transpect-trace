"""Profile compatibility checks; no administrator or real ETW session required."""
import hashlib
import io
import json

import pytest

from transpect_trace.behavior.collector import CodexBehaviorCollector
from transpect_trace.guard import BINARY_SHA256


def make_collector(tmp_path, monkeypatch, requested, ready_profile, terminal_profile):
    import transpect_trace.behavior.collector as module
    import transpect_trace.observe.windows as windows
    executable=tmp_path/'etw.exe';executable.write_bytes(b'fake-test-collector')
    (tmp_path/'build-manifest.json').write_text(json.dumps({'artifacts_sha256':{
        executable.name:hashlib.sha256(executable.read_bytes()).hexdigest()}}))
    monkeypatch.setattr(windows,'identity',lambda pid:{'pid':pid,'creation_filetime':42,'image_sha256':BINARY_SHA256})
    seen=[]
    class Process:
        def __init__(self,args,**kwargs):
            seen.append(args)
            ready={'kind':'etw.ready'}
            stopped={'kind':'etw.stopped','status':0,'counters_verified':True,'events_lost':0,
                     'buffers_lost':0,'decode_errors':0,'filtered_file_metadata':17}
            if ready_profile is not None:ready['file_profile']=ready_profile
            if terminal_profile is not None:stopped['file_profile']=terminal_profile
            self.stdout=io.BytesIO(b'\n'.join(json.dumps(v).encode() for v in (ready,stopped))+b'\n')
        def wait(self):return 0
    monkeypatch.setattr(module.subprocess,'Popen',Process)
    identity={'pid':100,'creation_filetime':42,'baseline':{'sha256':BINARY_SHA256,'supported':True}}
    collector=CodexBehaviorCollector(identity,executable,tmp_path/'audit',duration=1,file_profile=requested)
    collector.start();collector.wait()
    return collector,seen


def test_old_all_metadata_collector_still_compatible(tmp_path,monkeypatch):
    collector,seen=make_collector(tmp_path,monkeypatch,'all',None,None)
    assert '--io-evidence' not in seen[0]
    assert collector.index.health()['state']=='stopped'


def test_explicit_profile_passed_and_accounted_without_manufacturing_loss(tmp_path,monkeypatch):
    collector,seen=make_collector(tmp_path,monkeypatch,'io-evidence','io-evidence','io-evidence')
    assert seen[0][-1]=='--io-evidence'
    assert collector.filtered_file_metadata==17
    assert collector.index.health()['events_lost']==0
    status=json.loads((tmp_path/'audit/status.json').read_bytes())
    assert status['file_profile']=='io-evidence' and status['filtered_file_metadata']==17


@pytest.mark.parametrize('ready,terminal',[(None,None),('all','io-evidence'),('io-evidence','all')])
def test_unattested_or_changed_profile_fails_health(tmp_path,monkeypatch,ready,terminal):
    collector,_=make_collector(tmp_path,monkeypatch,'io-evidence',ready,terminal)
    assert 'collector_file_profile_mismatch' in collector.index.health()['gaps']
    assert collector.index.health()['state']=='degraded'
