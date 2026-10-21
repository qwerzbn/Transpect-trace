import importlib.util
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest


def probe_type(monkeypatch):
    scripts=Path(__file__).resolve().parents[1]/'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    spec=importlib.util.spec_from_file_location('tls_backend_probe',scripts/'probe_codex_tls_backends.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.TLSProbe


@pytest.mark.parametrize('ready,terminal,loss,errors,expected',[
    (False,False,None,['administrator_privileges_required'],'unavailable'),
    (True,False,0,[],'unavailable'),
    (True,True,1,[],'unavailable'),
    (True,True,0,[],'unknown'),
])
def test_zero_events_never_prove_tls_backend_or_complete_capture(tmp_path,monkeypatch,ready,terminal,loss,errors,expected):
    probe=probe_type(monkeypatch).__new__(probe_type(monkeypatch))
    probe.root=tmp_path;probe.build={'variant':'enhanced'};probe.failure=None
    probe.module_evidence=[dict(module='secur32.dll',sha256='a'*64,evidence='loaded_module_identity')]
    ready_event=threading.Event()
    if ready:ready_event.set()
    probe.collector=SimpleNamespace(ready=ready_event,structured=SimpleNamespace(terminal=terminal,lost=loss),errors=errors)
    probe.pipeline=SimpleNamespace(rows=[],gaps=[])
    result=probe.report([{'sha256':'b'*64}])
    assert result['status']==expected
    assert result['actual_tls_backend']=='unknown'
    assert result['source_hashes_match'] is False


def test_same_layer_receipt_and_full_health_can_certify_schannel(tmp_path,monkeypatch):
    cls=probe_type(monkeypatch);probe=cls.__new__(cls)
    probe.root=tmp_path;probe.build={'variant':'enhanced'};probe.failure=None;probe.module_evidence=[]
    ready=threading.Event();ready.set()
    probe.collector=SimpleNamespace(ready=ready,structured=SimpleNamespace(terminal=True,lost=0),errors=[])
    probe.pipeline=SimpleNamespace(rows=[{'completeness':'complete','content_sha256':'a'*64}],gaps=[])
    result=probe.report([{'sha256':'a'*64}])
    assert result['status']=='complete' and result['actual_tls_backend']=='schannel'
    assert result['source_hashes_match']


def test_partial_receipt_hash_coverage_is_not_complete_tls_capture(tmp_path,monkeypatch):
    cls=probe_type(monkeypatch);probe=cls.__new__(cls)
    probe.root=tmp_path;probe.build={'variant':'enhanced'};probe.failure=None;probe.module_evidence=[]
    ready=threading.Event();ready.set()
    probe.collector=SimpleNamespace(ready=ready,structured=SimpleNamespace(terminal=True,lost=0),errors=[])
    probe.pipeline=SimpleNamespace(rows=[{'completeness':'complete','content_sha256':'a'*64}],gaps=[])
    result=probe.report([{'sha256':'a'*64},{'sha256':'b'*64}])
    assert result['status']=='partial' and result['actual_tls_backend']=='unknown'
    assert not result['source_hashes_match']


def test_missing_identical_retry_is_not_hidden_by_equal_hash_sets(tmp_path,monkeypatch):
    cls=probe_type(monkeypatch);probe=cls.__new__(cls)
    probe.root=tmp_path;probe.build={'variant':'enhanced'};probe.failure=None;probe.module_evidence=[]
    ready=threading.Event();ready.set()
    probe.collector=SimpleNamespace(ready=ready,structured=SimpleNamespace(terminal=True,lost=0),errors=[])
    probe.pipeline=SimpleNamespace(rows=[{'completeness':'complete','content_sha256':'a'*64}],gaps=[])
    result=probe.report([{'sha256':'a'*64},{'sha256':'a'*64}])
    assert result['status']=='partial'
    assert not result['source_hashes_match']
