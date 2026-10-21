"""SSPI ownership is independent of Codex request-body observation."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from transpect_trace.observe import ecapture


def test_sspi_owner_is_scoped_but_actual_entry_conflicts_are_rejected():
    root=Path(__file__).resolve().parents[1]
    companion=(root/'patches/ecapture-windows/enhanced/schannel_hook.c').read_text()
    observer=(root/'native/observe/observer.c').read_text()
    assert 'ttrace-sspi-owner-%lu-%llu' in companion
    assert 'ttrace-observe-owner-%lu-%llu' not in companion
    assert 'ttrace-observe-owner-%lu-%llu' in observer
    # A different owner name must never permit overwriting another detour.
    for source in (companion,observer):
        assert 'target.AllocationBase!=image.AllocationBase' in source or 'target.AllocationBase!=m.AllocationBase' in source
        assert 'p[0]==0xff&&p[1]==0x25' in source
        assert 'ERROR_ALREADY_EXISTS' in source


@pytest.mark.parametrize('stage,winerror,reason',[
    (-2,183,'dll_hook_owner_conflict'),(-3,5,'dll_pipe_open_failed'),
    (-6,0,'dll_hook_entry_initialization_failed'),
])
def test_pipe_failure_diagnostics_preserve_fixed_stage_and_numeric_error(monkeypatch,stage,winerror,reason):
    subject={'pid':12,'creation_filetime':100,'image_sha256':'0'*64}
    collector=ecapture.ECaptureCollector(subject,SimpleNamespace(mode='schannel'),Path('ecapture.exe'),None)
    collector._verified_manifest={'variant':'enhanced','artifacts_sha256':{'schannel_hook.dll':'a'*64}}
    seen=[]
    def snapshot(actual_subject,dll,digest):
        seen.append((actual_subject,dll,digest))
        return {'state':'observed','stage':stage,'winerror':winerror,'reason':reason}
    monkeypatch.setattr(ecapture,'_dll_initialization_snapshot',snapshot)
    collector._diagnose_initialization();collector._diagnose_initialization()
    assert seen[0]==(subject,Path('schannel_hook.dll'),'a'*64)
    assert collector.native_initialization['winerror']==winerror
    assert collector.errors==[reason]


def test_initialization_diagnostics_require_verified_enhanced_companion(monkeypatch):
    collector=ecapture.ECaptureCollector({},SimpleNamespace(),Path('ecapture.exe'),None)
    monkeypatch.setattr(ecapture,'_dll_initialization_snapshot',lambda *args:pytest.fail('unverified read'))
    collector._diagnose_initialization()
    collector._verified_manifest={'variant':'upstream','artifacts_sha256':{'schannel_hook.dll':'a'*64}}
    collector._diagnose_initialization()
    assert collector.native_initialization is None


def test_initialization_diagnostics_refuse_reused_pid_before_reading_module(monkeypatch):
    from transpect_trace.observe import windows
    subject={'pid':12,'creation_filetime':100,'image_sha256':'0'*64}
    monkeypatch.setattr(windows,'identity',lambda pid:{**subject,'creation_filetime':101})
    monkeypatch.setattr(windows,'modules',lambda pid:pytest.fail('PID generation was not checked'))
    assert ecapture._dll_initialization_snapshot(subject,Path('schannel_hook.dll'),'a'*64)=={'state':'unavailable'}
