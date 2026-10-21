import struct
import ctypes

import pytest

from transpect_trace.behavior.native_egress import (
    CHILD, CONNECT, HELD, MAGIC, REGISTER, REQUEST, EgressController,
    destination_decision, normalize_policy,
)


def test_tcp_destination_rules_and_ipv4_mapped_are_equivalent():
    policy = normalize_policy({"targets": [{"address": "127.0.0.1", "port": 443, "action": "block"}]})
    assert destination_decision(policy, "127.0.0.1", 443) == "block"
    assert destination_decision(policy, "::ffff:127.0.0.1", 443) == "block"
    assert destination_decision(policy, "::ffff:7f00:1", 443) == "block"
    assert destination_decision(policy, "::1", 443) == "allow"
    assert destination_decision(policy, "127.0.0.1", 444) == "allow"


@pytest.mark.parametrize("policy", [
    {"default_action": "audit"},
    {"typo_targets": []},
    {"targets": "wrong"},
    {"targets": [{}]},
    {"targets": [{"address": "localhost", "port": 443}]},
    {"targets": [{"address": "fe80::1%12", "port": 443}]},
    {"targets": [{"address": "127.0.0.1", "port": True}]},
    {"targets": [{"address": "127.0.0.1", "port": 0}]},
    {"targets": [{"address": "127.0.0.1", "port": 443, "protocol": "udp"}]},
    {"targets": [{"address": "127.0.0.1", "port": 443, "action": "terminate"}]},
    {"targets": [{"address": "127.0.0.1", "port": 443}, {"address": "::ffff:127.0.0.1", "port": 443}]},
    {"allowed_image_hashes": ["not-a-sha256"]},
])
def test_invalid_or_ambiguous_policy_rejected(policy):
    with pytest.raises(ValueError):
        normalize_policy(policy)


def message(controller, *, pid=10, created=20, kind=REGISTER, token=None):
    return REQUEST.unpack(REQUEST.pack(MAGIC, 1, kind, pid, created, token or controller.token, 0, 0, 0, 4, 443, b"\x7f\0\0\x01" + b"\0" * 12, -1, 10013, 1))


def test_unregistered_peer_and_payload_pid_cannot_enroll(tmp_path):
    controller = EgressController({"pid": 10, "creation_filetime": 20}, tmp_path / "missing.dll", {}, tmp_path)
    assert controller._handle(10, message(controller)) == (False, 2)
    assert controller._handle(11, message(controller)) == (False, 1)
    assert controller._handle(10, message(controller, token=b"x" * 32)) == (False, 1)


def test_pid_reuse_is_rejected_before_registration(monkeypatch, tmp_path):
    controller = EgressController({"pid": 10, "creation_filetime": 20}, tmp_path / "missing.dll", {}, tmp_path)
    controller.members[10] = {"pid": 10, "creation_filetime": 20, "image_name": "tool.exe"}
    monkeypatch.setattr("transpect_trace.behavior.native_egress.inspect_process", lambda *_a, **_kw: {"creation_filetime": 21, "image_name": "tool.exe"})
    assert controller._handle(10, message(controller)) == (False, 2)


def test_root_cannot_be_misreported_as_tool_connect(monkeypatch, tmp_path):
    controller = EgressController({"pid": 10, "creation_filetime": 20}, tmp_path / "missing.dll", {}, tmp_path)
    controller.members[10] = {"pid": 10, "creation_filetime": 20, "image_name": "codex.exe", "registered": True, "ready": True, "root": True}
    monkeypatch.setattr("transpect_trace.behavior.native_egress.inspect_process", lambda *_a, **_kw: {"creation_filetime": 20, "image_name": "codex.exe"})
    assert controller._handle(10, message(controller, kind=CONNECT)) == (False, 9)


def test_wire_has_fixed_size_and_sequence():
    assert REQUEST.size == 112
    assert REQUEST.unpack(REQUEST.pack(MAGIC, 1, REGISTER, 10, 20, bytes(32), 0, 0, 0, 0, 0, bytes(16), 0, 0, 55))[-1] == 55


def test_ready_child_held_after_resume_failure_remains_visible(monkeypatch, tmp_path):
    controller = EgressController({"pid": 10, "creation_filetime": 20}, tmp_path / "missing.dll", {}, tmp_path)
    controller.members[10] = {"pid": 10, "creation_filetime": 20, "image_name": "codex.exe", "registered": True, "ready": True, "root": True}
    controller.members[11] = {"pid": 11, "creation_filetime": 30, "image_name": "tool.exe", "registered": True, "ready": True, "root": False}
    monkeypatch.setattr("transpect_trace.behavior.native_egress.inspect_process", lambda pid, **kw: {"creation_filetime": 20 if pid == 10 else 30, "parent_pid": 1 if pid == 10 else 10, "image_sha256":"b"*64, "image_name": "codex.exe" if pid == 10 else "tool.exe"})
    values = list(message(controller, kind=HELD))
    values[6], values[8] = 11, 30
    assert controller._handle(10, tuple(values)) == (True, 0)
    assert controller.members[11]["held"]
    controller.close()
    assert controller.state["held_processes"][0]["pid"] == 11


def rejected_child_fixture(monkeypatch,tmp_path):
    controller=EgressController({'pid':10,'creation_filetime':20},tmp_path/'missing.dll',
        {'allowed_image_hashes':['a'*64]},tmp_path)
    root={'pid':10,'creation_filetime':20,'parent_pid':1,'image_name':'codex.exe','image_sha256':'c'*64}
    child={'pid':11,'creation_filetime':30,'parent_pid':10,'image_name':'tool.exe','image_sha256':'b'*64}
    controller.members[10]=dict(root,registered=True,ready=True,root=True)
    monkeypatch.setattr('transpect_trace.behavior.native_egress.inspect_process',
        lambda pid,**kw:dict(root if pid==10 else child))
    values=list(message(controller,kind=CHILD));values[6],values[8]=11,30
    return controller,root,child,values


def test_refused_enrollment_still_reports_exact_held_child_without_authorizing_it(monkeypatch,tmp_path):
    controller,_,_,values=rejected_child_fixture(monkeypatch,tmp_path)
    assert controller._handle(10,tuple(values))==(False,7)
    assert 11 not in controller.members
    values[2]=HELD
    assert controller._handle(10,tuple(values))==(True,0)
    assert 11 not in controller.members
    assert controller._handle(11,message(controller,pid=11,created=30))==(False,2)
    controller.close()
    actual=controller.state['held_processes']
    assert len(actual)==1
    assert actual[0]['pid']==11 and actual[0]['creation_filetime']==30
    assert actual[0]['parent_identity']=='10-20' and actual[0]['image_sha256']=='b'*64
    assert actual[0]['enrollment']=='not_registered'
    assert actual[0]['cleanup']=='explicit_operator_action_required_no_automatic_resume'


@pytest.mark.parametrize('field,value',[('creation_filetime',31),('parent_pid',99)])
def test_held_claim_requires_observed_child_lifetime_and_parent(monkeypatch,tmp_path,field,value):
    controller,_,child,values=rejected_child_fixture(monkeypatch,tmp_path)
    child[field]=value;values[2]=HELD
    assert controller._handle(10,tuple(values))==(False,6)
    assert not controller.held_candidates and 11 not in controller.members
    assert controller.state['last_unverified_held_claim']['identity_verified'] is False


def test_reused_held_pid_is_not_offered_for_operator_cleanup(monkeypatch,tmp_path):
    controller,_,child,values=rejected_child_fixture(monkeypatch,tmp_path)
    values[2]=HELD
    assert controller._handle(10,tuple(values))==(True,0)
    child['creation_filetime']=31
    controller.close()
    assert not controller.state['held_processes']


def test_access_denied_does_not_silently_erase_previously_verified_held_child(monkeypatch,tmp_path):
    controller,root,_,values=rejected_child_fixture(monkeypatch,tmp_path)
    values[2]=HELD
    assert controller._handle(10,tuple(values))==(True,0)
    error=OSError('synthetic permission failure');error.winerror=5
    def inspect(pid,**_kw):
        if pid==11:raise error
        return root
    monkeypatch.setattr('transpect_trace.behavior.native_egress.inspect_process',inspect)
    controller.close()
    assert controller.state['held_processes'][0]['liveness']=='unknown'
    assert controller.state['held_processes'][0]['creation_filetime']==30


def test_verified_but_excessive_held_candidates_are_bounded(monkeypatch,tmp_path):
    controller,_,_,values=rejected_child_fixture(monkeypatch,tmp_path)
    controller.held_candidates={(pid,100):{'pid':pid,'creation_filetime':100} for pid in range(1000,1256)}
    values[2]=HELD
    assert controller._handle(10,tuple(values))==(False,13)
    assert len(controller.held_candidates)==256 and 11 not in controller.members
    assert controller.state['state']=='degraded_held_capacity'


def test_close_serializes_with_enrollment_and_joins_its_new_worker(monkeypatch,tmp_path):
    import threading
    from types import SimpleNamespace
    controller,root,child,values=rejected_child_fixture(monkeypatch,tmp_path)
    controller.policy['allowed_image_hashes']=[]
    inspecting=threading.Event();release=threading.Event();closed=threading.Event()
    results=[]
    def inspect(pid,**_kw):
        if pid==11:
            inspecting.set()
            assert release.wait(3)
        return dict(root if pid==10 else child)
    monkeypatch.setattr('transpect_trace.behavior.native_egress.inspect_process',inspect)
    monkeypatch.setattr('transpect_trace.behavior.native_egress.restricted_process_sids',lambda *_:[])
    monkeypatch.setattr('transpect_trace.behavior.native_egress.descendant_pipe_security',lambda *_:SimpleNamespace(descriptor=2))
    controller.k=SimpleNamespace(CreateFileW=lambda *_:ctypes.c_void_p(-1).value,LocalFree=lambda *_:None)
    controller.security=SimpleNamespace(descriptor=1)
    def serve(_name,_security,listening):
        listening.set();controller.stop.wait(3)
    controller._serve=serve
    def enroll():
        with controller.lock:results.append(controller._handle(10,tuple(values)))
    def close():
        controller.close();closed.set()
    enrolling=threading.Thread(target=enroll);enrolling.start()
    assert inspecting.wait(3)
    closing=threading.Thread(target=close);closing.start()
    try:
        assert not closed.wait(.05)
    finally:
        release.set();enrolling.join(3);closing.join(3)
    assert results==[(True,0)] and closed.is_set()
    assert all(not thread.is_alive() for thread in controller.threads)
    assert controller._handle(10,tuple(values))==(False,14)


def test_module_snapshot_retries_bad_length_without_leaking_handles(monkeypatch,tmp_path):
    from types import SimpleNamespace
    from transpect_trace.behavior.native_egress import _module_base
    target=tmp_path/'kernelbase.dll';snapshots=iter([ctypes.c_void_p(-1).value]*2+[123]);closed=[]
    def first(_handle,pointer):
        pointer._obj.path=str(target);pointer._obj.base=0x12340000
        return True
    kernel=SimpleNamespace(CreateToolhelp32Snapshot=lambda *_:next(snapshots),
        Module32FirstW=first,Module32NextW=lambda *_:False,CloseHandle=closed.append)
    monkeypatch.setattr('transpect_trace.behavior.native_egress.api',lambda:kernel)
    monkeypatch.setattr(ctypes,'get_last_error',lambda:24,raising=False)
    monkeypatch.setattr('transpect_trace.behavior.native_egress.time.sleep',lambda *_:None)
    assert _module_base(10,target)==0x12340000
    assert closed==[123]


def test_missing_module_diagnostic_uses_basename_and_does_not_wait_for_unloaded_dll(monkeypatch,tmp_path):
    from types import SimpleNamespace
    from transpect_trace.behavior.native_egress import _module_base
    closed=[]
    kernel=SimpleNamespace(CreateToolhelp32Snapshot=lambda *_:123,
        Module32FirstW=lambda *_:False,CloseHandle=closed.append)
    monkeypatch.setattr('transpect_trace.behavior.native_egress.api',lambda:kernel)
    target=tmp_path/'not-loaded.dll'
    with pytest.raises(RuntimeError,match='not-loaded.dll') as failure:_module_base(10,target)
    assert str(tmp_path) not in str(failure.value) and closed==[123]


def test_startup_module_wait_requires_same_lifetime_before_and_after_recovery(monkeypatch,tmp_path):
    from transpect_trace.behavior.native_egress import _wait_startup_module
    checks=[];lookups=[]
    transient=OSError('synthetic partial snapshot');transient.winerror=299
    results=iter([RuntimeError('empty startup module list'),transient,0x12340000])
    def lookup(pid,path):
        lookups.append((pid,path));value=next(results)
        if isinstance(value,Exception):raise value
        return value
    monkeypatch.setattr('transpect_trace.behavior.native_egress._module_base',lookup)
    monkeypatch.setattr('transpect_trace.behavior.native_egress._verify_process_lifetime',lambda k,p,b:checks.append((p,b)))
    monkeypatch.setattr('transpect_trace.behavior.native_egress.time.sleep',lambda *_:None)
    target=tmp_path/'kernelbase.dll'
    assert _wait_startup_module(10,target,None,123,20)==0x12340000
    assert len(lookups)==3 and checks==[(123,20)]*4


def test_startup_module_missing_until_deadline_fails_without_releasing_work(monkeypatch,tmp_path):
    from transpect_trace.behavior.native_egress import _wait_startup_module
    clock=iter([0,3]);lookups=[]
    def absent(*_):
        lookups.append(1);raise RuntimeError('still absent')
    monkeypatch.setattr('transpect_trace.behavior.native_egress._module_base',absent)
    monkeypatch.setattr('transpect_trace.behavior.native_egress._verify_process_lifetime',lambda *_:None)
    monkeypatch.setattr('transpect_trace.behavior.native_egress.time.monotonic',lambda:next(clock))
    with pytest.raises(TimeoutError,match='kernelbase.dll'):
        _wait_startup_module(10,tmp_path/'kernelbase.dll',None,123,20,timeout=2)
    assert lookups==[1]


def test_startup_module_access_denied_is_not_retried(monkeypatch,tmp_path):
    from transpect_trace.behavior.native_egress import _wait_startup_module
    error=OSError('synthetic access denied');error.winerror=5
    lookups=[]
    def denied(*_):
        lookups.append(1);raise error
    monkeypatch.setattr('transpect_trace.behavior.native_egress._module_base',denied)
    monkeypatch.setattr('transpect_trace.behavior.native_egress._verify_process_lifetime',lambda *_:None)
    with pytest.raises(OSError):_wait_startup_module(10,tmp_path/'kernelbase.dll',None,123,20)
    assert lookups==[1]


@pytest.mark.parametrize('observed_birth,wait,error',[(21,258,ValueError),(20,0,RuntimeError)])
def test_startup_process_reuse_or_exit_is_rejected(observed_birth,wait,error):
    from types import SimpleNamespace
    from transpect_trace.behavior.native_egress import _verify_process_lifetime
    def times(_handle,created,*_):
        created._obj.dwLowDateTime=observed_birth;created._obj.dwHighDateTime=0
        return True
    kernel=SimpleNamespace(GetProcessTimes=times,WaitForSingleObject=lambda *_:wait)
    with pytest.raises(error):_verify_process_lifetime(kernel,123,20)


@pytest.mark.parametrize('winerror,ended',[(5,False),(87,True),(1168,True),(1234,False)])
def test_unknown_or_access_denied_process_does_not_get_retired(monkeypatch,winerror,ended):
    from types import SimpleNamespace
    from transpect_trace.behavior.native_egress import process_lifetime_ended
    monkeypatch.setattr(ctypes,'get_last_error',lambda:winerror,raising=False)
    monkeypatch.setattr('transpect_trace.behavior.native_egress.api',lambda:SimpleNamespace(OpenProcess=lambda *_:0))
    assert process_lifetime_ended(123,456) is ended
