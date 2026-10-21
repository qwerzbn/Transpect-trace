from pathlib import Path
from types import SimpleNamespace

import pytest


def sample(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    from probe_native_egress_boundaries import BEFORE,AFTER,DATAGRAM,assess
    rows=[{'kind':'fixture.preexisting_ready','socket_inheritable':True},
        {'kind':'fixture.child_main_started','pid':2},
        {'kind':'boundary.new_tcp','result':-1,'error':10013},
        {'kind':'boundary.existing_tcp','peer_matches':True,'sent_bytes':len(AFTER),'error':0},
        {'kind':'boundary.udp_connect','result':0,'error':0},
        {'kind':'boundary.udp_sendto','sent_bytes':len(DATAGRAM),'error':0}]
    records=[{'kind':'connection.decision','pid':2,'attempt_id':1,'decision':'block'},
        {'kind':'connection.rejected','pid':2,'attempt_id':1,'native_result':-1,'winsock_error':10013}]
    members=[{'pid':2,'root':False,'ready':True}]
    kwargs={'tcp_before':BEFORE,'tcp_after':BEFORE+AFTER,'tcp_connections':1,'udp_payload':DATAGRAM,'exit_code':0}
    return assess,rows,records,members,kwargs


def test_excluded_sends_are_reported_as_gaps_not_protected_paths(monkeypatch):
    assess,rows,records,members,kwargs=sample(monkeypatch)
    value=assess(rows,records,members,**kwargs)
    assert value['experiment_valid'] and value['boundary_characterization_passed']
    assert value['new_tcp']['protected']
    assert value['existing_tcp']['send_after_native_ready_observed'] and not value['existing_tcp']['protected']
    assert value['udp_sendto']['datagram_after_native_ready_observed'] and not value['udp_sendto']['protected']
    assert not value['udp_connect']['protected'] and not value['loader_tls_callbacks']['tested']
    assert value['udp_connect']['original_api_passthrough_succeeded']


def test_udp_connect_false_denial_invalidates_tcp_only_boundary_regression(monkeypatch):
    assess,rows,records,members,kwargs=sample(monkeypatch)
    next(row for row in rows if row['kind']=='boundary.udp_connect').update(result=-1,error=10013)
    value=assess(rows,records,members,**kwargs)
    assert value['new_tcp']['protected']
    assert not value['udp_connect']['original_api_passthrough_succeeded']
    assert not value['boundary_characterization_passed']


def test_source_zero_does_not_replace_native_connection_refusal(monkeypatch):
    assess,rows,records,members,kwargs=sample(monkeypatch)
    value=assess(rows,[],members,**kwargs)
    assert not value['new_tcp']['protected'] and not value['boundary_characterization_passed']


def test_missing_ready_or_extra_tcp_connection_is_not_certified(monkeypatch):
    assess,rows,records,members,kwargs=sample(monkeypatch)
    assert not assess(rows,records,[],**kwargs)['experiment_valid']
    kwargs['tcp_connections']=2
    assert not assess(rows,records,members,**kwargs)['new_tcp']['protected']


def exit_receipt(**kwargs):
    return {'kind':'fixture.child_exited','pid':2,'creation_filetime':30,'exit_code':0,
        'handle_wait_confirmed':True,'identity_from_process_handle':True,**kwargs}


def test_confirmed_child_handle_exit_avoids_racy_pid_reopen(monkeypatch,tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    from probe_native_egress_boundaries import cleanup_children
    file=tmp_path/'fixture.exe';file.write_bytes(b'synthetic fixture')
    controller=SimpleNamespace(members={2:{'pid':2,'creation_filetime':30,'root':False}})
    def must_not_reopen(_pid):raise AssertionError('An exited process should not be reopened by PID')
    monkeypatch.setattr('probe_native_egress_boundaries.inspect_process',must_not_reopen)
    assert cleanup_children(controller,file,[exit_receipt()])==[]


@pytest.mark.parametrize('receipt',[
    exit_receipt(creation_filetime=31),exit_receipt(pid=3),exit_receipt(handle_wait_confirmed=False),
    exit_receipt(identity_from_process_handle=False),exit_receipt(exit_code=None),exit_receipt(exit_code=True),
    exit_receipt(kind='fixture.child_main_started'),exit_receipt(creation_filetime=0),
])
def test_missing_or_wrong_lifetime_exit_proof_keeps_cleanup_unknown(monkeypatch,tmp_path,receipt):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    from probe_native_egress_boundaries import cleanup_children
    file=tmp_path/'fixture.exe';file.write_bytes(b'synthetic fixture')
    controller=SimpleNamespace(members={2:{'pid':2,'creation_filetime':30,'root':False}})
    def denied(_pid):
        error=OSError('synthetic access denied');error.winerror=5;raise error
    monkeypatch.setattr('probe_native_egress_boundaries.inspect_process',denied)
    assert cleanup_children(controller,file,[receipt])==[{'pid':2,'state':'identity_unavailable'}]
