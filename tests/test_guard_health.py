import json
from types import SimpleNamespace

from transpect_trace.guard.manager import update_health,close_components


def test_policy_workers_exit_cannot_leave_active_guard_status(tmp_path):
    server=SimpleNamespace(threads=[SimpleNamespace(is_alive=lambda:False)],errors=[],
        etw=SimpleNamespace(state={'state':'unavailable'}))
    state={'state':'active_limited'};path=tmp_path/'status.json'
    update_health(server,state,path)
    actual=json.loads(path.read_text())
    assert actual['state']=='degraded_policy_service_fail_closed'
    assert actual['policy_service']['live_workers']==0


def test_observation_failure_does_not_fabricate_failed_request_execution(tmp_path):
    server=SimpleNamespace(threads=[SimpleNamespace(is_alive=lambda:True)],errors=[],
        request_capture=SimpleNamespace(status=lambda:{'state':'degraded','can_enforce':False}),
        etw=SimpleNamespace(state={'state':'unavailable'}))
    state={'state':'active_limited'};update_health(server,state,tmp_path/'status.json')
    assert state['policy_service']['state']=='ready'
    assert state['capture']['state']=='degraded'
    assert state['state']=='active_limited'


def test_terminal_io_failure_cannot_leave_healthy_interactive_status(tmp_path):
    server=SimpleNamespace(threads=[SimpleNamespace(is_alive=lambda:True)],errors=[],
        etw=SimpleNamespace(state={'state':'unavailable'}))
    terminal=SimpleNamespace(thread=SimpleNamespace(is_alive=lambda:False),
        errors=['terminal_output_unavailable'],poll=lambda:None,
        input_ready=SimpleNamespace(is_set=lambda:True))
    state={'state':'active_limited'};path=tmp_path/'status.json'
    update_health(server,state,path,terminal=terminal)
    actual=json.loads(path.read_text())
    assert actual['state']=='degraded_terminal_io'
    assert actual['terminal']['state']=='degraded_io'
    assert actual['policy_service']['state']=='ready'


def test_capture_cleanup_failure_does_not_skip_egress_and_etw_cleanup(tmp_path):
    calls=[]
    def broken_capture():
        calls.append('capture');raise OSError('synthetic-private-data-must-not-be-logged')
    server=SimpleNamespace(close=lambda:calls.append('policy'),records=[],
        request_capture=SimpleNamespace(close=broken_capture,status=lambda:{'state':'degraded'}),
        egress=SimpleNamespace(close=lambda:calls.append('egress'),state={'state':'stopped'}),
        etw=SimpleNamespace(close=lambda *_:calls.append('etw'),state={'state':'stopped'}))
    state={};close_components(server,state,tmp_path/'status.json')
    assert calls==['policy','capture','egress','etw']
    assert state['cleanup']=={'complete':False,'errors':[{'component':'request_capture','error_type':'OSError'}]}
    assert 'synthetic-private-data' not in json.dumps(state)
    assert state['etw']['state']=='stopped'
