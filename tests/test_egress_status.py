from transpect_trace.behavior.egress_status import FILTER_NOT_FOUND, lease_status, protection_summary
import pytest


def status(**changes):
    values = dict(controller_identity_matches=True, filter_id=321, query_error=0,
                  query_tick_ms=10000, now_tick_ms=10010)
    return lease_status(**(values | changes))


def test_live_readback_has_only_path_scope():
    value = status()
    assert value['protected'] and not value['pid_isolated'] and not value['process_tree_inheritance']


@pytest.mark.parametrize('changes', [
    dict(controller_identity_matches=False),  # PID reused or controller killed
    dict(query_tick_ms=1), dict(query_tick_ms=None), dict(query_tick_ms=10011),
    dict(query_error=5), dict(query_error=FILTER_NOT_FOUND), dict(filter_id=None),
    dict(install_error=5), dict(cleanup_requested=True),
])
def test_no_false_ready_after_fault(changes):
    assert not status(**changes)['protected']


def test_remove_error_requires_independent_absence_confirmation():
    assert status(cleanup_requested=True, remove_error=5)['state'] == 'cleanup_unconfirmed'
    closed = status(cleanup_requested=True, remove_error=5, query_error=FILTER_NOT_FOUND)
    assert closed['cleanup_confirmed'] and closed['reasons'] == ['explicit_remove_failed']
    assert not status(cleanup_requested=True, query_error=5)['cleanup_confirmed']


@pytest.mark.parametrize('state,lost', [('degraded', 2), ('stopped', 0), ('ready', None), ('ready', 1), ('unavailable', 0)])
def test_etw_fault_does_not_silently_show_combined_ready(state, lost):
    value = protection_summary(llm_gate_ready=True, egress=status(), etw_state=state, etw_events_lost=lost)
    assert value['llm_gate_ready'] and not value['combined_ready']
