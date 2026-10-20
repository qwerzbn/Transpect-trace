"""Conservative status projection for the isolated WFP lease experiment.

This does not install filters or infer process-tree coverage. BFE observations
must be obtained by the trusted local controller, never by reading an old log.
"""
from __future__ import annotations

FILTER_NOT_FOUND = 0x80320003


def lease_status(*, controller_identity_matches: bool, filter_id: int | None,
                 query_error: int | None, query_tick_ms: int | None,
                 now_tick_ms: int, cleanup_requested: bool = False,
                 install_error: int = 0, remove_error: int = 0,
                 max_age_ms: int = 1000) -> dict:
    fresh = (query_tick_ms is not None and
             0 <= now_tick_ms - query_tick_ms <= max_age_ms)
    present = bool(filter_id and fresh and query_error == 0)
    absent = bool(filter_id and fresh and query_error == FILTER_NOT_FOUND)
    reasons = []
    if cleanup_requested:
        state = 'closed' if absent else 'cleanup_unconfirmed'
        if remove_error:
            reasons.append('explicit_remove_failed')
    elif install_error:
        state = 'unavailable'
        reasons.append('install_failed')
    elif not controller_identity_matches:
        state = 'protection_lost'
        reasons.append('controller_dead_or_identity_mismatch')
    elif not fresh:
        state = 'unknown'
        reasons.append('missing_or_stale_bfe_readback')
    elif not present:
        state = 'protection_lost'
        reasons.append('filter_missing_or_query_failed')
    else:
        state = 'ready'
    return dict(state=state, protected=state == 'ready', filter_present=present,
                cleanup_confirmed=cleanup_requested and absent, reasons=reasons,
                scope='image_path_ipv4_tcp_loopback_port',
                pid_isolated=False, process_tree_inheritance=False)


def protection_summary(*, llm_gate_ready: bool, egress: dict, etw_state: str,
                       etw_events_lost: int | None) -> dict:
    """Evidence failure degrades the combined view without changing Native Gate."""
    evidence_ready = etw_state == 'ready' and etw_events_lost == 0
    return dict(llm_gate_ready=llm_gate_ready, egress=egress,
                behavior_evidence='ready' if evidence_ready else 'unavailable_or_incomplete',
                combined_ready=llm_gate_ready and egress['protected'] and evidence_ready)
