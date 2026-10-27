"""Conservative assessment over independent evidence, never fixture verdicts."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from .models import BusinessScenarioReport, ScenarioCapabilities

_COLLECTOR = {'native_io': 'native_io', 'etw': 'etw', 'ecapture': 'ecapture',
              'native_request': 'native_request'}
_BASE_REQUIREMENTS = {
    'export': {'native_io', 'etw', 'client_result'},
    'tool': {'native_request', 'etw', 'client_result'},
    'transform': {'native_io', 'etw', 'client_result'},
    'upload': {'source_receipt', 'client_result'},
    'commit': {'git_object', 'client_result'},
    'push': {'source_receipt', 'git_object', 'client_result'},
}


def _file_handoff(left, right, records):
    if not (left.file_identity and left.file_identity == right.file_identity and
            left.io_operation == 'write' and right.io_operation == 'read' and
            left.io_offset == right.io_offset and left.qpc_frequency and
            left.qpc_frequency == right.qpc_frequency and
            left.io_completed_qpc <= right.io_started_qpc):
        return False
    for other in records:
        if (other.evidence_id == left.evidence_id or other.provenance != 'native_io' or
                other.file_identity != left.file_identity or other.io_operation != 'write'):
            continue
        # Missing clock/range evidence for an observed competing write cannot
        # establish a stable version, even if that write's content was lost.
        if other.qpc_frequency != left.qpc_frequency or other.body_bytes is None:
            return False
        overlaps_time = (other.io_started_qpc <= right.io_completed_qpc and
                         other.io_completed_qpc >= left.io_completed_qpc)
        overlaps_range = (other.io_offset < right.io_offset + right.body_bytes and
                          other.io_offset + other.body_bytes > right.io_offset)
        if overlaps_time and overlaps_range:
            return False
    return True


def _git_inspection(report, evidence, usable):
    if report.scenario != 'git':
        return not (report.git_objects or report.git_scans)
    object_keys = Counter((r.attempt_id, r.object_id) for r in report.git_objects)
    scan_counts = Counter(r.attempt_id for r in report.git_scans)
    okay = True
    inspected_evidence = set()
    for item in report.git_objects:
        observed = evidence.get(item.evidence_id)
        valid = bool(observed and usable[item.evidence_id] and
                     observed.provenance == 'git_object' and observed.object_location == 'origin' and
                     observed.object_id == item.object_id and observed.attempt_id == item.attempt_id and
                     observed.body_sha256 == item.body_sha256 and observed.body_bytes == item.body_bytes and
                     item.detection_status != 'incomplete' and not item.limitations and
                     object_keys[(item.attempt_id, item.object_id)] == 1)
        if not valid:
            item.limitations = sorted(set(item.limitations + ['received_object_inspection_unverified']))
        okay &= valid
        inspected_evidence.add(item.evidence_id)
    for scan in report.git_scans:
        observed = evidence.get(scan.evidence_id)
        objects = [row for row in report.git_objects if row.attempt_id == scan.attempt_id]
        valid = bool(scan.complete and not scan.limitations and scan_counts[scan.attempt_id] == 1 and
                     observed and usable[scan.evidence_id] and observed.provenance == 'git_object' and
                     observed.object_location == 'origin' and observed.object_id is None and
                     observed.attempt_id == scan.attempt_id and
                     observed.observed_blob_count == scan.received_blob_count == len(objects))
        if not valid:
            scan.limitations = sorted(set(scan.limitations + ['received_object_scan_incomplete']))
        okay &= valid
    for outbound in report.outbound:
        if scan_counts[outbound.attempt_id] != 1:
            outbound.limitations = sorted(set(outbound.limitations + ['received_object_scan_missing']))
            okay = False
    attempts = {r.attempt_id for r in report.outbound}
    if any(r.attempt_id not in attempts for r in [*report.git_scans, *report.git_objects]):
        okay = False
    if any(row.provenance == 'git_object' and row.object_location == 'origin' and row.object_id
           and row.evidence_id not in inspected_evidence for row in report.evidence):
        okay = False
    return okay


def assess(value: BusinessScenarioReport | dict) -> BusinessScenarioReport:
    """Return a fresh assessment without changing supplied evidence records.

    Callers provide observed facts. Truth fixtures and previously saved summary
    booleans never satisfy a collector, content boundary or source receipt.
    """
    report = (value if isinstance(value, BusinessScenarioReport) else
              BusinessScenarioReport.model_validate(value)).model_copy(deep=True)
    gaps = list(report.limitations)
    evidence = {row.evidence_id: row for row in report.evidence}
    if len(evidence) != len(report.evidence):
        gaps.append('duplicate_evidence_identifier')
    if len({p.key for p in report.participants}) != len(report.participants):
        gaps.append('duplicate_process_instance')
    identities = {p.key: p.image_sha256 for p in report.participants}
    usable = {}
    for key, row in evidence.items():
        accepted = row.complete and not row.limitations and row.provenance != 'fixture_truth'
        if row.provenance in _COLLECTOR:
            health = report.health.get(_COLLECTOR[row.provenance])
            accepted &= bool(health and health.complete)
            accepted &= bool(row.process and identities.get(row.process.key) == row.process.image_sha256)
            accepted &= bool(row.event_ids)
        if row.provenance == 'client_result':
            expected_ref_rejection = (report.scenario == 'git' and report.case == 'reject_ref'
                                      and row.stage_id == 'push' and row.success is False)
            accepted &= row.success is True or expected_ref_rejection
        usable[key] = accepted
    required_stages = {'export', 'tool', 'transform', 'upload'} if report.scenario == 'webhook' else {
        'export', 'tool', 'transform', 'commit', 'push'}
    if {s.stage_id for s in report.stages} != required_stages or len(report.stages) != len(required_stages):
        gaps.append('required_stage_graph_missing')
    for stage in report.stages:
        required = _BASE_REQUIREMENTS.get(stage.stage_id, set()) | set(stage.required_provenance)
        stage_gaps = list(stage.limitations)
        selected = [evidence[k] for k in stage.evidence_ids if k in evidence and usable[k]
                    and evidence[k].stage_id == stage.stage_id]
        supplied = {r.provenance for r in selected}
        for missing in sorted(required - supplied):
            stage_gaps.append('missing_' + missing)
        if stage.stage_id in {'upload', 'push'} and not supplied & {'ecapture', 'native_request'}:
            stage_gaps.append('missing_content_capture')
        if any(k not in evidence or evidence[k].stage_id != stage.stage_id for k in stage.evidence_ids):
            stage_gaps.append('invalid_stage_evidence_reference')
        stage.limitations = sorted(set(stage_gaps))
        stage.state = 'complete' if not stage.limitations and selected else 'partial'

    used_captures, used_receipts = Counter(), Counter()
    attempts = Counter(row.attempt_id for row in report.outbound)
    for outbound in report.outbound:
        outbound.receipt_match = False
        outbound.source_received = None
        row_gaps = list(outbound.limitations)
        capture = evidence.get(outbound.capture_evidence_id)
        receipt = evidence.get(outbound.receipt_evidence_id)
        if capture:
            used_captures[capture.evidence_id] += 1
        if receipt:
            used_receipts[receipt.evidence_id] += 1
        if attempts[outbound.attempt_id] != 1:
            row_gaps.append('duplicate_attempt_identifier')
        if outbound.association_basis == 'unknown':
            row_gaps.append('receipt_association_unknown')
        elif outbound.association_basis == 'exact_runtime_id':
            # No exact runtime-ID propagation adapter is certified in this
            # iteration. A caller-supplied label cannot create that proof.
            row_gaps.append('exact_runtime_mapping_not_certified')
        expected_provenance = outbound.capture_source
        valid_capture = bool(capture and usable[capture.evidence_id] and
                             capture.provenance == expected_provenance and
                             capture.attempt_id == outbound.attempt_id and
                             capture.process and outbound.process and
                             capture.process == outbound.process and
                             capture.body_sha256 == outbound.body_sha256 and
                             capture.body_bytes == outbound.body_bytes and
                             outbound.body_sha256 is not None)
        valid_receipt = bool(receipt and usable[receipt.evidence_id] and
                             receipt.provenance == 'source_receipt' and
                             receipt.attempt_id == outbound.attempt_id and receipt.success is True)
        if valid_receipt:
            outbound.source_received = True
        if not valid_capture:
            row_gaps.append('outbound_capture_unverified')
        if not valid_receipt:
            row_gaps.append('source_receipt_unverified')
        if valid_capture and valid_receipt:
            outbound.receipt_match = (capture.body_sha256 == receipt.body_sha256 and
                                      capture.body_bytes == receipt.body_bytes)
            if not outbound.receipt_match:
                row_gaps.append('capture_receipt_mismatch')
        if (outbound.completeness != 'complete' or outbound.detection_status == 'incomplete' or
                outbound.detection_status == 'unsupported' and report.scenario != 'git'):
            row_gaps.append('content_check_incomplete')
        if report.scenario == 'git' and outbound.detection_status != 'unsupported':
            row_gaps.append('git_transport_requires_object_detection')
        outbound.limitations = sorted(set(row_gaps))
    for outbound in report.outbound:
        if used_captures[outbound.capture_evidence_id] > 1 or used_receipts[outbound.receipt_evidence_id] > 1:
            outbound.limitations = sorted(set(outbound.limitations + ['evidence_reused_across_attempts']))
            outbound.receipt_match = False
    for row in report.evidence:
        if row.stage_id not in {'upload', 'push'}:
            continue
        if row.provenance == 'source_receipt' and used_receipts[row.evidence_id] != 1:
            gaps.append('unassociated_source_receipt')
        if row.provenance in {'ecapture', 'native_request'} and used_captures[row.evidence_id] != 1:
            gaps.append('unassociated_capture_attempt')
    if not report.outbound:
        gaps.append('no_observed_outbound_attempt')

    object_inspection_ok = _git_inspection(report, evidence, usable)
    if not object_inspection_ok:
        gaps.append('received_object_inspection_incomplete')

    content_edges = []
    handoffs = []
    for relation in report.relations:
        references = [evidence[k] for k in relation.evidence_ids if k in evidence and usable[k]]
        endpoints = relation.left_id in evidence and relation.right_id in evidence
        if (not endpoints or not references or len(references) != len(relation.evidence_ids) or
                any(not usable.get(k, False) for k in (relation.left_id, relation.right_id))):
            relation.confidence = 'Unknown'
            relation.limitations = sorted(set(relation.limitations + ['relation_evidence_incomplete']))
        elif relation.method == 'timing_candidate':
            relation.confidence = 'Low'
            relation.limitations = sorted(set(relation.limitations + ['candidate_not_unique_source']))
        elif relation.method in {'content_candidate', 'observed_file_handoff'}:
            left, right = evidence[relation.left_id], evidence[relation.right_id]
            exact = bool(left.body_sha256 and left.body_bytes and
                         left.body_sha256 == right.body_sha256 and left.body_bytes == right.body_bytes)
            registered = bool(set(left.content_registration_ids) & set(right.content_registration_ids))
            valid = exact or registered
            if relation.method == 'observed_file_handoff':
                valid = bool(exact and left.provenance == right.provenance == 'native_io' and
                             left.process and right.process and left.process.key != right.process.key and
                             _file_handoff(left, right, report.evidence))
            if not valid:
                relation.confidence = 'Unknown'
                relation.limitations = sorted(set(relation.limitations + ['content_or_handoff_evidence_missing']))
            else:
                relation.confidence = 'Medium'
                relation.limitations = sorted(set(relation.limitations + ['candidate_not_unique_source']))
                content_edges.append((left.evidence_id, right.evidence_id))
                if relation.method == 'observed_file_handoff':
                    handoffs.append((left.evidence_id, right.evidence_id))
        elif relation.confidence == 'High':
            # Generic references cannot certify a byte range or protocol ID
            # mapping; retain evidence without manufacturing that assertion.
            relation.confidence = 'Medium'
            relation.limitations = sorted(set(relation.limitations + ['direct_mapping_not_certified']))
    collector_ok = all(report.health.get(name) and report.health[name].complete
                       for name in {'etw', 'native_io'})
    system_ok = collector_ok and bool(report.participants) and any(
        usable[r.evidence_id] and r.provenance == 'etw' for r in report.evidence)
    content_ok = object_inspection_ok and bool(report.outbound) and all(not r.limitations for r in report.outbound)
    receipt_ok = bool(report.outbound) and all(r.source_received is True and r.receipt_match is True
                                            for r in report.outbound)
    # A timing-only chain is never a content propagation result. Require a
    # content-backed cross-process handoff and a path to each captured attempt.
    reachable = {left for left, _ in handoffs if evidence[left].stage_id == 'export'}
    for _ in range(len(content_edges) + 1):
        expanded = reachable | {right for left, right in content_edges if left in reachable}
        if expanded == reachable:
            break
        reachable = expanded
    linked_outbound = bool(report.outbound) and all(row.capture_evidence_id in reachable for row in report.outbound)
    if report.scenario == 'git':
        matched_objects = [row for row in report.git_objects if row.detection_status == 'matched']
        linked_outbound = (any(row.evidence_id in reachable for row in report.git_objects) and
                           all(row.evidence_id in reachable for row in matched_objects))
    negative = ((report.scenario == 'webhook' and report.case == 'public' and
                 report.outbound and all(r.detection_status == 'no_match' for r in report.outbound)) or
                (report.scenario == 'git' and report.case in {'public', 'untracked', 'old_commit'} and
                 object_inspection_ok and all(r.detection_status == 'no_match' for r in report.git_objects)))
    propagation_ok = bool(handoffs) and (linked_outbound or bool(negative and content_ok))
    report.capabilities = ScenarioCapabilities(
        system_behavior='complete' if system_ok else 'partial',
        content_detection='complete' if content_ok else 'partial',
        propagation='complete' if propagation_ok else 'partial',
        source_receipt='complete' if receipt_ok else 'partial')
    if not system_ok:
        gaps.append('system_evidence_incomplete')
    if not content_ok:
        gaps.append('outbound_content_incomplete')
    if not receipt_ok:
        gaps.append('receipt_evidence_incomplete')
    if not propagation_ok:
        gaps.append('propagation_evidence_incomplete')
    report.limitations = sorted(set(gaps))
    complete = not report.limitations and all(s.state == 'complete' for s in report.stages)
    report.certified = complete
    report.state = 'complete' if complete else ('partial' if report.evidence else 'unavailable')
    return report


def read_report(directory):
    path = Path(directory) / 'business-report.json'
    if not path.is_file():
        return {'schema_version': 'transpect.business.report/1.0', 'state': 'unavailable',
                'limitations': ['business_evidence_not_available'], 'certified': False, 'can_enforce': False}
    return assess(BusinessScenarioReport.model_validate_json(path.read_bytes())).model_dump(mode='json')
