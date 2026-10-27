"""Conservative evidence checks for a real file-modify/upload experiment.

This is an evidence assessor, not an I/O detector or a protection component.
``original_*`` and ``modified_*`` are independent deterministic test-oracle
digests, computed from the controlled input and specified transformation. They
must not be populated by reading the actual output and calling it an oracle.
Only complete, single synchronous I/O ranges are certified by this first
assessor. Arbitrary chunk reconstruction and byte-level causality are outside
its scope. Input text, paths, findings and collector errors are never echoed.
"""
from __future__ import annotations

from collections import Counter
import re


LIMIT = 1024 * 1024
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_FILE = re.compile(r"[a-f0-9]{8}:[a-f0-9]{16}\Z")
_SOURCE = "python-httpx-outbound-native/1"


def _integer(value, minimum=1):
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _hash(value):
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _token(value):
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _subject(value):
    return (isinstance(value, dict)
            and all(_integer(value.get(k)) for k in ('pid', 'creation_filetime', 'parent_pid'))
            and _hash(value.get('image_sha256')))


def _belongs(row, subject):
    return (isinstance(row, dict) and isinstance(subject, dict)
            and row.get('pid') == subject.get('pid')
            and row.get('creation_filetime') == subject.get('creation_filetime'))


def _clock(row):
    return (all(_integer(row.get(k)) for k in ('qpc', 'completed_qpc', 'qpc_frequency'))
            and row['completed_qpc'] >= row['qpc'])


def _range(row, subject, kind, role, digest, size):
    """Require actual completed bytes, not requested length or parse success."""
    return (_hash(digest) and _integer(size) and size <= LIMIT
            and _belongs(row, subject) and row.get('provider') == 'native-io'
            and row.get('capture_layer') == 'win32-sync-io'
            and row.get('kind') == kind and row.get('path_role') == role
            and row.get('object_kind') == 'file' and row.get('success') is True
            and row.get('capture_gap') is False and row.get('data_truncated') is False
            and row.get('unsupported') == [] and row.get('lost_events') == 0
            and row.get('win32_error') == 0
            and isinstance(row.get('file_identity'), str)
            and _FILE.fullmatch(row['file_identity']) is not None
            and _integer(row.get('open_generation')) and _token(row.get('event_id'))
            and type(row.get('offset')) is int and row['offset'] == 0
            and row.get('data_sha256') == digest
            and row.get('data_bytes') == row.get('length') == row.get('completed_length') == size
            and _integer(row.get('requested_length'), size)
            and _clock(row))


def _io_healthy(value, subject):
    return (isinstance(value, dict) and _belongs(value, subject)
            and value.get('ready') is True and value.get('terminal') is True
            and value.get('terminal_health') is True
            and value.get('lost_events') == 0 and value.get('errors') == [])


def _no_intervening_write(rows, selected, read):
    """A missing clock/range on another write cannot establish stable version."""
    for row in rows:
        if row.get('kind') != 'write' or row.get('object_kind') != 'file':
            continue
        if row.get('path_role') == 'transfer' and row.get('file_identity') != selected['file_identity']:
            # A replacement at the observed transfer path cannot be silently
            # dropped because it lacks the previously selected file identity.
            return False
        if (row.get('file_identity') != selected['file_identity']
                or row.get('event_id') == selected['event_id']):
            continue
        if not _clock(row) or row['qpc_frequency'] != selected['qpc_frequency']:
            return False
        # Includes same-byte rewrites and overlapping/in-flight writes. These
        # are distinct versions even when the digest does not change.
        if row['qpc'] <= read['completed_qpc'] and row['completed_qpc'] >= selected['qpc']:
            return False
    return True


def assess_file_upload(*, subjects, io_rows, original_sha256, original_bytes,
                       modified_sha256, modified_bytes, body_capture,
                       execution_records, receipts, health, expected_block):
    """Assess independently observed A-read/modify -> B-read/request evidence.

    Native I/O rows are decoded collector rows, with ``data`` removed and
    ``data_sha256``/``data_bytes`` added. A/B collector statuses must include
    their PID and birth. Gate health attests the existing verified native pipe
    identity and complete execution-evidence drain; the receiver must explicitly
    attest readiness and completion even when there are no received requests.
    No missing, malformed, duplicate or additional attempts are discarded.
    """
    subjects = subjects if isinstance(subjects, dict) else {}
    health = health if isinstance(health, dict) else {}
    a = subjects.get('A') if isinstance(subjects.get('A'), dict) else {}
    b = subjects.get('B') if isinstance(subjects.get('B'), dict) else {}
    checks = {}
    checks['independent_application_identities'] = (
        _subject(a) and _subject(b) and a['pid'] != b['pid']
        and a['image_sha256'] != b['image_sha256']
        and a['parent_pid'] != b['pid'] and b['parent_pid'] != a['pid'])
    checks['independent_transformation_oracle'] = (
        _hash(original_sha256) and _hash(modified_sha256)
        and original_sha256 != modified_sha256
        and _integer(original_bytes) and original_bytes <= LIMIT
        and _integer(modified_bytes) and modified_bytes <= LIMIT)
    shape = (isinstance(io_rows, list) and len(io_rows) <= 10000
             and all(isinstance(row, dict) for row in io_rows))
    rows = io_rows if shape else []
    event_ids = [row.get('event_id') for row in rows]
    checks['io_event_identity_integrity'] = (
        shape and bool(rows) and all(_token(eid) for eid in event_ids)
        and len(set(event_ids)) == len(event_ids))
    checks['io_identity_scope_and_continuity'] = bool(rows) and all(
        (_belongs(row, a) or _belongs(row, b))
        and row.get('provider') == 'native-io' and row.get('kind') != 'gap'
        and row.get('capture_gap') is False and row.get('lost_events') == 0
        for row in rows)
    checks['native_io_health'] = (_io_healthy(health.get('A'), a)
                                 and _io_healthy(health.get('B'), b))
    reads = [row for row in rows if _range(row, a, 'read', 'source', original_sha256, original_bytes)]
    writes = [row for row in rows if _range(row, a, 'write', 'transfer', modified_sha256, modified_bytes)]
    uploads = [row for row in rows if _range(row, b, 'read', 'transfer', modified_sha256, modified_bytes)]
    checks['A_read_original_complete'] = bool(reads)
    checks['A_write_modified_complete'] = bool(writes)
    checks['B_read_modified_complete'] = bool(uploads)
    # The controlled experiment has one transformation and bounded repeats.
    # Do not permit hostile metadata to create cubic, unbounded work.
    candidate_limit = all(len(group) <= 8 for group in (reads, writes, uploads))
    checks['bounded_file_version_candidates'] = candidate_limit
    if not candidate_limit:
        reads, writes, uploads = [], [], []
    chains = []
    for source in reads:
        for write in writes:
            for read in uploads:
                if (source['qpc_frequency'] == write['qpc_frequency'] == read['qpc_frequency']
                        and source['completed_qpc'] <= write['qpc']
                        and write['completed_qpc'] <= read['qpc']
                        and write['file_identity'] == read['file_identity']
                        and _no_intervening_write(rows, write, read)):
                    chains.append((source, write, read))
    # A second full matching write is a second version, not an additional
    # independent confirmation of the one controlled modification. General
    # multi-version attribution needs a separate version/rewrite model.
    checks['stable_observed_file_handoff'] = bool(chains) and len(writes) == 1
    gate = health.get('gate', {})
    checks['native_gate_health_and_identity'] = (
        isinstance(gate, dict) and gate.get('ready') is True
        and gate.get('identity_verified') is True and gate.get('execution_drained') is True
        and gate.get('errors') == [])
    captures_shape = (isinstance(body_capture, list) and 0 < len(body_capture) <= 4096
                      and all(isinstance(row, dict) for row in body_capture))
    captures = body_capture if captures_shape else []
    ids = [row.get('attempt_id') for row in captures]
    checks['distinct_request_attempts'] = (
        captures_shape and all(_token(i) and len(i) <= 64 for i in ids)
        and len(set(ids)) == len(ids))
    checks['native_snapshot_matches_modified_file'] = (
        _hash(modified_sha256) and _integer(modified_bytes) and modified_bytes <= LIMIT
        and bool(captures) and all(
        _belongs(row, b) and row.get('completeness') == 'complete'
        and row.get('source') == _SOURCE and row.get('capture_layer') == 'request-body'
        and row.get('body_sha256') == modified_sha256 and row.get('body_bytes') == modified_bytes
        for row in captures))
    expected_decision = 'BLOCK' if expected_block is True else 'ALLOW'
    checks['content_policy_decision'] = isinstance(expected_block, bool) and bool(captures) and all(
        row.get('decision') == expected_decision
        and row.get('detection_status') == ('matched' if expected_block else 'no_match')
        and isinstance(row.get('findings'), list)
        and (bool(row['findings']) if expected_block else not row['findings'])
        for row in captures)
    executions_shape = (isinstance(execution_records, list) and len(execution_records) <= 4096
                        and all(isinstance(row, dict) for row in execution_records))
    executions = execution_records if executions_shape else []
    executed_ids = [row.get('attempt_id') for row in executions]
    checks['native_execution_matches_every_attempt'] = (
        executions_shape and checks['distinct_request_attempts']
        and len(executions) == len(captures)
        and all(_token(i) for i in executed_ids)
        and len(set(executed_ids)) == len(executed_ids)
        and set(executed_ids) == set(ids)
        and all(row.get('pid') == b.get('pid') and _integer(row.get('qpc'))
                and row.get('creation_filetime', b.get('creation_filetime')) == b.get('creation_filetime')
                and row.get('action') == ('block_request' if expected_block else 'none')
                and row.get('result') == ('native_rejection' if expected_block else 'transport_authorized')
                for row in executions))
    checks['native_execution_after_observed_read'] = (
        checks['native_execution_matches_every_attempt'] and bool(chains)
        and all(any(row['qpc'] >= read['completed_qpc'] for _, _, read in chains)
                for row in executions))
    receiver = health.get('receiver', {})
    checks['receiver_observation_complete'] = (
        isinstance(receiver, dict) and receiver.get('ready') is True
        and receiver.get('terminal') is True and receiver.get('pending_requests') == 0
        and receiver.get('errors') == [])
    receipts_shape = (isinstance(receipts, list) and len(receipts) <= 4096
                      and all(isinstance(row, dict) for row in receipts))
    received = receipts if receipts_shape else []
    valid_receipts = receipts_shape and all(
        row.get('complete') is True and _hash(row.get('body_sha256'))
        and _integer(row.get('body_bytes'), 0) and row['body_bytes'] <= LIMIT
        for row in received)
    if expected_block:
        checks['receiver_matches_actual_action'] = receipts_shape and not received
    else:
        checks['receiver_matches_actual_action'] = (
            checks['native_snapshot_matches_modified_file'] and valid_receipts
            and Counter((row.get('body_sha256'), row.get('body_bytes')) for row in captures)
            == Counter((row['body_sha256'], row['body_bytes']) for row in received))
    passed = all(checks.values())
    # Only validated digest/identifier-shaped metadata reaches the report.
    chain_ids = sorted({row['event_id'] for chain in chains for row in chain})
    return {
        'schema_version': 'transpect.file-upload.assessment/1.0',
        'passed': passed, 'checks': checks,
        'limitations': [key for key, value in checks.items() if not value] + [
            'controlled_registered_applications_and_single_sync_io_ranges_only',
            'content_and_file_version_evidence_is_not_byte_level_causality',
            'matching_content_does_not_prove_unique_source',
            'request_control_requires_separate_native_execution_evidence',
        ],
        'expected_action': 'block_request' if expected_block else 'allow',
        'capture_layer': 'request-body', 'business_transport': 'regular-file',
        'attempt_count': len(captures), 'receipt_count': len(received),
        'received_body_bytes': sum(row['body_bytes'] for row in received
                                   if _integer(row.get('body_bytes'), 0) and row['body_bytes'] <= LIMIT),
        'evidence': {'io_event_ids': chain_ids,
                     'attempt_ids': sorted(i for i in ids if _token(i) and len(i) <= 64)},
        'propagation': {
            'confidence': 'Medium' if passed else 'Unknown',
            'unique_source_proven': False, 'byte_level_taint_proof': False,
        },
    }
