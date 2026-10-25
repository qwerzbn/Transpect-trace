"""Observed agent messages and declared parent links, without implicit taint."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re

from transpect_trace.flow.models import LIMIT, CollectorHealth, FlowProcess, OutboundContentObservation, TransferObservation
from transpect_trace.observe.semantics import SemanticPart
from transpect_trace.protect.detection import detect
from .models import AgentFlowSession, AgentMessageObservation, AgentPropagationRelation
from .protocol import parse_message, parse_outbound


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return (value.encode('utf-8') if isinstance(value, str) else
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8'))


class AgentEvidence:
    """All bodies are ephemeral callback arguments; retained state is metadata."""

    def __init__(self, session_id, subjects, task_id, index=None):
        subjects = [FlowProcess.model_validate(s).model_copy(deep=True) for s in subjects]
        if (len(subjects) != 2 or {s.role for s in subjects} != {'A', 'B'}
                or len({s.key for s in subjects}) != 2):
            raise ValueError('agent evidence requires two distinct registered subjects')
        if not isinstance(task_id, str) or re.fullmatch(r'[a-f0-9]{32}', task_id) is None:
            raise ValueError('invalid agent task identity')
        self.session = AgentFlowSession(session_id=session_id, task_id_sha256=_sha(task_id.encode()), subjects=subjects)
        self.subjects = {s.key: s for s in subjects}
        self.index = index
        self.observations = []
        self.relations = []
        self.gaps = []
        self._ids = set()
        self._timing = {}
        self._base_snapshots = {}
        self._result = None

    def _gap(self, reason):
        if reason not in self.gaps:
            self.gaps.append(reason)

    def _identity(self, row):
        subject = self.subjects.get(row.process.key)
        if subject is None or subject != row.process or row.session_id != self.session.session_id:
            self._gap('observation_identity_mismatch')
            return False
        if row.observation_id in self._ids:
            self._gap('duplicate_observation_callback')
            return False
        if len(self.observations) >= 10000:
            self._gap('agent_observation_limit')
            return False
        self._ids.add(row.observation_id)
        return True

    def _inspect(self, value, location):
        data = _canonical(value)
        if len(data) > LIMIT:
            raise ValueError('agent_semantic_snapshot_size_limit')
        field = SemanticPart(location=location, representation='text' if isinstance(value, str) else 'json',
                             bytes=len(data), sha256=_sha(data), inspected=True, value=value)
        return detect([field], self.index), _sha(data), len(data)

    def _record(self, row, data, stage, *, capture_source, capture_layer, evidence_ids):
        if self._result is not None:
            raise RuntimeError('agent evidence already finalized')
        if not self._identity(row):
            return
        if not isinstance(data, bytes) or len(data) > LIMIT:
            self._gap('agent_snapshot_invalid_or_oversized')
            return
        expected_hash = row.content_sha256 if isinstance(row, TransferObservation) else row.decoded_body_sha256
        expected_length = row.captured_bytes if isinstance(row, TransferObservation) else row.body_bytes
        if _sha(data) != expected_hash or len(data) != expected_length:
            self._gap('agent_snapshot_identity_mismatch')
            return
        limits = []
        if row.completeness != 'complete' or row.limitations:
            limits.append('capture_incomplete')
        if isinstance(row, TransferObservation) and row.completed_bytes != len(data):
            limits.append('transfer_range_incomplete')
        if isinstance(row, OutboundContentObservation) and (row.encoding_state != 'identity'
                or row.parsing_state not in {'text', 'json'} or row.detection_status == 'incomplete'):
            limits.append('outbound_inspection_incomplete')
        record = AgentMessageObservation(original_observation_id=row.observation_id,
            session_id=self.session.session_id, stage=stage, process=row.process.model_copy(deep=True),
            agent_id='agent-a' if row.process.role == 'A' else 'agent-b',
            capture_source=capture_source, capture_layer=capture_layer,
            protocol_status='not_applicable' if stage == 'source_read' else 'invalid',
            body_sha256=_sha(data), body_bytes=len(data), completeness=row.completeness,
            detection_status='incomplete', evidence_event_ids=list(evidence_ids), limitations=limits)
        value, location = None, '$'
        try:
            if stage == 'source_read':
                value = data.decode('utf-8-sig', errors='strict')
            else:
                protocol = parse_outbound(data) if stage == 'outbound' else parse_message(data)
                record.task_id_sha256 = _sha(protocol['task_id'].encode())
                if record.task_id_sha256 != self.session.task_id_sha256:
                    record.limitations.append('message_task_mismatch')
                elif stage == 'outbound':
                    record.parent_message_id_sha256 = _sha(protocol['parent_message_id'].encode())
                    record.tool_call_id_sha256 = _sha(protocol['tool_call_id'].encode())
                    record.protocol_attempt_id_sha256 = _sha(protocol['attempt_id'].encode())
                    record.local_attempt_id = row.attempt_id
                    record.protocol_status = 'valid'
                else:
                    record.message_id_sha256 = _sha(protocol['message_id'].encode())
                    record.protocol_status = 'valid'
                value = protocol['report' if stage == 'outbound' else 'payload']
                location = '$.report' if stage == 'outbound' else '$.payload'
            record.findings, record.payload_sha256, record.payload_bytes = self._inspect(value, location)
            record.payload_representation = 'text' if isinstance(value, str) else 'json'
            record.detection_status = 'incomplete' if record.limitations else 'matched' if record.findings else 'no_match'
            record.sensitivity_labels = sorted({finding.sensitivity for finding in record.findings})
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            record.limitations.append('agent_protocol_or_content_inspection_failed')
        if stage != 'source_read' and record.protocol_status != 'valid':
            record.limitations.append('agent_protocol_unverified')
        if isinstance(row, OutboundContentObservation):
            record.llm_classification = row.llm_classification
        record.limitations = sorted(set(record.limitations))
        if record.limitations:
            record.detection_status = 'incomplete'
            for gap in record.limitations:
                self._gap(gap)
        self.observations.append(record)
        self._base_snapshots[row.observation_id] = row.model_dump()
        self._timing[record.observation_id] = (
            row.last_qpc if isinstance(row, TransferObservation) else row.captured_qpc,
            row.qpc_frequency,
            row.first_qpc if isinstance(row, TransferObservation) else row.captured_qpc)

    def consume_transfer(self, row, data):
        row = TransferObservation.model_validate(row)
        if row.process.role == 'A' and row.object_kind == 'file' and row.resource_role == 'source' and row.operation == 'read':
            stage = 'source_read'
        elif row.object_kind == 'pipe' and row.resource_role == 'pipe' and (
                (row.process.role, row.operation) in {('A', 'write'), ('B', 'read')}):
            stage = 'message_write' if row.operation == 'write' else 'message_read'
        else:
            self._gap('agent_transfer_stage_unsupported')
            return
        self._record(row, data, stage, capture_source='native-io', capture_layer='io', evidence_ids=row.evidence_event_ids)

    def consume_outbound(self, row, data):
        row = OutboundContentObservation.model_validate(row)
        if row.process.role != 'B' or row.provider != 'ecapture-windows' or row.capture_layer != 'tls':
            self._gap('agent_outbound_capture_unsupported')
            return
        self._record(row, data, 'outbound', capture_source='ecapture-windows', capture_layer='tls',
                     evidence_ids=[row.original_observation_id])

    @staticmethod
    def _overlap(left, right):
        shared = sorted({f.registration_id for f in left.findings if f.registration_id}
                        & {f.registration_id for f in right.findings if f.registration_id})
        if (left.payload_sha256 and left.payload_sha256 == right.payload_sha256
                and left.payload_representation == right.payload_representation):
            return 'exact_payload', shared
        return ('registered_content_overlap' if shared else 'none'), shared

    def _before(self, left, right):
        end, frequency, _ = self._timing[left.observation_id]
        _, other_frequency, start = self._timing[right.observation_id]
        return frequency > 0 and frequency == other_frequency and 0 < end <= start

    def _relate(self, left, right, kind, confidence, method, *, base=(), limits=(), declared=False):
        if len(self.relations) >= 4096:
            self._gap('agent_relation_limit')
            return
        overlap, shared = self._overlap(left, right)
        self.relations.append(AgentPropagationRelation(left_id=left.observation_id, right_id=right.observation_id,
            relation_kind=kind, confidence=confidence, method=method, content_evidence=overlap,
            shared_registration_ids=shared, base_relation_ids=list(base),
            evidence_event_ids=sorted(set(left.evidence_event_ids + right.evidence_event_ids)),
            limitations=sorted(set([*limits, 'content_match_does_not_prove_unique_source'])),
            protocol_declaration_only=declared))

    def finish(self, flow_result, fixture_truth=None):
        if self._result is not None:
            return self._result
        # Fixture truth is never ingested into observations, identities or links.
        fixture_count = len(fixture_truth) if isinstance(fixture_truth, list) else 0
        base = flow_result if isinstance(flow_result, dict) else {}
        base_session = base.get('session', {})
        base_status = base_session.get('status', 'unknown')
        self.session.base_flow_status = base_status if base_status in {'starting', 'observing', 'complete', 'partial', 'unavailable'} else 'unknown'
        identity_ok = False
        try:
            base_subjects = {FlowProcess.model_validate(s).key: FlowProcess.model_validate(s) for s in base_session.get('subjects', [])}
            identity_ok = base_session.get('session_id') == self.session.session_id and base_subjects == self.subjects
        except (TypeError, ValueError):
            pass
        if not identity_ok:
            self._gap('base_flow_identity_mismatch')
        health = base_session.get('health', {})
        healthy = False
        try:
            healthy = all(CollectorHealth.model_validate(health[k]).complete
                          for k in ('native-io:A', 'native-io:B', 'etw', 'ecapture'))
        except (TypeError, ValueError, KeyError):
            pass
        if not healthy:
            self._gap('base_collector_health_incomplete')
        if base_status != 'complete' or base.get('coverage_gaps'):
            self._gap('base_flow_incomplete')
        if not base.get('origin_receipts', {}).get('hash_multiset_matches', False):
            self._gap('origin_receipts_unmatched')
        if base.get('can_enforce') is not False:
            self._gap('base_observe_only_contract_invalid')

        base_rows = {}
        try:
            for value in base.get('system_behavior', {}).get('transfers', []):
                row = TransferObservation.model_validate(value)
                if row.observation_id in base_rows:
                    self._gap('duplicate_base_observation_identifier')
                base_rows[row.observation_id] = row
            for value in base.get('content_detection', {}).get('outbound', []):
                row = OutboundContentObservation.model_validate(value)
                if row.observation_id in base_rows:
                    self._gap('duplicate_base_observation_identifier')
                base_rows[row.observation_id] = row
        except (TypeError, ValueError):
            self._gap('base_observation_invalid')
        verified = set()
        for row in self.observations:
            original = base_rows.get(row.original_observation_id)
            original_hash = (original.content_sha256 if isinstance(original, TransferObservation) else
                             original.decoded_body_sha256 if isinstance(original, OutboundContentObservation) else None)
            if (identity_ok and original is not None and original.process == row.process
                    and original_hash == row.body_sha256 and original.completeness == row.completeness
                    and original.model_dump() == self._base_snapshots[row.original_observation_id]):
                verified.add(row.observation_id)
            else:
                self._gap('observation_missing_from_base_flow')
        stages = defaultdict(list)
        for row in self.observations:
            stages[row.stage].append(row)
        for stage in ('source_read', 'message_write', 'message_read', 'outbound'):
            if not stages[stage]:
                self._gap(stage + '_not_observed')

        writes, reads = defaultdict(list), defaultdict(list)
        for stage, target in (('message_write', writes), ('message_read', reads)):
            for row in stages[stage]:
                if row.protocol_status == 'valid':
                    target[row.message_id_sha256].append(row)
        ambiguous_ids = {key for key in writes.keys() | reads.keys() if len(writes[key]) != 1 or len(reads[key]) != 1}
        if ambiguous_ids:
            self._gap('message_identifier_missing_or_ambiguous')
        attempt_counts = Counter(row.protocol_attempt_id_sha256 for row in stages['outbound'] if row.protocol_status == 'valid')
        if any(count > 1 for count in attempt_counts.values()):
            self._gap('duplicate_protocol_attempt_identifier')
        supported_reads = set()
        base_relations = base.get('propagation', {}).get('relations', [])
        for message_id in writes.keys() & reads.keys():
            for write in writes[message_id]:
                for read in reads[message_id]:
                    matches = [r for r in base_relations if r.get('left_id') == write.original_observation_id
                               and r.get('right_id') == read.original_observation_id
                               and r.get('relation_kind') == 'pipe_handoff_candidate'
                               and r.get('confidence') in {'High', 'Medium'}]
                    valid = (message_id not in ambiguous_ids and write.observation_id in verified
                             and read.observation_id in verified and len(matches) == 1
                             and write.payload_sha256 == read.payload_sha256
                             and write.body_sha256 == read.body_sha256
                             and not write.limitations and not read.limitations)
                    if valid:
                        supported_reads.add(read.observation_id)
                    else:
                        self._gap('agent_message_handoff_unverified')
                    self._relate(write, read, 'agent_message_handoff', 'Medium' if valid else 'Unknown',
                                 'observed_protocol_and_native_handoff',
                                 base=[r['relation_id'] for r in matches],
                                 limits=['protocol_ids_are_application_declared', *([] if valid else ['handoff_mapping_incomplete'])])
        for source in stages['source_read']:
            for write in stages['message_write']:
                overlap, _ = self._overlap(source, write)
                if source.process == write.process and self._before(source, write) and overlap != 'none':
                    self._relate(source, write, 'source_message_candidate', 'Low',
                                 'same_process_registered_content_or_exact_payload',
                                 limits=['in_process_transformation_unobserved'])
        for outbound in stages['outbound']:
            if outbound.protocol_status != 'valid':
                continue
            parents = reads.get(outbound.parent_message_id_sha256, [])
            if not parents:
                self._gap('outbound_parent_not_observed')
            for parent in parents:
                valid = (len(parents) == 1 and parent.observation_id in supported_reads
                         and outbound.observation_id in verified and self._before(parent, outbound)
                         and attempt_counts[outbound.protocol_attempt_id_sha256] == 1
                         and not outbound.limitations)
                if not valid:
                    self._gap('outbound_parent_mapping_unverified')
                self._relate(parent, outbound, 'protocol_parent_reference', 'Medium' if valid else 'Unknown',
                             'outbound_declared_parent_identifier', declared=True,
                             limits=['protocol_parent_is_not_byte_causality', *([] if valid else ['parent_mapping_incomplete'])])
        if not supported_reads:
            self._gap('no_supported_agent_handoff')
        if self.gaps:
            reason = ('base_evidence_incomplete' if not healthy or not identity_ok or base_status != 'complete'
                      else 'agent_evidence_incomplete')
            for relation in self.relations:
                relation.confidence = 'Unknown'
                relation.limitations = sorted(set(relation.limitations + [reason]))
        self.session.status = 'partial' if self.gaps else 'complete'
        self.session.limitations = list(self.gaps)
        self._result = {
            'schema_version': 'transpect.agent.report/1.0', 'session': self.session.model_dump(),
            'observations': [row.model_dump() for row in self.observations],
            'relations': [row.model_dump() for row in self.relations],
            'coverage_gaps': list(self.gaps),
            'stage_counts': {stage: len(stages[stage]) for stage in ('source_read', 'message_write', 'message_read', 'outbound')},
            'fixture_truth': {'entry_count': fixture_count, 'evidence_source': 'fixture_self_reported_test_truth',
                             'used_for_certification': False, 'content_persisted': False},
            'can_enforce': False, 'blocked_requests': 0, 'plaintext_exported': False,
            'byte_level_taint_proof': False, 'runtime_certification': 'not_automatically_granted',
        }
        return self._result
