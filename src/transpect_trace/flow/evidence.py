"""Bounded evidence correlation. Hash matches remain candidates, never taint proof."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from transpect_trace.observe.classification import classify
from transpect_trace.observe.semantics import SemanticPart
from transpect_trace.protect.detection import detect
from .models import (LIMIT, CollectorHealth, CrossApplicationSession, FlowProcess,
                     OutboundContentObservation, PropagationRelation, TransferObservation)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _technical(value):
    # Never persist arbitrary exception messages, OS paths or process payloads.
    return value if isinstance(value, str) and len(value) <= 96 and all(c.isalnum() or c in '_.:-' for c in value) else 'unspecified_gap'


class FlowEvidence:
    def __init__(self, session_id, subjects, index=None, directory: Path | None = None, *, transfer_sink=None):
        self.session = CrossApplicationSession(session_id=session_id, subjects=[FlowProcess.model_validate(s) for s in subjects])
        self.subjects = {s.key: s for s in self.session.subjects}
        if len(self.subjects) != len(subjects) or {s.role for s in self.subjects.values()} != {'A', 'B'} or len(subjects) != 2:
            raise ValueError('flow requires distinct explicit A and B process instances')
        self.index = index
        self.directory = Path(directory) if directory else None
        # Optional synchronous in-memory consumer. No new persisted v1 fields.
        self.transfer_sink = transfer_sink
        self.transfers = []
        self.outbound = []
        self.relations = []
        self.receipts = []
        self.native_events = []
        self.gaps = []
        self._states = {}
        self._handles = {}
        self._pipe_generations = {}
        self._sequence = {}
        self._finished = False
        self._result = None

    def gap(self, reason):
        reason = _technical(reason)
        if reason not in self.gaps:
            self.gaps.append(reason)

    def health(self, component, *, ready=False, terminal=False, lost_events=0, errors=0,
               limitations=(), identity_verified=False):
        if component not in {'native-io:A', 'native-io:B', 'etw', 'ecapture'}:
            raise ValueError('unknown flow collector')
        if int(lost_events) < 0 or int(errors) < 0:
            raise ValueError('collector counters must be nonnegative')
        state = self.session.health.setdefault(component, CollectorHealth())
        state.ready |= bool(ready)
        state.terminal |= bool(terminal)
        state.identity_verified |= bool(identity_verified)
        state.lost_events = max(state.lost_events, int(lost_events))
        state.errors = max(state.errors, int(errors))
        state.limitations = sorted(set(state.limitations + [_technical(v) for v in limitations]))
        if ready:
            self.session.status = 'observing'

    def _inspect(self, data, *, json_content=False):
        value = data.decode('utf-8-sig', errors='strict')
        if json_content:
            value = json.loads(value)
        field = SemanticPart(location='$', representation='json' if json_content else 'text',
                             bytes=len(data), sha256=digest(data), inspected=True, value=value)
        return detect([field], self.index), value

    def consume_native(self, event):
        if self._finished:
            raise RuntimeError('flow already finalized')
        try:
            self._consume_native(event)
        except (ValueError, TypeError, KeyError, OverflowError):
            self.gap('native_event_invalid')

    def _consume_native(self, event):
        subject = self.subjects.get((int(event.get('pid', 0)), int(event.get('creation_filetime', 0))))
        if subject is None:
            self.gap('unregistered_process_identity')
            return
        kind = event.get('kind')
        if event.get('capture_gap') or event.get('data_truncated'):
            self.gap('native_reported_gap')
        if kind in {'ready', 'terminal', 'gap'}:
            self.health('native-io:' + subject.role, ready=kind == 'ready', terminal=kind == 'terminal',
                        lost_events=event.get('lost_events', 0), errors=event.get('errors', 0),
                        limitations=['native_reported_gap'] if kind == 'gap' else [])
            if kind == 'gap':
                self.gap('native_reported_gap')
            return
        if kind not in {'open', 'read', 'write', 'close', 'pipe_connect', 'pipe_disconnect'}:
            self.gap('native_event_kind_unsupported')
            return
        sequence = int(event.get('sequence', 0))
        prior = self._sequence.get(subject.key)
        if sequence <= 0 or prior is not None and sequence != prior + 1:
            self.gap('native_sequence_gap')
        self._sequence[subject.key] = sequence
        key = (*subject.key, str(event.get('handle_id', '')), int(event.get('open_generation', 0)))
        supplied_id = event.get('event_id')
        eid = supplied_id if supplied_id and _technical(supplied_id) != 'unspecified_gap' else uuid4().hex
        # The audit view is a strict allowlist, not a copy of the native message.
        raw = {'event_id': eid, 'kind': kind, 'pid': subject.pid, 'creation_filetime': subject.creation_filetime,
               'sequence': sequence, 'qpc': int(event.get('qpc', 0)),
               'qpc_frequency': int(event.get('qpc_frequency', 0)), 'success': bool(event.get('success', False)),
               'win32_error': int(event.get('win32_error', 0)), 'can_enforce': False}
        if len(self.native_events) >= 10000:
            self.gap('native_event_limit')
            return
        self.native_events.append(raw)
        if kind in {'open', 'pipe_connect'}:
            if not event.get('success', False):
                return
            self._handles[key] = {k: event.get(k) for k in ('object_kind', 'file_identity', 'path_role', 'connection_generation',
                                                         'peer_pid', 'peer_creation_filetime', 'pipe_identity')}
            # A connection can be replaced without transferring any message on
            # the previous instance. Transfer rows alone cannot reveal that gap.
            if event.get('object_kind') == 'pipe' and event.get('pipe_identity') and event.get('connection_generation'):
                pipe_key = (*subject.key, digest(str(event['pipe_identity']).casefold().encode()))
                generations = self._pipe_generations.setdefault(pipe_key, set())
                generations.add(int(event['connection_generation']))
                if len(generations) > 1:
                    self.gap('pipe_connection_mapping_ambiguous')
            return
        if kind in {'close', 'pipe_disconnect'}:
            for state_key in list(self._states):
                if state_key[:4] == key:
                    self._finish_transfer(state_key, boundary=bool(event.get('success', False)), boundary_id=eid,
                                          boundary_qpc=int(event.get('completed_qpc') or raw['qpc']))
            self._handles.pop(key, None)
            return
        metadata = dict(self._handles.get(key, {}))
        metadata.update({k: v for k, v in event.items() if v is not None})
        if metadata.get('object_kind') not in {'file', 'pipe'}:
            self.gap('io_object_kind_unknown')
            return
        if metadata.get('unsupported'):
            self.gap('native_io_unsupported')
        if not event.get('success', False) and int(event.get('win32_error', 0)) != 234:
            self.gap('io_operation_failed')
            return
        state_key = (*key, kind)
        if state_key not in self._states:
            if len(self._states) >= 32:
                self.gap('active_transfer_limit')
                return
            self._states[state_key] = {'subject': subject, 'metadata': metadata, 'data': bytearray(), 'completed': 0,
                                      'first_qpc': raw['qpc'], 'last_qpc': raw['qpc'], 'frequency': raw['qpc_frequency'],
                                      'first_offset': event.get('offset'), 'limits': [], 'events': [], 'sequence': sequence}
        state = self._states[state_key]
        state['last_qpc'] = int(event.get('completed_qpc') or raw['qpc'])
        state['events'].append(eid)
        for name in ('peer_pid', 'peer_creation_filetime', 'connection_generation'):
            if metadata.get(name):
                state['metadata'][name] = metadata[name]
        completed = int(event.get('completed_length', 0))
        requested = int(event.get('requested_length', completed))
        if completed < 0 or requested < completed:
            state['limits'].append('invalid_completed_length')
            return
        data = event.get('data', b'')
        if not isinstance(data, bytes):
            data = base64.b64decode(event.get('data_b64', ''), validate=True)
        if len(data) != completed or event.get('data_truncated') or event.get('capture_gap') or metadata.get('unsupported'):
            state['limits'].append('io_snapshot_incomplete')
        if raw['qpc'] <= 0 or state['last_qpc'] < raw['qpc'] or raw['qpc_frequency'] <= 0 or raw['qpc_frequency'] != state['frequency']:
            state['limits'].append('clock_identity_unknown')
        if metadata['object_kind'] == 'file':
            offset = event.get('offset')
            if offset is None or int(offset) != state['completed']:
                state['limits'].append('file_range_noncontiguous')
        state['completed'] += completed
        if state['completed'] > LIMIT:
            state['limits'].append('transfer_size_limit')
        room = LIMIT - len(state['data'])
        state['data'].extend(data[:min(room, completed)])
        if metadata['object_kind'] == 'pipe' and metadata.get('message_complete') and int(event.get('win32_error', 0)) != 234:
            self._finish_transfer(state_key, boundary=True)

    def _finish_transfer(self, key, *, boundary, boundary_id=None, boundary_qpc=None):
        state = self._states.pop(key)
        meta = state['metadata']
        limits = state['limits']
        if boundary_qpc is not None:
            state['last_qpc'] = boundary_qpc
        if not boundary:
            limits.append('transfer_boundary_unknown')
        if meta['object_kind'] == 'file' and not meta.get('file_identity'):
            limits.append('file_identity_unknown')
        if meta['object_kind'] == 'pipe' and not (meta.get('peer_pid') and meta.get('peer_creation_filetime') and meta.get('connection_generation')):
            limits.append('pipe_identity_unknown')
        if meta['object_kind'] == 'pipe' and not meta.get('pipe_identity'):
            limits.append('pipe_name_identity_unknown')
        data = bytes(state['data'])
        findings = []
        try:
            findings, _ = self._inspect(data)
        except (ValueError, UnicodeError, RecursionError):
            limits.append('transfer_content_uninspected')
        object_id = meta.get('file_identity') if meta['object_kind'] == 'file' else str(meta.get('pipe_identity') or '').casefold()
        # Pipes deliberately do not equate independent per-process generation counters.
        resource_id = digest(str(object_id).encode()) if object_id else None
        row = TransferObservation(session_id=self.session.session_id, process=state['subject'],
            object_kind=meta['object_kind'], operation=key[-1], resource_id=resource_id,
            resource_role=meta.get('path_role') if meta.get('path_role') in {'source', 'transfer', 'pipe'} else 'unknown',
            open_generation=key[3], connection_generation=int(meta.get('connection_generation') or 0),
            peer_pid=meta.get('peer_pid'), peer_creation_filetime=meta.get('peer_creation_filetime'),
            first_qpc=state['first_qpc'], last_qpc=state['last_qpc'], qpc_frequency=max(1, state['frequency']),
            first_offset=state['first_offset'], completed_bytes=state['completed'], captured_bytes=len(data),
            content_sha256=digest(data), completeness='partial' if limits else 'complete',
            evidence_event_ids=state['events'] + ([boundary_id] if boundary_id else []), findings=findings,
            limitations=sorted(set(limits)))
        if row.object_kind == 'file' and row.operation == 'write':
            row.file_version = row.observation_id
        self.transfers.append(row)
        try:
            if self.transfer_sink is not None:
                self.transfer_sink(row.model_copy(deep=True), data)
        except Exception:
            self.gap('transfer_sink_failed')
        finally:
            state['data'].clear()

    def consume_body(self, event, body, observation_id):
        if self._finished:
            raise RuntimeError('flow already finalized')
        subject = self.subjects.get((event.pid, event.creation_filetime))
        if subject is None:
            self.gap('outbound_process_unregistered')
            return
        if event.image_sha256 is not None and event.image_sha256 != subject.image_sha256:
            self.gap('outbound_image_identity_mismatch')
            return
        if len(self.outbound) >= 10000:
            self.gap('outbound_observation_limit')
            return
        limits = [_technical(s) for s in body.limitations]
        if event.truncated or event.lost_events:
            limits.append('capture_incomplete')
        if event.connection_identity != 'stable':
            limits.append('connection_identity_unknown')
        if body.protocol != 'http/1.1':
            limits.append('protocol_not_certified')
        if len(body.data) > LIMIT:
            limits.append('body_size_limit')
        # Transport completeness is independent of interpretation and LLM class.
        transport_complete = not limits
        ctype = body.headers.get('content-type', '').split(';', 1)[0].strip().lower()
        if ctype not in {'text/plain', 'application/json'}:
            ctype = 'unsupported'
            limits.append('content_type_unsupported')
        encoding = body.headers.get('content-encoding', 'identity').strip().lower() or 'identity'
        if encoding != 'identity':
            limits.append('encoding_unsupported')
        findings, value = [], None
        parsing = 'unsupported'
        if len(body.data) <= LIMIT and ctype != 'unsupported' and encoding == 'identity':
            try:
                findings, value = self._inspect(body.data, json_content=ctype == 'application/json')
                parsing = 'json' if ctype == 'application/json' else 'text'
            except (ValueError, UnicodeError, RecursionError):
                parsing = 'failed'
                limits.append('body_inspection_failed')
        inspection_complete = transport_complete and parsing in {'text', 'json'} and encoding == 'identity'
        category = classify(observation_id, value, body.headers, event.application, complete=transport_complete,
                            decoded=inspection_complete, empty=not body.data).category
        host = None
        try:
            authority = body.headers.get(':authority', body.headers.get('host', ''))
            parsed = urlsplit('https://' + authority)
            if parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.path:
                host = parsed.hostname
        except ValueError:
            pass
        row = OutboundContentObservation(original_observation_id=observation_id, session_id=self.session.session_id,
            process=subject, provider=event.provider, capture_layer=event.capture_point,
            connection_id_sha256=digest(event.connection_id.encode()), stream_id=body.stream_id, protocol=body.protocol,
            destination_host=host, captured_qpc=event.captured_qpc, qpc_frequency=event.qpc_frequency,
            body_bytes=len(body.data), raw_body_sha256=digest(body.data),
            decoded_body_sha256=digest(body.data) if encoding == 'identity' else None,
            completeness='complete' if transport_complete else 'partial', content_type=ctype,
            encoding_state='identity' if encoding == 'identity' else 'unsupported', parsing_state=parsing,
            llm_classification=category, detection_status='incomplete' if not inspection_complete else 'matched' if findings else 'no_match',
            findings=findings, limitations=sorted(set(limits)),
            send_evidence='encryption_input_observed' if event.capture_point == 'tls' else 'request_constructed')
        self.outbound.append(row)

    def add_receipt(self, body_sha256, body_bytes, receipt_id):
        if len(body_sha256) != 64 or any(c not in '0123456789abcdef' for c in body_sha256) or body_bytes < 0:
            raise ValueError('invalid origin receipt')
        if len(self.receipts) >= 10000:
            self.gap('origin_receipt_limit')
            return
        self.receipts.append({'receipt_id_sha256': digest(str(receipt_id).encode()), 'body_sha256': body_sha256,
                              'body_bytes': int(body_bytes), 'evidence_source': 'controlled_origin', 'can_enforce': False})

    def _add_relation(self, left, right, kind, confidence, method, limits=()):
        ids = list(left.evidence_event_ids)
        ids += right.evidence_event_ids if isinstance(right, TransferObservation) else [right.original_observation_id]
        if self.gaps or not all(h.complete for h in self.session.health.values()):
            confidence = 'Unknown'
            limits = [*limits, 'collector_health_incomplete']
        self.relations.append(PropagationRelation(left_id=left.observation_id, right_id=right.observation_id,
            relation_kind=kind, confidence=confidence, method=method, evidence_event_ids=ids,
            limitations=[*limits, 'content_match_does_not_prove_unique_source']))

    @staticmethod
    def _before(left, right):
        rq = right.first_qpc if isinstance(right, TransferObservation) else right.captured_qpc
        return left.last_qpc * right.qpc_frequency <= rq * left.qpc_frequency

    @staticmethod
    def _overlap_content(left, right):
        exact = left.captured_bytes > 0 and left.content_sha256 == (right.content_sha256 if isinstance(right, TransferObservation) else right.decoded_body_sha256)
        registered_left = {f.registration_id for f in left.findings if f.registration_id}
        registered_right = {f.registration_id for f in right.findings if f.registration_id}
        return exact or bool(registered_left & registered_right), exact

    def _correlate(self):
        # Validate file versions even if their bytes have no matching earlier
        # writer. Content matching must not hide observed concurrent mutation.
        file_writes = [t for t in self.transfers if t.object_kind == 'file' and t.operation == 'write' and t.resource_id]
        for pos, write in enumerate(file_writes):
            for other in file_writes[pos + 1:]:
                if (write.resource_id == other.resource_id and not self._before(write, other)
                        and not self._before(other, write)):
                    for row in (write, other):
                        row.limitations = sorted(set(row.limitations + ['file_write_order_ambiguous']))
                        row.completeness = 'partial'
                    self.gap('file_write_order_ambiguous')
        for read in (t for t in self.transfers if t.object_kind == 'file' and t.operation == 'read' and t.resource_id):
            if any(w.resource_id == read.resource_id and not self._before(read, w) and not self._before(w, read)
                   for w in file_writes):
                read.limitations = sorted(set(read.limitations + ['file_modified_during_read']))
                read.completeness = 'partial'
                self.gap('file_modified_during_read')
        for read in (t for t in self.transfers if t.operation == 'read'):
            matches = []
            for write in (t for t in self.transfers if t.operation == 'write' and t.process.key != read.process.key):
                content, exact = self._overlap_content(write, read)
                if not content or write.object_kind != read.object_kind:
                    continue
                if read.object_kind == 'file':
                    if not self._before(write, read):
                        continue
                    if not write.resource_id or write.resource_id != read.resource_id:
                        continue
                    competing = [w for w in self.transfers if w.operation == 'write' and w.resource_id == read.resource_id
                                 and w.observation_id != write.observation_id and self._before(write, w) and self._before(w, read)]
                    if competing:
                        continue
                    matches.append((write, exact))
                elif (write.peer_pid, write.peer_creation_filetime) == read.process.key and (read.peer_pid, read.peer_creation_filetime) == write.process.key:
                    if not write.resource_id or write.resource_id != read.resource_id:
                        continue
                    # A pipe read can start before a blocking writer returns.
                    # Only reject a write known to start after this read ended.
                    if write.first_qpc * read.qpc_frequency <= read.last_qpc * write.qpc_frequency:
                        matches.append((write, exact))
            for write, exact in matches:
                complete = write.completeness == read.completeness == 'complete'
                if read.object_kind == 'file':
                    # Observed closed write version is a candidate, not an OS-wide generation guarantee.
                    if complete and exact and len(matches) == 1:
                        read.file_version = write.file_version
                    confidence = 'High' if complete and exact and len(matches) == 1 else 'Medium'
                    self._add_relation(write, read, 'file_handoff_candidate', confidence,
                                       'file_identity_closed_write_range_and_content', ['unobserved_writers_not_excluded'])
                else:
                    generations = [{t.connection_generation for t in self.transfers
                                    if t.object_kind == 'pipe' and t.process.key == member.process.key and t.resource_id == read.resource_id}
                                   | self._pipe_generations.get((*member.process.key, read.resource_id), set())
                                   for member in (write, read)]
                    ambiguous = len(matches) != 1 or any(len(values) > 1 for values in generations)
                    if ambiguous:
                        self.gap('pipe_connection_mapping_ambiguous')
                    self._add_relation(write, read, 'pipe_handoff_candidate', 'Medium' if complete and exact and not ambiguous else 'Low',
                                       'pipe_name_reciprocal_endpoint_identity_and_message_content',
                                       ['cross_endpoint_generation_mapping_unverified', *(['pipe_connection_mapping_ambiguous'] if ambiguous else [])])
        # Equal messages on one local connection also need explicit framing
        # mapping; one write cannot silently certify several separate reads.
        pipe_relations = [r for r in self.relations if r.relation_kind == 'pipe_handoff_candidate']
        for relation in pipe_relations:
            if sum(r.left_id == relation.left_id for r in pipe_relations) > 1:
                relation.limitations.append('pipe_message_mapping_ambiguous')
                if relation.confidence != 'Unknown':
                    relation.confidence = 'Low'
                self.gap('pipe_message_mapping_ambiguous')
        for write in (t for t in self.transfers if t.operation == 'write'):
            for read in (t for t in self.transfers if t.operation == 'read' and t.process.key == write.process.key):
                content, _ = self._overlap_content(read, write)
                if content and self._before(read, write):
                    self._add_relation(read, write, 'within_process_content_candidate', 'Low',
                                       'same_process_content_and_order', ['in_process_transformation_unobserved'])
        for outbound in self.outbound:
            for read in (t for t in self.transfers if t.operation == 'read' and t.process.key == outbound.process.key):
                content, exact = self._overlap_content(read, outbound)
                if content and self._before(read, outbound):
                    confidence = 'Medium' if read.completeness == outbound.completeness == 'complete' else 'Low'
                    self._add_relation(read, outbound, 'outbound_content_candidate', confidence,
                                       'same_process_exact_body_and_order' if exact else 'same_process_registered_content_and_order',
                                       ['request_to_read_mapping_unverified'])

    def _collection_coverage(self):
        """Ready and terminal are health, not evidence that any I/O was captured.

        A complete controlled handoff requires both actual endpoints and a
        bounded, complete transfer range. The outbound content may legitimately
        differ, so no read-to-network content relation is required here.
        """
        source_reads = [t for t in self.transfers if t.process.role == 'A' and t.operation == 'read'
                        and t.object_kind == 'file' and t.resource_role == 'source' and t.completeness == 'complete']
        writes = [t for t in self.transfers if t.process.role == 'A' and t.operation == 'write'
                  and t.resource_role in {'transfer', 'pipe'} and t.completeness == 'complete']
        reads = [t for t in self.transfers if t.process.role == 'B' and t.operation == 'read'
                 and t.resource_role in {'transfer', 'pipe'} and t.completeness == 'complete']
        write_by_id = {t.observation_id: t for t in writes}
        read_by_id = {t.observation_id: t for t in reads}
        supported = []
        ordered_source = False
        for relation in self.relations:
            if relation.relation_kind not in {'file_handoff_candidate', 'pipe_handoff_candidate'}:
                continue
            write = write_by_id.get(relation.left_id)
            read = read_by_id.get(relation.right_id)
            if not write or not read or write.object_kind != read.object_kind:
                continue
            if write.captured_bytes != write.completed_bytes or read.captured_bytes != read.completed_bytes:
                continue
            if write.completed_bytes != read.completed_bytes or write.content_sha256 != read.content_sha256:
                continue
            if write.object_kind == 'file':
                if write.first_offset is None or write.first_offset != read.first_offset or not write.resource_id or write.resource_id != read.resource_id:
                    continue
            elif not (write.connection_generation and read.connection_generation):
                continue
            if any('mapping_ambiguous' in limitation for limitation in relation.limitations):
                continue
            supported.append(relation.relation_id)
            ordered_source |= any(self._before(source, write) for source in source_reads)
        checks = {'a_source_read_observed': bool(source_reads), 'a_handoff_write_observed': bool(writes),
                  'b_handoff_read_observed': bool(reads), 'handoff_object_range_supported': bool(supported),
                  'source_read_before_handoff_observed': ordered_source}
        for name, passed in checks.items():
            if not passed:
                self.gap(name + '_missing')
        return {**checks, 'complete': all(checks.values()),
                'source_read_observation_ids': [t.observation_id for t in source_reads],
                'handoff_write_observation_ids': list(write_by_id),
                'handoff_read_observation_ids': list(read_by_id),
                'supported_relation_ids': supported, 'outbound_content_match_required': False,
                'byte_level_taint_proof': False, 'can_enforce': False}

    def finish(self):
        if self._finished:
            return self._result
        for key in list(self._states):
            self._finish_transfer(key, boundary=False)
        required = ('native-io:A', 'native-io:B', 'etw', 'ecapture')
        for name in required:
            state = self.session.health.setdefault(name, CollectorHealth())
            if not state.complete:
                self.gap(name.replace(':', '_') + '_health_incomplete')
        if not self.outbound:
            self.gap('no_outbound_body_observed')
        # Compare multisets, preserving duplicate attempts and receipts. Matching
        # counts are transport evidence, not an exact request-ID mapping.
        from collections import Counter
        captured = Counter((o.decoded_body_sha256, o.body_bytes) for o in self.outbound if o.completeness == 'complete' and o.provider == 'ecapture-windows' and o.capture_layer == 'tls')
        received = Counter((r['body_sha256'], r['body_bytes']) for r in self.receipts)
        origin_match = bool(captured) and captured == received
        if not origin_match:
            self.gap('origin_capture_multiplicity_not_verified')
        self._correlate()
        association_incomplete = (bool(self.gaps) or any(t.completeness != 'complete' for t in self.transfers)
                                  or any(o.completeness != 'complete' or o.detection_status == 'incomplete' for o in self.outbound))
        coverage = self._collection_coverage()
        # A shared registered fragment does not certify that a whole handoff
        # had matching object/range evidence. Do not hide such a candidate just
        # because a different handoff in the same run passed the coverage gate.
        supported = set(coverage['supported_relation_ids'])
        if any(r.relation_kind in {'file_handoff_candidate', 'pipe_handoff_candidate'} and r.relation_id not in supported
               for r in self.relations):
            self.gap('handoff_object_range_unverified')
            association_incomplete = True
        # Correlation itself may discover ambiguity after adding an earlier
        # edge. Final health must apply to every edge, not its insertion order.
        if association_incomplete:
            for relation in self.relations:
                relation.confidence = 'Unknown'
                relation.limitations = sorted(set(relation.limitations + ['association_evidence_incomplete']))
        self.session.status = 'partial' if self.gaps or any(t.completeness != 'complete' for t in self.transfers) or any(o.completeness != 'complete' or o.detection_status == 'incomplete' for o in self.outbound) else 'complete'
        self.session.limitations = list(self.gaps)
        result = {'schema_version': 'transpect.flow.report/1.0', 'session': self.session.model_dump(),
                  'system_behavior': {'events': self.native_events, 'transfers': [t.model_dump() for t in self.transfers]},
                  'collection_coverage': coverage,
                  'content_detection': {'outbound': [o.model_dump() for o in self.outbound]},
                  'propagation': {'relations': [r.model_dump() for r in self.relations], 'byte_level_taint_proof': False},
                  'origin_receipts': {'receipts': self.receipts, 'captured_count': sum(captured.values()), 'received_count': sum(received.values()),
                                      'hash_multiset_matches': origin_match, 'request_identity_mapping': 'unverified'},
                  'coverage_gaps': self.gaps, 'can_enforce': False, 'blocked_requests': 0,
                  'plaintext_exported': False, 'runtime_certification': 'not_automatically_granted'}
        self._result = result
        self._finished = True
        if self.directory:
            self.directory.mkdir(parents=True, exist_ok=True)
            (self.directory / 'flow-evidence.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return result
