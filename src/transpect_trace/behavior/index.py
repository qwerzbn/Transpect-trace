"""Conservative event attribution using process lifetimes, never bare PID joins."""
from __future__ import annotations

import ipaddress
import ntpath
from uuid import NAMESPACE_URL, uuid5

from transpect_trace.guard.etw import PROCESS, FILE, NETWORK, canonical_path, number
from transpect_trace.guard.evidence import evidence_dict
from .models import BehaviorEvent, ProcessIdentity


class BehaviorIndex:
    def __init__(self, root: ProcessIdentity, run_id: str, *, limit=100_000, resolver=None):
        self.root, self.run_id, self.limit, self.resolver = root, run_id, limit, resolver
        self.generations = {root.key: dict(subject=root, parent=None, start=0, end=None)}
        self.events = []
        self.files = {}
        self.clock = None
        self.gaps = set()
        self.ready = False
        self.terminal = False
        self.unavailable = False
        self.lost = 0
        self.decoder_fields = {}
        self._emit("process.snapshot", root, 0, "win32_process_identity")

    def _emit(self, kind, subject, tick, method, **values):
        if len(self.events) >= self.limit:
            self.gaps.add("event_capacity_exceeded")
            return None
        row = BehaviorEvent(run_id=self.run_id,
            event_id=str(uuid5(NAMESPACE_URL, f"{self.run_id}:{len(self.events)}:{subject.key}:{tick}")),
            kind=kind, subject=subject, timestamp_qpc=max(0, tick), evidence_method=method, **values)
        self.events.append(row)
        return row

    def at(self, pid, tick):
        matches = [g for g in self.generations.values() if g['subject'].pid == pid
                   and g['start'] <= tick and (g['end'] is None or tick < g['end'])]
        return matches[0] if len(matches) == 1 else None

    def health(self):
        state = "unavailable" if self.unavailable else "unknown" if not self.ready else "degraded" if self.gaps or self.lost else "stopped" if self.terminal else "ready"
        return dict(state=state, ready_observed=self.ready, terminal_observed=self.terminal,
                    events_lost=self.lost, gaps=sorted(self.gaps), can_enforce=False)

    def eof(self, exit_code):
        if not self.terminal and not self.unavailable:
            self.gaps.add("collector_exit_without_terminal")
        if exit_code and not self.unavailable:
            self.gaps.add("collector_nonzero_exit")

    def consume(self, row):
        kind = row.get('kind')
        if kind == 'etw.ready':
            self.ready = True
            self.clock = row
            return None
        if kind == 'etw.unavailable':
            self.unavailable = True
            self.gaps.add('etw_unavailable')
            return None
        if kind == 'etw.stopped':
            self.terminal = True
            self.lost += sum(max(0, number(row.get(k))) for k in ('events_lost', 'buffers_lost', 'decode_errors'))
            if number(row.get('status')) not in (0,):
                self.gaps.add('etw_terminal_error')
            if row.get('counters_verified') is not True:
                self.gaps.add('terminal_counters_not_verified')
            return None
        if kind != 'etw.event':
            return None
        props = row.get('properties', {})
        provider = str(row.get('provider', '')).strip('{}').lower()
        pid = number(props.get('ProcessID', props.get('ProcessId', props.get('PID', row.get('header_pid')))))
        tick = number(row.get('timestamp_qpc'))
        task, opcode = str(row.get('task', '')).lower(), number(row.get('opcode'))
        if tick <= 0:
            return None
        generation = self.at(pid, tick)
        if provider == PROCESS and ('process' in task or not task):
            birth = number(props.get('CreateTime'))
            if opcode in (1, 3):
                if not birth:
                    # A new lifetime without a creation time cannot inherit a
                    # previously observed PID, even when its parent is unknown.
                    if generation:
                        generation['end'] = tick
                        self.gaps.add('process_identity_invalidated')
                    if generation or self.at(number(props.get('ParentProcessID', props.get('ParentProcessId'))), tick):
                        self.gaps.add('child_creation_time_missing')
                    return None
                parent = self.at(number(props.get('ParentProcessID', props.get('ParentProcessId'))), tick)
                if not parent and not (pid == self.root.pid and birth == self.root.creation_filetime):
                    # A new unrelated generation invalidates the old PID from this point.
                    if generation and birth and birth != generation['subject'].creation_filetime:
                        generation['end'] = tick
                    return None
                if not birth:
                    self.gaps.add('child_creation_time_missing')
                    return None
                if parent and birth < parent['subject'].creation_filetime:
                    self.gaps.add('parent_lifetime_mismatch')
                    return None
                subject = ProcessIdentity(pid=pid, creation_filetime=birth)
                name=props.get('ImageName',props.get('ImageFileName'))
                if isinstance(name,str):subject.image_name=ntpath.basename(name)[:260]
                if subject.key == self.root.key:
                    subject = self.root
                elif self.resolver:
                    try:
                        observed = self.resolver(pid)
                        if observed['creation_filetime'] == birth:
                            subject.image_sha256 = observed.get('image_sha256')
                            subject.image_name = ntpath.basename(observed.get('image_path',''))[:260] or subject.image_name
                    except (OSError, ValueError, RuntimeError):
                        pass  # A short-lived process may already be gone; hash stays unknown.
                if generation and generation['subject'].key != subject.key:
                    generation['end'] = tick
                if subject.key in self.generations:
                    return None  # Rundown/snapshot is not another process launch.
                if len(self.generations) >= self.limit:
                    self.gaps.add('process_capacity_exceeded')
                    return None
                self.generations[subject.key] = dict(subject=subject, parent=parent['subject'].key if parent else None, start=tick, end=None)
                return self._emit('process.start', subject, tick, 'etw_process_start_with_creation_time',
                                  parent_identity=parent['subject'].key if parent else None, provider=provider, opcode=opcode)
            if opcode in (2, 4) and generation:
                if birth and birth != generation['subject'].creation_filetime:
                    self.gaps.add('stale_process_exit')
                    return None
                generation['end'] = tick
                return self._emit('process.exit', generation['subject'], tick, 'etw_process_exit', provider=provider, opcode=opcode)
            return None
        if not generation:
            return None
        subject = generation['subject']
        # Schema diagnostics only, never values. Useful when TDH property names
        # differ across Windows builds; scoped events only, bounded cardinality.
        label = f'{provider}:{task}:{opcode}'
        if label in self.decoder_fields or len(self.decoder_fields) < 256:
            self.decoder_fields[label] = sorted(set(self.decoder_fields.get(label, [])) | set(props))[:64]
        common = dict(parent_identity=generation['parent'], provider=provider, opcode=opcode)
        if provider == FILE:
            # Do not guess a subject from a recycled thread ID. Missing process attribution
            # remains a gap; file-object names are scoped to a process generation.
            key = (subject.key, str(props.get('FileObject', props.get('FileKey', ''))))
            path = props.get('FileName', props.get('FilePath', props.get('OpenPath')))
            if task in ('create', 'createnewfile'):
                # Object addresses can be reused even when a close/name event
                # was missing. A new open must never inherit an old path.
                self.files.pop(key, None)
            if isinstance(path, str) and len(path) <= 32768 and key[1] and task in ('create','createnewfile','read','write'):
                if len(self.files) < self.limit:
                    self.files[key] = canonical_path(path)
                else:
                    self.gaps.add('file_map_capacity_exceeded')
            path = self.files.get(key)
            kind = 'file.read' if 'read' in task else 'file.write' if 'write' in task else 'file.access'
            # Provider-specific opcode 67 is not assumed to mean a successful read.
            result = self._emit(kind, subject, tick, 'etw_file_metadata', path=path,
                                reported_size=max(0, number(props.get('IOSize',props.get('IoSize')))) if 'IoSize' in props or 'IOSize' in props else None,
                                limitations=['File operation observed; completion and bytes returned unknown'], **common)
            if 'close' in task or 'cleanup' in task:
                self.files.pop(key, None)
            return result
        if provider == NETWORK:
            destination = props.get('daddr')
            try:
                destination = str(ipaddress.ip_address(str(destination)))
            except ValueError:
                destination = None
            port = number(props.get('dport'), -1)
            return self._emit('network.activity', subject, tick, 'etw_network_metadata',
                destination_address=destination, destination_port=port if 0 <= port <= 65535 else None,
                protocol='tcp' if 'tcp' in task else 'udp' if 'udp' in task else 'unknown',
                reported_size=max(0, number(props.get('size'))) if 'size' in props else None,
                limitations=['No payload inspection or LLM classification; opcode retained without send-success inference'], **common)
        return None

    def lineage(self, key):
        result, seen = [], set()
        while key in self.generations and key not in seen:
            seen.add(key)
            result.append(key)
            if key == self.root.key:
                return list(reversed(result))
            key = self.generations[key]['parent']
        return []

    def correlate(self, decision):
        # Explicit run binding is supplied by the caller after verifying audit PID/birth.
        tick = number(decision.get('captured_qpc'))
        matched = {canonical_path(p) for p in decision.get('candidate_source_paths', []) if isinstance(p, str)}
        reads = [e for e in self.events if e.kind == 'file.read' and e.path and 0 < e.timestamp_qpc <= tick]
        if matched:
            reads = [e for e in reads if canonical_path(e.path) in matched]
        else:
            freq = number(decision.get('qpc_frequency'))
            reads = [e for e in reads if freq > 0 and tick - e.timestamp_qpc <= 5 * freq]
        starts = [e.event_id for e in self.events if e.kind in ('process.start', 'process.snapshot')
                  and any(e.subject.key in self.lineage(r.subject.key) for r in reads)]
        healthy = self.health()['state'] in ('ready', 'stopped')
        relation = evidence_dict(paths=[e.path for e in reads], file_event_ids=[e.event_id for e in reads],
            process_event_ids=starts, content_event_ids=[decision['request_id']] if matched else [],
            reliable_identity=healthy and bool(reads), time_related=bool(reads), dropped_events=self.lost + len(self.gaps),
            snapshot_current=not any(e.kind == 'file.write' and e.path in {r.path for r in reads} for e in self.events))
        if not healthy:
            relation['confidence'] = 'Unknown'
        return dict(request_id=decision['request_id'], run_id=self.run_id, source_relation=relation,
                    relation_kind='content_and_access_candidate' if matched else 'temporal_candidate',
                    limitations=['No proof that candidate file bytes were transmitted'])
