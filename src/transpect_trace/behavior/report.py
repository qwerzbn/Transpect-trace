"""Policy recommendation and actual execution are intentionally separate."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from .index import BehaviorIndex
from .models import BehaviorEvent, EgressRule, ProcessIdentity


def evaluate_egress(event: BehaviorEvent, rules: list[EgressRule]):
    matches = [r.rule_id for r in rules if event.kind == 'network.activity'
        and event.subject.image_sha256 == r.image_sha256 and event.destination_address == r.destination_address
        and event.destination_port == r.destination_port and event.protocol == r.protocol]
    block = any(r.rule_id in matches and r.action == 'recommend_block' for r in rules)
    return dict(event_id=event.event_id, decision='recommend_block' if block else 'audit',
                matched_rule_ids=matches, actual_action='none', can_enforce=False,
                payload_classification='unknown', llm_classification='unknown',
                limitations=['Destination policy only; file access is not a deny condition',
                             'Reactive ETW observation does not prevent an already initiated connection'])


def _valid_clock(clock: object) -> dict | None:
    if not isinstance(clock, dict):
        return None
    keys = ('qpc_frequency', 'clock_qpc', 'clock_filetime')
    if any(not isinstance(clock.get(key), int) or clock[key] <= 0 for key in keys):
        return None
    return {key: clock[key] for key in keys}


def _wall_time(tick: int, clock: dict | None) -> str | None:
    if not clock or tick <= 0:
        return None
    # Windows FILETIME uses 100 ns intervals since 1601-01-01 UTC.
    filetime = clock['clock_filetime'] + (tick - clock['clock_qpc']) * 10_000_000 // clock['qpc_frequency']
    unix_ns = (filetime - 116_444_736_000_000_000) * 100
    seconds, nanoseconds = divmod(unix_ns, 1_000_000_000)
    try:
        instant = datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(microseconds=nanoseconds // 1000)
    except (OverflowError, OSError, ValueError):
        return None
    return instant.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _timeline(index: BehaviorIndex, clock: dict | None) -> list[dict]:
    result = []
    for event in sorted(index.events, key=lambda row: (row.timestamp_qpc, row.event_id)):
        row = dict(event_id=event.event_id, kind=event.kind,
                   timestamp_qpc=event.timestamp_qpc,
                   subject_identity=event.subject.key,
                   lineage=index.lineage(event.subject.key),
                   evidence_method=event.evidence_method)
        wall = _wall_time(event.timestamp_qpc, clock)
        if wall is not None:
            row['timestamp_utc'] = wall
        for key in ('parent_identity', 'path', 'destination_address', 'destination_port',
                    'protocol', 'reported_size', 'provider', 'opcode'):
            value = getattr(event, key)
            if value is not None and not (key == 'protocol' and value == 'unknown'):
                row[key] = value
        result.append(row)
    return result


def build_report(directory: Path, *, guard_directory: Path | None = None, rules=()):
    status = json.loads((directory / 'status.json').read_text(encoding='utf-8'))
    channel = status.get('channel', 'cli')
    if channel == 'desktop' and guard_directory is not None:
        raise ValueError('Desktop ETW observation cannot bind an unvalidated Guard audit')
    clock = _valid_clock(status.get('clock'))
    index = BehaviorIndex(ProcessIdentity.model_validate(status['root']), status['run_id'])
    index.events = [BehaviorEvent.model_validate_json(line) for line in (directory / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
    for event in index.events:
        if event.kind == 'process.start':
            index.generations[event.subject.key] = dict(subject=event.subject, parent=event.parent_identity, start=event.timestamp_qpc, end=None)
    health = status['health']
    index.ready, index.terminal = health['ready_observed'], health['terminal_observed']
    index.unavailable = health['state'] == 'unavailable'
    index.gaps.update(health['gaps']); index.lost = health['events_lost']
    if not index.terminal and not index.unavailable:
        # This offline reader cannot attest a collector from a saved ready row.
        index.gaps.add('terminal_health_not_confirmed')
    if channel == 'desktop' and clock is None and not index.unavailable:
        index.gaps.add('clock_anchor_unavailable')
    health = index.health()
    decisions, associations, outcomes, binding = [], [], [], 'no_guard_audit'
    request_semantics=[];egress_execution=[]
    if guard_directory:
        # Verify controller-recorded birth and image identity. PID or matching hash alone
        # never binds an audit to a running instance.
        guard = json.loads((guard_directory / 'status.json').read_text(encoding='utf-8'))
        subject = guard['identity']
        if (subject['pid'], subject['creation_filetime'], subject['baseline']['sha256']) != (index.root.pid, index.root.creation_filetime, index.root.image_sha256):
            raise ValueError('Guard/behavior run identity mismatch')
        binding = 'same_verified_process_lifetime'
        for line in (guard_directory / 'audit.jsonl').read_text(encoding='utf-8').splitlines():
            row = json.loads(line)
            if row.get('kind') == 'policy.decision':
                decisions.append({k: row[k] for k in ('request_id', 'decision', 'action', 'policy_version', 'captured_qpc', 'captured_at_unix_ns') if k in row})
                associations.append(index.correlate(row))
            elif row.get('kind') == 'native.outcome':
                outcomes.append({k:row[k] for k in ('request_id','native_event_id','action','action_execution','captured_qpc') if k in row})
        capture_path=guard_directory/'capture/request-semantics.jsonl'
        if capture_path.is_file():
            from transpect_trace.observe.semantics import RequestSemantics
            request_semantics=[RequestSemantics.model_validate_json(line).model_dump() for line in capture_path.read_text(encoding='utf-8').splitlines()]
        egress_path=guard_directory/'egress/egress-audit.jsonl'
        if egress_path.is_file():
            egress_status=json.loads((egress_path.parent/'egress-status.json').read_text(encoding='utf-8'))
            roots=[m for m in egress_status.get('members',[]) if m.get('root')]
            if len(roots)!=1 or (roots[0].get('pid'),roots[0].get('creation_filetime'),roots[0].get('image_sha256'))!=(index.root.pid,index.root.creation_filetime,index.root.image_sha256):
                raise ValueError('Native egress/behavior run identity mismatch')
            for line in egress_path.read_text(encoding='utf-8').splitlines():
                event=json.loads(line)
                if event.get('kind') not in {'process.register','process.enroll','process.ready','process.held','connection.decision','connection.rejected'}:continue
                # Metadata projection only; never copy arbitrary execution input.
                record={k:event[k] for k in ('kind','run_id','timestamp_unix_ns','pid','creation_filetime','attempt_id','destination_address',
                    'destination_port','protocol','decision','execution','native_result','winsock_error','evidence') if k in event}
                subject=event.get('subject')
                if isinstance(subject,dict):record['subject']={k:subject[k] for k in ('pid','creation_filetime','parent_identity','image_sha256','root','ready') if k in subject}
                record['tool_call_mapping']='unknown_no_direct_runtime_mapping'
                egress_execution.append(record)
    networks = [e for e in index.events if e.kind == 'network.activity']
    file_reads = [e for e in index.events if e.kind == 'file.read']
    report = dict(schema='transpect.codex.behavior.report/1.0', run_id=index.run_id, health=health,
        channel=channel, clock=clock, behavior_timeline=_timeline(index, clock),
        llm_audit_binding=binding, llm_decisions=decisions, source_relations=associations,
        native_outcomes=outcomes,
        request_semantics=request_semantics,tool_egress_execution=egress_execution,
        tool_execution_mapping=('unvalidated_no_native_audit' if channel=='desktop'
                                else 'candidate_unless_explicit_runtime_mapping'),
        file_coverage=dict(read_events=len(file_reads),reads_with_path=sum(bool(e.path) for e in file_reads),
                           unresolved_paths=sum(not e.path for e in file_reads),read_completion='not_verified'),
        process_lineage=[dict(identity=k, parent=g['parent'], chain=index.lineage(k)) for k, g in index.generations.items()],
        network_observations=[dict(event=e.model_dump(), lineage=index.lineage(e.subject.key),
                                   policy=evaluate_egress(e, list(rules))) for e in networks],
        gaps=sorted(index.gaps), can_enforce=False, byte_level_taint_proof=False,
        limitations=['Behavior report is not an execution receipt', 'LLM gate and egress filter require independent validation',
                     'No inference of transmitted file contents from temporal adjacency', 'Child hash may be unknown after rapid exit'])
    if channel == 'desktop':
        report.update(model_egress_status='MODEL_EGRESS_NOT_COVERED',
                      agent_tool_egress_covered=False, model_request_mapping='unvalidated')
        report['limitations'].append('No verified desktop model-request or tool-call mapping')
    return report
