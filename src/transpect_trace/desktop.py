"""Read-only Codex rollout listener. Log evidence is not kernel evidence."""
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from transpect_trace.tree_export import export_data
from transpect_trace.core.storage import atomic_write


def explicit_parent(meta):
    """Only explicit parent identities, never proximity or process IDs."""
    if isinstance(meta, dict):
        for key in ('parent_thread_id', 'parent_session_id'):
            if isinstance(meta.get(key), str):
                return meta[key]
        for value in meta.values():
            parent = explicit_parent(value)
            if parent:
                return parent
    return None


def discover_session(path):
    with path.open('rb') as handle:
        for _ in range(20):
            line = handle.readline()
            if not line:
                break
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get('type') == 'session_meta':
                meta = row['payload']
                return dict(id=meta.get('id') or meta.get('session_id') or path.stem, parent=explicit_parent(meta))
    return dict(id=path.stem, parent=None)


def process_snapshot():
    if os.name != 'nt':
        return []
    command = "Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,CreationDate | ConvertTo-Json -Compress"
    result = subprocess.run(['powershell', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Windows process sampling failed')
    rows = json.loads(result.stdout or '[]')
    rows = rows if isinstance(rows, list) else [rows]
    selected = {r['ProcessId'] for r in rows if r['Name'].lower() == 'codex.exe'}
    excluded = {os.getpid()}
    for _ in range(len(rows)):
        before = (len(selected), len(excluded))
        for r in rows:
            if r['ParentProcessId'] in selected:
                selected.add(r['ProcessId'])
            if r['ParentProcessId'] in excluded:
                excluded.add(r['ProcessId'])
        if before == (len(selected), len(excluded)):
            break
    rows = [r for r in rows if r['ProcessId'] in selected - excluded]
    ids = {r['ProcessId']: f"process:desktop:{r['ProcessId']}:{r['CreationDate']}" for r in rows}
    return [dict(id=ids[r['ProcessId']], parent=ids.get(r['ParentProcessId']), pid=r['ProcessId'],
                 label=f"{r['Name']} · PID {r['ProcessId']}", scope='desktop_shared_codex',
                 attribution='thread_unknown', method='windows_process_snapshot') for r in rows]


def project_session(path, processes=None):
    rows = []
    with path.open('rb') as handle:
        for ordinal, line in enumerate(handle, 1):
            if not line.endswith(b'\n'):
                break
            try:
                row = json.loads(line)
            except ValueError:
                rows.append(dict(type='parse_error', ordinal=ordinal))
                continue
            row['ordinal'] = ordinal
            rows.append(row)
    meta = next((r['payload'] for r in rows if r.get('type') == 'session_meta'), {})
    thread = meta.get('id') or meta.get('session_id') or path.stem
    agent_id = 'agent:' + thread
    tools, records, exposure, events = {}, [], set(), []
    for row in rows:
        p = row.get('payload', {})
        evidence = f"{path.name}:{row['ordinal']}"
        kind = p.get('type')
        if row.get('type') == 'response_item' and kind in {'function_call', 'custom_tool_call'}:
            call = p.get('call_id') or p.get('id') or evidence
            key = 'tool:' + thread + ':' + call
            tools[call] = dict(id=key, agent_id=thread, label=(p.get('namespace', '') + '.' + p.get('name', '')).strip('.'),
                               time=row.get('timestamp'), evidence=evidence, state='started',
                               input=p.get('arguments', p.get('input')))
            if exposure:
                records.append(dict(target=key, sources=sorted(exposure), evidence=evidence, certainty='possible_dependency',
                                    method='prior_tool_result_exposure'))
        elif row.get('type') == 'response_item' and kind in {'function_call_output', 'custom_tool_call_output'}:
            call = p.get('call_id')
            if call in tools:
                tools[call]['state'] = 'returned'
                tools[call]['return_evidence'] = evidence
            source = 'tool-result:' + str(call or evidence)
            exposure.add(source)
        elif row.get('type') == 'response_item' and kind == 'message' and p.get('role') == 'assistant' and exposure:
            records.append(dict(target='message:' + evidence, sources=sorted(exposure), evidence=evidence,
                                certainty='possible_dependency', method='prior_tool_result_exposure'))
        elif row.get('type') == 'event_msg' and kind == 'item_completed':
            item = p.get('item', {})
            if item.get('type') == 'CommandExecution':
                # This is an execution handle, never an OS PID.
                events.append(dict(kind='command_execution', evidence=evidence, execution_handle=item.get('process_id'),
                                   command=item.get('command'), exit_code=item.get('exit_code'), status=item.get('status')))
    coverage = dict(mode='desktop_log', file_reads='not_observed', upstream_delivery='not_observed',
                    process_tree='shared_codex_polling_no_thread_attribution', native_subagents='explicit_parent_metadata_only',
                    rewrite_tracking='possible_tool_result_dependency')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(schema='transpect.report/1.0', revision=f"{len(rows)}:{digest[:12]}",
                manifest=dict(run_id=thread, status='observing'), coverage=coverage,
                agents=[dict(id=agent_id, label='Codex Thread · ' + thread,
                             parent=('agent:' + explicit_parent(meta)) if explicit_parent(meta) else None, thread_id=thread)],
                tools=list(tools.values()), processes=processes or [], nodes=[], edges=[], events=events,
                source=dict(path=str(path.resolve()), parsed_lines=len(rows), sha256_at_projection=digest),
                provenance=dict(records=records, policy='All previous tool results are conservatively possible sources; semantic origin is unproven.'),
                limits=['日志不证明文件真实读取或模型服务接收。', '进程轮询可能漏掉短命进程；系统进程与 Thread 未关联。',
                        '改写标签是可能依赖，不是逐字节污点证明；原生 subagent 跨 Thread 关联尚未实现。'])


def journal_session(path, destination):
    """Append complete source log records with stable line identities; resume after restart."""
    state_path = destination / 'cursor.json'
    state = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else dict(offset=0, line=0, generation=0)
    if path.stat().st_size < state['offset']:
        state = dict(offset=0, line=0, generation=state['generation'] + 1)
    destination.mkdir(parents=True, exist_ok=True)
    with path.open('rb') as source, (destination / 'events.jsonl').open('ab') as target:
        source.seek(state['offset'])
        while True:
            line = source.readline()
            if not line or not line.endswith(b'\n'):
                break
            state['line'] += 1
            state['offset'] = source.tell()
            try:
                payload = json.loads(line)
            except ValueError:
                payload = dict(type='parse_error', raw=line.decode('utf-8', errors='replace'))
            target.write((json.dumps(dict(source=str(path), generation=state['generation'], line=state['line'], record=payload), ensure_ascii=False) + '\n').encode())
    atomic_write(state_path, json.dumps(state).encode())


def watch_desktop(sessions: Path, output: Path, thread=None, interval=3, once=False, sample_processes=True):
    fingerprints = {}
    started = time.time()
    projections = {}
    registry = {}
    observed_processes = {}
    history_path = output / 'process-tree.json'
    if history_path.exists():
        observed_processes = {p['id']: p for p in json.loads(history_path.read_text(encoding='utf-8')).get('nodes', [])}
    while True:
        try:
            processes = process_snapshot() if sample_processes else []
        except Exception as error:
            atomic_write(output / 'process-sampler-error.json', json.dumps(dict(error=str(error))).encode())
            processes = []
        observed_at = time.time()
        active = {p['id'] for p in processes}
        for process in processes:
            previous = observed_processes.get(process['id'], {})
            observed_processes[process['id']] = dict(process, first_observed=previous.get('first_observed', observed_at),
                                                     last_observed=observed_at, currently_observed=True)
        for key, process in observed_processes.items():
            process['currently_observed'] = key in active
        processes = list(observed_processes.values())
        paths = sorted(sessions.rglob('rollout-*.jsonl'))
        for path in paths:
            if path not in registry:
                registry[path] = discover_session(path)
        allowed = {thread} if thread else set()
        for _ in range(len(registry)):
            before = len(allowed)
            for identity in registry.values():
                if identity['parent'] in allowed:
                    allowed.add(identity['id'])
            if len(allowed) == before:
                break
        for path in paths:
            if thread and registry[path]['id'] not in allowed:
                continue
            stat = path.stat()
            if not thread and not once and stat.st_mtime < started and path not in fingerprints:
                continue
            fingerprint = (stat.st_size, stat.st_mtime_ns)
            if fingerprints.get(path) == fingerprint:
                continue
            data = project_session(path, processes)
            destination = output / data['manifest']['run_id']
            journal_session(path, destination)
            export_data(data, destination)
            projections[path] = data
            fingerprints[path] = fingerprint
        if projections:
            export_data(dict(manifest=dict(run_id='desktop', status='observing'), revision=time.time_ns(),
                             coverage=dict(mode='desktop_log', file_reads='not_observed', upstream_delivery='not_observed',
                                           process_tree='shared_codex_polling_no_thread_attribution',
                                           native_subagents='explicit_parent_metadata_only'),
                             agents=[a for d in projections.values() for a in d['agents']],
                             tools=[t for d in projections.values() for t in d['tools']], processes=processes), output)
        if once:
            return
        time.sleep(interval)
