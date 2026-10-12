"""Conservative exposure labels, not proof of semantic dependence."""
from collections import defaultdict


def controlled_provenance(bundle, events, report):
    seeds, exposed, requests = defaultdict(set), defaultdict(set), {}
    records = []
    sessions = {}
    for edge in report['edges']:
        if edge['source'].startswith('file:') and edge['target'].startswith('request:'):
            seeds[edge['target']].add(edge['source'])
    for e in sorted(events, key=lambda e: e['time']['wall']):
        kind, a = e['kind'], e['attributes']
        agent = a.get('agent_id') or 'main'
        target, method, sources = None, None, set()
        if kind == 'client.session.started':
            session = e['correlation'].get('session_id')
            if agent in sessions and sessions[agent] != session:
                exposed[agent].clear()
            sessions[agent] = session
        elif kind == 'model.request':
            rid = e['correlation'].get('request_id')
            requests[rid] = (agent, set(exposed[agent]) | seeds['request:' + str(rid)])
        elif kind == 'model.response.started':
            owner, sources = requests.get(e['correlation'].get('request_id'), (agent, set()))
            exposed[owner].update(sources)
        elif kind == 'model.response.completed':
            rid = e['correlation'].get('request_id')
            owner, sources = requests.get(rid, (agent, set()))
            exposed[owner].update(sources)
            target, method = 'model-output:' + str(rid), 'request_context_exposure'
        elif kind == 'demo.agent.started':
            exposed[agent].update(exposed['main'])
            target, sources, method = 'agent:' + agent, exposed[agent], 'parent_exposure_at_spawn'
        elif kind == 'demo.agent.completed':
            exposed['main'].update(exposed[agent])
            target, sources, method = 'agent:main', exposed[agent], 'explicit_child_return_exposure'
        elif kind.startswith('client.tool.'):
            target = 'tool:' + agent + ':' + str(e['correlation'].get('tool_call_id') or e['event_id'])
            sources, method = exposed[agent], 'agent_exposure_at_tool_call'
        elif kind in {'demo.tool.received', 'demo.sink.received'}:
            target, sources, method = 'receipt:' + a['invocation_id'], exposed[agent], 'agent_exposure_at_receipt'
        elif kind == 'system.file.write' and isinstance(a.get('result'), int) and a['result'] > 0:
            path = e.get('operation', {}).get('target') or ''
            if path.startswith('/workspace/') and a.get('process_scope', 'agent') == 'agent':
                pid = e['correlation'].get('pid')
                process = next((p for p in report.get('processes', []) if p.get('pid') == pid and p.get('scope') == 'agent'), {})
                owner = process.get('agent_id', 'agent:main').removeprefix('agent:')
                target, sources, method = 'file:' + path[len('/workspace/'):], exposed[owner], 'agent_exposure_at_workspace_write'
        if target and sources:
            records.append(dict(target=target, sources=sorted(sources), evidence=e['event_id'], time=e['time']['wall'],
                                method=method, certainty='possible_dependency'))
    return dict(schema='transpect.provenance/1.0', records=records,
                policy='Per-agent context exposure accumulates; possible dependency does not prove semantic origin or transmission.',
                limitations=['Context truncation may cause over-attribution.', 'Tool labels use temporal exposure, not verified output call IDs.',
                             'Write labels are agent exposure candidates; exact file versions and encoding transformations are not attributed.'])
