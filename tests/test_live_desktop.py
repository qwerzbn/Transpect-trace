import json
from transpect_trace.desktop import project_session, watch_desktop, journal_session, explicit_parent
from transpect_trace.tree_export import tree_text
from transpect_trace.provenance import controlled_provenance


def test_desktop_partial_line_and_execution_handle(tmp_path):
    log = tmp_path / 'rollout-test.jsonl'
    rows = [dict(type='session_meta', payload=dict(id='test')),
            dict(type='response_item', payload=dict(type='function_call', name='exec', call_id='c', arguments='{}')),
            dict(type='response_item', payload=dict(type='function_call_output', call_id='c', output='source material')),
            dict(type='response_item', payload=dict(type='message', role='assistant', content=['paraphrase'])),
            dict(type='event_msg', payload=dict(type='item_completed', item=dict(type='CommandExecution', process_id='123')))]
    log.write_text(''.join(json.dumps(r) + '\n' for r in rows) + '{', encoding='utf-8')
    data = project_session(log)
    assert data['source']['parsed_lines'] == 5
    assert data['provenance']['records'][0]['sources'] == ['tool-result:c']
    assert data['events'][0]['execution_handle'] == '123'
    assert data['processes'] == []
    watch_desktop(tmp_path, tmp_path / 'out', once=True, sample_processes=False)
    assert (tmp_path / 'out/test/process-tree.txt').exists()


def test_rewrite_exposure_never_flows_backwards():
    def event(kind, time, rid=None):
        return dict(kind=kind, event_id=time, time=dict(wall=time), attributes={}, correlation=dict(request_id=rid))
    events = [event('client.tool.started', '1'), event('model.request', '2', 'r'),
              event('model.response.completed', '3', 'r'), event('client.tool.started', '4')]
    report = dict(edges=[dict(source='file:notes', target='request:r')])
    result = controlled_provenance(None, events, report)
    assert [r['evidence'] for r in result['records']] == ['3', '4']
    assert all(r['certainty'] == 'possible_dependency' for r in result['records'])


def test_tree_cycles_terminate():
    text = tree_text([dict(id='a', parent='b', label='A'), dict(id='b', parent='a', label='B')], 'tree')
    assert '[cycle]' in text


def test_journal_resume_partial_and_truncate(tmp_path):
    path, destination = tmp_path / 'rollout.jsonl', tmp_path / 'out'
    path.write_bytes(b'{"type":"one"}\n{"type":')
    journal_session(path, destination)
    journal_session(path, destination)
    assert len((destination / 'events.jsonl').read_text().splitlines()) == 1
    with path.open('ab') as handle:
        handle.write(b'"two"}\n')
    journal_session(path, destination)
    assert len((destination / 'events.jsonl').read_text().splitlines()) == 2
    path.write_bytes(b'{}\n')
    journal_session(path, destination)
    assert json.loads((destination / 'events.jsonl').read_text().splitlines()[-1])['generation'] == 1


def test_parent_requires_explicit_identity():
    assert explicit_parent(dict(source=dict(subagent=dict(thread_spawn=dict(parent_thread_id='parent'))))) == 'parent'
    assert explicit_parent(dict(pid=123, thread_name='child')) is None


def test_blocked_request_does_not_expose_model_context():
    rows = [dict(kind=kind, event_id=str(i), time=dict(wall=str(i)), attributes={}, correlation=dict(request_id='r'))
            for i, kind in enumerate(['model.request', 'model.request.blocked', 'client.tool.started'])]
    result = controlled_provenance(None, rows, dict(edges=[dict(source='file:notes', target='request:r')]))
    assert not result['records']


def test_selected_thread_includes_explicit_child(tmp_path):
    for identity, parent in [('parent', None), ('child', 'parent'), ('other', None)]:
        meta = dict(id=identity)
        if parent:
            meta['source'] = dict(subagent=dict(parent_thread_id=parent))
        (tmp_path / f'rollout-{identity}.jsonl').write_text(json.dumps(dict(type='session_meta', payload=meta)) + '\n')
    output = tmp_path / 'out'
    watch_desktop(tmp_path, output, thread='parent', once=True, sample_processes=False)
    assert (output / 'child/agent-tree.json').exists()
    assert not (output / 'other').exists()
    child = json.loads((output / 'child/agent-tree.json').read_text(encoding='utf-8'))
    assert child['nodes'][0]['parent'] == 'agent:parent'


def test_export_commit_status(tmp_path):
    from transpect_trace.tree_export import export_data
    export_data(dict(manifest=dict(run_id='test', status='complete')), tmp_path)
    status = json.loads((tmp_path / 'status.json').read_text())
    trace = json.loads((tmp_path / 'trace.json').read_text())
    assert status['phase'] == 'ready'
    assert status['revision'] == trace['revision']


def test_live_changes_refresh_and_unchanged_skips(tmp_path, monkeypatch):
    from transpect_trace import live
    (tmp_path / 'raw').mkdir()
    raw = tmp_path / 'raw/source.jsonl'
    raw.write_text('{}\n')
    monkeypatch.setattr(live, 'normalize_run', lambda root, write: [])
    monkeypatch.setattr(live, 'project_report', lambda root, event_rows: dict(manifest=dict(run_id='test', status='running')))
    writer = live.RunLiveWriter(tmp_path)
    writer.update()
    writer.update()
    assert writer.revision == 1
    raw.write_text('{}\n{}\n')
    writer.update()
    assert writer.revision == 2
    assert not (tmp_path / 'normalized').exists()
