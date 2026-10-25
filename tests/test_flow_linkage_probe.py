"""Qualification regressions with report doubles, not real capture certification."""
import copy
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
from types import SimpleNamespace
import threading

import pytest


@pytest.fixture
def probe(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    import probe_flow_linkage
    return probe_flow_linkage


def reports(probe, mode):
    spec = probe.LinkageExperiment(mode) if mode in probe.MODES else None
    rounds, attempts = (spec.rounds, spec.attempts) if spec else (1, 1)
    expected = rounds * attempts
    complete = spec is None or spec.expects_complete
    state = 'complete' if complete else 'partial'
    gaps = [] if complete else ['qualification_evidence_gap']
    flow_gaps = list(gaps)
    if mode in ('reconnect_unique', 'duplicate_message', 'conflicting_message'):
        flow_gaps.append('pipe_connection_mapping_ambiguous')
    if mode in ('duplicate_message', 'conflicting_message'):
        gaps.append('message_identifier_missing_or_ambiguous')
    if mode == 'duplicate_attempt':
        gaps.append('duplicate_protocol_attempt_identifier')
    subjects = [dict(role=role, pid=pid, creation_filetime=1000+pid, image_sha256='a'*64)
                for role, pid in [('A', 11), ('B', 12)]]
    health = {name: dict(ready=True, terminal=True, identity_verified=True,
                        lost_events=0, errors=0, limitations=[])
              for name in ('native-io:A', 'native-io:B', 'etw', 'ecapture')}
    receipt = dict(body_sha256='b'*64, body_bytes=140000, evidence_source='controlled_origin')
    tls = dict(provider='ecapture-windows', capture_layer='tls', completeness='complete',
               encoding_state='identity', send_evidence='encryption_input_observed',
               decoded_body_sha256=receipt['body_sha256'], body_bytes=receipt['body_bytes'])
    flow = dict(session=dict(status=state, health=health),
                content_detection=dict(outbound=[] if mode == 'ecapture_exit' else [copy.deepcopy(tls) for _ in range(expected)]),
                origin_receipts=dict(receipts=[copy.deepcopy(receipt) for _ in range(expected)],
                                     hash_multiset_matches=mode != 'ecapture_exit'),
                propagation=dict(relations=[dict(confidence='Medium' if complete else 'Unknown')]),
                coverage_gaps=flow_gaps, can_enforce=False, blocked_requests=0)
    findings = [dict(registration_id=probe.REGISTRATION, data_types=['registered_text'])]
    rows = [dict(stage='source_read')]
    rows += [dict(stage=stage) for stage in ('message_write', 'message_read') for _ in range(rounds)]
    for i in range(0 if mode == 'ecapture_exit' else expected):
        public = mode == 'concurrent_public' or mode == 'conflicting_message' and i == 1
        rows.append(dict(stage='outbound', detection_status='no_match' if public else 'matched',
                         findings=[] if public else copy.deepcopy(findings)))
    agent = dict(session=dict(status=state), observations=rows, coverage_gaps=gaps,
                 relations=[dict(confidence='Medium' if complete else 'Unknown')],
                 can_enforce=False, blocked_requests=0)
    runtime = dict(state=state, subjects=subjects, can_enforce=False, client_send_completed=True,
                   fixture_exit_codes=dict(A=0, B=0), etw_event_count=9, etw_coverage=dict(gaps=[]),
                   coverage_gaps=gaps, gaps=gaps, origin_response_statuses=[503, 200])
    metadata = []
    if mode in probe.FAULTS:
        runtime['fault_injection'] = dict(phase='http_body_prefix_sent',
            observed_tls_send_bytes_at_stop=66000, origin_receipts_at_stop=0)
        metadata = [dict(provider='ecapture-windows', capture_point='tls', direction='send',
                         event='data', truncated=False, lost_events=0, captured_bytes=66000,
                         data_sha256='c'*64, sequence=1, **subjects[1])]
    return runtime, flow, agent, metadata


def evaluate(probe, folder, mode, values):
    runtime, flow, agent, metadata = values
    folder.mkdir(exist_ok=True)
    (folder / 'flow-evidence.json').write_text(json.dumps(flow), encoding='utf-8')
    (folder / 'agent-evidence.json').write_text(json.dumps(agent), encoding='utf-8')
    if metadata is not None:
        (folder / 'observe').mkdir(exist_ok=True)
        (folder / 'observe/capture-metadata.jsonl').write_text(
            ''.join(json.dumps(row)+'\n' for row in metadata), encoding='utf-8')
    return probe.assess(mode, runtime, folder)


@pytest.mark.parametrize('mode', ['repeated_sends', 'retry_after_503', 'reconnect_unique',
    'duplicate_message', 'conflicting_message', 'duplicate_attempt', 'ecapture_exit',
    'etw_exit', 'native_io_stop', 'concurrent', 'concurrent_public'])
def test_complete_and_expected_degradation_are_separate_results(tmp_path, probe, mode):
    values = reports(probe, mode)
    result = evaluate(probe, tmp_path, mode, values)
    assert result['accepted'], result['checks']
    assert result['collection_state'] == values[0]['state']
    assert result['can_enforce'] is False


@pytest.mark.parametrize('fault', ['zero_etw', 'missing_terminal', 'native_loss', 'wrong_provider',
    'wrong_layer', 'partial_extra_tls', 'empty_receipts', 'invalid_receipt_hash', 'invalid_receipt_size',
    'fixture_failed', 'missing_stage', 'unknown_relations', 'missing_registration', 'secret_in_audit'])
def test_complete_state_or_parseable_reports_do_not_replace_required_evidence(tmp_path, probe, fault):
    values = reports(probe, 'repeated_sends')
    runtime, flow, agent, _ = values
    if fault == 'zero_etw': runtime['etw_event_count'] = 0
    elif fault == 'missing_terminal': flow['session']['health']['ecapture']['terminal'] = False
    elif fault == 'native_loss': flow['session']['health']['native-io:A']['lost_events'] = 1
    elif fault == 'wrong_provider': flow['content_detection']['outbound'][0]['provider'] = 'fixture_truth'
    elif fault == 'wrong_layer': flow['content_detection']['outbound'][0]['capture_layer'] = 'request'
    elif fault == 'partial_extra_tls': flow['content_detection']['outbound'].append(dict(completeness='partial'))
    elif fault == 'empty_receipts': flow['origin_receipts']['receipts'] = []
    elif fault == 'invalid_receipt_hash': flow['origin_receipts']['receipts'][0]['body_sha256'] = None
    elif fault == 'invalid_receipt_size': flow['origin_receipts']['receipts'][0]['body_bytes'] = True
    elif fault == 'fixture_failed': runtime['fixture_exit_codes']['B'] = 1
    elif fault == 'missing_stage': agent['observations'] = agent['observations'][1:]
    elif fault == 'unknown_relations': runtime['coverage_gaps'] = ['unresolved_relation']
    elif fault == 'missing_registration': agent['observations'][-1]['findings'] = []
    elif fault == 'secret_in_audit': (tmp_path / 'accidental.txt').write_text(probe.SECRET, encoding='utf-8')
    result = evaluate(probe, tmp_path, 'repeated_sends', values)
    assert not result['accepted']


@pytest.mark.parametrize('fault', ['no_metadata', 'wrong_pid', 'wrong_birth', 'wrong_image', 'wrong_provider',
    'receive_only', 'not_data', 'truncated', 'missing_hash', 'lost_events', 'small_prefix', 'origin_already_received'])
def test_fault_acceptance_requires_real_prefix_metadata_bound_to_b(tmp_path, probe, fault):
    values = reports(probe, 'ecapture_exit')
    runtime, _, _, metadata = values
    if fault == 'no_metadata': metadata.clear()
    elif fault == 'wrong_pid': metadata[0]['pid'] = 999
    elif fault == 'wrong_birth': metadata[0]['creation_filetime'] += 1
    elif fault == 'wrong_image': metadata[0]['image_sha256'] = 'd'*64
    elif fault == 'wrong_provider': metadata[0]['provider'] = 'native-io'
    elif fault == 'receive_only': metadata[0]['direction'] = 'receive'
    elif fault == 'not_data': metadata[0]['event'] = 'ready'
    elif fault == 'truncated': metadata[0]['truncated'] = True
    elif fault == 'missing_hash': metadata[0].pop('data_sha256')
    elif fault == 'lost_events': metadata[0]['lost_events'] = 1
    elif fault == 'small_prefix': runtime['fault_injection']['observed_tls_send_bytes_at_stop'] = 1
    elif fault == 'origin_already_received': runtime['fault_injection']['origin_receipts_at_stop'] = 1
    result = evaluate(probe, tmp_path, 'ecapture_exit', values)
    assert not result['accepted'] and not result['checks']['during_actual_upload']


@pytest.mark.parametrize('fault', ['arbitrary_gap', 'missing_sensitive_attempt', 'missing_public_attempt',
    'flow_relations_not_degraded', 'agent_relations_not_degraded'])
def test_conflicting_message_requires_both_content_outcomes_and_specific_gap(tmp_path, probe, fault):
    values = reports(probe, 'conflicting_message')
    _, flow, agent, _ = values
    final = [r for r in agent['observations'] if r['stage'] == 'outbound']
    if fault == 'arbitrary_gap': flow['coverage_gaps'] = ['some_unrelated_gap']
    elif fault == 'missing_sensitive_attempt': final[0].update(detection_status='unknown', findings=[])
    elif fault == 'missing_public_attempt': final[1].update(detection_status='unknown')
    elif fault == 'flow_relations_not_degraded': flow['propagation']['relations'][0]['confidence'] = 'High'
    elif fault == 'agent_relations_not_degraded': agent['relations'][0]['confidence'] = 'Medium'
    assert not evaluate(probe, tmp_path, 'conflicting_message', values)['accepted']


def concurrent_states():
    return [dict(task_id_sha256=str(i+1)*64, released_at_utc='2026-10-23T10:00:00+00:00',
                 workflow_completed_at_utc='2026-10-23T10:00:02+00:00', ended_at_utc='2026-10-23T10:00:09+00:00',
                 subjects=[dict(pid=i*2+j, creation_filetime=100+i*2+j) for j in (1, 2)]) for i in range(3)]


@pytest.mark.parametrize('fault', [None, 'empty_results', 'missing_task', 'duplicate_task', 'shared_process',
    'one_failed', 'cleanup_only_overlap'])
def test_concurrent_acceptance_requires_three_distinct_live_workflows(probe, fault):
    states, results = concurrent_states(), [dict(accepted=True) for _ in range(3)]
    if fault == 'empty_results': results.clear()
    elif fault == 'missing_task': states[0].pop('task_id_sha256')
    elif fault == 'duplicate_task': states[0]['task_id_sha256'] = states[1]['task_id_sha256']
    elif fault == 'shared_process': states[0]['subjects'][0] = states[1]['subjects'][0]
    elif fault == 'one_failed': results[0]['accepted'] = False
    elif fault == 'cleanup_only_overlap': states[1]['released_at_utc'] = '2026-10-23T10:00:03+00:00'
    assert probe.concurrent_isolation(states, results)['accepted'] is (fault is None)


def test_fake_source_is_explicit_utf8_even_with_windows_legacy_default(tmp_path, monkeypatch, probe):
    original_write = Path.write_text
    def legacy_write(path, data, encoding=None, errors=None, newline=None):
        return original_write(path, data, encoding=encoding or 'cp936', errors=errors, newline=newline)
    monkeypatch.setattr(Path, 'write_text', legacy_write)
    monkeypatch.setattr(probe, 'is_elevated', lambda: True)
    source_bytes = []
    def prepare(*args, **kwargs):
        raw = kwargs['source'].read_bytes()
        assert json.loads(raw.decode('utf-8'))['public_text'] == '普通文本'
        source_bytes.append(raw)
        return tmp_path / 'synthetic.manifest.json'
    monkeypatch.setattr(probe, 'prepare_manifest', prepare)
    monkeypatch.setattr(probe, 'run', lambda *a, **k: {})
    monkeypatch.setattr(probe, 'assess', lambda *a: dict(accepted=True))
    code = probe.main(['--output', str(tmp_path / 'run'), '--certificate', str(tmp_path / 'cert'),
                       '--private-key', str(tmp_path / 'key'), '--case', 'repeated_sends'])
    assert code == 0 and source_bytes


@pytest.mark.parametrize('cleanup_confirmed', [True, False])
def test_probe_failure_cleans_test_trust_and_never_logs_exception_secret(tmp_path, monkeypatch, probe, cleanup_confirmed):
    cleaned = []
    class Lease:
        certificate, private_key = tmp_path / 'cert', tmp_path / 'key'
        def __init__(self, *a, **k): pass
        def prepare(self): return self
        def install(self): pass
        def cleanup(self):
            cleaned.append(True)
            return dict(cleanup_confirmed=cleanup_confirmed)
    monkeypatch.setattr(probe, 'LocalTestTrust', Lease)
    monkeypatch.setattr(probe, 'is_elevated', lambda: True)
    monkeypatch.setattr(probe, 'prepare_manifest', lambda *a, **k: None)
    def fail(*a, **k): raise RuntimeError('SECRET-EXCEPTION-BODY-MUST-NOT-PERSIST')
    monkeypatch.setattr(probe, 'run', fail)
    output = tmp_path / 'run'
    assert probe.main(['--output', str(output), '--prepare-test-trust', '--case', 'repeated_sends']) == 2
    saved = (output / 'summary.json').read_text(encoding='utf-8')
    result = json.loads(saved)
    assert cleaned == [True] and result['test_trust_cleanup_confirmed'] is cleanup_confirmed
    assert result['state'] == ('unavailable' if cleanup_confirmed else 'partial')
    assert result['error_type'] == 'RuntimeError' and 'SECRET-EXCEPTION' not in saved


@pytest.mark.parametrize('mode', ['repeated_sends', 'retry_after_503', 'reconnect_unique',
    'ecapture_exit', 'etw_exit', 'native_io_stop'])
def test_runtime_experiment_order_and_cleanup_stay_partial_without_real_evidence(tmp_path, monkeypatch, mode):
    from test_agent_flow_runtime import harness
    from transpect_trace.flow import origin
    h = harness(tmp_path, monkeypatch)
    if mode == 'retry_after_503':
        base = origin.Origin
        class RetryOrigin(base):
            def __init__(self, *args, **kwargs):
                assert kwargs == dict(response_statuses=(503, 200))
                super().__init__(*args)
        monkeypatch.setattr(origin, 'Origin', RetryOrigin)
    result = h.runtime.run(tmp_path / 'synthetic.manifest.json', experiment=mode)
    assert result['state'] == 'partial' and result['client_send_completed']
    assert not result['certified'] and h.origins[0].closed and all(f.process.poll() == 0 for f in h.fixtures)
    if mode == 'repeated_sends': assert h.timeline.count(('B', 'wait:sent')) == 3
    elif mode == 'retry_after_503':
        assert h.timeline.index(('B', 'wait:attempt_failed')) < h.timeline.index(('B', 'wait:sent'))
    elif mode == 'reconnect_unique':
        assert h.commands == [('B', 'release'), ('A', 'release'), ('B', 'next'), ('A', 'next')]
        assert h.timeline.count(('B', 'wait:pipe_ready')) == 2
    else:
        assert h.timeline.index(('B', 'wait:upload_paused')) < h.timeline.index(('B', 'send:continue_upload'))
        assert result['fault_injection']['phase'] == 'http_body_prefix_sent'
        assert result['fault_injection']['observed_tls_send_bytes_at_stop'] == 0


def test_failed_concurrent_barrier_keeps_agents_idle_and_closes_everything(tmp_path, monkeypatch):
    from test_agent_flow_runtime import harness
    h = harness(tmp_path, monkeypatch)
    class Barrier:
        def wait(self, *, timeout):
            assert 0 < timeout <= 20
            raise threading.BrokenBarrierError()
    result = h.runtime.run(tmp_path / 'synthetic.manifest.json', _start_barrier=Barrier())
    assert not h.commands and not result['data_released'] and not result['certified']
    assert h.origins[0].closed and all(f.process.poll() == 0 for f in h.fixtures)


def fake_http(monkeypatch, *, write_mode='short'):
    from transpect_trace.flow.agents import winhttp
    sent, calls, closed = bytearray(), [], []
    def send(request, headers, header_length, buffer, length, total, context):
        calls.append(('send', length, total)); sent.extend(c.string_at(buffer, length)); return True
    def write(request, buffer, length, count):
        amount = 0 if write_mode == 'zero' else length+1 if write_mode == 'oversize' else min(7, length)
        c.cast(count, c.POINTER(w.DWORD))[0] = amount
        calls.append(('write', amount))
        if 0 < amount <= length: sent.extend(c.string_at(buffer, amount))
        return True
    def query(request, flags, name, status, size, index):
        c.cast(status, c.POINTER(w.DWORD))[0] = 200; return True
    def read(request, buffer, length, count):
        c.cast(count, c.POINTER(w.DWORD))[0] = 0; return True
    api = SimpleNamespace(WinHttpOpen=lambda *a: 1, WinHttpConnect=lambda *a: 2,
        WinHttpOpenRequest=lambda *a: 3, WinHttpSetTimeouts=lambda *a: True,
        WinHttpSetOption=lambda *a: True, WinHttpSendRequest=send, WinHttpWriteData=write,
        WinHttpReceiveResponse=lambda *a: calls.append(('receive',)) or True,
        WinHttpQueryHeaders=query, WinHttpReadData=read,
        WinHttpCloseHandle=lambda handle: closed.append(handle) or True)
    monkeypatch.setattr(winhttp, 'preload', lambda: api)
    return winhttp, sent, calls, closed


def test_winhttp_checkpoint_sends_real_prefix_then_handles_short_suffix_writes(monkeypatch):
    winhttp, sent, calls, closed = fake_http(monkeypatch)
    body = '中文假数据'.encode('utf-8') * 13
    def checkpoint():
        assert bytes(sent) == body[:len(body)//2]
        calls.append(('checkpoint',))
    assert winhttp.upload('https://localhost:12345/upload', body, checkpoint=checkpoint) == dict(bytes=len(body), http_status=200)
    assert bytes(sent) == body and calls[0] == ('send', len(body)//2, len(body))
    assert calls[1] == ('checkpoint',) and calls[-1] == ('receive',) and closed == [3, 2, 1]


@pytest.mark.parametrize('failure', ['checkpoint', 'zero', 'oversize'])
def test_winhttp_checkpoint_and_suffix_failure_closes_all_handles(monkeypatch, failure):
    winhttp, sent, calls, closed = fake_http(monkeypatch, write_mode=failure)
    def checkpoint():
        if failure == 'checkpoint': raise RuntimeError('synthetic_checkpoint_failure')
    with pytest.raises(RuntimeError if failure == 'checkpoint' else ValueError):
        winhttp.upload('https://localhost:12345/upload', b'x'*100, checkpoint=checkpoint)
    assert closed == [3, 2, 1] and ('receive',) not in calls
    assert bytes(sent) == b'x'*50
