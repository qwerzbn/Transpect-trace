"""Fixed Agent fixtures: real Win32 IPC, deterministic transforms and TLS rejection.

These tests neither install trust nor certify ETW/eCapture observation.
"""
from concurrent.futures import ThreadPoolExecutor
import ctypes as c
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from uuid import uuid4

import pytest

from transpect_trace.flow.agents import participant, protocol, winhttp
from transpect_trace.flow.participant import MAX_BYTES, PIPE_PREFIX, handoff, open_handle
from transpect_trace.flow.origin import Origin

WINDOWS = pytest.mark.skipif(sys.platform != 'win32', reason='Windows x64 fixture')
SOURCE = {'public_text': '普通报告', 'api_key': 'fake-agent-key-for-unit-tests',
          'document': '登记机密仅用于测试', 'irrelevant': '无需传递的背景'}


def fixture_command(role, pipe, task, *arguments):
    return [sys._base_executable, '-I', str(Path(participant.__file__).resolve()),
            '--role', role, '--task-id', task, '--handoff', pipe, *map(str, arguments)]


def next_event(process, expected):
    result = queue.Queue()
    thread = threading.Thread(target=lambda: result.put(process.stdout.readline()), daemon=True)
    thread.start()
    row = json.loads(result.get(timeout=10))
    assert row['kind'] == expected, row
    assert row['evidence_origin'] == 'fixture_truth'
    return row


def command(process, value):
    process.stdin.write((value + '\n').encode())
    process.stdin.flush()


def cleanup(process):
    if process.poll() is None:
        process.terminate()
    process.wait(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        stream.close()


@pytest.mark.parametrize('mode', protocol.MODES)
def test_query_and_transforms_keep_explicit_sensitive_and_public_boundaries(mode):
    payload = participant.query_result(protocol.encode(SOURCE))
    assert set(payload) == {'public_text', 'api_key', 'document'}
    assert SOURCE['irrelevant'] not in protocol.encode(payload).decode()
    report = protocol.transform_payload(payload, mode)
    encoded = protocol.make_outbound('a' * 32, 'b' * 32, 'c' * 32, 'd' * 32, report)
    assert protocol.parse_outbound(encoded)['report'] == report
    if mode == 'public':
        assert SOURCE['api_key'].encode() not in encoded
        assert SOURCE['document'].encode() not in encoded
    else:
        assert SOURCE['api_key'].encode() in encoded
        assert SOURCE['document'].encode() in encoded
    public_payload = participant.query_result(protocol.encode(SOURCE), public_only=True)
    assert public_payload == {'public_text': SOURCE['public_text']}


def test_agent_step_exports_only_identifier_hashes(capsys):
    participant.step('A', 'delegate', task_id='a' * 32, message_id='b' * 32)
    row = json.loads(capsys.readouterr().out)
    assert row == {'kind': 'agent_step', 'role': 'A', 'evidence_origin': 'fixture_truth', 'step': 'delegate',
                   'task_id_sha256': hashlib.sha256(b'a' * 32).hexdigest(),
                   'message_id_sha256': hashlib.sha256(b'b' * 32).hexdigest()}


@pytest.mark.parametrize('url', ['http://localhost/upload', 'https://example.com/upload',
    'https://127.0.0.1/upload', 'https://user:password@localhost/upload', 'https://localhost/elsewhere',
    'https://localhost/upload?secret=x', 'https://localhost/upload#secret', 'https://localhost:0/upload'])
def test_winhttp_destination_scope_is_checked_before_connect(url):
    with pytest.raises(ValueError):
        winhttp.endpoint(url)


@WINDOWS
def test_agent_a_waits_for_release_then_sends_large_message_over_real_pipe(tmp_path):
    source = tmp_path / 'source-not-created-before-ready.json'
    pipe, task, message = PIPE_PREFIX + uuid4().hex, uuid4().hex, uuid4().hex
    process = subprocess.Popen(fixture_command('A', pipe, task, '--source', source, '--message-id', message),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ready = threading.Event()
    api = participant.io_api()
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        row = next_event(process, 'ready')
        assert row['pid'] == process.pid and row['source_access_started'] is False
        assert not source.exists()
        data = {**SOURCE, 'document': '中文固定报告\r\n' * 10000}
        source.write_bytes(protocol.encode(data))
        received = pool.submit(participant.receive, api, pipe, ready=ready.set)
        assert ready.wait(3)
        output, error = process.communicate(b'release\nfinish\n', timeout=20)
        assert process.returncode == 0 and not error
        envelope = protocol.parse_message(received.result(timeout=3))
        assert envelope['task_id'] == task and envelope['message_id'] == message
        assert envelope['payload'] == {key: data[key] for key in ('public_text', 'api_key', 'document')}
        assert len(protocol.encode(envelope)) > 65536
        rows = [json.loads(line) for line in output.splitlines()]
        assert [row['kind'] for row in rows] == ['agent_step', 'agent_step', 'transfer_complete', 'finished']
        assert SOURCE['api_key'].encode() not in output + error
        assert data['document'].encode() not in output + error
    finally:
        cleanup(process)
        pool.shutdown(wait=True)


@WINDOWS
def test_pipe_connect_timeout_and_disconnected_client_are_bounded():
    api = participant.io_api()
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        participant.receive(api, PIPE_PREFIX + uuid4().hex, timeout_seconds=0.2)
    assert time.monotonic() - started < 3
    pipe, ready = PIPE_PREFIX + uuid4().hex, threading.Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        received = pool.submit(participant.receive, api, pipe, ready=ready.set, timeout_seconds=1)
        assert ready.wait(3)
        handle = open_handle(api, pipe, write=True, pipe=True)
        api.CloseHandle(handle)
        with pytest.raises(OSError):
            received.result(timeout=3)


@WINDOWS
def test_agent_a_oversized_input_never_starts_delegation_and_redacts_error(tmp_path):
    source = tmp_path / 'fake-private-dataset.json'
    source.write_bytes(b'x' * (MAX_BYTES + 1))
    result = subprocess.run(fixture_command('A', PIPE_PREFIX + uuid4().hex, uuid4().hex,
        '--source', source, '--message-id', uuid4().hex), input=b'release\nfinish\n',
        capture_output=True, timeout=20)
    assert result.returncode == 2
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row['kind'] for row in rows] == ['ready', 'error']
    assert rows[-1]['stage'] == 'query'
    assert b'fake-private-dataset' not in result.stdout + result.stderr


@WINDOWS
def test_agent_b_reads_transforms_then_winhttp_rejects_untrusted_tls_without_upload(tmp_path, monkeypatch):
    # WinHTTP uses the Windows trust store; no per-call cafile replacement is
    # available here. Prove real rejection rather than disabling verification.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    from _local_test_trust import LocalTestTrust
    def forbidden(*_):
        raise AssertionError('test must never read or modify the Windows trust store')
    trust = LocalTestTrust(tmp_path / 'private-origin', store_reader=forbidden, command_runner=forbidden)
    trust.prepare()
    origin = Origin(trust.certificate, trust.private_key).start()
    pipe, task = PIPE_PREFIX + uuid4().hex, uuid4().hex
    process = subprocess.Popen(fixture_command('B', pipe, task, '--url', origin.url, '--transform', 'nested'),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        ready = next_event(process, 'ready')
        assert ready['pid'] == process.pid and not origin.receipts
        command(process, 'release')
        next_event(process, 'pipe_ready')
        with participant.BoundedIO(participant.io_api()):
            handoff(participant.io_api(), pipe,
                    protocol.make_message(task, uuid4().hex, participant.query_result(protocol.encode(SOURCE))), 'pipe')
        output, error = process.communicate(b'finish\n', timeout=20)
        assert process.returncode == 2 and not error
        rows = [json.loads(line) for line in output.splitlines()]
        assert [row['kind'] for row in rows] == ['received', 'agent_step', 'agent_step', 'error']
        assert rows[-1]['stage'] == 'http_upload'
        assert rows[-1]['win32_error'] == 12175  # ERROR_WINHTTP_SECURE_FAILURE
        assert SOURCE['api_key'].encode() not in output + error
        assert all(row['evidence_origin'] == 'fixture_truth' for row in rows)
    finally:
        cleanup(process)
        origin.close()
    assert origin.receipts == []
    # Schannel can reject the chain after the server's handshake has finished;
    # either phase is valid evidence of a failed upload, never a body receipt.
    assert origin.errors and set(origin.errors) <= {'origin_handshake_incomplete', 'origin_request_incomplete'}
