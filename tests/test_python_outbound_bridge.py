"""Request snapshots must be authorized before the actual HTTPX delegate runs."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time

import pytest

httpx = pytest.importorskip('httpx', minversion='0.28.1')

from transpect_trace.protect import python_bridge


@pytest.fixture
def setup_gate(tmp_path, monkeypatch):
    image = tmp_path / 'python.exe'
    image.write_bytes(b'controlled interpreter image')
    dll = tmp_path / '_ttrace_native_gate.pyd'
    dll.write_bytes(b'controlled native artifact')
    manifest = tmp_path / 'native-build.json'
    manifest.write_text(json.dumps({
        'schema_version': 'transpect.protect.native-build/1.0',
        'artifacts': {dll.name: python_bridge.digest(dll)},
        'runtime_files': {str(image): python_bridge.digest(image)},
    }), encoding='utf-8')
    monkeypatch.setattr(python_bridge, 'identity', lambda _: {
        'pid': 42, 'creation_filetime': 101, 'image_sha256': python_bridge.digest(image),
    })
    sent = []

    def delegate(_, request):
        sent.append((request, request.read()))
        return httpx.Response(200, json={'received': True})

    async def async_delegate(_, request):
        sent.append((request, await request.aread()))
        return httpx.Response(200, json={'received': True})

    monkeypatch.setattr(httpx.HTTPTransport, 'handle_request', delegate)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', async_delegate)
    monkeypatch.setattr(httpx.HTTPTransport, '_ttrace_owner', None, raising=False)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, '_ttrace_owner', None, raising=False)

    class Native:
        requests = []
        deny = False
        callback = None

        def configure(self, pid):
            self.server_pid = pid

        def authorize(self, payload, attempt):
            assert not sent, 'transport was delegated before authorization'
            self.requests.append((json.loads(payload), attempt))
            if self.callback:
                self.callback()
            if self.deny:
                raise PermissionError('PROTECT_REQUEST_DENIED')

    native = Native()
    monkeypatch.setattr(python_bridge, '_load_native', lambda _: native)

    def install(mode='outbound-json'):
        return python_bridge.install(dll, 123, 'controlled-run', manifest, mode=mode)

    return install, native, sent, dll, manifest, image


def request(raw=b'{"report":"ordinary"}', **kwargs):
    headers = {'content-type': 'application/json', **kwargs.pop('headers', {})}
    return httpx.Request(kwargs.pop('method', 'POST'), 'https://localhost/upload?private=unlogged',
                         content=raw, headers=headers, **kwargs)


def sync_send(value):
    return httpx.HTTPTransport.handle_request(object(), value)


def test_outbound_snapshot_authorized_and_forwarded_exactly(setup_gate):
    install, native, sent, *_ = setup_gate
    ready = install()
    raw = '{"report":"假机密\\n保留原格式", "count":2}'.encode()
    value = request(raw, headers={'Authorization': 'Bearer hidden', 'Cookie': 'secret=cookie'})
    assert sync_send(value).status_code == 200
    assert ready['mode'] == 'outbound-json' and ready['gate_ready']
    assert sent[0][1] == raw
    wire, attempt = native.requests[0]
    event = wire['event']
    assert event['adapter_id'] == event['gate_owner'] == 'python-httpx-outbound-native/1'
    assert event['api_path'] == 'unknown' and event['application'] == 'python-outbound'
    assert event['attempt_id'] == attempt
    assert event['body_sha256'] == hashlib.sha256(raw).hexdigest()
    assert event['body_bytes'] == len(raw) and base64.b64decode(wire['body_b64']) == raw
    assert 'body' not in event
    assert all(word not in json.dumps(event) for word in ['hidden', 'cookie', 'private=', 'upload'])
    assert sent[0][0].headers['Content-Length'] == str(len(raw))


def test_native_denial_does_not_delegate_and_gate_stays_installed(setup_gate):
    install, native, sent, *_ = setup_gate
    install()
    native.deny = True
    for _ in range(2):
        with pytest.raises(PermissionError, match='PROTECT_REQUEST_DENIED'):
            sync_send(request())
    assert not sent and len(native.requests) == 2
    assert native.requests[0][1] != native.requests[1][1]
    native.deny = False
    assert sync_send(request()).status_code == 200


@pytest.mark.parametrize('raw,headers,method,error', [
    (b'{invalid', {}, 'POST', 'JSON_UNINSPECTABLE'),
    (b'{"x":"\xff"}', {}, 'POST', 'JSON_UNINSPECTABLE'),
    (b'{}', {'content-type': 'multipart/form-data'}, 'POST', 'CONTENT_TYPE_UNSUPPORTED'),
    (b'{}', {'content-encoding': 'gzip'}, 'POST', 'ENCODING_UNSUPPORTED'),
    (b'{}', {}, 'DELETE', 'METHOD_UNSUPPORTED'),
    (b'"' + b'a' * (1024 * 1024) + b'"', {}, 'POST', 'BODY_LIMIT'),
], ids=['invalid-json', 'invalid-utf8', 'multipart', 'compressed', 'method', 'oversize'])
def test_uninspectable_outbound_body_is_rejected_before_native_or_transport(
        setup_gate, raw, headers, method, error):
    install, native, sent, *_ = setup_gate
    install()
    with pytest.raises(PermissionError, match=error):
        sync_send(request(raw, headers=headers, method=method))
    assert not native.requests and not sent


def test_one_mib_json_snapshot_and_fragment_boundary(setup_gate):
    install, native, sent, *_ = setup_gate
    install()
    raw = b'"' + b'a' * (1024 * 1024 - 2) + b'"'
    value = httpx.Request('PUT', 'https://localhost/upload', headers={'content-type': 'application/json'},
                          content=iter([raw[:65536], raw[65536:]]))
    assert sync_send(value).status_code == 200
    assert sent[0][1] == raw and native.requests[0][0]['event']['body_bytes'] == 1024 * 1024
    assert 'transfer-encoding' not in sent[0][0].headers


@pytest.mark.parametrize('changed', ['dll', 'runtime'])
def test_identity_change_rejects_before_loading(setup_gate, monkeypatch, changed):
    install, native, sent, dll, _, image = setup_gate
    (dll if changed == 'dll' else image).write_bytes(b'changed')
    monkeypatch.setattr(python_bridge, '_load_native', lambda _: pytest.fail('must not load mismatched code'))
    with pytest.raises(ValueError, match='identity mismatch'):
        install()
    assert not sent and not native.requests


def test_existing_hook_owner_is_not_replaced(setup_gate, monkeypatch):
    install, _, _, *_ = setup_gate
    monkeypatch.setattr(httpx.HTTPTransport, '_ttrace_owner', 'other-owner')
    with pytest.raises(RuntimeError, match='owner already installed'):
        install()


def test_legacy_default_still_identifies_model_request(setup_gate):
    install, native, sent, *_ = setup_gate
    install('llm')
    value = httpx.Request('POST', 'https://localhost/v1/responses',
                         headers={'content-type': 'application/json'}, content=b'{"input":"hello"}')
    assert sync_send(value).status_code == 200
    assert native.requests[0][0]['event']['adapter_id'] == 'python-httpx-native/1'
    assert native.requests[0][0]['event']['api_path'] == '/responses'


def test_async_authorization_does_not_block_loop_and_matches_snapshot(setup_gate):
    install, native, sent, *_ = setup_gate
    install()
    native.callback = lambda: time.sleep(0.05)

    async def scenario():
        operation = asyncio.create_task(httpx.AsyncHTTPTransport.handle_async_request(object(), request()))
        await asyncio.sleep(0.01)
        assert not operation.done() and not sent
        assert (await operation).status_code == 200

    asyncio.run(scenario())
    assert len(native.requests) == len(sent) == 1


def test_async_cancel_during_native_wait_cannot_send(setup_gate):
    install, native, sent, *_ = setup_gate
    install()
    entered = threading.Event()

    def wait():
        entered.set()
        time.sleep(0.05)

    native.callback = wait

    async def scenario():
        task = asyncio.create_task(httpx.AsyncHTTPTransport.handle_async_request(object(), request()))
        while not entered.is_set():
            await asyncio.sleep(0.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert len(native.requests) == 1 and not sent


def test_async_native_denial_keeps_transport_gated_for_next_request(setup_gate):
    install, native, sent, *_ = setup_gate
    install()

    async def scenario():
        native.deny = True
        for _ in range(2):
            with pytest.raises(PermissionError, match='PROTECT_REQUEST_DENIED'):
                await httpx.AsyncHTTPTransport.handle_async_request(object(), request())
        assert not sent
        native.deny = False
        response = await httpx.AsyncHTTPTransport.handle_async_request(object(), request())
        assert response.status_code == 200

    asyncio.run(scenario())
    assert len(native.requests) == 3 and len(sent) == 1
    assert len({attempt for _, attempt in native.requests}) == 3


def test_runner_waits_for_explicit_release_and_passes_mode(monkeypatch):
    import io
    from transpect_trace.protect import python_runner
    config = {'dll': 'gate.pyd', 'manifest': 'build.json', 'server_pid': 1,
              'run_id': 'run', 'script': 'uploader.py', 'mode': 'outbound-json'}
    monkeypatch.setattr(python_bridge, 'install', lambda *_, **kw: {'gate_ready': True, 'mode': kw['mode']})
    monkeypatch.setattr(python_runner.sys, 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(config).encode() + b'\nNO\n')))
    monkeypatch.setattr(python_runner.runpy, 'run_path', lambda *_a, **_kw: pytest.fail('user script ran before RUN'))
    with pytest.raises(SystemExit, match='startup not released'):
        python_runner.main()
