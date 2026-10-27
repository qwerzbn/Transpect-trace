"""Real loopback TLS framing tests, not endpoint collection certification."""
from email.message import Message
import hashlib
import http.client
import io
import json
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
import gzip
import zlib

import pytest

from test_flow_origin import tls_files, wait_until
from transpect_trace.flow.scenarios.sources import BodyError, BusinessOrigin, LIMIT, read_bounded_body


def headers(*pairs):
    value = Message()
    for key, item in pairs:
        value[key] = item
    return value


@pytest.mark.parametrize(('fields', 'body', 'reason'), [
    ([('Content-Length', '2'), ('Transfer-Encoding', 'chunked')], b'', 'ambiguous_body_framing'),
    ([('Content-Length', '2'), ('Content-Length', '2')], b'', 'ambiguous_body_framing'),
    ([('Content-Length', '-1')], b'', 'invalid_body_length'),
    ([], b'', 'missing_body_length'),
    ([('Content-Length', '3')], b'ab', 'truncated_body'),
    ([('Transfer-Encoding', 'gzip')], b'', 'unsupported_transfer_encoding'),
    ([('Transfer-Encoding', 'chunked')], b'2;secret=1\r\nab\r\n0\r\n\r\n', 'unsupported_chunk_header'),
    ([('Transfer-Encoding', 'chunked')], b'2\r\na', 'truncated_body'),
    ([('Transfer-Encoding', 'chunked')], b'1\r\naX\r0\r\n\r\n', 'truncated_chunk_end'),
    ([('Transfer-Encoding', 'chunked')], b'0\r\nCookie: secret\r\n\r\n', 'unsupported_chunk_trailers'),
])
def test_ambiguous_partial_and_unsupported_framing(fields, body, reason):
    with pytest.raises(BodyError, match=reason):
        read_bounded_body(io.BytesIO(body), headers(*fields))


def test_length_and_chunk_boundaries():
    value = b'x' * LIMIT
    assert read_bounded_body(io.BytesIO(value), headers(('Content-Length', str(LIMIT)))) == value
    assert read_bounded_body(io.BytesIO(b'2\r\nab\r\n1\r\nc\r\n0\r\n\r\n'), headers(('Transfer-Encoding', 'chunked'))) == b'abc'
    with pytest.raises(BodyError, match='body_limit_exceeded'):
        read_bounded_body(io.BytesIO(b''), headers(('Content-Length', str(LIMIT + 1))))
    with pytest.raises(BodyError, match='body_limit_exceeded'):
        read_bounded_body(io.BytesIO(b'100001\r\n'), headers(('Transfer-Encoding', 'chunked')))


def request(origin, ca, method, path, body=None, extra_headers=None, **kwargs):
    context = ssl.create_default_context(cafile=str(ca))
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    connection = http.client.HTTPSConnection('localhost', origin.port, context=context, timeout=5)
    try:
        connection.request(method, path, body, extra_headers or {}, **kwargs)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_count(origin, count, timeout=3):
    deadline = time.monotonic() + timeout
    while len(origin.receipts) < count and time.monotonic() < deadline:
        time.sleep(.01)
    assert len(origin.receipts) == count


def test_ticket_webhook_chunked_retry_and_redaction(tls_files):
    ca, certificate, key = tls_files
    observed = []
    secret = 'FAKE_ONLY_business_秘密'
    body = json.dumps({'report': secret}, ensure_ascii=False).encode()
    origin = BusinessOrigin(certificate, key, ticket_bytes=body,
                            on_body=lambda data, row: observed.append((data, row)),
                            response_statuses=(503, 200)).start()
    try:
        assert request(origin, ca, 'GET', '/ticket') == (200, body)
        for status in (503, 200):
            assert request(origin, ca, 'POST', '/webhook', iter((body[:12], body[12:])),
                           {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + secret.encode().hex(),
                            'Cookie': 'secret=' + secret.encode().hex()}, encode_chunked=True) == (status, b'OK')
        wait_count(origin, 3)
        assert observed[0][0] == observed[1][0] == body
        rows = [row for row in origin.receipts if row['route'] == 'webhook']
        assert [row['response_status'] for row in rows] == [503, 200]
        assert len({row['attempt_id'] for row in rows}) == 2
        assert all(row['body_sha256'] == hashlib.sha256(body).hexdigest() for row in rows)
        assert all(row['completeness'] == 'complete' for row in rows)
        exported = json.dumps(origin.receipts + origin.errors, ensure_ascii=False)
        assert secret not in exported and secret.encode().hex() not in exported
        assert 'Authorization' not in exported and 'Cookie' not in exported
    finally:
        origin.close()
    assert origin.errors == []


def test_reject_query_without_logging_it_and_redact_callback_failure(tls_files):
    ca, certificate, key = tls_files
    def fail(*_):
        raise ValueError('FAKE_PRIVATE_TEXT')
    origin = BusinessOrigin(certificate, key, on_body=fail).start()
    try:
        assert request(origin, ca, 'POST', '/webhook?token=FAKE_PRIVATE_TEXT', b'x')[0] == 404
        assert request(origin, ca, 'PUT', '/webhook', b'FAKE_PRIVATE_TEXT')[0] == 500
        wait_count(origin, 2)
        assert 'FAKE_PRIVATE_TEXT' not in json.dumps(origin.receipts + origin.errors)
        assert origin.receipts[1]['error'] == 'origin_request_or_callback_failed'
    finally:
        origin.close()


def test_incomplete_tls_upload_never_complete(tls_files):
    ca, certificate, key = tls_files
    origin = BusinessOrigin(certificate, key).start()
    context = ssl.create_default_context(cafile=str(ca))
    try:
        peer = context.wrap_socket(socket.create_connection(('localhost', origin.port)), server_hostname='localhost')
        peer.sendall(b'POST /webhook HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nfake')
        wait_until(lambda: 'body' in list(origin._active.values()))
        origin.close()
        peer.close()
        wait_count(origin, 1)
        row = origin.receipts[0]
        assert row['completeness'] == 'partial' and 0 <= row['body_bytes'] <= 4
        assert row['error'] in ('truncated_body', 'body_read_failed')
    finally:
        origin.close()


def test_model_callback_sse_is_memory_only(tls_files):
    ca, certificate, key = tls_files
    seen = []
    def reply(body, receipt):
        seen.append((json.loads(body), receipt))
        return [{'type': 'response.completed', 'response': {'id': 'fixture', 'output': []}}]
    origin = BusinessOrigin(certificate, key, model_reply=reply).start()
    try:
        status, raw = request(origin, ca, 'POST', '/responses', b'{"input":"FAKE_ONLY_PRIVATE"}')
        assert status == 200 and b'response.completed' in raw
        wait_count(origin, 1)
        assert seen[0][0]['input'] == 'FAKE_ONLY_PRIVATE'
        assert origin.receipts[0]['route'] == 'model'
        assert 'FAKE_ONLY_PRIVATE' not in json.dumps(origin.receipts)
    finally:
        origin.close()


def test_equal_body_concurrency_keeps_independent_receipts_and_tls_metadata(tls_files):
    ca, certificate, key = tls_files
    origin = BusinessOrigin(certificate, key).start()
    body = '中文'.encode() * 16384
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(request, origin, ca, 'PUT', '/webhook', body) for _ in range(2)]
            assert all(future.result() == (200, b'OK') for future in futures)
        wait_count(origin, 2)
        assert len({row['attempt_id'] for row in origin.receipts}) == 2
        assert {row['body_sha256'] for row in origin.receipts} == {hashlib.sha256(body).hexdigest()}
        assert all(row['body_bytes'] == len(body) and row['tls_version'].startswith('TLS') for row in origin.receipts)
        assert all(row['tls_cipher'] for row in origin.receipts)
    finally:
        origin.close()


def test_real_one_mib_tls_body_and_oversize_request(tls_files):
    ca, certificate, key = tls_files
    origin = BusinessOrigin(certificate, key).start()
    body = b'{' + b' ' * (LIMIT - 2) + b'}'
    try:
        assert request(origin, ca, 'POST', '/webhook', body) == (200, b'OK')
        assert request(origin, ca, 'POST', '/webhook', b'', {'Content-Length': str(LIMIT + 1)})[0] == 413
        wait_count(origin, 2)
        assert origin.receipts[0]['body_sha256'] == hashlib.sha256(body).hexdigest()
        assert origin.receipts[0]['body_bytes'] == LIMIT
        assert origin.receipts[1]['completeness'] == 'partial'
    finally:
        origin.close()


def encode_model(data, encoding):
    if encoding == 'identity':
        return data
    if encoding == 'gzip':
        return gzip.compress(data)
    if encoding == 'deflate':
        return zlib.compress(data)
    import zstandard
    return zstandard.ZstdCompressor().compress(data)


@pytest.mark.parametrize('encoding', ['identity', 'gzip', 'deflate', 'zstd'])
def test_model_decodes_complete_body_and_separates_raw_decoded_hashes(tls_files, encoding):
    ca, certificate, key = tls_files
    body = json.dumps({'input': 'FAKE_ONLY_PRIVATE_中文' * 3000}, ensure_ascii=False).encode()
    wire = encode_model(body, encoding)
    seen = []
    origin = BusinessOrigin(certificate, key, model_reply=lambda value, row: seen.append((value, row)) or []).start()
    try:
        assert request(origin, ca, 'POST', '/responses', wire, {'Content-Encoding': encoding})[0] == 200
        wait_count(origin, 1)
        assert seen[0][0] == body
        row = origin.receipts[0]
        assert row['completeness'] == 'complete'
        assert row['body_sha256'] == row['raw_body_sha256'] == hashlib.sha256(wire).hexdigest()
        assert row['body_bytes'] == row['raw_body_bytes'] == len(wire)
        assert row['decoded_body_sha256'] == hashlib.sha256(body).hexdigest()
        assert row['decoded_body_bytes'] == len(body)
        assert row['decoding_state'] == ('identity' if encoding == 'identity' else 'decoded')
        assert 'FAKE_ONLY_PRIVATE' not in json.dumps(origin.receipts)
    finally:
        origin.close()


@pytest.mark.parametrize(('encoding', 'variant', 'status', 'state'), [
    ('gzip', 'truncated', 400, 'failed'),
    ('zstd', 'truncated', 400, 'failed'),
    ('gzip', 'multiple', 400, 'failed'),
    ('zstd', 'oversized', 413, 'oversized'),
    ('br', 'unsupported', 415, 'unsupported'),
    ('gzip, deflate', 'unsupported', 415, 'unsupported'),
])
def test_invalid_model_encoding_never_calls_model_or_changes_transport_fact(tls_files, encoding, variant, status, state):
    ca, certificate, key = tls_files
    body = b'{"input":"FAKE_ONLY_PRIVATE"}'
    if variant == 'oversized':
        wire = encode_model(b' ' * (LIMIT + 1), encoding)
    elif variant == 'unsupported':
        wire = body
    else:
        wire = encode_model(body, encoding)
        wire = wire[:-1] if variant == 'truncated' else wire + wire
    seen = []
    origin = BusinessOrigin(certificate, key, model_reply=lambda *_: seen.append(True) or []).start()
    try:
        assert request(origin, ca, 'POST', '/responses', wire, {'Content-Encoding': encoding})[0] == status
        wait_count(origin, 1)
        row = origin.receipts[0]
        assert not seen
        assert row['completeness'] == 'complete'  # encoded HTTP body did arrive
        assert row['decoding_state'] == state and row['decoded_body_sha256'] is None
        assert row['body_sha256'] == row['raw_body_sha256'] == hashlib.sha256(wire).hexdigest()
        assert row['raw_body_bytes'] == len(wire)
        assert 'FAKE_ONLY_PRIVATE' not in json.dumps(origin.receipts)
    finally:
        origin.close()


def test_webhook_content_encoding_keeps_original_body_layer(tls_files):
    ca, certificate, key = tls_files
    body = gzip.compress(b'{"report":"FAKE_ONLY_COMPRESSED"}')
    seen = []
    origin = BusinessOrigin(certificate, key, on_body=lambda data, row: seen.append(data)).start()
    try:
        assert request(origin, ca, 'POST', '/webhook', body, {'Content-Encoding': 'gzip'})[0] == 200
        wait_count(origin, 1)
        assert seen == [body]
        assert origin.receipts[0]['body_sha256'] == hashlib.sha256(body).hexdigest()
        assert 'decoded_body_sha256' not in origin.receipts[0]
    finally:
        origin.close()


def test_model_rejects_duplicate_encoding_headers_without_exporting_values():
    from transpect_trace.flow.scenarios.sources import decode_model_body, ModelEncodingError
    row = {}
    with pytest.raises(ModelEncodingError, match='ambiguous_model_content_encoding'):
        decode_model_body(b'{}', headers(('Content-Encoding', 'gzip'), ('Content-Encoding', 'FAKE_ONLY_HEADER')), row)
    assert row['decoding_state'] == 'unsupported' and row['decoded_body_sha256'] is None
    assert 'FAKE_ONLY_HEADER' not in json.dumps(row)
