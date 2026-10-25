"""Actual loopback TLS sockets; no OS trust-store changes or collector claims."""
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import socket
import ssl
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from transpect_trace.flow.origin import IO_TIMEOUT, LIMIT, Origin


@pytest.fixture
def tls_files(tmp_path):
    # A test-local trust anchor and localhost leaf, trusted only by this client's
    # SSLContext. The Windows certificate stores are never read or changed.
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'flow socket test CA')])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(root_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(root_key, hashes.SHA256()))
    ca, certificate, private_key = (tmp_path / name for name in ('ca.pem', 'localhost.pem', 'key.pem'))
    ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    certificate.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private_key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                                                  serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    return ca, certificate, private_key


def wait_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), 'socket fixture did not reach expected phase'


def active_phase(origin, phase):
    with origin.lock:
        return any(state['phase'] == phase for state in origin._active.values())


def close_bounded(origin):
    failures = []
    def close():
        try:
            origin.close()
        except Exception as exc:
            failures.append(type(exc).__name__)
    closer = threading.Thread(target=close, daemon=True)
    closer.start()
    closer.join(IO_TIMEOUT + 4)
    assert not closer.is_alive(), 'origin cleanup exceeded bounded shutdown'
    assert failures == []
    assert not origin.thread.is_alive()
    with origin.lock:
        assert not origin._active
    assert 'origin_close_incomplete' not in origin.errors


def test_normal_tls_upload_receipt_matches_body_and_does_not_export_secret(tls_files):
    ca, certificate, private_key = tls_files
    origin = Origin(certificate, private_key).start()
    context = ssl.create_default_context(cafile=str(ca))
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    body = json.dumps({'report': '假机密-ONLY-FIXTURE-' * 10000}, ensure_ascii=False).encode()
    assert 65536 < len(body) <= LIMIT
    client = http.client.HTTPSConnection('localhost', origin.server.server_port, context=context, timeout=3)
    try:
        client.request('POST', '/upload', body=body, headers={'Content-Type': 'application/json'})
        response = client.getresponse()
        assert response.status == 200 and response.read() == b'OK'
        wait_until(lambda: not origin._active)
    finally:
        client.close()
        close_bounded(origin)
    assert origin.errors == []
    assert len(origin.receipts) == 1
    receipt = origin.receipts[0]
    assert receipt['body_bytes'] == len(body)
    assert receipt['body_sha256'] == hashlib.sha256(body).hexdigest()
    assert 'ONLY-FIXTURE' not in json.dumps(origin.receipts + origin.errors)


def test_close_cancels_peer_that_never_sends_tls_client_hello(tls_files):
    _, certificate, private_key = tls_files
    origin = Origin(certificate, private_key).start()
    peer = socket.create_connection(('127.0.0.1', origin.server.server_port), timeout=3)
    try:
        wait_until(lambda: active_phase(origin, 'handshake'))
        close_bounded(origin)
    finally:
        peer.close()
        origin.close()
    assert origin.receipts == []
    assert origin.errors == ['origin_handshake_incomplete']


def test_close_cancels_incomplete_tls_body_and_records_gap(tls_files):
    ca, certificate, private_key = tls_files
    origin = Origin(certificate, private_key).start()
    context = ssl.create_default_context(cafile=str(ca))
    peer = context.wrap_socket(socket.create_connection(('127.0.0.1', origin.server.server_port), timeout=3),
                               server_hostname='localhost')
    try:
        peer.sendall(b'POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 65536\r\n\r\nFAKE-SECRET')
        wait_until(lambda: active_phase(origin, 'request'))
        close_bounded(origin)
    finally:
        peer.close()
        origin.close()
    assert origin.receipts == []
    assert origin.errors == ['origin_request_incomplete']
    assert 'FAKE-SECRET' not in json.dumps(origin.receipts + origin.errors)


def test_oversized_request_keeps_existing_one_mib_limit(tls_files):
    ca, certificate, private_key = tls_files
    origin = Origin(certificate, private_key).start()
    context = ssl.create_default_context(cafile=str(ca))
    peer = context.wrap_socket(socket.create_connection(('127.0.0.1', origin.server.server_port), timeout=3),
                               server_hostname='localhost')
    try:
        peer.sendall(f'POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {LIMIT + 1}\r\n\r\n'.encode())
        wait_until(lambda: bool(origin.errors))
    finally:
        peer.close()
        close_bounded(origin)
    assert origin.receipts == []
    assert origin.errors == ['origin_request_incomplete']
