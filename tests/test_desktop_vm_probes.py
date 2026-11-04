"""Local synthetic controls for the VM-only network validation scripts."""
from __future__ import annotations

import hashlib
from pathlib import Path
import socket
import ssl
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from probe_codex_tls import certificate
from probe_desktop_origin_vm import ControlledOrigin
from probe_desktop_wfp_vm import Receiver, send_probes


def _until(predicate, seconds: float = 3) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate()


def test_raw_socket_receipts_are_receiver_side_and_cover_four_paths():
    try:
        receiver = Receiver()
    except OSError as error:
        pytest.skip(f"IPv4/IPv6 loopback unavailable: {error}")
    try:
        assert receiver.snapshot()["all_received_zero"]
        marker = b"FAKE_WFP_PROBE_four_paths"
        result = send_probes(receiver.manifest(), marker=marker)
        assert set(result["attempts"]) == {"tcp4", "udp4", "tcp6", "udp6"}
        _until(lambda: all(row["received_bytes"] == len(marker)
                           for row in receiver.snapshot()["endpoints"].values()))
        assert all(row["received_sha256"] == hashlib.sha256(marker).hexdigest()
                   for row in receiver.snapshot()["endpoints"].values())
    finally:
        receiver.close()


def _tls_client(ca: Path, port: int) -> ssl.SSLSocket:
    context = ssl.create_default_context(cafile=str(ca))
    return context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=3),
                               server_hostname="localhost")


def test_controlled_origin_counts_http_chunked_upload_and_wss_without_plaintext(tmp_path):
    cert, key, ca = certificate(tmp_path)
    marker = b"FAKE_DESKTOP_ORIGIN_test_marker"
    origin = ControlledOrigin(cert, key, marker=marker)
    origin.start()
    assert origin.snapshot()["complete_body_bytes"] == 0
    try:
        body_http = b'{"input":"' + marker + b'"}'
        with _tls_client(ca, origin.port) as client:
            client.sendall(b"POST /responses HTTP/1.1\r\nHost: localhost\r\nContent-Length: " +
                           str(len(body_http)).encode() + b"\r\n\r\n" + body_http)
            assert client.recv(1024).startswith(b"HTTP/1.1 200")

        body_upload = b"--fixture\r\nContent-Disposition: form-data; name=upload\r\n\r\n" + marker + b"\r\n--fixture--\r\n"
        pieces = [body_upload[:17], body_upload[17:]]
        with _tls_client(ca, origin.port) as client:
            client.sendall(b"POST /files HTTP/1.1\r\nHost: localhost\r\n"
                           b"Transfer-Encoding: chunked\r\nContent-Type: multipart/form-data; boundary=fixture\r\n\r\n")
            for piece in pieces:
                client.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            client.sendall(b"0\r\n\r\n")
            assert client.recv(1024).startswith(b"HTTP/1.1 200")

        body_wss = b'{"type":"response.create","input":"' + marker + b'"}'
        mask = b"\x12\x34\x56\x78"
        frame = (b"\x81" + bytes([0x80 | len(body_wss)]) + mask +
                 bytes(byte ^ mask[i % 4] for i, byte in enumerate(body_wss)))
        with _tls_client(ca, origin.port) as client:
            client.sendall(b"GET /realtime HTTP/1.1\r\nHost: localhost\r\n"
                           b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                           b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
            assert client.recv(1024).startswith(b"HTTP/1.1 101")
            client.sendall(frame)
        _until(lambda: len(origin.snapshot()["connections"]) == 3)
        rows = origin.snapshot()["connections"]
        assert [row["body_bytes"] for row in rows] == [len(body_http), len(body_upload), len(body_wss)]
        assert all(row["synthetic_marker_present"] and row["complete"] for row in rows)
        assert all("request_line" not in row and "FAKE_DESKTOP" not in str(row) for row in rows)
        assert origin.snapshot()["unverified_connections"] == 0
    finally:
        origin.close()
