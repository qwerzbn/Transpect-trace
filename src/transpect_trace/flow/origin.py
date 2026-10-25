"""Loopback HTTPS origin. No forwarding, TLS keys, headers or body persistence."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import ssl
import threading
import time
from uuid import uuid4

LIMIT = 1024 * 1024
IO_TIMEOUT = 10


class Origin:
    def __init__(self, certificate, private_key, *, response_statuses=()):
        if (not isinstance(response_statuses, tuple) or len(response_statuses)>4
                or any(type(s) is not int or s not in (200,503) for s in response_statuses)):
            raise ValueError('invalid_test_response_sequence')
        self.receipts = []
        self.errors = []
        self.lock = threading.Lock()
        self._changed = threading.Condition(self.lock)
        self._closing = threading.Event()
        self._active = {}
        owner = self

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(str(certificate), str(private_key))

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    length = int(self.headers.get('Content-Length', '-1'))
                    if self.path != '/upload' or self.headers.get('Transfer-Encoding') or not 0 <= length <= LIMIT:
                        raise ValueError('unsupported_request')
                    remaining, digest = length, hashlib.sha256()
                    while remaining:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            raise ValueError('incomplete_body')
                        remaining -= len(chunk)
                        digest.update(chunk)
                    with owner.lock:
                        status = response_statuses[len(owner.receipts)] if len(owner.receipts)<len(response_statuses) else 200
                        owner.receipts.append({'receipt_id': uuid4().hex, 'body_sha256': digest.hexdigest(),
                                               'body_bytes': length, 'evidence_source': 'controlled_origin',
                                               **({'response_status':status} if response_statuses else {})})
                    self.send_response(status)
                    self.send_header('Content-Length', '2')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(b'OK')
                    with owner.lock:
                        owner._active[self.connection]['phase'] = 'complete'
                except (ValueError, OSError):
                    self.close_connection = True

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def process_request(self, request, client_address):
                # Register before spawning: close() must also see accepted sockets
                # whose worker has not started yet. The listen socket stays raw.
                with owner.lock:
                    if owner._closing.is_set():
                        self.shutdown_request(request)
                        owner.errors.append('origin_shutdown_pending_connection')
                        return
                    owner._active[request] = {'phase': 'handshake'}
                try:
                    super().process_request(request, client_address)
                except Exception:
                    with owner._changed:
                        owner._active.pop(request, None)
                        owner.errors.append('origin_worker_unavailable')
                        owner._changed.notify_all()
                    self.shutdown_request(request)

            def process_request_thread(self, request, client_address):
                connection = request
                try:
                    # Wrapping does not handshake. Swap the registered socket
                    # atomically so close() cannot miss the descriptor transfer.
                    with owner.lock:
                        if owner._closing.is_set():
                            return
                        connection = context.wrap_socket(request, server_side=True,
                                                         do_handshake_on_connect=False)
                        state = owner._active.pop(request)
                        owner._active[connection] = state
                        connection.settimeout(IO_TIMEOUT)
                    connection.do_handshake()
                    with owner.lock:
                        state['phase'] = 'request'
                    self.finish_request(connection, client_address)
                except Exception:
                    # Exception text may contain request material. The phase
                    # below provides the only exported error information.
                    pass
                finally:
                    self.shutdown_request(connection)
                    with owner._changed:
                        state = owner._active.pop(connection, None)
                        if state and state['phase'] != 'complete':
                            owner.errors.append('origin_handshake_incomplete' if state['phase'] == 'handshake'
                                                else 'origin_request_incomplete')
                        owner._changed.notify_all()

            def handle_error(self, request, client_address):
                with owner.lock:
                    owner.errors.append('origin_worker_unavailable')

        self.server = Server(('127.0.0.1', 0), Handler)
        self.server.timeout = 0.1
        self.url = f'https://localhost:{self.server.server_port}/upload'
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        # handle_request has a bounded poll; neither TLS handshake nor request
        # body reading can block this loop.
        while not self._closing.is_set():
            try:
                self.server.handle_request()
            except (OSError, ValueError):
                if not self._closing.is_set():
                    with self.lock:
                        self.errors.append('origin_accept_failed')
                return

    def start(self):
        self.thread.start()
        return self

    def close(self):
        # Windows may leave an in-flight SSL read asleep after shutdown. Keep
        # the normal I/O timeout and give it a bounded chance to finish, rather
        # than imposing a shorter timeout on otherwise valid fixture uploads.
        deadline = time.monotonic() + IO_TIMEOUT + 2
        self._closing.set()
        self.server.server_close()
        with self.lock:
            connections = list(self._active)
        for connection in connections:
            # shutdown wakes both handshake and makefile-backed body reads;
            # socket.close alone need not interrupt their outstanding handles.
            try:
                # Bypass SSLSocket.shutdown's mutation of _sslobj while a
                # worker may be inside SSL_read; only interrupt the transport.
                socket.socket.shutdown(connection, socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if self.thread.is_alive():
            self.thread.join(2)
        with self._changed:
            while self._active and (remaining := deadline - time.monotonic()) > 0:
                self._changed.wait(remaining)
            if self._active or self.thread.is_alive():
                self.errors.append('origin_close_incomplete')
