"""Non-forwarding localhost TLS fixtures and redacted reception evidence.

The Git repository is an explicit fake-data fixture, not a default audit log.
Bodies are passed to in-memory callbacks; receipt files are never written by
this module. Receiving bytes, inspecting objects, and updating refs are separate
facts. These source-side facts do not certify any endpoint collector.
"""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import subprocess
import sys
import threading
import time
import zlib
from urllib.parse import urlsplit
from uuid import uuid4

LIMIT = 1024 * 1024
GIT_TRANSPORT_LIMIT = 8 * LIMIT
GIT_OBJECT_BYTES_LIMIT = 16 * LIMIT
GIT_OBJECT_COUNT_LIMIT = 2048
IO_TIMEOUT = 10


def clean_git_environment():
    """Isolate the fixture from credential helpers and user's Git configuration."""
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith('GIT_') and k.upper() not in
           {'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'SSH_ASKPASS'} }
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT='0', GCM_INTERACTIVE='never')
    return env


class BodyError(ValueError):
    def __init__(self, code, observed=b''):
        super().__init__(code)
        self.code, self.observed = code, observed


class ModelEncodingError(ValueError):
    def __init__(self, code, status):
        super().__init__(code)
        self.code, self.status = code, status


class GitCommandError(ValueError):
    def __init__(self, result):
        super().__init__('git_fixture_command_failed')
        self.diagnostic = {'returncode': result.returncode,
            'stdout_bytes': len(result.stdout), 'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'stderr_bytes': len(result.stderr), 'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}


def decode_model_body(body, headers, receipt):
    """Keep transport evidence separate from the model fixture's decoded JSON."""
    from transpect_trace.observe.protocol import decode_body
    receipt.update(raw_body_sha256=hashlib.sha256(body).hexdigest(), raw_body_bytes=len(body),
                   decoded_body_sha256=None, decoded_body_bytes=None, decoding_state='unknown')
    values = headers.get_all('Content-Encoding', [])
    if len(values) > 1:
        receipt.update(content_encoding='unknown', decoding_state='unsupported')
        raise ModelEncodingError('ambiguous_model_content_encoding', 400)
    encoding = values[0].strip().lower() if values else 'identity'
    if encoding not in {'identity', 'gzip', 'deflate', 'zstd'}:
        # Never put an arbitrary header value into the default audit.
        receipt.update(content_encoding='unsupported', decoding_state='unsupported')
        raise ModelEncodingError('unsupported_model_content_encoding', 415)
    receipt['content_encoding'] = encoding
    try:
        # The shared decoder validates frame completion/trailers and has its own
        # finite 16 MiB ceiling. This fixture imposes the stricter 1 MiB ceiling
        # before any JSON parsing or model callback.
        decoded = decode_body(body, encoding)
    except (ValueError, zlib.error):
        receipt['decoding_state'] = 'failed'
        raise ModelEncodingError('invalid_model_encoded_body', 400) from None
    if len(decoded) > LIMIT:
        receipt.update(decoding_state='oversized', decoded_body_bytes=len(decoded))
        raise ModelEncodingError('decoded_model_body_limit_exceeded', 413)
    receipt.update(decoded_body_sha256=hashlib.sha256(decoded).hexdigest(), decoded_body_bytes=len(decoded),
                   decoding_state='identity' if encoding == 'identity' else 'decoded')
    return decoded


def read_bounded_body(stream, headers, limit=LIMIT):
    """Read entity bytes, validating HTTP framing before trusting completeness."""
    lengths = headers.get_all('Content-Length', [])
    encodings = headers.get_all('Transfer-Encoding', [])
    if len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings):
        raise BodyError('ambiguous_body_framing')
    result = bytearray()

    def exact(count):
        while count:
            try:
                # BufferedReader.read(n) may discard an already received prefix
                # when a later socket read times out. Retain each available
                # prefix so partial reception remains measurable.
                data = (stream.read1 if hasattr(stream, 'read1') else stream.read)(min(count, 65536))
            except (OSError, TimeoutError):
                raise BodyError('body_read_failed', bytes(result)) from None
            if not data:
                raise BodyError('truncated_body', bytes(result))
            result.extend(data)
            count -= len(data)

    if encodings:
        if encodings[0].strip().lower() != 'chunked':
            raise BodyError('unsupported_transfer_encoding')
        while True:
            try:
                line = stream.readline(1025)
            except OSError:
                raise BodyError('truncated_chunk_header', bytes(result)) from None
            if len(line) > 1024 or not re.fullmatch(rb'[0-9A-Fa-f]{1,8}\r\n', line):
                raise BodyError('unsupported_chunk_header', bytes(result))
            count = int(line[:-2], 16)
            if count > limit - len(result):
                raise BodyError('body_limit_exceeded', bytes(result))
            if count == 0:
                # No request trailers in these explicit controlled fixtures.
                if stream.readline(3) != b'\r\n':
                    raise BodyError('unsupported_chunk_trailers', bytes(result))
                return bytes(result)
            exact(count)
            if stream.read(2) != b'\r\n':
                raise BodyError('truncated_chunk_end', bytes(result))
    if not lengths:
        raise BodyError('missing_body_length')
    if not re.fullmatch(r'[0-9]{1,10}', lengths[0].strip()):
        raise BodyError('invalid_body_length')
    count = int(lengths[0])
    if count > limit:
        raise BodyError('body_limit_exceeded')
    exact(count)
    return bytes(result)


class GitStore:
    """An isolated small bare repository with live quarantine observation."""
    def __init__(self, root, git, *, on_blob=None, reject_refs=False):
        self.root, self.git = Path(root).resolve(), str(Path(git).resolve())
        self.root.mkdir(parents=True, exist_ok=False)
        self.bare = self.root / 'target.git'
        self.env, self.on_blob, self.reject_refs = clean_git_environment(), on_blob, reject_refs
        self.lock = threading.Lock()
        self.run(['init', '--bare', str(self.bare)])
        self.run(['--git-dir', str(self.bare), 'config', 'http.receivepack', 'true'])
        self.run(['--git-dir', str(self.bare), 'config', 'receive.maxInputSize', str(GIT_TRANSPORT_LIMIT)])
        directory = Path(self.run(['--exec-path']).stdout.decode().strip())
        self.backend = directory / ('git-http-backend.exe' if os.name == 'nt' else 'git-http-backend')
        if not self.backend.is_file():
            raise ValueError('git_http_backend_unavailable')
        helper = Path(__file__).with_name('_git_receive.py').resolve()
        # Fixed executable + source path. Neither request data nor ref names are
        # interpolated into this hook command. No user's shell/profile is used.
        python = Path(sys.base_prefix) / ('python.exe' if os.name == 'nt' else 'bin/python3')
        if not python.is_file():
            python = Path(sys.executable)
        hook = self.bare / 'hooks/pre-receive'
        hook.write_text('#!/bin/sh\nexec ' + shlex.quote(python.as_posix()) + ' -I -S -B '
                        + shlex.quote(helper.as_posix()) + '\n', encoding='utf-8', newline='\n')
        if os.name != 'nt':
            hook.chmod(0o700)

    def run(self, arguments, *, environment=None, data=None):
        result = subprocess.run([self.git, '-c', 'credential.helper=', '-c', 'http.proxy=', *arguments],
                                env=environment or self.env, input=data, capture_output=True, timeout=20)
        if result.returncode:
            raise GitCommandError(result)
        if len(result.stdout) > GIT_OBJECT_BYTES_LIMIT:
            raise ValueError('git_command_output_limit')
        return result

    def refs(self):
        raw = self.run(['--git-dir', str(self.bare), 'for-each-ref', '--format=%(refname) %(objectname)']).stdout
        result = {}
        for line in raw.splitlines():
            name, oid = line.rsplit(b' ', 1)
            result[hashlib.sha256(name).hexdigest()] = oid.decode('ascii')
        return result

    def objects(self, environment=None):
        raw = self.run(['--git-dir', str(self.bare), 'cat-file', '--batch-all-objects',
                        '--batch-check=%(objectname) %(objecttype) %(objectsize)'], environment=environment).stdout
        objects, total = {}, 0
        for line in raw.splitlines():
            oid, kind, length = line.decode('ascii').split()
            count = int(length)
            total += count
            if len(objects) >= GIT_OBJECT_COUNT_LIMIT or count > LIMIT or total > GIT_OBJECT_BYTES_LIMIT:
                raise ValueError('git_object_inspection_limit')
            objects[oid] = (kind, count)
        return objects

    def _inspect_new(self, before, environment, evidence):
        evidence['inspection_phase'] = 'enumerate_objects'
        received = self.objects(environment)
        evidence['new_objects'] = []
        for oid, (kind, size) in received.items():
            if oid in before:
                continue
            row = {'object_id': oid, 'object_type': kind, 'object_bytes': size,
                   'attempt_id': evidence['attempt_id'],
                   'evidence_source': 'controlled_git_quarantine', 'can_enforce': False}
            blob = None
            evidence['inspection_phase'] = 'inspect_' + kind
            if kind == 'blob':
                data = self.run(['--git-dir', str(self.bare), 'cat-file', 'blob', oid], environment=environment).stdout
                if len(data) != size:
                    raise ValueError('git_blob_length_mismatch')
                row['content_sha256'] = hashlib.sha256(data).hexdigest()
                blob = data
            elif kind == 'commit':
                data = self.run(['--git-dir', str(self.bare), 'cat-file', 'commit', oid], environment=environment).stdout
                header = data.split(b'\n\n', 1)[0].splitlines()
                tree = [line[5:].decode('ascii') for line in header if line.startswith(b'tree ')]
                parents = [line[7:].decode('ascii') for line in header if line.startswith(b'parent ')]
                if len(tree) != 1 or len(parents) > 64 or any(not re.fullmatch(r'[0-9a-f]{40,64}', item) for item in tree + parents):
                    raise ValueError('git_commit_graph_invalid')
                row.update(tree_object_id=tree[0], parent_object_ids=parents)
            elif kind == 'tree':
                data = self.run(['--git-dir', str(self.bare), 'ls-tree', '-z', oid], environment=environment).stdout
                entries = []
                for entry in data.split(b'\0'):
                    if not entry:
                        continue
                    attributes, name = entry.split(b'\t', 1)
                    mode, entry_kind, entry_oid = attributes.decode('ascii').split()
                    if len(entries) >= GIT_OBJECT_COUNT_LIMIT:
                        raise ValueError('git_tree_inspection_limit')
                    entries.append({'mode': mode, 'object_type': entry_kind, 'object_id': entry_oid,
                                    'name_sha256': hashlib.sha256(name).hexdigest()})
                row['entries'] = entries
            evidence['new_objects'].append(row)
            if blob is not None and self.on_blob is not None:
                evidence['inspection_phase'] = 'blob_callback'
                self.on_blob(blob, dict(row))
        evidence['inspection_phase'] = 'complete'

    def dispatch(self, method, path, query, body, content_type, attempt_id):
        """Return CGI status/headers/payload plus source-only reception evidence."""
        with self.lock:
            incoming = method == 'POST'
            env = dict(self.env, GIT_PROJECT_ROOT=self.root.as_posix(), GIT_HTTP_EXPORT_ALL='1',
                       PATH_INFO=path, QUERY_STRING=query, REQUEST_METHOD=method,
                       CONTENT_TYPE=content_type, CONTENT_LENGTH=str(len(body)),
                       REMOTE_USER='fixture', REMOTE_ADDR='127.0.0.1', SERVER_PROTOCOL='HTTP/1.1')
            evidence = {'attempt_id': attempt_id, 'refs_before': self.refs(), 'refs_after': {},
                        'new_objects': [], 'quarantine_observed': False, 'inspection_complete': False,
                        'ref_update_observed': False, 'can_enforce': False, 'limitations': [],
                        'evidence_source': 'controlled_git_origin'}
            before = self.objects()
            handoff = self.root / 'capture-handoffs' / attempt_id
            if incoming:
                handoff.mkdir(parents=True)
                env['TTRACE_GIT_CAPTURE_DIR'] = str(handoff)
            process = subprocess.Popen([str(self.backend)], env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result, failures = [], []

            def communicate():
                try:
                    result.append(process.communicate(body, timeout=30))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    failures.append('git_backend_timeout')

            worker = threading.Thread(target=communicate, daemon=True)
            worker.start()
            handled = False

            def release(decision):
                pending = handoff / 'release.pending'
                pending.write_bytes(decision)
                pending.replace(handoff / 'release')

            try:
                deadline = time.monotonic() + 25
                while worker.is_alive() and time.monotonic() < deadline:
                    ready = handoff / 'ready.json'
                    if incoming and not handled and ready.is_file():
                        handled = True
                        evidence['inspection_phase'] = 'read_ready_metadata'
                        value = json.loads(ready.read_text(encoding='utf-8'))
                        evidence['inspection_phase'] = 'validate_quarantine_identity'
                        directory = Path(value['object_directory']).resolve()
                        if (not directory.is_relative_to((self.bare / 'objects').resolve())
                                or directory == (self.bare / 'objects').resolve()):
                            raise ValueError('git_quarantine_identity_invalid')
                        quarantine_env = dict(self.env, GIT_OBJECT_DIRECTORY=str(directory),
                                              GIT_ALTERNATE_OBJECT_DIRECTORIES=str(self.bare / 'objects'))
                        evidence['quarantine_observed'] = True
                        self._inspect_new(before, quarantine_env, evidence)
                        evidence['inspection_complete'] = True
                        release(b'reject' if self.reject_refs else b'allow')
                    worker.join(.01)
                if worker.is_alive():
                    raise ValueError('git_backend_timeout')
            except Exception as error:
                evidence['limitations'].append('git_quarantine_inspection_failed')
                evidence['inspection_error_type'] = type(error).__name__
                known = {'git_quarantine_identity_invalid', 'git_object_inspection_limit', 'git_fixture_command_failed',
                         'git_command_output_limit', 'git_blob_length_mismatch', 'git_commit_graph_invalid',
                         'git_tree_inspection_limit', 'git_backend_timeout'}
                if isinstance(error, ValueError) and error.args and isinstance(error.args[0], str) and error.args[0] in known:
                    evidence['inspection_error_code'] = error.args[0]
                if isinstance(error, OSError):
                    evidence['inspection_os_error'] = {'errno': error.errno, 'winerror': getattr(error, 'winerror', None)}
                if isinstance(error, GitCommandError):
                    evidence['git_command_diagnostic'] = error.diagnostic
                if incoming:
                    release(b'reject')
                worker.join(2)
                if worker.is_alive():
                    process.kill()
                    worker.join(3)
            evidence['backend_exit'] = process.poll()
            decision_file = handoff / 'decision.json'
            if incoming and decision_file.is_file():
                decision = json.loads(decision_file.read_text(encoding='utf-8')).get('decision')
                if decision in ('allow', 'reject'):
                    evidence['fixture_pre_receive_decision'] = decision
            evidence['refs_after'] = self.refs()
            evidence['ref_update_observed'] = evidence['refs_before'] != evidence['refs_after']
            if incoming and not handled:
                evidence['limitations'].append('git_quarantine_not_observed')
            if failures:
                evidence['limitations'].extend(failures)
            if not result or process.returncode != 0:
                return 502, {}, b'fixture backend failed', evidence
            output = result[0][0]
            evidence['backend_stderr_bytes'] = len(result[0][1])
            evidence['backend_stderr_sha256'] = hashlib.sha256(result[0][1]).hexdigest()
            if len(output) > GIT_TRANSPORT_LIMIT:
                evidence['limitations'].append('git_response_limit')
                return 502, {}, b'fixture response too large', evidence
            header, separator, payload = output.partition(b'\r\n\r\n')
            if not separator:
                header, separator, payload = output.partition(b'\n\n')
            if not separator or len(header) > 65536:
                return 502, {}, b'fixture invalid response', evidence
            headers = {}
            status = 200
            for line in header.splitlines():
                key, _, value = line.decode('latin1').partition(':')
                if key.lower() == 'status':
                    status = int(value.strip().split()[0])
                elif key.lower() in ('content-type', 'cache-control', 'expires', 'pragma'):
                    headers[key] = value.strip()
            return status, headers, payload, evidence


class BusinessOrigin:
    def __init__(self, certificate, private_key, *, ticket_bytes=b'{}', on_body=None,
                 git_root=None, git=None, on_git_blob=None, reject_refs=False, response_statuses=(),
                 git_auth_challenge=False, model_reply=None, before_git_reply=None):
        if not isinstance(ticket_bytes, bytes) or len(ticket_bytes) > LIMIT:
            raise ValueError('ticket_limit_or_type')
        if (not isinstance(response_statuses, tuple) or len(response_statuses) > 16
                or any(type(s) is not int or s not in (200, 503) for s in response_statuses)):
            raise ValueError('invalid_response_sequence')
        self.receipts, self.git_receipts, self.errors = [], [], []
        self.lock, self._closing = threading.Lock(), threading.Event()
        self._active, self.on_body, self._webhook_count = {}, on_body, 0
        self.git_store = GitStore(git_root, git, on_blob=on_git_blob, reject_refs=reject_refs) if git_root and git else None
        if bool(git_root) != bool(git):
            raise ValueError('git_root_and_binary_required')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(str(certificate), str(private_key))
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def send_result(self, status, payload, headers=None):
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(payload)
                self.close_connection = True

            def dispatch(self):
                attempt_id = uuid4().hex
                with owner.lock:
                    owner._active[self.connection] = 'body'
                row = {'attempt_id': attempt_id, 'receipt_id': attempt_id, 'method': self.command,
                       'route': 'unknown', 'body_bytes': 0, 'body_sha256': hashlib.sha256(b'').hexdigest(),
                       'completeness': 'unknown', 'evidence_source': 'controlled_origin', 'can_enforce': False}
                row['tls_version'] = self.connection.version()
                cipher = self.connection.cipher()
                row['tls_cipher'] = cipher[0] if cipher else None
                row['alpn'] = self.connection.selected_alpn_protocol()
                status = 400
                try:
                    url = urlsplit(self.path)
                    key = self.command, url.path, url.query
                    if key == ('POST', '/responses', '') and model_reply is not None:
                        row['route'] = 'model'
                        body = read_bounded_body(self.rfile, self.headers)
                        row.update(body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest(), completeness='complete')
                        decoded = decode_model_body(body, self.headers, row)
                        events = model_reply(decoded, dict(row))
                        if not isinstance(events, list) or len(events) > 64 or any(not isinstance(event, dict) for event in events):
                            raise ValueError('invalid_controlled_model_events')
                        payload = b''.join(b'data: ' + json.dumps(event, ensure_ascii=False).encode('utf-8') + b'\n\n' for event in events)
                        if len(payload) > LIMIT:
                            raise ValueError('model_fixture_response_limit')
                        status = 200
                        self.send_result(status, payload, {'Content-Type': 'text/event-stream'})
                    elif key == ('GET', '/ticket', ''):
                        row['route'] = 'ticket'
                        row['completeness'] = 'complete'
                        row['response_body_bytes'] = len(ticket_bytes)
                        row['response_body_sha256'] = hashlib.sha256(ticket_bytes).hexdigest()
                        status = 200
                        self.send_result(status, ticket_bytes, {'Content-Type': 'application/json; charset=utf-8'})
                    elif self.command in ('POST', 'PUT') and url.path == '/webhook' and not url.query:
                        row['route'] = 'webhook'
                        body = read_bounded_body(self.rfile, self.headers)
                        row.update(body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest(), completeness='complete')
                        if owner.on_body is not None:
                            owner.on_body(body, dict(row))
                        with owner.lock:
                            index = owner._webhook_count
                            owner._webhook_count += 1
                        status = response_statuses[index] if index < len(response_statuses) else 200
                        self.send_result(status, b'OK')
                    elif owner.git_store and key in (
                            ('GET', '/target.git/info/refs', 'service=git-receive-pack'),
                            ('POST', '/target.git/git-receive-pack', '')):
                        row['route'] = 'git_advertisement' if self.command == 'GET' else 'git_receive'
                        # Deliberately public fake fixture credentials. The
                        # challenge is a controlled startup rendezvous, not
                        # evidence that any real service authentication passed.
                        if git_auth_challenge and self.headers.get('Authorization') != 'Basic Zml4dHVyZTpmaXh0dXJl':
                            row['completeness'] = 'complete' if self.command == 'GET' else 'unknown'
                            row['fixture_authentication'] = 'challenged'
                            status = 401
                            self.send_result(status, b'fixture authentication required', {'WWW-Authenticate': 'Basic realm="transpect-fake-only"'})
                            return
                        body = read_bounded_body(self.rfile, self.headers, GIT_TRANSPORT_LIMIT) if self.command == 'POST' else b''
                        row.update(body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest(), completeness='complete')
                        if body and owner.on_body is not None:
                            owner.on_body(body, dict(row))
                        status, headers, response, evidence = owner.git_store.dispatch(
                            self.command, url.path, url.query, body, self.headers.get('Content-Type', ''), attempt_id)
                        if self.command == 'POST':
                            with owner.lock:
                                owner.git_receipts.append(evidence)
                            if before_git_reply is not None:
                                before_git_reply(dict(evidence))
                        self.send_result(status, response, headers)
                    else:
                        row['error'] = 'unsupported_route'
                        status = 404
                        self.send_result(status, b'unsupported fixture route')
                except ModelEncodingError as error:
                    row['error'] = error.code
                    status = error.status
                    try:
                        self.send_result(status, b'invalid fixture model encoding')
                    except OSError:
                        pass
                except BodyError as error:
                    row.update(completeness='partial', body_bytes=len(error.observed),
                               body_sha256=hashlib.sha256(error.observed).hexdigest(), error=error.code)
                    status = 413 if error.code == 'body_limit_exceeded' else 400
                    try:
                        self.send_result(status, b'invalid fixture request')
                    except OSError:
                        pass
                except Exception:
                    row['error'] = 'origin_request_or_callback_failed'
                    status = 500
                    try:
                        self.send_result(status, b'fixture processing failed')
                    except OSError:
                        pass
                finally:
                    row['response_status'] = status
                    with owner.lock:
                        owner.receipts.append(row)
                        owner._active[self.connection] = 'complete'

            do_GET = dispatch
            do_POST = dispatch
            do_PUT = dispatch

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def process_request(self, request, client_address):
                with owner.lock:
                    if owner._closing.is_set():
                        self.shutdown_request(request)
                        return
                    owner._active[request] = 'handshake'
                super().process_request(request, client_address)

            def process_request_thread(self, request, client_address):
                connection = request
                try:
                    with owner.lock:
                        connection = context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                        owner._active.pop(request, None)
                        owner._active[connection] = 'handshake'
                        connection.settimeout(IO_TIMEOUT)
                    connection.do_handshake()
                    with owner.lock:
                        owner._active[connection] = 'request'
                    self.finish_request(connection, client_address)
                except Exception:
                    pass
                finally:
                    self.shutdown_request(connection)
                    with owner.lock:
                        phase = owner._active.pop(connection, None)
                        if phase != 'complete':
                            owner.errors.append('origin_handshake_incomplete' if phase == 'handshake' else 'origin_request_incomplete')

            def handle_error(self, *_):
                with owner.lock:
                    owner.errors.append('origin_worker_failed')

        self.server = Server(('127.0.0.1', 0), Handler)
        self.server.timeout = .1
        self.port = self.server.server_port
        self.url = f'https://localhost:{self.port}'
        self.ticket_url, self.webhook_url, self.git_url = (self.url + path for path in ('/ticket', '/webhook', '/target.git'))
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._closing.is_set():
            try:
                self.server.handle_request()
            except (OSError, ValueError):
                if not self._closing.is_set():
                    self.errors.append('origin_accept_failed')
                return

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self._closing.set()
        self.server.server_close()
        with self.lock:
            connections = list(self._active)
        for connection in connections:
            try:
                socket.socket.shutdown(connection, socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if self.thread.is_alive():
            self.thread.join(2)
        deadline = time.monotonic() + IO_TIMEOUT + 2
        while self._active and time.monotonic() < deadline:
            time.sleep(.01)
        if self._active or self.thread.is_alive():
            self.errors.append('origin_close_incomplete')
