"""Restricted, explicit-process Native I/O observation. Payloads stay in memory."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import struct
import threading
import time

LIMIT = 1024 * 1024
HEADER = struct.Struct('<4sI22Q')
FIELDS = ('pid', 'tid', 'creation_filetime', 'sequence', 'qpc', 'handle_id',
          'open_generation', 'connection_generation', 'volume', 'file_id', 'offset',
          'requested_length', 'completed_length', 'win32_error', 'flags', 'peer_pid',
          'peer_creation_filetime', 'length', 'lost_events', 'scope', 'reason', 'completed_qpc')
KINDS = {1: 'init', 2: 'ready', 3: 'open', 4: 'read', 5: 'write', 6: 'close',
         7: 'pipe_connect', 8: 'pipe_disconnect', 9: 'gap', 10: 'terminal'}
REASONS = {0: None, 1: 'size_limit', 2: 'overlapped_io', 3: 'concurrent_handle_io',
           4: 'allocation_failure', 5: 'handle_capacity', 6: 'unsupported_pipe_mode',
           7: 'snapshot_unavailable', 8: 'terminal_with_inflight_io'}


def decode_frame(raw: bytes, data: bytes, *, subject: dict, scopes: list[dict], frequency: int) -> dict:
    """Validate frame shape before exposing bytes to the in-memory consumer."""
    magic, kind, *values = HEADER.unpack(raw)
    if magic != b'FIO1' or kind not in KINDS:
        raise ValueError('invalid_native_io_frame')
    row = dict(zip(FIELDS, values, strict=True))
    if row['pid'] != subject['pid'] or row['creation_filetime'] != subject['creation_filetime']:
        raise ValueError('native_io_identity_mismatch')
    if row['length'] != len(data) or row['length'] > LIMIT:
        raise ValueError('native_io_payload_limit')
    flags = row.pop('flags')
    scope = row.pop('scope')
    if row['completed_qpc'] < row['qpc'] or frequency <= 0:
        raise ValueError('native_io_clock_invalid')
    if kind in (4, 5):
        if row['completed_length'] > row['requested_length']:
            raise ValueError('native_io_completed_range_invalid')
        if not flags & 512 and len(data) != row['completed_length']:
            raise ValueError('native_io_snapshot_range_invalid')
    elif data:
        raise ValueError('native_io_unexpected_payload')
    if kind not in (1, 2, 10) and scope >= len(scopes):
        raise ValueError('native_io_scope_mismatch')
    reason = REASONS.get(row.pop('reason'), 'unknown_native_reason')
    row.update(provider='native-io', kind=KINDS[kind], capture_layer='win32-sync-io',
               can_enforce=False, qpc_frequency=frequency,
               event_id=f"io:{row['pid']}:{row['creation_filetime']}:{row['sequence']}",
               object_kind='file' if flags & 8 else 'pipe' if flags & 16 else 'unknown',
               success=bool(flags & 1), more_data=bool(flags & 2),
               message_complete=bool(flags & 64), data_truncated=bool(flags & 512),
               capture_gap=bool(flags & (4 | 512)), unsupported=[reason or 'unsupported_io'] if flags & 4 else [],
               reason=reason, pipe_server=bool(flags & 1024),
               file_identity=f"{row['volume']:08x}:{row['file_id']:016x}" if flags & 128 else None,
               path_role=scopes[scope]['role'] if kind not in (1, 2, 10) else None,
               data=data)
    if row['object_kind'] == 'pipe':
        row['pipe_identity'] = scopes[scope]['path']
    if not flags & 256:
        row['offset'] = None
    row['handle_id'] = f"{row['handle_id']:x}"
    if not row['peer_pid']:
        row['peer_pid'] = row['peer_creation_filetime'] = None
    return row


def validate_build(dll: Path, build_manifest: Path) -> dict:
    manifest = json.loads(Path(build_manifest).read_text(encoding='utf-8'))
    if manifest.get('protocol') != 'FIO1' or manifest.get('can_enforce') is not False:
        raise ValueError('native_io_build_protocol_mismatch')
    if manifest.get('audit_transport', 'FIO1-legacy') not in {'FIO1-legacy', 'FIO1-ACK1'}:
        raise ValueError('native_io_audit_transport_unsupported')
    expected = manifest.get('artifacts', {}).get(Path(dll).name, {}).get('sha256')
    if not expected or hashlib.sha256(Path(dll).read_bytes()).hexdigest() != expected:
        raise ValueError('native_io_build_hash_mismatch')
    return manifest


class NativeIOCollector:
    def __init__(self, subject: dict, dll: Path, build_manifest: Path, callback, *, scopes: list[dict]):
        from transpect_trace.guard.pipe import windows_api, pipe_security
        self.subject = dict(subject)
        self.dll = Path(dll).resolve()
        self.manifest = validate_build(self.dll, Path(build_manifest))
        self.audit_transport = self.manifest.get('audit_transport', 'FIO1-legacy')
        if not 1 <= len(scopes) <= 4:
            raise ValueError('native_io_scope_count')
        self.scopes = []
        for entry in scopes:
            role = entry['role']
            if role not in {'source', 'transfer', 'pipe'}:
                raise ValueError('native_io_scope_role')
            path = str(entry['path']) if role == 'pipe' else str(Path(entry['path']).resolve())
            if role == 'pipe' and not path.lower().startswith('\\\\.\\pipe\\transpectflowbusiness-'):
                raise ValueError('native_io_business_pipe_required')
            if '\0' in path or len(path.encode('utf-16-le')) > 2046:
                raise ValueError('native_io_scope_path_limit')
            self.scopes.append({'role': role, 'path': path})
        if len({item['path'].casefold() for item in self.scopes}) != len(self.scopes):
            raise ValueError('native_io_scope_alias_conflict')
        self.callback = callback
        paths = [entry['path'].encode('utf-16-le').ljust(2048, b'\0') for entry in self.scopes]
        self.config = struct.pack('<4sIQ', b'FIC1', len(paths), subject['creation_filetime']) + b''.join(paths).ljust(8192, b'\0')
        self.k = windows_api()
        self.security = pipe_security(self.k)
        self.name = rf"\\.\pipe\ttrace-flow-io-{subject['pid']}-{subject['creation_filetime']}"
        self.ready = threading.Event()
        self.terminal = threading.Event()
        self.listening = threading.Event()
        self.stop = threading.Event()
        self._frame_expired = threading.Event()
        self.thread = None
        self.errors = []
        self.lost_events = 0
        self.sequence = 0
        self._closed = False
        frequency = c.c_longlong()
        c.windll.kernel32.QueryPerformanceFrequency(c.byref(frequency))
        self.frequency = frequency.value

    def _read(self, handle, size):
        result = bytearray()
        while len(result) < size:
            if self.stop.is_set() or self._frame_expired.is_set():
                raise TimeoutError('native_io_read_cancelled')
            buffer = c.create_string_buffer(min(65536, size - len(result)))
            count = w.DWORD()
            if not self.k.ReadFile(handle, buffer, len(buffer), c.byref(count), None) or not count.value:
                raise OSError('native_io_frame_incomplete')
            result.extend(buffer.raw[:count.value])
        return bytes(result)

    def _verify_peer(self, handle):
        from transpect_trace.observe.windows import identity
        peer = w.ULONG()
        if not self.k.GetNamedPipeClientProcessId(handle, c.byref(peer)) or peer.value != self.subject['pid']:
            raise ValueError('native_io_pipe_peer_mismatch')
        current = identity(peer.value)
        if any(current[key] != self.subject[key] for key in ('creation_filetime', 'image_sha256')):
            raise ValueError('native_io_pipe_generation_mismatch')

    def _serve(self):
        while not self.stop.is_set():
            handle = self.k.CreateNamedPipeW(self.name, 3 | 0x80000, 8, 1, 65536, 65536, 2000, c.byref(self.security))
            if handle == w.HANDLE(-1).value:
                self.errors.append('native_io_pipe_create_failed')
                return
            self.listening.set()
            deadline = None
            try:
                if self.stop.is_set():
                    continue
                if not self.k.ConnectNamedPipe(handle, None):
                    error = c.get_last_error()
                    if error != 535:
                        if not self.stop.is_set():
                            # A legacy writer may finish and close before this
                            # accept. Windows returns ERROR_NO_DATA even though
                            # WriteFile succeeded; no frame can be certified.
                            self.errors.append('native_io_peer_closed_before_accept' if error == 232
                                               else 'native_io_pipe_connect_failed')
                        continue
                if self.stop.is_set():
                    continue
                self._frame_expired.clear()
                deadline = threading.Timer(10, self._expire_reader)
                deadline.daemon = True
                deadline.start()
                self._verify_peer(handle)
                raw = self._read(handle, HEADER.size)
                header = HEADER.unpack(raw)
                length = header[2 + FIELDS.index('length')]
                if length > LIMIT:
                    raise ValueError('native_io_payload_limit')
                data = self._read(handle, length)
                event = decode_frame(raw, data, subject=self.subject, scopes=self.scopes, frequency=self.frequency)
                if event['kind'] == 'init':
                    count = w.DWORD()
                    if not self.k.WriteFile(handle, self.config, len(self.config), c.byref(count), None) or count.value != len(self.config):
                        raise OSError('native_io_config_write_failed')
                    self.k.FlushFileBuffers(handle)
                else:
                    if event['sequence'] != self.sequence + 1:
                        self.errors.append('native_io_sequence_gap')
                    self.sequence = event['sequence']
                    self.lost_events = max(self.lost_events, event['lost_events'])
                    if event['capture_gap']:
                        self.errors.append(event['reason'] or 'native_io_coverage_gap')
                    self.callback(event)
                    if self.audit_transport == 'FIO1-ACK1':
                        # The ACK is an audit receipt only: the frame identity,
                        # declared bytes and callback have all been checked.
                        # It is never an application authorization decision.
                        count = w.DWORD()
                        if (not self.k.WriteFile(handle, b'\x06', 1, c.byref(count), None)
                                or count.value != 1):
                            raise OSError('native_io_ack_write_failed')
                if self.stop.is_set() or self._frame_expired.is_set():
                    raise TimeoutError('native_io_read_cancelled')
                # ACK1 workers keep their handle until receiving the receipt.
                # Legacy workers close after write completion without a flush;
                # this EOF check cannot repair their pre-accept close race.
                # Waiting for EOF avoids disconnecting an unread ACK/config.
                extra = c.create_string_buffer(1)
                count = w.DWORD()
                ok = self.k.ReadFile(handle, extra, 1, c.byref(count), None)
                if ok and count.value:
                    raise ValueError('native_io_trailing_frame')
                if not ok and c.get_last_error() not in (109, 232):
                    raise OSError('native_io_eof_unconfirmed')
                if event['kind'] == 'ready':
                    self.ready.set()
                if event['kind'] == 'terminal':
                    self.terminal.set()
            except Exception as error:
                self.errors.append(type(error).__name__)
            finally:
                if deadline:
                    deadline.cancel()
                    deadline.join()
                self.k.DisconnectNamedPipe(handle)
                self.k.CloseHandle(handle)

    def _expire_reader(self):
        self._frame_expired.set()
        # Cancellation may race peer verification immediately before ReadFile.
        # Future reads see the flag; repeat briefly to cover entering the API.
        for _ in range(5):
            self._cancel_reader()
            time.sleep(.02)

    def _cancel_reader(self):
        if not self.thread or not self.thread.native_id:
            return
        kernel = c.WinDLL('kernel32', use_last_error=True)
        kernel.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        kernel.OpenThread.restype = w.HANDLE
        kernel.CancelSynchronousIo.argtypes = [w.HANDLE]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        handle = kernel.OpenThread(1, False, self.thread.native_id)
        if handle:
            kernel.CancelSynchronousIo(handle)
            kernel.CloseHandle(handle)

    def start(self):
        from transpect_trace.observe.windows import inject, modules
        if any(Path(module['path']).name.lower() == self.dll.name.lower() for module in modules(self.subject['pid'])):
            raise ValueError('native_io_owner_already_resident')
        self.thread = threading.Thread(target=self._serve, name='flow-native-io', daemon=True)
        self.thread.start()
        if not self.listening.wait(5):
            raise RuntimeError('native_io_listener_unavailable')
        inject(self.subject['pid'], self.dll, self.subject)
        if not self.ready.wait(15):
            raise RuntimeError('native_io_ready_unverified')
        if self.errors:
            raise RuntimeError('native_io_start_failed')
        return self

    def status(self):
        return dict(provider='native-io', pid=self.subject['pid'], creation_filetime=self.subject['creation_filetime'],
                    audit_transport=self.audit_transport,
                    state='degraded' if self.errors or self.lost_events else 'stopped' if self._closed else 'observing' if self.ready.is_set() else 'initializing',
                    ready=self.ready.is_set(), terminal=self.terminal.is_set(), lost_events=self.lost_events,
                    errors=sorted(set(self.errors)), can_enforce=False,
                    terminal_health=self._closed and self.terminal.is_set() and not self.errors and not self.lost_events)

    def _stop_native(self):
        from transpect_trace.observe.windows import identity, modules, exports
        from transpect_trace.guard.native import api
        current = identity(self.subject['pid'])
        if any(current[key] != self.subject[key] for key in ('creation_filetime', 'image_sha256')):
            raise ValueError('native_io_stop_identity_mismatch')
        loaded = next((item for item in modules(self.subject['pid']) if Path(item['path']).resolve() == self.dll), None)
        address = exports(self.dll).get('flow_io_stop')
        if not loaded or not address:
            raise ValueError('native_io_stop_export_unavailable')
        kernel = api()
        handle = kernel.OpenProcess(0x2 | 0x10 | 0x400 | 0x100000, False, self.subject['pid'])
        if not handle:
            raise OSError('native_io_stop_process_unavailable')
        thread = None
        try:
            thread = kernel.CreateRemoteThread(handle, None, 0, loaded['base'] + address, None, 0, None)
            if not thread or kernel.WaitForSingleObject(thread, 10000) != 0:
                raise OSError('native_io_stop_unconfirmed')
            kernel.GetExitCodeThread.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
            kernel.GetExitCodeThread.restype = w.BOOL
            code = w.DWORD()
            if not kernel.GetExitCodeThread(thread, c.byref(code)) or code.value != 0:
                raise OSError('native_io_stop_failed')
            if not self.terminal.wait(2):
                raise OSError('native_io_terminal_missing')
        finally:
            if thread:
                kernel.CloseHandle(thread)
            kernel.CloseHandle(handle)

    def close(self):
        if self._closed:
            return
        try:
            if self.ready.is_set():
                self._stop_native()
        except Exception:
            self.errors.append('native_io_terminal_unavailable')
        self.stop.set()
        self._cancel_reader()
        # Wake an idle ConnectNamedPipe listener after the native worker drained.
        handle = self.k.CreateFileW(self.name, 0xC0000000, 0, None, 3, 0, None)
        if handle != w.HANDLE(-1).value:
            self.k.CloseHandle(handle)
        if self.thread:
            deadline = time.monotonic() + 3
            while self.thread.is_alive() and time.monotonic() < deadline:
                self._cancel_reader()
                self.thread.join(.05)
            if self.thread.is_alive():
                self.errors.append('native_io_listener_stop_unconfirmed')
        if not self.thread or not self.thread.is_alive():
            self.k.LocalFree(self.security.descriptor)
        self._closed = True
