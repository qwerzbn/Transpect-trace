"""Explicit one-shot UAC launch of the verified enhanced collector only.

The medium-integrity controller owns a local user/SYSTEM pipe. Both peers check
Windows-reported process identities. Application data stays in bounded memory.
"""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import os
import struct
import subprocess
import threading
import time
from uuid import uuid4

from transpect_trace.guard.pipe import windows_api, pipe_security


def is_elevated(pid=None):
    if os.name != 'nt':
        return False
    adv = c.WinDLL('advapi32', use_last_error=True)
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    token = w.HANDLE(); value = w.DWORD(); size = w.DWORD()
    k=windows_api();process=w.HANDLE(-1)
    if pid is not None:
        k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
        process=k.OpenProcess(0x1000,False,pid)
        if not process:raise c.WinError(c.get_last_error())
    try:
        if not adv.OpenProcessToken(process, 8, c.byref(token)):
            raise c.WinError(c.get_last_error())
        if not adv.GetTokenInformation(token, 20, c.byref(value), c.sizeof(value), c.byref(size)):
            raise c.WinError(c.get_last_error())
        return bool(value.value)
    finally:
        if token:k.CloseHandle(token)
        if pid is not None:k.CloseHandle(process)


def elevation_error(code):
    return 'elevation_cancelled' if code == 1223 else 'elevation_access_denied' if code == 5 else 'elevation_launch_failed'


def validate_relay_header(raw):
    if len(raw) != 5:
        raise ValueError('invalid_elevation_frame')
    kind, length = raw[:1], struct.unpack('<I', raw[1:])[0]
    limits = {b'D': 65648, b'E': 512, b'X': 4}
    if kind not in limits or not 0 < length <= limits[kind] or (kind == b'X' and length != 4):
        raise ValueError('invalid_elevation_frame')
    return kind, length


class BoundedStream:
    """Small blocking byte stream; overload is an explicit capture failure."""
    def __init__(self, limit=1024*1024):
        self.limit = limit; self.buffer = bytearray(); self.condition = threading.Condition()
        self.eof = False; self.closed = False

    def feed(self, data):
        with self.condition:
            if self.closed or self.eof:
                raise OSError('elevation_stream_closed')
            if len(self.buffer) + len(data) > self.limit:
                raise OSError('elevation_buffer_limit')
            self.buffer.extend(data); self.condition.notify_all()

    def finish(self):
        with self.condition:
            self.eof = True; self.condition.notify_all()

    def _read(self, size, line=False):
        if size <= 0:
            return b''
        with self.condition:
            while True:
                end = self.buffer.find(b'\n') + 1 if line else 0
                if self.closed or self.eof or (self.buffer and not line) or end or len(self.buffer) >= size:
                    count = min(size, end or len(self.buffer))
                    result = bytes(self.buffer[:count]); del self.buffer[:count]
                    return result
                self.condition.wait()

    def read(self, size): return self._read(size)
    def readline(self, size): return self._read(size, True)
    def close(self):
        with self.condition:
            self.closed = True; self.buffer.clear(); self.condition.notify_all()


class ShellExecuteInfo(c.Structure):
    _fields_ = [('cbSize', w.DWORD), ('fMask', w.ULONG), ('hwnd', w.HWND),
                ('lpVerb', w.LPCWSTR), ('lpFile', w.LPCWSTR), ('lpParameters', w.LPCWSTR),
                ('lpDirectory', w.LPCWSTR), ('nShow', c.c_int), ('hInstApp', w.HINSTANCE),
                ('lpIDList', c.c_void_p), ('lpClass', w.LPCWSTR), ('hkeyClass', w.HKEY),
                ('dwHotKey', w.DWORD), ('hIcon', w.HANDLE), ('hProcess', w.HANDLE)]


class StopInput:
    def __init__(self, owner): self.owner = owner; self.closed = False
    def write(self, data):
        if self.closed or data != b'X': raise OSError('invalid_elevation_stop')
        sent = w.DWORD()
        if not self.owner.k.WriteFile(self.owner.pipe, data, 1, c.byref(sent), None) or sent.value != 1:
            raise OSError('elevation_stop_failed')
        return 1
    def flush(self): pass
    def close(self): self.closed = True


class ElevatedCapture:
    """Popen-compatible subset; no shell interpolation or inherited environment."""
    def __init__(self, executable, subject, manifest):
        self.executable = executable.resolve(); self.subject = subject; self.manifest = manifest
        self.stdout = BoundedStream(); self.stderr = BoundedStream(4096); self.stdin = StopInput(self)
        self.errors = []; self.process_handle = None; self.pipe = None; self.pid = None; self.thread = None
        self.closed = threading.Event(); self.returncode = None
        self.k = windows_api()
        signatures = {
            'GetProcessId': ([w.HANDLE], w.DWORD),
            'GetExitCodeProcess': ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
            'WaitForSingleObject': ([w.HANDLE, w.DWORD], w.DWORD),
            'TerminateProcess': ([w.HANDLE, w.UINT], w.BOOL),
            'PeekNamedPipe': ([w.HANDLE,c.c_void_p,w.DWORD,c.c_void_p,c.POINTER(w.DWORD),c.c_void_p],w.BOOL),
        }
        for name, (args, result) in signatures.items():
            getattr(self.k, name).argtypes = args; getattr(self.k, name).restype = result

    def start(self):
        from .windows import identity
        parent = identity(os.getpid())
        name = rf'\\.\pipe\ttrace-ecapture-uac-{uuid4().hex}'
        security = pipe_security(self.k)
        try:
            self.pipe = self.k.CreateNamedPipeW(name, 3|0x80000, 1|8, 1, 65536, 65536, 1000, c.byref(security))
        finally:
            self.k.LocalFree(security.descriptor)
        if self.pipe == w.HANDLE(-1).value:
            self.pipe = None
            raise c.WinError(c.get_last_error())
        args = ['--ttrace-elevated-ECW2', name, str(parent['pid']), str(parent['creation_filetime']),
                str(self.subject['pid']), str(self.subject['creation_filetime']), self.subject['image_sha256'],
                self.manifest['artifacts_sha256']['schannel_hook.dll'], self.manifest['artifacts_sha256']['ecapture.exe']]
        info = ShellExecuteInfo(cbSize=c.sizeof(ShellExecuteInfo), fMask=0x40|0x100|0x400,
            lpVerb='runas', lpFile=str(self.executable), lpParameters=subprocess.list2cmdline(args),
            lpDirectory=str(self.executable.parent), nShow=0)
        shell = c.WinDLL('shell32', use_last_error=True)
        shell.ShellExecuteExW.argtypes = [c.POINTER(ShellExecuteInfo)]; shell.ShellExecuteExW.restype = w.BOOL
        try:
            # Windows displays UAC. Consent is always handled by the human user.
            if not shell.ShellExecuteExW(c.byref(info)):
                reason = elevation_error(c.get_last_error()); self.errors.append(reason)
                raise OSError(reason)
            self.process_handle = info.hProcess; self.pid = self.k.GetProcessId(self.process_handle)
            if not self.pid: raise OSError('elevation_process_identity_unavailable')
            deadline = time.monotonic() + 15
            while True:
                if self.k.ConnectNamedPipe(self.pipe, None) or c.get_last_error() == 535: break
                if c.get_last_error() != 536 or self.poll() is not None or time.monotonic() > deadline:
                    raise OSError('elevation_handshake_failed')
                time.sleep(.01)
            peer = w.ULONG()
            if not self.k.GetNamedPipeClientProcessId(self.pipe, c.byref(peer)) or peer.value != self.pid:
                raise OSError('elevation_peer_mismatch')
            self.thread = threading.Thread(target=self._relay, daemon=True)
            self.thread.start()
            return self
        except BaseException:
            if self.process_handle and self.poll() is None:
                self.terminate(); self.wait(5)
            self.close()
            raise

    def _read_exact(self, count):
        result = bytearray()
        while len(result) < count and not self.closed.is_set():
            available = w.DWORD()
            if not self.k.PeekNamedPipe(self.pipe, None, 0, None, c.byref(available), None):
                raise EOFError('elevation_pipe_disconnected')
            if not available.value:
                if self.poll() is not None: raise EOFError('elevation_process_exited')
                self.closed.wait(.005); continue
            buf = c.create_string_buffer(min(count-len(result), available.value)); got = w.DWORD()
            if not self.k.ReadFile(self.pipe, buf, len(buf), c.byref(got), None) or not got.value:
                raise OSError('elevation_read_failed')
            result.extend(buf.raw[:got.value])
        if len(result) != count: raise EOFError('elevation_closed')
        return bytes(result)

    def _relay(self):
        try:
            while not self.closed.is_set():
                kind, size = validate_relay_header(self._read_exact(5)); data = self._read_exact(size)
                if kind == b'X':
                    code = struct.unpack('<I', data)[0]
                    if code: self.errors.append('elevated_collector_failed')
                    if self.wait(7) != code: self.errors.append('elevation_exit_mismatch')
                    return
                (self.stdout if kind == b'D' else self.stderr).feed(data)
        except (OSError, EOFError, ValueError, subprocess.TimeoutExpired):
            self.errors.append('elevation_transport_failed')
        finally:
            self.stdout.finish(); self.stderr.finish()

    def poll(self):
        if self.returncode is not None: return self.returncode
        if not self.process_handle: return None
        if self.k.WaitForSingleObject(self.process_handle, 0) == 0:
            code = w.DWORD()
            if not self.k.GetExitCodeProcess(self.process_handle, c.byref(code)): raise c.WinError(c.get_last_error())
            self.returncode = code.value
        return self.returncode

    def wait(self, timeout=None):
        milliseconds = 0xffffffff if timeout is None else max(0, int(timeout*1000))
        if self.k.WaitForSingleObject(self.process_handle, milliseconds) != 0:
            raise subprocess.TimeoutExpired('elevated ecapture', timeout)
        return self.poll()

    def terminate(self):
        if self.poll() is None and not self.k.TerminateProcess(self.process_handle, 1):
            raise c.WinError(c.get_last_error())

    def close(self):
        self.closed.set()
        if self.thread: self.thread.join(2)
        for stream in (self.stdout, self.stderr, self.stdin): stream.close()
        if self.pipe: self.k.CloseHandle(self.pipe); self.pipe = None
        if self.process_handle: self.k.CloseHandle(self.process_handle); self.process_handle = None
