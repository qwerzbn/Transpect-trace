"""Windows pipe-server failure test; does not certify injected Native collection."""
import hashlib
import json
import subprocess
import sys
import threading
import time

import pytest


pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Windows Named Pipe cancellation')


def test_close_cancels_partial_frame_without_claiming_terminal(tmp_path):
    from transpect_trace.flow.native import NativeIOCollector
    from transpect_trace.observe.windows import identity

    child = r'''
import ctypes as c
from ctypes import wintypes as w
import sys
import time
k = c.WinDLL('kernel32', use_last_error=True)
k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
k.CreateFileW.restype = w.HANDLE
k.WriteFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
print('ready', flush=True)
name = sys.stdin.readline().strip()
h = k.CreateFileW(name, 0xc0000000, 0, None, 3, 0, None)
if h == w.HANDLE(-1).value:
    raise SystemExit(2)
n = w.DWORD()
if not k.WriteFile(h, b'FIO1', 4, c.byref(n), None):
    raise SystemExit(3)
print('partial-frame-sent', flush=True)
time.sleep(30)
'''
    process = subprocess.Popen([getattr(sys, '_base_executable', sys.executable), '-I', '-c', child],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    collector = None
    try:
        assert process.stdout.readline().strip() == b'ready'
        subject = identity(process.pid)
        dll = tmp_path / 'server-test-not-loaded.dll'
        dll.write_bytes(b'not injected or loaded')
        manifest = tmp_path / 'native-build.json'
        manifest.write_text(json.dumps({'protocol': 'FIO1', 'can_enforce': False,
                                       'artifacts': {dll.name: {'sha256': hashlib.sha256(dll.read_bytes()).hexdigest()}}}))
        collector = NativeIOCollector(subject, dll, manifest, lambda row: None,
                                      scopes=[{'role': 'source', 'path': str(tmp_path / 'fake-source')}])
        collector.thread = threading.Thread(target=collector._serve, daemon=True)
        collector.thread.start()
        assert collector.listening.wait(3)
        process.stdin.write((collector.name + '\n').encode())
        process.stdin.flush()
        assert process.stdout.readline().strip() == b'partial-frame-sent'
        started = time.monotonic()
        collector.close()
        assert time.monotonic() - started < 5
        assert not collector.thread.is_alive()
        assert not collector.status()['terminal']
        assert not collector.status()['terminal_health']
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        if collector and not collector._closed:
            collector.close()
