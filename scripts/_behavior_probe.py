"""Explicit UAC research harness; the Codex process remains unelevated."""
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import subprocess
import sys
import time

from transpect_trace.observe.elevation import ShellExecuteInfo
from transpect_trace.guard.native import api


class ElevatedProcess:
    def __init__(self, executable, arguments, cwd):
        self.handle = None
        shell = c.WinDLL('shell32', use_last_error=True)
        shell.ShellExecuteExW.argtypes = [c.POINTER(ShellExecuteInfo)]
        shell.ShellExecuteExW.restype = w.BOOL
        info = ShellExecuteInfo(); info.cbSize = c.sizeof(info)
        info.fMask = 0x40 | 0x100; info.lpVerb = 'runas'
        info.lpFile = str(executable); info.lpParameters = subprocess.list2cmdline(list(map(str, arguments)))
        info.lpDirectory = str(cwd); info.nShow = 0
        if not shell.ShellExecuteExW(c.byref(info)):
            raise c.WinError(c.get_last_error())
        self.handle = info.hProcess

    def poll(self):
        if api().WaitForSingleObject(self.handle, 0) == 258:
            return None
        k = api(); k.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
        k.GetExitCodeProcess.restype = w.BOOL
        result = w.DWORD()
        if not k.GetExitCodeProcess(self.handle, c.byref(result)):
            raise c.WinError(c.get_last_error())
        return result.value

    def wait(self, timeout=45):
        end = time.monotonic() + timeout
        while self.poll() is None and time.monotonic() < end:
            time.sleep(.1)
        return self.poll()

    def close(self):
        if self.handle:
            api().CloseHandle(self.handle); self.handle = None


class BehaviorComparison:
    def __init__(self, pid, output, *, elevate=False, collector=None):
        self.output = Path(output); self.elevate = elevate; self.process = None; self.reason = None
        self.pid = pid
        self.collector = collector

    def start(self):
        root = Path(__file__).resolve().parents[1]
        from transpect_trace.observe.windows import identity
        birth = identity(self.pid)['creation_filetime']
        argv = ['-m', 'transpect_trace.cli', 'behavior', 'attach', '--pid', str(self.pid),
                '--expected-creation-filetime', str(birth),
                '--output', str(self.output), '--duration', '20', '--collector', str(self.collector or root / 'build/behavior/etw.exe')]
        try:
            self.process = ElevatedProcess(sys.executable, argv, root) if self.elevate else subprocess.Popen(
                [sys.executable, *argv], cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=0x08000000)
            until = time.monotonic() + 15
            while self.process.poll() is None and time.monotonic() < until:
                path = self.output / 'status.json'
                if path.exists():
                    state = json.loads(path.read_text())['health']['state']
                    if state in ('ready', 'unavailable', 'degraded'):
                        return
                time.sleep(.1)
            self.reason = 'collector_not_ready'
        except OSError as error:
            self.reason = f'launch_error_{getattr(error, "winerror", None)}'

    def close(self):
        if self.process:
            self.process.wait(timeout=35)
            if self.elevate:
                self.process.close()

    def report(self):
        path = self.output / 'status.json'
        return json.loads(path.read_text()) if path.exists() else dict(state='unavailable', reason=self.reason)
