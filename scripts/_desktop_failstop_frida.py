"""Opt-in fail-stop experiment for one isolated synthetic app-server child.

This is not a desktop controller or a graceful deny ABI. A marker match stops
the lab process with exit code 76 before its selected HTTP/WSS send can resume.
The caller must confirm zero target bytes at an independent local receiver.
"""
from __future__ import annotations

import os
from pathlib import Path

from _desktop_capture_frida import CaptureSession
from transpect_trace.guard.desktop import _cim_process, desktop_mode
from transpect_trace.guard.native import command_arguments


class FailStopSession(CaptureSession):
    def __init__(self, pid: int, backend_path: Path, backend_sha256: str,
                 creation_filetime: int, marker: bytes, *, capture_wss: bool = False):
        row = _cim_process(pid)
        if (row.get("ParentProcessId") != os.getpid()
                or desktop_mode(command_arguments(row.get("CommandLine") or "")) != "app-server"):
            raise ValueError("fail-stop target must be a direct synthetic app-server child")
        super().__init__(pid, backend_path, backend_sha256, creation_filetime, marker,
                         capture_wss=capture_wss, fail_stop_on_marker=True)
