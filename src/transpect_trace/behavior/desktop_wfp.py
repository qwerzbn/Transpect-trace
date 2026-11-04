"""VM-only WFP boundary for a pinned Codex desktop demo.

The native utility owns BFE objects. This wrapper never silently installs or
removes persistent policy. A live permit exists only while its process holds a
dynamic WFP session, and only after a guarded process signals readiness.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable
import ipaddress
import json
import os
from pathlib import Path
from queue import Queue, Empty
import re
import subprocess
from threading import Thread


class WfpBoundaryError(RuntimeError):
    pass


def _own_creation_filetime() -> int:
    """Bind a lease to this controller instance, not merely its reusable PID."""
    import ctypes
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileTime),
                                       ctypes.POINTER(FileTime), ctypes.POINTER(FileTime),
                                       ctypes.POINTER(FileTime)]
    times = [FileTime() for _ in range(4)]
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), *(ctypes.byref(t) for t in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    return times[0].low | (times[0].high << 32)


@dataclass
class WfpLease:
    process: subprocess.Popen
    filter_id: int
    pid_exact_filter: bool

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    def close(self) -> None:
        if self.alive:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()

    def __enter__(self) -> WfpLease:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class WfpBoundary:
    def __init__(self, executable: Path, sid: str, *, isolated_vm: bool = False,
                 tool_sids: Iterable[str] = ()):
        if not isolated_vm:
            raise WfpBoundaryError("WFP desktop policy is restricted to an isolated VM")
        sid_pattern = r"S-1-5-21-(?:\d+-){2}\d+-\d+"
        if not re.fullmatch(sid_pattern, sid):
            raise ValueError("expected a dedicated local user SID")
        tool_sids = tuple(tool_sids)
        if any(not re.fullmatch(sid_pattern, item) for item in tool_sids):
            raise ValueError("expected dedicated local tool user SIDs")
        if sid in tool_sids or len(set(tool_sids)) != len(tool_sids):
            raise ValueError("tool SIDs must be unique and distinct from desktop SID")
        self.executable = Path(executable).resolve(strict=True)
        self.sid = sid
        self.tool_sids = tool_sids

    def _args(self, command: str, *extra: str, sid: str | None = None) -> list[str]:
        return [str(self.executable), command, sid or self.sid, *extra, "--isolated-vm"]

    @staticmethod
    def _record(result: subprocess.CompletedProcess) -> dict:
        try:
            record = json.loads(result.stdout.splitlines()[-1])
        except (IndexError, ValueError, TypeError) as error:
            raise WfpBoundaryError("WFP utility returned no valid status") from error
        if not isinstance(record, dict):
            raise WfpBoundaryError("WFP utility returned invalid status")
        return record

    def _command(self, command: str, *, sid: str | None = None) -> dict:
        result = subprocess.run(self._args(command, sid=sid), capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=15, check=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        record = self._record(result)
        if result.returncode or record.get("error") != 0:
            raise WfpBoundaryError(f"WFP {command} failed (code {record.get('error')})")
        return record

    def install_default_deny(self) -> None:
        """Explicit elevated setup in the isolated VM; never called by attach."""
        self._command("install")
        self._assert_sid_default_deny(self.sid)

    def _assert_sid_default_deny(self, sid: str) -> dict:
        record = self._command("status", sid=sid)
        if record.get("installed") is not True or not all(
            type(record.get(k)) is int and record[k] > 0
            for k in ("v4_filter_id", "v6_filter_id", "in_v4_filter_id", "in_v6_filter_id")
        ):
            raise WfpBoundaryError(f"persistent IPv4/IPv6 SID denies not attested for {sid}")
        return record

    def assert_tool_default_deny(self) -> dict[str, dict]:
        """Attest every sandbox tool identity before permitting the desktop."""
        return {sid: self._assert_sid_default_deny(sid) for sid in self.tool_sids}

    def assert_default_deny(self) -> dict:
        """Attest desktop SID and all configured, distinct sandbox tool SIDs."""
        record = self._assert_sid_default_deny(self.sid)
        self.assert_tool_default_deny()
        return record

    def remove_default_deny(self) -> None:
        """Explicit elevated teardown after stopping the dedicated VM user."""
        self._command("remove")

    def start_guarded_lease(self, *, pid: int, creation_filetime: int,
                            image_sha256: str, ip: str, port: int,
                            seconds: int = 300) -> WfpLease:
        self.assert_default_deny()
        if pid <= 0 or creation_filetime <= 0 or not re.fullmatch(r"[0-9a-fA-F]{64}", image_sha256):
            raise ValueError("invalid guarded process identity")
        address = ipaddress.ip_address(ip)
        if not 1 <= port <= 65535 or not 1 <= seconds <= 300:
            raise ValueError("invalid narrow permit bounds")
        args = self._args("lease", str(pid), str(creation_filetime), image_sha256.lower(),
                          str(address), str(port), "tcp", str(seconds),
                          str(os.getpid()), str(_own_creation_filetime()))
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8", errors="replace",
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        lines: Queue[str] = Queue(maxsize=1)
        Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
        try:
            line = lines.get(timeout=10)
            record = json.loads(line)
            if (process.poll() is not None or record.get("state") != "permit_active" or
                    record.get("pid_exact_filter") is not False or
                    not isinstance(record.get("filter_id"), int) or record["filter_id"] <= 0):
                raise WfpBoundaryError("guarded WFP permit did not become active")
            return WfpLease(process, record["filter_id"], pid_exact_filter=False)
        except (Empty, ValueError, WfpBoundaryError) as error:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
            raise WfpBoundaryError("guarded WFP permit startup failed") from error
