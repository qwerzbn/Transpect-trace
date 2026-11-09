"""Resident decision service for the Codex hook gate.

Every hook event used to start a fresh Python process, import the engine and
load the archive key: ~140 ms per event, and with `PostToolUse` a tool call
costs two events. The service keeps one `CodexHookGate` loaded and answers over
a named pipe; the native client (`native/protect/codex_gate_client.c`) is what
Codex actually runs.

Wire format, both directions: 4-byte little-endian length, then bytes. The
request is the raw hook event exactly as Codex wrote it to stdin; the reply is
the JSON reply object, or zero bytes for "allow, print nothing".

Failure semantics are the client's: if the pipe is absent, slow or returns
garbage, the client runs the per-event Python gate instead, which fails closed.
So a stopped service costs latency, never an allow.

The pipe DACL admits only the current user and SYSTEM. It does not stop another
process of the *same* user from squatting the pipe name before the service
starts; that is the same trust boundary as the user-writable gate files, and
the health check reports it rather than this module pretending otherwise.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import threading
import time

from .codex_hook_gate import CodexHookGate, GateConfig, MAX_EVENT_BYTES, read_event, run_event

PIPE_PREFIX = r"\\.\pipe\transpect-codex-gate-"
STATUS_SCHEMA = "transpect.codex-gate-service.status/1.0"
_PIPE_ACCESS_DUPLEX = 0x3
_PIPE_TYPE_BYTE_WAIT = 0x0
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_ERROR_PIPE_CONNECTED = 535


def pipe_name(config_path: Path) -> str:
    """One pipe per gate configuration; the client receives the same name."""
    key = str(Path(config_path).resolve()).casefold().encode("utf-8")
    return PIPE_PREFIX + hashlib.sha256(key).hexdigest()[:16]


class _ConfigCache:
    """Reload the gate when its configuration file changes on disk."""

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.lock = threading.Lock()
        self._stamp: tuple[int, int] | None = None
        self._gate: CodexHookGate | None = None

    def gate(self) -> CodexHookGate:
        stat = self.path.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
        with self.lock:
            if self._gate is None or stamp != self._stamp:
                gate = CodexHookGate(GateConfig.load(self.path))
                gate._prepare()  # load archive key and engine now, not on first event
                self._gate, self._stamp = gate, stamp
            return self._gate


def decide_raw(raw: bytes, cache: _ConfigCache) -> bytes:
    """Same decision path as the per-event process; returns reply bytes."""
    event, name = read_event(_Bytes(raw))
    try:
        gate = cache.gate()
    except Exception:
        gate = None
    # With no loadable gate, run_event's own config path raises and denies.
    response = run_event(event, name, str(cache.path) if gate is None else None, gate)
    return (json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8") if response else b""


class _Bytes:
    def __init__(self, data: bytes):
        self.data = data

    def read(self, size: int) -> bytes:
        return self.data[:size]


class GateService:
    def __init__(self, config_path: Path, workers: int = 8):
        from transpect_trace.guard.pipe import pipe_security, windows_api
        self.cache = _ConfigCache(config_path)
        self.name = pipe_name(config_path)
        self.workers = workers
        self.k = windows_api()
        self.k.WaitNamedPipeW.argtypes = [w.LPCWSTR, w.DWORD]
        self.k.WaitNamedPipeW.restype = w.BOOL
        self.security = pipe_security(self.k)
        self.stop = threading.Event()
        self.listening = threading.Event()
        self.errors: list[str] = []
        self.served = 0
        self._first = threading.Lock()
        self._first_taken = False

    def start(self) -> None:
        self.cache.gate()  # fail at startup, not on the first prompt
        for _ in range(self.workers):
            threading.Thread(target=self._serve, daemon=True).start()
        if not self.listening.wait(5):
            raise RuntimeError(f"named pipe listener unavailable: {self.errors}")

    def _create(self):
        flags = _PIPE_ACCESS_DUPLEX
        with self._first:
            if not self._first_taken:
                # Refuse to start if someone already owns this pipe name.
                flags |= _FILE_FLAG_FIRST_PIPE_INSTANCE
                self._first_taken = True
        return self.k.CreateNamedPipeW(self.name, flags, _PIPE_TYPE_BYTE_WAIT, 255,
                                       65536, 65536, 2000, c.byref(self.security))

    def _read(self, handle, size: int) -> bytes:
        out = bytearray()
        while len(out) < size:
            chunk = c.create_string_buffer(min(size - len(out), 1 << 20))
            got = w.DWORD()
            if not self.k.ReadFile(handle, chunk, len(chunk), c.byref(got), None) or not got.value:
                raise OSError("pipe closed mid-frame")
            out.extend(chunk.raw[:got.value])
        return bytes(out)

    def _write(self, handle, data: bytes) -> None:
        frame = struct.pack("<I", len(data)) + data
        sent = w.DWORD()
        if not self.k.WriteFile(handle, frame, len(frame), c.byref(sent), None) \
                or sent.value != len(frame):
            raise OSError("incomplete reply write")
        self.k.FlushFileBuffers(handle)

    def _serve(self) -> None:
        while not self.stop.is_set():
            handle = self._create()
            if handle == w.HANDLE(-1).value:
                self.errors.append(f"CreateNamedPipeW:{c.get_last_error()}")
                self.stop.set()
                return
            self.listening.set()
            try:
                if (not self.k.ConnectNamedPipe(handle, None)
                        and c.get_last_error() != _ERROR_PIPE_CONNECTED):
                    continue
                if self.stop.is_set():
                    continue
                size = struct.unpack("<I", self._read(handle, 4))[0]
                if size > MAX_EVENT_BYTES + 1:
                    # Read nothing more; the client treats a closed pipe as
                    # "service failed" and falls back to the per-event gate.
                    continue
                reply = decide_raw(self._read(handle, size), self.cache)
                self._write(handle, reply)
                self.served += 1
            except Exception as error:
                self.errors.append(type(error).__name__)
                del self.errors[:-64]
            finally:
                self.k.DisconnectNamedPipe(handle)
                self.k.CloseHandle(handle)

    def shutdown(self) -> None:
        self.stop.set()
        # Wake every blocked ConnectNamedPipe so the workers can exit.
        for _ in range(self.workers):
            try:
                with open(self.name, "r+b", buffering=0):
                    pass
            except OSError:
                pass


def query(name: str, raw: bytes, timeout_ms: int = 5000) -> bytes:
    """Python client, for the health check and tests. The hook uses the native one."""
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        try:
            with open(name, "r+b", buffering=0) as pipe:
                pipe.write(struct.pack("<I", len(raw)) + raw)
                header = pipe.read(4)
                if len(header) != 4:
                    raise OSError("short reply header")
                size = struct.unpack("<I", header)[0]
                body = b""
                while len(body) < size:
                    chunk = pipe.read(size - len(body))
                    if not chunk:
                        raise OSError("short reply body")
                    body += chunk
                return body
        except FileNotFoundError:
            raise
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.02)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", type=Path)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--status-file", type=Path, default=None)
    args = parser.parse_args(argv)
    service = GateService(args.config, args.workers)
    service.start()
    status = {"schema": STATUS_SCHEMA, "pid": os.getpid(), "pipe": service.name,
              "config": str(service.cache.path), "started_at": time.time()}
    status_file = args.status_file or service.cache.path.parent / "service-status.json"
    status_file.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(status), flush=True)
    try:
        while not service.stop.wait(1.0):
            pass
    except KeyboardInterrupt:
        service.shutdown()
    return 1 if service.errors and service.stop.is_set() else 0


if __name__ == "__main__":
    sys.exit(main())
