"""Restricted Windows named-pipe policy service for Content Analysis Agent."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import secrets
import struct
import threading
import time

from transpect_trace.guard.pipe import pipe_security, windows_api
from transpect_trace.observe.windows import identity

from .policy import ContentAnalysisEngine
from .protocol import (
    MAX_HEADER_BYTES,
    ContentAnalysisProtocolError,
    decode_request,
    encode_reply,
    request_body_size,
)


class ContentAnalysisPipeServer:
    """Serve decisions only to the exact native-agent process started by us."""

    def __init__(
        self,
        engine: ContentAnalysisEngine,
        audit: Path,
        *,
        expected_pid: int | None = None,
        pipe_name: str | None = None,
        workers: int = 4,
        decision_timeout_seconds: float = 2.0,
    ):
        self.engine = engine
        self.audit = Path(audit)
        self.workers = workers
        self.decision_timeout_seconds = decision_timeout_seconds
        suffix = secrets.token_hex(16)
        self.name = pipe_name or rf"\\.\pipe\ttrace-content-policy-{suffix}"
        self.k = windows_api()
        self.security = pipe_security(self.k)
        self.expected_pid = expected_pid
        self.expected_identity = identity(expected_pid) if expected_pid is not None else None
        self.expected_ready = threading.Event()
        if expected_pid is not None:
            self.expected_ready.set()
        self.stop = threading.Event()
        self.listening = threading.Event()
        self.lock = threading.Lock()
        self.threads: list[threading.Thread] = []
        self.handles: set[int] = set()
        self.errors: list[str] = []
        self.records: list[dict] = []
        self.closed = False

    def set_expected_process(self, pid: int) -> None:
        if pid <= 0:
            raise ValueError("expected PID must be positive")
        with self.lock:
            if self.expected_pid is not None and self.expected_pid != pid:
                raise RuntimeError("native agent identity is already fixed")
            self.expected_pid = pid
            self.expected_identity = identity(pid)
            self.expected_ready.set()

    def start(self) -> None:
        self.audit.parent.mkdir(parents=True, exist_ok=True)
        for index in range(self.workers):
            thread = threading.Thread(
                target=self._serve, name=f"content-policy-{index}", daemon=True
            )
            thread.start()
            self.threads.append(thread)
        if not self.listening.wait(5):
            raise RuntimeError(f"content policy listener unavailable: {self.errors}")

    def _read_exact(self, handle, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            buffer = c.create_string_buffer(min(65536, size - len(data)))
            count = w.DWORD()
            if (
                not self.k.ReadFile(handle, buffer, len(buffer), c.byref(count), None)
                or not count.value
            ):
                raise OSError("pipe disconnected or frame incomplete")
            data.extend(buffer.raw[: count.value])
        return bytes(data)

    def _serve(self) -> None:
        while not self.stop.is_set():
            handle = self.k.CreateNamedPipeW(
                self.name,
                3,
                0x8,
                self.workers,
                65536,
                65536,
                2000,
                c.byref(self.security),
            )
            if handle == w.HANDLE(-1).value:
                with self.lock:
                    self.errors.append("pipe_create_failed")
                return
            with self.lock:
                self.handles.add(handle)
            self.listening.set()
            try:
                if not self.k.ConnectNamedPipe(handle, None) and c.get_last_error() != 535:
                    continue
                if self.stop.is_set():
                    continue
                if not self.expected_ready.wait(5) or self.expected_pid is None:
                    raise ValueError("native agent identity unavailable")
                peer = w.ULONG()
                if (
                    not self.k.GetNamedPipeClientProcessId(handle, c.byref(peer))
                    or peer.value != self.expected_pid
                ):
                    raise ValueError("native agent identity mismatch")
                current = identity(peer.value)
                if self.expected_identity is None or (
                    current["creation_filetime"], current["image_sha256"]
                ) != (
                    self.expected_identity["creation_filetime"],
                    self.expected_identity["image_sha256"],
                ):
                    raise ValueError("native agent lifetime changed")
                header_size = struct.unpack("<I", self._read_exact(handle, 4))[0]
                if not 0 < header_size <= MAX_HEADER_BYTES:
                    raise ValueError("invalid header length")
                header = self._read_exact(handle, header_size)
                body_size = request_body_size(header)
                body = self._read_exact(handle, body_size) if body_size else b""
                request = decode_request(header, body)
                began = time.monotonic()
                verdict, audit = self.engine.evaluate(request)
                elapsed = time.monotonic() - began
                if elapsed >= self.decision_timeout_seconds:
                    timed_out = request.model_copy(
                        update={
                            "limitations": sorted(
                                {*request.limitations, "decision_deadline_exceeded"}
                            )
                        }
                    )
                    verdict, audit = self.engine.evaluate(timed_out)
                row = audit.model_dump(mode="json")
                with self.lock:
                    with self.audit.open("a", encoding="utf-8") as output:
                        output.write(json.dumps(row, ensure_ascii=True) + "\n")
                        output.flush()
                    self.records.append(row)
                reply = encode_reply(verdict)
                sent = w.DWORD()
                if (
                    not self.k.WriteFile(handle, reply, len(reply), c.byref(sent), None)
                    or sent.value != len(reply)
                ):
                    raise OSError("decision write incomplete")
                self.k.FlushFileBuffers(handle)
            except (
                OSError,
                TypeError,
                ValueError,
                RecursionError,
                ContentAnalysisProtocolError,
            ):
                # Closing without a valid reply is deliberately fail-closed in
                # the native agent and in Chrome's default_action policy.
                with self.lock:
                    self.errors.append("request_or_transport_invalid")
            finally:
                with self.lock:
                    self.handles.discard(handle)
                self.k.DisconnectNamedPipe(handle)
                self.k.CloseHandle(handle)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        for _ in range(self.workers):
            handle = self.k.CreateFileW(self.name, 0xC0000000, 0, None, 3, 0, None)
            if handle != w.HANDLE(-1).value:
                self.k.CloseHandle(handle)
        for thread in self.threads:
            thread.join(timeout=3)
        if not any(thread.is_alive() for thread in self.threads):
            self.k.LocalFree(self.security.descriptor)
