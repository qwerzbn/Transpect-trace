"""Binary-safe, fail-closed local decision pipe for a *future* desktop upload Hook.

There is no verified Electron upload Hook in this repository.  This service
cannot authorize network egress on its own.  The fixed-build native caller must
send the complete immutable bytes before its first network write, and treat a
timeout, disconnect, malformed reply, or DENY as a stopped upload.
"""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import re
import struct
import threading
import time

from .pipe import pipe_security, windows_api


SCHEMA = "transpect.desktop.upload.request/1.0"
REPLY_SCHEMA = "transpect.desktop.upload.decision/1.0"
MAX_HEADER_BYTES = 8192
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
DEADLINE_SECONDS = 5.0
_IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_REFERENCE = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_ERROR_IO_PENDING = 997
_ERROR_PIPE_CONNECTED = 535
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_FILE_FLAG_OVERLAPPED = 0x40000000


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate desktop upload JSON key")
        value[key] = item
    return value


class _Overlapped(c.Structure):
    _fields_ = [("Internal", c.c_size_t), ("InternalHigh", c.c_size_t),
                ("Offset", w.DWORD), ("OffsetHigh", w.DWORD), ("hEvent", w.HANDLE)]


def _configure_upload_winapi(k) -> None:
    """Preserve pointer-sized HANDLE results on 64-bit Windows."""
    signatures = {
        "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
        "WaitForMultipleObjects": ([w.DWORD, c.POINTER(w.HANDLE), w.BOOL, w.DWORD], w.DWORD),
        "CreateEventW": ([c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR], w.HANDLE),
        "GetOverlappedResult": ([w.HANDLE, c.POINTER(_Overlapped), c.POINTER(w.DWORD), w.BOOL], w.BOOL),
        "CancelIoEx": ([w.HANDLE, c.POINTER(_Overlapped)], w.BOOL),
    }
    for name, (args, result) in signatures.items():
        fn = getattr(k, name)
        fn.argtypes, fn.restype = args, result


def parse_upload_header(data: bytes, *, subject: dict) -> dict:
    """Reject unknown shapes before a file byte can receive ALLOW."""
    if not 0 < len(data) <= MAX_HEADER_BYTES:
        raise ValueError("invalid upload header length")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object)
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("invalid upload event schema")
    kind = value.get("kind")
    required = ({"schema", "request_id", "kind", "pid", "creation_filetime"} if kind == "upload.ready" else
                {"schema", "request_id", "kind", "pid", "creation_filetime", "filename",
                 "body_bytes", "body_sha256"} if kind == "upload.bytes" else
                {"schema", "request_id", "kind", "pid", "creation_filetime", "filename",
                 "body_bytes", "body_sha256", "approval_id", "reference_id"} if kind == "upload.reference" else None)
    if required is None or set(value) != required:
        raise ValueError("unsupported upload event shape")
    if not isinstance(value["request_id"], str) or not _IDENTIFIER.fullmatch(value["request_id"]):
        raise ValueError("invalid upload request id")
    if any(not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 1
           for key in ("pid", "creation_filetime")):
        raise ValueError("invalid upload process identity")
    if value["pid"] != subject["pid"] or value["creation_filetime"] != subject["creation_filetime"]:
        raise ValueError("upload process identity mismatch")
    if kind == "upload.ready":
        return value
    name = value["filename"]
    if not isinstance(name, str) or not 1 <= len(name) <= 255 or any(char in name for char in ("/", "\\", "\0")):
        raise ValueError("invalid attachment filename")
    if not isinstance(value["body_sha256"], str) or not _SHA256.fullmatch(value["body_sha256"]):
        raise ValueError("invalid upload content hash")
    length = value["body_bytes"]
    if not isinstance(length, int) or isinstance(length, bool):
        raise ValueError("invalid upload content length")
    if kind == "upload.bytes":
        if not 0 < length <= MAX_UPLOAD_BYTES:
            raise ValueError("upload exceeds inspection limit")
    else:
        if length != 0 or not all(isinstance(value[key], str) and _REFERENCE.fullmatch(value[key])
                                  for key in ("approval_id", "reference_id")):
            raise ValueError("invalid upload reference binding")
    return value


def decide_upload_event(header: dict, payload: bytes, bridge) -> dict:
    """The bridge archives and scans before the reply can be ALLOW."""
    decision, reason, approval_id, rules = "deny", "UPLOAD_INSPECTION_FAILED", None, ()
    try:
        if len(payload) != header.get("body_bytes", 0):
            raise ValueError("incomplete upload payload")
        if header["kind"] == "upload.ready":
            decision, reason = "allow", "UPLOAD_GATE_READY_ACK"
        elif header["kind"] == "upload.bytes":
            if hashlib.sha256(payload).hexdigest() != header["body_sha256"]:
                raise ValueError("upload payload hash mismatch")
            approval = bridge.evaluate_attachment(header["filename"], payload)
            rules = approval.rule_ids
            if approval.decision == "ALLOW":
                decision, reason, approval_id = "allow", "APPROVED_FILE_BYTES", approval.approval_id
            else:
                reason = "CONTENT_OR_FORMAT_DENIED"
        elif header["kind"] == "upload.reference":
            bridge.bind_reference(header["approval_id"], header["reference_id"],
                                  header["filename"], header["body_sha256"])
            decision, reason = "allow", "APPROVED_REFERENCE_BOUND"
    except Exception:
        pass
    return {"schema": REPLY_SCHEMA, "request_id": header["request_id"],
            "decision": decision, "reason": reason, "approval_id": approval_id,
            "rule_ids": list(rules)}


def verify_live_upload_subject(subject: dict, adapter: dict) -> None:
    """Pin the exact desktop upload process before creating its decision pipe."""
    from transpect_trace.observe.windows import identity as image_identity
    from .desktop import _cim_process, validate_desktop_adapter
    validate_desktop_adapter(adapter)
    expected = adapter["coverage"]["attachment.upload"]
    current = image_identity(subject["pid"])
    if (current["creation_filetime"] != subject["creation_filetime"]
            or current["image_sha256"] != expected["process_image_sha256"]
            or current["image_sha256"] != subject["image_sha256"]):
        raise ValueError("desktop upload process image changed")
    row = _cim_process(subject["pid"])
    if row.get("UserSid") != subject["user_sid"]:
        raise ValueError("desktop upload process SID changed")
    if expected["process_role"] == "desktop-network-service":
        parent_pid = subject.get("desktop_pid")
        parent_birth = subject.get("desktop_creation_filetime")
        if (not isinstance(parent_pid, int) or not isinstance(parent_birth, int)
                or row.get("ParentProcessId") != parent_pid):
            raise ValueError("upload network service parent is not pinned desktop")
        parent = image_identity(parent_pid)
        if (parent["creation_filetime"] != parent_birth
                or parent["image_sha256"] != adapter["desktop_image_sha256"]
                or adapter["package_full_name"].lower() not in parent["image_path"].lower()
                or _cim_process(parent_pid).get("UserSid") != subject["user_sid"]):
            raise ValueError("upload network service desktop parent changed")
        if (adapter["package_full_name"].lower() not in current["image_path"].lower()
                or "network.mojom.NetworkService" not in (row.get("CommandLine") or "")):
            raise ValueError("upload client is not the pinned desktop network service")
    elif expected["process_role"] == "app-server":
        from .desktop import collect_desktop_identity
        identity = collect_desktop_identity(subject["pid"], adapter, expected_sid=subject["user_sid"])
        if (identity["creation_filetime"] != subject["creation_filetime"]
                or identity["desktop_pid"] != subject.get("desktop_pid")
                or identity["desktop_creation_filetime"] != subject.get("desktop_creation_filetime")):
            raise ValueError("upload client is not a pinned app-server")


class DesktopUploadPipe:
    """One named pipe per pinned process, with a bounded synchronous response."""
    def __init__(self, subject: dict, adapter: dict, bridge, audit: Path, *, upload_dll: Path):
        verify_live_upload_subject(subject, adapter)
        self.subject, self.adapter, self.bridge = subject, adapter, bridge
        self.audit = Path(audit)
        self.upload_dll = Path(upload_dll).resolve()
        self.name = rf"\\.\pipe\ttrace-desktop-upload-{subject['pid']}"
        self.k = windows_api()
        _configure_upload_winapi(self.k)
        self.security = pipe_security(self.k, subject["user_sid"])
        self.process = self.k.OpenProcess(0x100000, False, subject["pid"])
        if not self.process:
            raise c.WinError(c.get_last_error())
        self.stop = threading.Event()
        self.listening = threading.Event()
        self.ready = threading.Event()
        self.errors: list[str] = []
        self.on_failure = None
        self.seen: set[str] = set()
        self.thread: threading.Thread | None = None
        self.closed = False
        self.audit.parent.mkdir(parents=True, exist_ok=True)

    def start(self) -> None:
        self.thread = threading.Thread(target=self._serve, name="desktop-upload-pipe", daemon=True)
        self.thread.start()
        if not self.listening.wait(5):
            raise RuntimeError("desktop upload pipe did not start")

    def _record_failure(self, reason: str) -> None:
        self.errors.append(reason)
        if self.on_failure is not None:
            try:
                self.on_failure()
            except Exception:
                # The caller still sees a failed gate; no ALLOW can be inferred.
                pass

    def _alive(self) -> bool:
        # WAIT_FAILED must not be mistaken for a running pinned process.
        return self.k.WaitForSingleObject(self.process, 0) == _WAIT_TIMEOUT

    def _event(self):
        event = self.k.CreateEventW(None, True, False, None)
        if not event:
            raise c.WinError(c.get_last_error())
        return event

    def _await_io(self, handle, operation: _Overlapped, deadline: float | None) -> None:
        """Wait for pipe I/O or target exit; cancel before buffers leave scope."""
        handles = (w.HANDLE * 2)(operation.hEvent, self.process)
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if self.stop.is_set() or remaining is not None and remaining <= 0:
                reason = "desktop upload pipe deadline or stop"
                break
            wait_ms = 100 if remaining is None else min(100, max(1, int(remaining * 1000)))
            status = self.k.WaitForMultipleObjects(2, handles, False, wait_ms)
            if status == _WAIT_OBJECT_0:
                return
            if status == _WAIT_OBJECT_0 + 1:
                reason = "desktop upload process exited"
                break
            if status != _WAIT_TIMEOUT:
                reason = "desktop upload pipe wait failed"
                break
        self.k.CancelIoEx(handle, c.byref(operation))
        transferred = w.DWORD()
        # Drain cancellation before the event/OVERLAPPED/buffer can be freed.
        self.k.GetOverlappedResult(handle, c.byref(operation), c.byref(transferred), True)
        raise TimeoutError(reason)

    def _connect(self, handle) -> bool:
        event = self._event()
        operation = _Overlapped(hEvent=event)
        try:
            if self.k.ConnectNamedPipe(handle, c.byref(operation)):
                return True
            error = c.get_last_error()
            if error == _ERROR_PIPE_CONNECTED:
                return True
            if error != _ERROR_IO_PENDING:
                return False
            self._await_io(handle, operation, None)
            transferred = w.DWORD()
            return bool(self.k.GetOverlappedResult(handle, c.byref(operation),
                                                   c.byref(transferred), False))
        finally:
            self.k.CloseHandle(event)

    def _transfer(self, handle, buffer, size: int, deadline: float, *, write: bool) -> int:
        if time.monotonic() >= deadline or not self._alive():
            raise TimeoutError("desktop upload pipe deadline or process exit")
        event = self._event()
        operation = _Overlapped(hEvent=event)
        try:
            method = self.k.WriteFile if write else self.k.ReadFile
            transferred = w.DWORD()
            if not method(handle, buffer, size, c.byref(transferred), c.byref(operation)):
                if c.get_last_error() != _ERROR_IO_PENDING:
                    raise OSError("desktop upload pipe transfer failed")
                self._await_io(handle, operation, deadline)
                if not self.k.GetOverlappedResult(handle, c.byref(operation),
                                                  c.byref(transferred), False):
                    raise OSError("desktop upload pipe transfer failed")
            if time.monotonic() >= deadline:
                raise TimeoutError("desktop upload pipe transfer exceeded deadline")
            if not transferred.value:
                raise OSError("desktop upload pipe disconnected")
            return transferred.value
        finally:
            self.k.CloseHandle(event)

    def _read(self, handle, size: int, deadline: float) -> bytes:
        result = bytearray()
        while len(result) < size:
            buffer = c.create_string_buffer(min(size - len(result), 65536))
            read = self._transfer(handle, buffer, len(buffer), deadline, write=False)
            result.extend(buffer.raw[:read])
        return bytes(result)

    def _reply(self, handle, value: dict, deadline: float) -> None:
        wire = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(wire) > MAX_HEADER_BYTES:
            raise ValueError("desktop upload reply too large")
        frame = struct.pack("<I", len(wire)) + wire
        buffer = c.create_string_buffer(frame)
        if self._transfer(handle, buffer, len(frame), deadline, write=True) != len(frame):
            raise OSError("desktop upload reply write failed")

    def _serve(self) -> None:
        while not self.stop.is_set():
            handle = self.k.CreateNamedPipeW(self.name, 3 | _FILE_FLAG_OVERLAPPED, 0x8,
                                             1, 65536, 65536, 5000,
                                             c.byref(self.security))
            if handle == w.HANDLE(-1).value:
                self._record_failure("pipe_create_failed")
                return
            self.listening.set()
            try:
                if not self._connect(handle):
                    continue
                if self.stop.is_set():
                    continue
                peer = w.ULONG()
                if (not self.k.GetNamedPipeClientProcessId(handle, c.byref(peer))
                        or peer.value != self.subject["pid"]
                        or not self._alive()):
                    raise ValueError("desktop upload pipe client identity mismatch")
                deadline = time.monotonic() + DEADLINE_SECONDS
                size = struct.unpack("<I", self._read(handle, 4, deadline))[0]
                if not 0 < size <= MAX_HEADER_BYTES:
                    raise ValueError("invalid desktop upload header size")
                header = parse_upload_header(self._read(handle, size, deadline), subject=self.subject)
                if header["request_id"] in self.seen or len(self.seen) >= 10000:
                    raise ValueError("duplicate or excessive upload request ids")
                self.seen.add(header["request_id"])
                payload = self._read(handle, header.get("body_bytes", 0), deadline)
                if header["kind"] != "upload.ready" and not self.ready.is_set():
                    response = {"schema": REPLY_SCHEMA, "request_id": header["request_id"],
                                "decision": "deny", "reason": "UPLOAD_GATE_NOT_READY",
                                "approval_id": None, "rule_ids": []}
                else:
                    response = decide_upload_event(header, payload, self.bridge)
                    if header["kind"] == "upload.ready":
                        self.ready.set()
                if time.monotonic() >= deadline:
                    response.update(decision="deny", reason="UPLOAD_DECISION_TIMEOUT", approval_id=None)
                row = {"kind": header["kind"], "request_id": header["request_id"],
                       "decision": response["decision"], "reason": response["reason"],
                       "body_sha256": header.get("body_sha256"), "body_bytes": header.get("body_bytes", 0),
                       "matched_rule_ids": response["rule_ids"]}
                with self.audit.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, separators=(",", ":")) + "\n")
                    stream.flush()
                if time.monotonic() >= deadline:
                    raise TimeoutError("desktop upload audit exceeded deadline")
                self._reply(handle, response, deadline)
                # Keep the instance alive until the native caller has read the
                # entire framed reply. A prompt DisconnectNamedPipe can discard
                # buffered reply bytes on Windows.
                if self._read(handle, 1, deadline) != b"\x06":
                    raise ValueError("desktop upload reply was not acknowledged")
            except (OSError, ValueError, TimeoutError) as error:
                self._record_failure(type(error).__name__)
                # A missing reply is a DENY in the native caller contract.
            finally:
                self.k.DisconnectNamedPipe(handle)
                self.k.CloseHandle(handle)

    def attest(self, adapter: dict, desktop_identity: dict) -> dict:
        """A policy pipe alone is never proof that the native upload Hook exists."""
        from transpect_trace.observe.windows import digest, identity as image_identity, modules
        expected = adapter["coverage"]["attachment.upload"]
        result = {"ready": False, "process_role": expected["process_role"],
                  "image_sha256": expected["process_image_sha256"],
                  "desktop_creation_filetime": self.subject.get("desktop_creation_filetime"),
                  "pid": self.subject["pid"]}
        if (not self.ready.is_set() or self.errors or self.thread is None or not self.thread.is_alive()
                or not self._alive() or self.subject.get("desktop_pid") != desktop_identity.get("desktop_pid")
                or self.subject.get("desktop_creation_filetime") != desktop_identity.get("desktop_creation_filetime")):
            return result
        try:
            verify_live_upload_subject(self.subject, adapter)
        except (OSError, ValueError, RuntimeError):
            return result
        current = image_identity(self.subject["pid"])
        if (current["creation_filetime"] != self.subject["creation_filetime"]
                or current["image_sha256"] != expected["process_image_sha256"]):
            return result
        expected_dll = expected.get("upload_dll_sha256")
        if not isinstance(expected_dll, str) or not _SHA256.fullmatch(expected_dll):
            return result
        if any(Path(row["path"]).resolve() == self.upload_dll and digest(row["path"]) == expected_dll
               for row in modules(self.subject["pid"])):
            result["ready"] = True
        return result

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        handle = self.k.CreateFileW(self.name, 0xc0000000, 0, None, 3, 0, None)
        if handle != w.HANDLE(-1).value:
            self.k.CloseHandle(handle)
        if self.thread is not None:
            self.thread.join(timeout=1)
        if self.thread is None or not self.thread.is_alive():
            self.k.CloseHandle(self.process)
            self.k.LocalFree(self.security.descriptor)
        else:
            # A stuck policy/audit call must never race freed Win32 resources.
            # The process lifetime owns these handles until this daemon exits.
            self._record_failure("upload_pipe_close_timeout")
