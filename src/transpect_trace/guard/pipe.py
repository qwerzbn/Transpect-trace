"""Restricted local named-pipe reference server. Native clients own their deadline."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import struct
import threading
import time
import uuid

from pydantic import ValidationError
import zstandard

from .policy import GuardDecision, GuardRequest, PolicyEngine
from .wire import MAX_FRAME_BYTES, encode_frame

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
# Bounds the decoded body; a compressed frame cannot expand past the largest
# frame the pipe would accept uncompressed.
MAX_DECODED_BODY_BYTES = MAX_FRAME_BYTES


def _decode_compressed_model_frame(frame: bytes) -> dict | None:
    """Recover a zstd-compressed HTTP model body from a Native frame.

    The Native ``quote()`` escapes only ``"``, ``\\`` and bytes below 0x20,
    copying every other byte verbatim, so a binary body yields a frame that is
    not valid UTF-8 JSON. On ChatGPT-auth HTTP, Codex zstd-compresses the
    already-inspected JSON body and the compressed bytes pass the same hook.
    Decoding with ``surrogateescape`` and re-encoding restores the original
    bytes exactly. Only a complete zstd stream that decompresses within the
    bound to strict UTF-8 is returned; anything else stays an invalid frame,
    which the Native caller blocks.
    """
    try:
        envelope = json.loads(frame.decode("utf-8", "surrogateescape"))
    except ValueError:
        return None
    if (not isinstance(envelope, dict) or envelope.get("kind") != "model.request"
            or envelope.get("protocol") != "http"
            or not isinstance(envelope.get("payload_utf8"), str)):
        return None
    try:
        raw = envelope["payload_utf8"].encode("utf-8", "surrogateescape")
    except UnicodeError:
        return None
    if not raw.startswith(ZSTD_MAGIC):
        return None
    try:
        reader = zstandard.ZstdDecompressor().stream_reader(
            raw, read_across_frames=True)
        decoded = reader.read(MAX_DECODED_BODY_BYTES + 1)
        if len(decoded) > MAX_DECODED_BODY_BYTES or reader.read(1):
            return None
        # The stream reader yields a truncated frame's prefix without error.
        # A one-shot decode of the now-bounded size rejects truncation, and a
        # mismatch rejects trailing concatenated frames.
        if zstandard.ZstdDecompressor().decompress(
                raw, max_output_size=max(len(decoded), 1)) != decoded:
            return None
        text = decoded.decode("utf-8")
    except (zstandard.ZstdError, UnicodeError):
        return None
    return {**envelope, "payload_utf8": text,
            "_decoded": {"content_encoding": "zstd", "compressed_bytes": len(raw),
                         "decoded_bytes": len(decoded)}}


@lru_cache(maxsize=1)
def _qpc_function():
    if os.name != "nt":
        return None
    kernel = c.WinDLL("kernel32", use_last_error=True)
    function = kernel.QueryPerformanceCounter
    function.argtypes = [c.POINTER(c.c_longlong)]
    function.restype = w.BOOL
    return function


def _qpc_now() -> int | None:
    """Optional timing only; a diagnostic failure must not affect a decision."""
    try:
        function = _qpc_function()
        if function is None:
            return None
        value = c.c_longlong()
        return value.value if function(c.byref(value)) else None
    except (OSError, AttributeError):
        return None


def _native_age_ms(request: GuardRequest, sampled_qpc: int | None) -> float | None:
    captured, frequency = request.captured_qpc, request.qpc_frequency
    if (sampled_qpc is None or not isinstance(captured, int)
            or not isinstance(frequency, int) or frequency <= 0
            or sampled_qpc < captured):
        return None
    return round((sampled_qpc - captured) * 1000 / frequency, 3)


def _safe_request_id(value: str) -> str:
    return value if re.fullmatch(r"[0-9]{1,10}-[0-9]{1,10}", value) else "untrusted_id"


def _wire_thread_ids(payload_utf8: str) -> frozenset[str]:
    """Return only Codex-owned top-level thread identifiers, never prompt text.

    A prompt cache key can identify a broader session and is never a thread
    selector. An unidentifiable request is outside this test-only scope;
    scoped mode does not attest global egress coverage.
    """
    try:
        body = json.loads(payload_utf8)
    except (TypeError, ValueError):
        return frozenset()
    if not isinstance(body, dict):
        return frozenset()
    metadata = body.get("client_metadata")
    thread_id = metadata.get("thread_id") if isinstance(metadata, dict) else None
    value = thread_id
    if not isinstance(value, str):
        return frozenset()
    try:
        return frozenset((str(uuid.UUID(value)),))
    except ValueError:
        return frozenset()


def windows_api():
    if os.name != "nt":
        raise RuntimeError("Windows named pipes are required")
    k = c.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateNamedPipeW": ([w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,c.c_void_p], w.HANDLE),
        "ConnectNamedPipe": ([w.HANDLE,c.c_void_p],w.BOOL),
        "DisconnectNamedPipe": ([w.HANDLE],w.BOOL),
        "FlushFileBuffers": ([w.HANDLE],w.BOOL),
        "CloseHandle": ([w.HANDLE],w.BOOL),
        "ReadFile": ([w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p],w.BOOL),
        "WriteFile": ([w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p],w.BOOL),
        "GetNamedPipeClientProcessId": ([w.HANDLE,c.POINTER(w.ULONG)],w.BOOL),
        "CreateFileW": ([w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE],w.HANDLE),
        "LocalFree": ([c.c_void_p],c.c_void_p),
    }
    for name,(args,result) in signatures.items():
        fn = getattr(k,name); fn.argtypes=args; fn.restype=result
    return k


class SecurityAttributes(c.Structure):
    _fields_ = [("length",w.DWORD),("descriptor",c.c_void_p),("inherit",w.BOOL)]


def _pipe_sddl(controller_sid: str, client_sid: str | None = None) -> str:
    for sid in (controller_sid, client_sid):
        if sid is not None and not re.fullmatch(r"S-\d+(?:-\d+)+", sid):
            raise ValueError("invalid pipe principal SID")
    client_ace = f"(A;;GRGW;;;{client_sid})" if client_sid and client_sid != controller_sid else ""
    return f"D:P(A;;GA;;;SY)(A;;GA;;;{controller_sid}){client_ace}"


def pipe_security(k, client_sid: str | None = None):
    adv = c.WinDLL("advapi32",use_last_error=True)
    adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,c.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.POINTER(w.DWORD)]
    adv.ConvertSidToStringSidW.argtypes=[c.c_void_p,c.POINTER(c.c_void_p)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p]
    token=w.HANDLE(); size=w.DWORD(); sid_string=c.c_void_p(); descriptor=c.c_void_p()
    if not adv.OpenProcessToken(w.HANDLE(-1),8,c.byref(token)):
        raise c.WinError(c.get_last_error())
    try:
        adv.GetTokenInformation(token,1,None,0,c.byref(size))
        data=c.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token,1,data,size,c.byref(size)):
            raise c.WinError(c.get_last_error())
        sid=c.cast(data,c.POINTER(c.c_void_p))[0]
        if not adv.ConvertSidToStringSidW(sid,c.byref(sid_string)):
            raise c.WinError(c.get_last_error())
        sddl=_pipe_sddl(c.wstring_at(sid_string), client_sid)
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,c.byref(descriptor),None):
            raise c.WinError(c.get_last_error())
        return SecurityAttributes(c.sizeof(SecurityAttributes),descriptor,False)
    finally:
        k.CloseHandle(token)
        if sid_string.value:k.LocalFree(sid_string)


class PipeServer:
    def __init__(self,pid:int,engine:PolicyEngine,audit:Path,workers:int=4,request_tap=None,
                 client_sid:str|None=None, target_thread_id:str|None=None):
        self.pid,self.engine,self.audit,self.workers=pid,engine,audit,workers
        self.target_thread_id = (str(uuid.UUID(target_thread_id))
                                 if target_thread_id is not None else None)
        self.name=rf"\\.\pipe\ttrace-guard-{pid}"
        self.k=windows_api();self.security=pipe_security(self.k,client_sid)
        self.stop=threading.Event();self.ready=threading.Event();self.listening=threading.Event()
        self.lock=threading.Lock();self.threads=[];self.errors=[];self.records=[]
        self.validation_error_count=0;self.validation_errors=[];self.decoded_frames=[]
        self.decision_delivery=[]
        # An outcome may arrive on another pipe worker before the original
        # worker finishes flushing and records its decision trace.
        self.pending_outcomes={}
        self.scope_lock=threading.Lock()
        self.scope_counts={"target":0,"bypassed":0,"unidentified_scope_bypass":0}
        self.closed=False
        self.request_tap=request_tap
        audit.parent.mkdir(parents=True,exist_ok=True)

    def start(self):
        for _ in range(self.workers):
            t=threading.Thread(target=self._serve,daemon=True);t.start();self.threads.append(t)
        if not self.listening.wait(5):raise RuntimeError(f"named-pipe listener unavailable: {self.errors}")

    def _read(self,handle,size):
        result=bytearray()
        while len(result)<size:
            buffer=c.create_string_buffer(min(size-len(result),65536));read=w.DWORD()
            if not self.k.ReadFile(handle,buffer,len(buffer),c.byref(read),None) or not read.value:
                raise OSError("pipe disconnected or incomplete frame")
            result.extend(buffer.raw[:read.value])
        return bytes(result)

    def _evaluate_request(self, request: GuardRequest) -> tuple[GuardDecision, dict | None]:
        # A scoped trial never enters the policy engine for another chat. This
        # check is before the engine lock, so one large target request cannot
        # stall unrelated chats on that lock. It also creates no content archive.
        if self.target_thread_id is not None and request.kind == "model.request":
            identifiers = _wire_thread_ids(request.payload_utf8)
            if self.target_thread_id not in identifiers:
                with self.scope_lock:
                    key = "bypassed" if identifiers else "unidentified_scope_bypass"
                    self.scope_counts[key] += 1
                return (GuardDecision(request_id=request.request_id,
                                      decision="allow",action="none",
                                      reason="OUTSIDE_TEST_THREAD_SCOPE",
                                      policy_version=self.engine.policy.version), None)
            with self.scope_lock:
                self.scope_counts["target"] += 1
        began=time.monotonic_ns()

        def commit(decision: GuardDecision, row: dict | None) -> tuple[GuardDecision, dict | None]:
            if request.kind=="model.request" and (time.monotonic_ns()-began)>2_000_000_000:
                decision=GuardDecision(request_id=request.request_id,decision="unknown",action="block_request",
                                       reason="DECISION_DEADLINE_EXCEEDED",policy_version=self.engine.policy.version)
                if row is not None:
                    row.update(decision="unknown",action="block_request",reason="DECISION_DEADLINE_EXCEEDED")
            if row:
                row["captured_at_unix_ns"]=time.time_ns()
                with self.audit.open("a",encoding="utf-8") as output:
                    output.write(json.dumps(row,ensure_ascii=False)+"\n");output.flush()
                self.records.append(row)
            return decision,row

        # The native collector preloads immutable DLP indexes, uses unique
        # archive files and locks its cache and collection writer. Its costly
        # inspection can overlap with another request; only this short audit
        # append needs the pipe's record lock. Other policy engines may carry
        # mutable session state and remain serialized.
        if getattr(self.engine, "concurrent_safe", False):
            decision,row=self.engine.evaluate(request)
            with self.lock:
                return commit(decision,row)
        with self.lock:
            decision,row=self.engine.evaluate(request)
            return commit(decision,row)

    def scope_snapshot(self) -> dict[str, int]:
        with self.scope_lock:
            return dict(self.scope_counts)

    def validation_snapshot(self) -> dict:
        """Return bounded, content-free diagnostics for rejected wire frames."""
        with self.lock:
            snapshot = {"count": self.validation_error_count,
                        "recent": [dict(item) for item in self.validation_errors]}
            decoded = getattr(self, "decoded_frames", [])
            if decoded:
                # Compressed bodies recovered and inspected, not rejected.
                snapshot["decoded_compressed"] = [dict(item) for item in decoded]
            return snapshot

    def decision_delivery_snapshot(self) -> list[dict]:
        """Bounded server-side timing; a write is not a Native allow ack."""
        with self.lock:
            return [dict(item) for item in self.decision_delivery]

    def _record_decision_delivery(self, request: GuardRequest,
                                  decision: GuardDecision, frame_bytes: int,
                                  received_qpc: int | None,
                                  evaluated_qpc: int | None,
                                  written_qpc: int | None,
                                  write_complete: bool,
                                  flush_complete: bool) -> None:
        if request.kind != "model.request":
            return
        trace = {
            "request_id": _safe_request_id(request.request_id),
            "protocol": request.protocol,
            "frame_bytes": frame_bytes,
            "decision": decision.decision,
            "action": decision.action,
            "age_at_frame_read_ms": _native_age_ms(request, received_qpc),
            "age_at_decision_ms": _native_age_ms(request, evaluated_qpc),
            "age_at_reply_write_ms": _native_age_ms(request, written_qpc),
            "server_reply_write_complete": write_complete,
            "server_flush_complete": flush_complete,
            "native_acceptance_attested": False,
            "native_outcome_action": None,
            "native_diagnostic_stage": None,
        }
        with self.lock:
            self.decision_delivery.append(trace)
            del self.decision_delivery[:-64]
            pending = self.pending_outcomes.pop(trace["request_id"], None)
            if pending is not None:
                self._apply_native_outcome(trace, **pending)

    @staticmethod
    def _apply_native_outcome(trace: dict, action: str, valid_frame: bool,
                              stage: str) -> None:
        trace["native_outcome_action"] = (
            action if valid_frame else "invalid_outcome_frame")
        trace["native_diagnostic_stage"] = stage or None
        # Only the diagnostic build explicitly reports that Native parsed an
        # allow reply. Older outcome frames carry no allow acknowledgement.
        trace["native_acceptance_attested"] = (
            valid_frame and action == "none" and stage == "parsed_allow"
            and trace["decision"] == "allow")

    def _note_native_outcome(self, parent_id: str, action: str,
                             *, valid_frame: bool, stage: str = "") -> None:
        identifier = _safe_request_id(parent_id)
        if identifier == "untrusted_id":
            return
        with self.lock:
            for trace in reversed(self.decision_delivery):
                if trace["request_id"] == identifier:
                    self._apply_native_outcome(trace, action, valid_frame, stage)
                    return
            self.pending_outcomes[identifier] = {
                "action": action, "valid_frame": valid_frame, "stage": stage}
            while len(self.pending_outcomes) > 64:
                self.pending_outcomes.pop(next(iter(self.pending_outcomes)))

    def _parse_request_frame(self, frame: bytes) -> GuardRequest | None:
        try:
            return GuardRequest.model_validate_json(frame)
        except ValidationError as error:
            recovered = _decode_compressed_model_frame(frame)
            if recovered is not None:
                decoded = recovered.pop("_decoded")
                try:
                    request = GuardRequest.model_validate(recovered)
                except ValidationError:
                    request = None
                if request is not None:
                    with self.lock:
                        if not hasattr(self, "decoded_frames"):
                            self.decoded_frames = []
                        self.decoded_frames.append(
                            {"request_id": request.request_id, **decoded})
                        del self.decoded_frames[:-16]
                    return request
            # No reply is sent for an invalid frame. The Native caller blocks
            # that model request on a missing valid decision. A malformed
            # outcome/telemetry frame must not release the controller lease and
            # make subsequent, valid model requests pass through uninspected.
            kind = "unknown"
            if len(frame) <= 4096:
                try:
                    envelope = json.loads(frame)
                except (UnicodeError, ValueError):
                    envelope = None
                if isinstance(envelope, dict) and envelope.get("kind") in (
                        "model.request", "native.initialize", "native.ready",
                        "native.outcome"):
                    kind = envelope["kind"]
                    if kind == "native.outcome":
                        parent = envelope.get("outcome_for_request_id")
                        if isinstance(parent, str):
                            self._note_native_outcome(parent, "", valid_frame=False)
            fields = frozenset(GuardRequest.model_fields) | {"schema"}
            issues = []
            for item in error.errors(include_input=False, include_context=False)[:8]:
                location = item.get("loc", ())
                field = location[0] if location and location[0] in fields else "frame"
                issues.append({"field": field, "type": item.get("type", "unknown")})
            diagnostic = {"kind_hint": kind, "frame_bytes": len(frame),
                          "issues": issues}
            with self.lock:
                self.validation_error_count += 1
                self.validation_errors.append(diagnostic)
                del self.validation_errors[:-16]
            return None

    def _serve(self):
        while not self.stop.is_set():
            handle=self.k.CreateNamedPipeW(self.name,3,0x8,self.workers,65536,65536,2000,c.byref(self.security))
            if handle==w.HANDLE(-1).value:
                self.errors.append(c.get_last_error());return
            self.listening.set()
            try:
                if not self.k.ConnectNamedPipe(handle,None) and c.get_last_error()!=535:
                    continue
                if self.stop.is_set():continue
                peer=w.ULONG()
                if not self.k.GetNamedPipeClientProcessId(handle,c.byref(peer)) or peer.value!=self.pid:
                    raise ValueError("named-pipe client identity mismatch")
                size=struct.unpack("<I",self._read(handle,4))[0]
                if not 0<size<=MAX_FRAME_BYTES:raise ValueError("invalid frame length")
                frame=self._read(handle,size)
                received_qpc=_qpc_now()
                request=self._parse_request_frame(frame)
                if request is None:
                    continue
                if request.pid!=peer.value:raise ValueError("payload PID mismatch")
                if request.kind=="native.outcome":
                    self._note_native_outcome(request.outcome_for_request_id,
                                              request.outcome_action,
                                              valid_frame=True,
                                              stage=getattr(request, "diagnostic_stage", ""))
                if self.request_tap:
                    try:self.request_tap(request)
                    except Exception:self.errors.append('observation_tap_failed')
                decision,row=self._evaluate_request(request)
                evaluated_qpc=_qpc_now()
                response=self.decision_frame(decision)
                sent=w.DWORD()
                write_complete=(bool(self.k.WriteFile(handle,response,len(response),
                                                      c.byref(sent),None))
                                and sent.value==len(response))
                written_qpc=_qpc_now()
                flush_complete=bool(self.k.FlushFileBuffers(handle)) if write_complete else False
                self._record_decision_delivery(
                    request,decision,len(frame),received_qpc,evaluated_qpc,
                    written_qpc,write_complete,flush_complete)
                if not write_complete:
                    raise OSError("incomplete decision write")
                if request.kind=="native.ready":self.ready.set()
            except (OSError,ValueError) as error:
                with self.lock:self.errors.append(type(error).__name__)
            finally:
                self.k.DisconnectNamedPipe(handle);self.k.CloseHandle(handle)

    def close(self):
        if self.closed:return
        self.closed=True
        self.stop.set()
        for _ in range(self.workers):
            handle=self.k.CreateFileW(self.name,0xc0000000,0,None,3,0,None)
            if handle!=w.HANDLE(-1).value:self.k.CloseHandle(handle)
        for thread in self.threads:thread.join(timeout=1)
        if not any(t.is_alive() for t in self.threads):self.k.LocalFree(self.security.descriptor)

    def decision_frame(self,decision):
        return encode_frame(decision.model_dump(by_alias=True))
