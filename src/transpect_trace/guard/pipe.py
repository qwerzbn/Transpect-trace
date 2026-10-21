"""Restricted local named-pipe reference server. Native clients own their deadline."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import struct
import threading
import time

from .policy import GuardDecision, GuardRequest, PolicyEngine
from .wire import MAX_FRAME_BYTES, encode_frame


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


def pipe_security(k):
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
        sddl=f"D:P(A;;GA;;;SY)(A;;GA;;;{c.wstring_at(sid_string)})"
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,c.byref(descriptor),None):
            raise c.WinError(c.get_last_error())
        return SecurityAttributes(c.sizeof(SecurityAttributes),descriptor,False)
    finally:
        k.CloseHandle(token)
        if sid_string.value:k.LocalFree(sid_string)


class PipeServer:
    def __init__(self,pid:int,engine:PolicyEngine,audit:Path,workers:int=4,request_tap=None):
        self.pid,self.engine,self.audit,self.workers=pid,engine,audit,workers
        self.name=rf"\\.\pipe\ttrace-guard-{pid}"
        self.k=windows_api();self.security=pipe_security(self.k)
        self.stop=threading.Event();self.ready=threading.Event();self.listening=threading.Event()
        self.lock=threading.Lock();self.threads=[];self.errors=[];self.records=[]
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
                request=GuardRequest.model_validate_json(self._read(handle,size))
                if request.pid!=peer.value:raise ValueError("payload PID mismatch")
                if self.request_tap:
                    try:self.request_tap(request)
                    except Exception:self.errors.append('observation_tap_failed')
                began=time.monotonic_ns()
                with self.lock:
                    decision,row=self.engine.evaluate(request)
                    if request.kind=="model.request" and (time.monotonic_ns()-began)>2_000_000_000:
                        decision=GuardDecision(request_id=request.request_id,decision="unknown",action="block_request",
                                               reason="DECISION_DEADLINE_EXCEEDED",policy_version=self.engine.policy.version)
                        row.update(decision="unknown",action="block_request",reason="DECISION_DEADLINE_EXCEEDED")
                    if row:
                        row["captured_at_unix_ns"]=time.time_ns()
                        with self.audit.open("a",encoding="utf-8") as output:
                            output.write(json.dumps(row,ensure_ascii=False)+"\n");output.flush()
                        self.records.append(row)
                response=self.decision_frame(decision)
                sent=w.DWORD()
                if not self.k.WriteFile(handle,response,len(response),c.byref(sent),None) or sent.value!=len(response):
                    raise OSError("incomplete decision write")
                self.k.FlushFileBuffers(handle)
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
