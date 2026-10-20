from __future__ import annotations
import base64
import ctypes as c
from ctypes import wintypes as w
from pathlib import Path
import struct
import threading
from transpect_trace.guard.pipe import windows_api,pipe_security
from .models import CaptureEvent
from .windows import inject

HEADER=struct.Struct("<4sIIIQQQQQII")


class NativeCollector:
    def __init__(self,subject,profile,dll,pipeline):
        self.subject,self.profile,self.dll,self.pipeline=subject,profile,dll,pipeline
        self.config=profile.configuration(subject)
        self.k=windows_api();self.security=pipe_security(self.k)
        self.name=rf"\\.\pipe\ttrace-observe-{subject['pid']}"
        self.stop=threading.Event();self.listening=threading.Event();self.ready=threading.Event();self.errors=[]
        self.thread=None;self._closed=False
        freq=c.c_longlong();c.windll.kernel32.QueryPerformanceFrequency(c.byref(freq));self.frequency=freq.value

    def read(self,pipe,size):
        result=bytearray()
        while len(result)<size:
            buffer=c.create_string_buffer(min(size-len(result),65536));n=w.DWORD()
            if not self.k.ReadFile(pipe,buffer,len(buffer),c.byref(n),None) or not n.value:raise OSError("incomplete capture frame")
            result.extend(buffer.raw[:n.value])
        return bytes(result)

    def finish_frame(self,pipe):
        # The native writer flushes then closes after each complete frame.
        # Disconnecting immediately after ReadFile races that flush and can
        # report a false send failure, permanently disabling capture. Wait for
        # the writer's EOF before disconnecting this one-frame connection.
        extra=c.create_string_buffer(1);size=w.DWORD()
        ok=self.k.ReadFile(pipe,extra,1,c.byref(size),None)
        if ok and size.value:raise ValueError('unexpected_trailing_capture_data')
        if not ok and c.get_last_error() not in (109,232):raise OSError('capture_close_unconfirmed')

    def start(self):
        self.thread=threading.Thread(target=self.serve,daemon=True);self.thread.start()
        if not self.listening.wait(5):raise RuntimeError("observer pipe did not start")
        inject(self.subject["pid"],self.dll,self.subject)
        if not self.ready.wait(15):
            from .windows import modules,exports
            loaded=next((m for m in modules(self.subject['pid']) if Path(m['path']).name.lower()==self.dll.name.lower()),None)
            stage='dll_not_loaded'
            if loaded:
                address=loaded['base']+exports(loaded['path']).get('observe_status',0)
                k=c.WinDLL('kernel32',use_last_error=True);k.ReadProcessMemory.argtypes=[w.HANDLE,c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)]
                from transpect_trace.guard.native import api
                handle=api().OpenProcess(0x10,False,self.subject['pid']);value=c.c_long();n=c.c_size_t()
                try:
                    if handle and k.ReadProcessMemory(handle,address,c.byref(value),4,c.byref(n)):stage=str(value.value)
                finally:
                    if handle:api().CloseHandle(handle)
            raise RuntimeError(f"observer readiness unverified: {stage}")

    def serve(self):
        while not self.stop.is_set():
            handle=self.k.CreateNamedPipeW(self.name,3,8,1,65536,65536,2000,c.byref(self.security))
            if handle==w.HANDLE(-1).value:self.errors.append("pipe_create_failed");return
            self.listening.set()
            complete=False
            try:
                if not self.k.ConnectNamedPipe(handle,None) and c.get_last_error()!=535:continue
                if self.stop.is_set():continue
                peer=w.ULONG()
                if not self.k.GetNamedPipeClientProcessId(handle,c.byref(peer)) or peer.value!=self.subject["pid"]:
                    raise ValueError("client_identity_mismatch")
                from transpect_trace.guard.native import api
                kernel=api();peer_handle=kernel.OpenProcess(0x1000,False,peer.value)
                try:
                    times=[w.FILETIME() for _ in range(4)]
                    if not peer_handle or not kernel.GetProcessTimes(peer_handle,*(c.byref(t) for t in times)) or times[0].dwLowDateTime+(times[0].dwHighDateTime<<32)!=self.subject['creation_filetime']:
                        raise ValueError('client_process_generation_mismatch')
                finally:
                    if peer_handle:kernel.CloseHandle(peer_handle)
                magic,pid,tid,direction,seq,low,high,epoch,qpc,length,flags=HEADER.unpack(self.read(handle,HEADER.size))
                if magic!=b"TTO1" or pid!=peer.value or direction>1 or length>65536:raise ValueError("invalid_capture_header")
                kind=flags&255
                if kind==4:
                    sent=w.DWORD()
                    if not self.k.WriteFile(handle,self.config,len(self.config),c.byref(sent),None) or sent.value!=len(self.config):raise OSError("configuration_write_failed")
                    self.k.FlushFileBuffers(handle)
                    complete=True
                    continue
                payload=self.read(handle,length)
                complete=True
                if kind==1:self.ready.set();continue
                self.consume_frame(kind,pid,tid,direction,seq,low,high,epoch,qpc,flags,payload)
            except Exception as error:
                # Never copy arbitrary parse errors / plaintext into diagnostics.
                self.errors.append(type(error).__name__)
                gap={'kind':'coverage_gap','pid':self.subject['pid'],'creation_filetime':self.subject['creation_filetime'],
                     'connection_id':'unknown','provider':'native-observer','reason':'capture_decode_or_processing_failure','can_enforce':False}
                self.pipeline.gaps.append(gap);self.pipeline.write('coverage-gaps.jsonl',gap)
            finally:
                if complete:
                    try:self.finish_frame(handle)
                    except Exception:self.errors.append('capture_close_unconfirmed')
                self.k.DisconnectNamedPipe(handle);self.k.CloseHandle(handle)

    def consume_frame(self,kind,pid,tid,direction,seq,low,high,epoch,qpc,flags,payload):
        if kind not in {0,2,16,32}:raise ValueError('unsupported legacy observer event kind')
        point="http-body" if kind==16 else "wss-message" if kind==32 else "tls"
        event=CaptureEvent(provider="native-observer",capture_point=point,pid=pid,tid=tid,
            creation_filetime=self.subject["creation_filetime"],connection_id=f"{low:x}:{high:x}:{epoch}",
            direction="recv" if direction else "send",sequence=seq,captured_qpc=qpc,qpc_frequency=self.frequency,
            data_b64=base64.b64encode(payload).decode(),truncated=bool(flags&256),lost_events=flags>>16,
            event="closed" if kind==2 else "data",application=self.profile.application,image_sha256=self.subject['image_sha256'])
        self.pipeline.consume(event)

    def check_health(self):
        if self.errors or not self.thread or not self.thread.is_alive():
            raise RuntimeError('Native collection unavailable')

    def _disable_capture(self):
        # Disable our own capture flag, not the gate DLL and not the process.
        from .windows import modules,exports
        from transpect_trace.guard.native import api
        k=api();handle=k.OpenProcess(0x2|0x10|0x400|0x100000,False,self.subject['pid'])
        if self.ready.is_set() and (not handle or k.WaitForSingleObject(handle,0)!=258):
            self.errors.append('terminal_capture_health_unavailable')
            gap={'kind':'coverage_gap','pid':self.subject['pid'],'creation_filetime':self.subject['creation_filetime'],
                 'connection_id':'unknown','provider':'native-observer','reason':'terminal_capture_health_unavailable','can_enforce':False}
            self.pipeline.gaps.append(gap);self.pipeline.write('coverage-gaps.jsonl',gap)
        if handle and self.ready.is_set() and k.WaitForSingleObject(handle,0)==258:
            try:
                times=[w.FILETIME() for _ in range(4)]
                same=k.GetProcessTimes(handle,*(c.byref(t) for t in times)) and times[0].dwLowDateTime+(times[0].dwHighDateTime<<32)==self.subject['creation_filetime']
                if same:
                    loaded=next((m for m in modules(self.subject['pid']) if Path(m['path']).resolve()==self.dll.resolve()),None)
                    if loaded:
                        symbols=exports(loaded['path']);rva=symbols.get('observe_disable')
                        if rva:
                            thread=k.CreateRemoteThread(handle,None,0,loaded['base']+rva,None,0,None)
                            if thread:
                                if k.WaitForSingleObject(thread,5000)!=0:self.errors.append('disable_unconfirmed')
                                k.CloseHandle(thread)
                            else:self.errors.append('disable_unconfirmed')
                        else:self.errors.append('disable_unconfirmed')
                        # A last lost frame may have no successor to carry the
                        # lost_events flag. Read the monotonic native counter.
                        dropped_rva=symbols.get('observe_dropped')
                        if dropped_rva:
                            reader=c.WinDLL('kernel32',use_last_error=True)
                            reader.ReadProcessMemory.argtypes=[w.HANDLE,c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)]
                            dropped=c.c_long();size=c.c_size_t()
                            if reader.ReadProcessMemory(handle,loaded['base']+dropped_rva,c.byref(dropped),4,c.byref(size)) and size.value==4:
                                if dropped.value:
                                    self.errors.append('native_capture_loss')
                                    gap={'kind':'coverage_gap','pid':self.subject['pid'],
                                        'creation_filetime':self.subject['creation_filetime'],'connection_id':'unknown',
                                        'provider':'native-observer','reason':'native_capture_loss','lost_events':dropped.value,'can_enforce':False}
                                    self.pipeline.gaps.append(gap);self.pipeline.write('coverage-gaps.jsonl',gap)
                            else:self.errors.append('native_loss_status_unavailable')
                        else:self.errors.append('native_loss_status_unavailable')
                    else:self.errors.append('disable_unconfirmed')
                else:self.errors.append('disable_unconfirmed')
            except OSError:self.errors.append('disable_unconfirmed')
            finally:k.CloseHandle(handle);handle=None
        if handle:k.CloseHandle(handle)

    def close(self):
        if self._closed:return
        self._closed=True
        try:self._disable_capture()
        except Exception:self.errors.append('disable_unconfirmed')
        finally:
            self.stop.set()
            handle=self.k.CreateFileW(self.name,0xc0000000,0,None,3,0,None)
            if handle!=w.HANDLE(-1).value:self.k.CloseHandle(handle)
            if self.thread:self.thread.join(timeout=2)
            if not self.thread or not self.thread.is_alive():self.k.LocalFree(self.security.descriptor)
            else:self.errors.append('collector_shutdown_unconfirmed')
