"""Protect v1 local IPC. Wire bodies are transient and never audit serialized."""
from __future__ import annotations
import base64,ctypes as c,json,os,struct,threading,time
from pathlib import Path
from ctypes import wintypes as w
from transpect_trace.guard.pipe import windows_api,pipe_security
from transpect_trace.guard.wire import encode_frame
from transpect_trace.observe.windows import identity
from .models import SemanticCaptureEvent,GateRequest,GateReply,ExecutionEvidence

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate field')
        result[key]=value
    return result

def parse_event(raw,subject):
    value=json.loads(raw,object_pairs_hook=unique_object)
    request=GateRequest.model_validate(value)
    event=request.event;event.body=base64.b64decode(request.body_b64,validate=True)
    import hashlib
    if len(event.body)!=event.body_bytes or hashlib.sha256(event.body).hexdigest()!=event.body_sha256:raise ValueError('invalid snapshot')
    if (event.pid,event.creation_filetime,event.image_sha256)!=(subject['pid'],subject['creation_filetime'],subject['image_sha256']):
        raise ValueError('process identity mismatch')
    return event

class ProtectionServer:
    def __init__(self,subject,engine,audit,*,workers=4,fault=None):
        self.subject,self.engine,self.audit=subject,engine,Path(audit)
        self.workers,self.fault=workers,fault
        self.name=rf'\\.\pipe\ttrace-protect-{subject["pid"]}'
        self.k=windows_api();self.security=pipe_security(self.k)
        self.stop=threading.Event();self.listening=threading.Event();self.threads=[];self.lock=threading.Lock()
        self.errors=[];self.records=[];self.execution_records=[];self.handles=set();self.closed=False
        from .correlation import RequestCorrelator
        self.correlator=RequestCorrelator()

    def start(self):
        self.audit.parent.mkdir(parents=True,exist_ok=True)
        for _ in range(self.workers):
            thread=threading.Thread(target=self._serve,daemon=True);thread.start();self.threads.append(thread)
        if not self.listening.wait(5):raise RuntimeError('Protect listener unavailable')

    def _read(self,h,size):
        data=bytearray()
        while len(data)<size:
            buf=c.create_string_buffer(min(65536,size-len(data)));n=w.DWORD()
            if not self.k.ReadFile(h,buf,len(buf),c.byref(n),None) or not n.value:raise OSError('incomplete frame')
            data.extend(buf.raw[:n.value])
        return bytes(data)

    def _serve(self):
        while not self.stop.is_set():
            h=self.k.CreateNamedPipeW(self.name,3,8,self.workers,65536,65536,2000,c.byref(self.security))
            if h==w.HANDLE(-1).value:self.errors.append('pipe_create_failed');return
            with self.lock:self.handles.add(h)
            self.listening.set()
            try:
                if not self.k.ConnectNamedPipe(h,None) and c.get_last_error()!=535:continue
                if self.stop.is_set():continue
                peer=w.ULONG()
                if not self.k.GetNamedPipeClientProcessId(h,c.byref(peer)) or peer.value!=self.subject['pid']:raise ValueError('peer mismatch')
                if identity(peer.value)!=self.subject:raise ValueError('peer lifetime changed')
                size=struct.unpack('<I',self._read(h,4))[0]
                if not 0<size<=24*1024*1024:raise ValueError('frame limit')
                raw=self._read(h,size)
                value=json.loads(raw,object_pairs_hook=unique_object)
                if value.get('schema_version')=='transpect.protect.execution/1.0':
                    execution=ExecutionEvidence.model_validate(value)
                    if execution.pid!=peer.value:raise ValueError('execution PID mismatch')
                    with self.lock:
                        self.execution_records.append(execution.model_dump())
                        with (self.audit.parent/'execution.jsonl').open('a',encoding='utf-8') as out:out.write(execution.model_dump_json()+'\n')
                    frame=encode_frame(GateReply(attempt_id=execution.attempt_id,decision='ALLOW',action='none',reason='EXECUTION_ACK',policy_version=self.engine.policy.version).model_dump())
                    count=w.DWORD();self.k.WriteFile(h,frame,len(frame),c.byref(count),None);self.k.FlushFileBuffers(h)
                    continue
                event=parse_event(raw,self.subject)
                self.correlator.add(event)
                if self.fault=='disconnect':continue
                started=time.monotonic()
                if self.fault=='timeout':time.sleep(2.2)
                verdict=self.engine.evaluate(event)
                if time.monotonic()-started>=2:
                    from .models import PolicyVerdict
                    verdict=PolicyVerdict(attempt_id=event.attempt_id,decision='UNKNOWN',reason='DECISION_DEADLINE_EXCEEDED',
                        policy_version=self.engine.policy.version,requested_action='block_request',detection_status='incomplete')
                row={'event':event.model_dump(),'verdict':verdict.model_dump(),'elapsed_ms':(time.monotonic()-started)*1000,
                     'action_execution':'not_confirmed','source_confidence':'Unknown'}
                from .unified import normalize
                row['unified_request']=normalize(event).model_dump()
                # Native has final deadline authority; policy output is never execution proof.
                response={'schema_version':'transpect.protect.reply/1.0','attempt_id':event.attempt_id,'decision':verdict.decision,
                    'action':verdict.requested_action,'reason':verdict.reason,'policy_version':verdict.policy_version}
                if self.fault=='stale_reply':response['attempt_id']='stale'
                frame=encode_frame(GateReply.model_validate(response).model_dump())
                if self.fault=='malformed_reply':
                    raw=frame[4:]+b' {}';frame=struct.pack('<I',len(raw))+raw
                with self.lock:
                    self.records.append(row)
                    with self.audit.open('a',encoding='utf-8') as out:out.write(json.dumps(row)+'\n')
                count=w.DWORD()
                if not self.k.WriteFile(h,frame,len(frame),c.byref(count),None) or count.value!=len(frame):raise OSError('reply disconnected')
                self.k.FlushFileBuffers(h)
            except (OSError,ValueError,KeyError,TypeError):
                with self.lock:self.errors.append('request_or_transport_invalid')
            finally:
                with self.lock:self.handles.discard(h)
                self.k.DisconnectNamedPipe(h);self.k.CloseHandle(h)

    def close(self):
        if self.closed:return
        self.closed=True;self.stop.set()
        # Wake listeners without injecting a policy request.
        for _ in range(self.workers):
            h=self.k.CreateFileW(self.name,0xc0000000,0,None,3,0,None)
            if h!=w.HANDLE(-1).value:self.k.CloseHandle(h)
        for t in self.threads:t.join(timeout=3)
        if not any(t.is_alive() for t in self.threads):self.k.LocalFree(self.security.descriptor)
