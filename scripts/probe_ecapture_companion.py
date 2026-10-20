"""Same-user ECW2 companion integration. Does NOT certify eCapture/ETW runtime.

Only injects the explicit isolated WinHTTP fake-data child created here.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import queue
import struct
import subprocess
import threading
import time
from uuid import uuid4
from probe_codex_tls import certificate, Origin
from transpect_trace.guard.pipe import windows_api, pipe_security
from transpect_trace.guard.policy import GuardPolicy
from transpect_trace.observe.ecapture import verify_build
from transpect_trace.observe.ecapture_enhanced import HEADER, StructuredCapture
from transpect_trace.observe.pipeline import Pipeline
from transpect_trace.observe.windows import discover_profile, inject, digest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('runs/ecapture/companion')/uuid4().hex)
    parser.add_argument('--scenario',choices=['text','binary'],default='text')
    args=parser.parse_args();root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    executable=Path('build/observe/ecapture-enhanced/ecapture.exe').resolve();manifest=verify_build(executable)
    if digest(executable.parent/'ecapture_fixture.exe')!=manifest['artifacts_sha256'].get('ecapture_fixture.exe'):
        raise ValueError('fixture_build_mismatch')
    cert,key,ca=certificate(root);fake='FAKE_COMPANION 中文 '*500
    payload=json.dumps({'model':'fixture','input':fake},ensure_ascii=False).encode() if args.scenario=='text' else b'\x00\xff\xfe'*4096
    body=root/'fake.json';body.write_bytes(payload)
    origin=Origin(root,cert,key,b'FAKE_COMPANION');origin.thread.start()
    child=subprocess.Popen([str(executable.parent/'ecapture_fixture.exe'),str(origin.port),str(body),'2','2'],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    pipeline=Pipeline(root,GuardPolicy());errors=[];stop=threading.Event();ready=threading.Event();thread=None;reader=None
    k=windows_api();security=pipe_security(k)
    k.PeekNamedPipe.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.c_void_p,c.POINTER(w.DWORD),c.c_void_p]
    k.PeekNamedPipe.restype=w.BOOL
    pipe=None
    try:
        if child.stdout.readline().strip()!=b'ready':raise RuntimeError('fixture_not_ready')
        subject,profile=discover_profile(child.pid,'schannel-fixture','schannel')
        reader=StructuredCapture(subject,'schannel-fixture',pipeline)
        name=rf"\\.\pipe\ecapture-enhanced-{child.pid}-{subject['creation_filetime']}"
        pipe=k.CreateNamedPipeW(name,3|0x80000,1|8,1,65536,65536,1000,c.byref(security))
        if pipe==w.HANDLE(-1).value:raise OSError('pipe_create_failed')

        def serve():
            try:
                deadline=time.monotonic()+12
                while not k.ConnectNamedPipe(pipe,None):
                    if c.get_last_error()==535:break
                    if c.get_last_error()!=536 or time.monotonic()>deadline:raise OSError('pipe_connect_failed')
                    time.sleep(.005)
                peer=w.ULONG()
                if not k.GetNamedPipeClientProcessId(pipe,c.byref(peer)) or peer.value!=subject['pid']:
                    raise ValueError('pipe_peer_mismatch')
                lo,hi=struct.unpack('<QQ',uuid4().bytes)
                config=HEADER.pack(b'ECW2',0,child.pid,0,5,0,0,0,subject['creation_filetime'],lo,hi,0,0,0,0,0,0,0)
                sent=w.DWORD()
                if not k.WriteFile(pipe,config,len(config),c.byref(sent),None) or sent.value!=len(config):raise OSError('config_write_failed')
                buffer=bytearray();stopping=False
                while not reader.terminal:
                    if stop.is_set() and not stopping:
                        if not k.WriteFile(pipe,b'STOP',4,c.byref(sent),None) or sent.value!=4:raise OSError('stop_write_failed')
                        stopping=True;deadline=time.monotonic()+7
                    if (not reader.ready or stopping) and time.monotonic()>deadline:raise TimeoutError('companion_timeout')
                    available=w.DWORD()
                    if not k.PeekNamedPipe(pipe,None,0,None,c.byref(available),None):raise OSError('capture_disconnected')
                    if not available.value:time.sleep(.005);continue
                    data=c.create_string_buffer(min(available.value,65536));got=w.DWORD()
                    if not k.ReadFile(pipe,data,len(data),c.byref(got),None) or not got.value:raise OSError('capture_read_failed')
                    buffer.extend(data.raw[:got.value])
                    while len(buffer)>=HEADER.size:
                        n=HEADER.unpack(buffer[:HEADER.size])[1]
                        if n>65536:raise ValueError('frame_limit')
                        if len(buffer)<HEADER.size+n:break
                        reader.consume(bytes(buffer[:HEADER.size]),bytes(buffer[HEADER.size:HEADER.size+n]));del buffer[:HEADER.size+n]
                        if reader.ready:ready.set()
            except Exception as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        inject(child.pid,executable.parent/'schannel_hook.dll',subject)
        if not ready.wait(15):raise RuntimeError('companion_readiness_unverified')
        child.stdin.write(b'1');child.stdin.flush();messages=queue.Queue()
        threading.Thread(target=lambda:messages.put(child.stdout.readline()),daemon=True).start()
        if messages.get(timeout=20).strip()!=b'sent':raise RuntimeError('fixture_not_sent')
        time.sleep(.2)
    except Exception as error:errors.append(type(error).__name__)
    finally:
        stop.set()
        if thread:thread.join(timeout=8)
        if thread and thread.is_alive():errors.append('companion_shutdown_unconfirmed')
        if child.poll() is None:child.terminate();child.wait(timeout=5)
        child.stdin.close();child.stdout.close()
        if pipe and pipe!=w.HANDLE(-1).value:k.DisconnectNamedPipe(pipe);k.CloseHandle(pipe)
        k.LocalFree(security.descriptor)
        origin.stop.set();origin.thread.join(timeout=10);origin.listener.close()
    if not reader or not reader.terminal:pipeline.gaps.append({'reason':'terminal_capture_health_unavailable'})
    pipeline.finish()
    receipts=[{'payload_sha256':r['payload_sha256'],'payload_bytes':r['payload_bytes']} for r in origin.records if r.get('payload_sha256')]
    (root/'origin-receipts.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in receipts),encoding='utf-8')
    expected=hashlib.sha256(payload).hexdigest()
    passed=bool(reader and reader.terminal and not errors and not pipeline.gaps and len(pipeline.rows)==4
                and all(r['content_sha256']==expected for r in pipeline.rows) and len(receipts)==4 and all(r['payload_sha256']==expected for r in receipts))
    result={'scope':'companion_only_no_ETW','collector_variant':'enhanced-companion','passed':passed,'scenario':args.scenario,
        'terminal_health_confirmed':bool(reader and reader.terminal),'lost':reader.lost if reader else None,
        'collector_errors':errors,'coverage_gaps':pipeline.gaps,'source_hash':expected,
        'observations':len(pipeline.rows),'ecapture_runtime_certified':False,'can_enforce':False,'actual_ai_channel_certified':False}
    (root/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps({'output':str(root),**result},indent=2))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
