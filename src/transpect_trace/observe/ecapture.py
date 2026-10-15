"""Adapter for the pinned upstream Windows preview stream, not a TLS gate.

Upstream text mode emits a 120-byte printable preview and lacks connection IDs.
It cannot certify complete HTTP payloads. Raw output is never persisted.
"""
from __future__ import annotations
import ast
import base64
import re
import subprocess
import threading
import time
from .models import CaptureEvent

PIN={"repository":"https://github.com/gojue/ecapture-windows",
     "commit":"7fb8347b7a3c28d2a094e35af38b1c471d194ebf",
     "transport":"loopback_tcp_port_file","connection_identity":"missing",
     "text_preview_limit":120,"production_ready":False}
PATTERN=re.compile(r'PID:(\d+) TID:(\d+) SSPIAppData (send|recv) len=(\d+) data=(".*")')


class ECaptureCollector:
    def __init__(self,subject,profile,executable,pipeline):
        self.subject,self.profile,self.executable,self.pipeline=subject,profile,executable,pipeline
        self.ready=threading.Event();self.errors=[];self.process=None;self.threads=[];self.sequence={}
        self.stopping=threading.Event()

    def line(self,line):
        match=PATTERN.search(line)
        if not match:
            if 'requires administrator privileges' in line:self.errors.append('administrator_privileges_required')
            if "Windows TLS probe started" in line:self.ready.set()
            return
        pid,tid,direction,length,quoted=match.groups();pid=int(pid);tid=int(tid);length=int(length)
        if pid!=self.subject["pid"]:return
        try:preview=ast.literal_eval(quoted).encode("utf-8")
        except (ValueError,SyntaxError):preview=b""
        key=(tid,direction);self.sequence[key]=self.sequence.get(key,0)+1
        event=CaptureEvent(provider="ecapture-windows",capture_point="tls",pid=pid,tid=tid,
            creation_filetime=self.subject["creation_filetime"],connection_id=f"unverified-thread-{tid}",
            direction=direction,sequence=self.sequence[key],captured_qpc=time.perf_counter_ns(),qpc_frequency=1_000_000_000,
            data_b64=base64.b64encode(preview).decode(),truncated=length!=len(preview),connection_identity="unknown",
            application=self.profile.application,image_sha256=self.subject.get('image_sha256'))
        self.pipeline.consume(event)

    def start(self):
        import json
        from .windows import identity,digest
        current=identity(self.subject['pid'])
        if current['creation_filetime']!=self.subject['creation_filetime'] or current['image_sha256']!=self.subject['image_sha256']:
            raise ValueError('eCapture target identity changed')
        manifest=json.loads((self.executable.parent/'ecapture-build.json').read_text(encoding='utf-8'))
        if manifest.get('commit')!=PIN['commit'] or any(manifest['artifacts_sha256'].get(name)!=digest(self.executable.parent/name)
                                                       for name in ['ecapture.exe','schannel_hook.dll']):
            raise ValueError('eCapture executable build manifest mismatch')
        self.process=subprocess.Popen([str(self.executable.resolve()),"tls","--schannel","--pid",str(self.subject["pid"]),"-m","text"],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=self.executable.parent.resolve())
        def read(stream):
            try:
                while True:
                    line=stream.readline(65536)
                    if not line:break
                    if not line.endswith(b"\n"):
                        if 'ecapture_output_line_limit' not in self.errors:self.errors.append('ecapture_output_line_limit')
                        continue
                    self.line(line.decode("utf-8",errors="replace"))
            except Exception:
                self.errors.append('ecapture_output_processing_failed')
        for stream in (self.process.stdout,self.process.stderr):
            thread=threading.Thread(target=read,args=(stream,),daemon=True);thread.start();self.threads.append(thread)
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if self.ready.wait(0.1):return
            if self.process.poll() is not None:raise RuntimeError("eCapture exited before readiness; verify ETW privileges and build manifest")
        raise RuntimeError("eCapture readiness unverified")

    def check_health(self):
        if self.process and self.process.poll() is not None and not self.stopping.is_set():
            if 'ecapture_process_exited' not in self.errors:self.errors.append('ecapture_process_exited')
        if self.errors:raise RuntimeError('eCapture collection unavailable')

    def close(self):
        if self.stopping.is_set():return
        try:self.check_health()
        except RuntimeError:pass
        self.stopping.set()
        if self.process and self.process.poll() is None:self.process.terminate();self.process.wait(timeout=5)
        for thread in self.threads:thread.join(timeout=2)
