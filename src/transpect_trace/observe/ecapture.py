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
import os
from .models import CaptureEvent

PIN={"repository":"https://github.com/gojue/ecapture-windows",
     "commit":"7fb8347b7a3c28d2a094e35af38b1c471d194ebf",
     "transport":"loopback_tcp_port_file","connection_identity":"missing",
     "text_preview_limit":120,"production_ready":False}
PATTERN=re.compile(r'PID:(\d+) TID:(\d+) SSPIAppData (send|recv) len=(\d+) data=(".*")')


def verify_build(executable):
    import json,hashlib
    from pathlib import Path
    from .windows import digest
    if executable.name.lower()!='ecapture.exe':raise ValueError('eCapture executable name mismatch')
    manifest=json.loads((executable.parent/'ecapture-build.json').read_text(encoding='utf-8'))
    variant=manifest.get('variant','upstream')
    if variant not in {'upstream','enhanced'} or manifest.get('commit')!=PIN['commit']:
        raise ValueError('eCapture build identity mismatch')
    if variant=='upstream' and (manifest.get('protocol','upstream-preview')!='upstream-preview' or manifest.get('patches_sha256')):
        raise ValueError('eCapture upstream variant metadata mismatch')
    for name in ['ecapture.exe','schannel_hook.dll']:
        if manifest.get('artifacts_sha256',{}).get(name)!=digest(executable.parent/name):
            raise ValueError('eCapture artifact mismatch')
    if variant=='enhanced':
        from .ecapture_enhanced import PROTOCOL
        root=Path(__file__).resolve().parents[3]
        patch_root=root/'patches/ecapture-windows'
        pin=json.loads((patch_root/'manifest.json').read_text(encoding='utf-8'))
        if (pin.get('base_commit')!=PIN['commit'] or manifest.get('protocol')!=PROTOCOL or manifest.get('patches_sha256')!=pin['sha256'] or
            any(hashlib.sha256((patch_root/name).read_bytes()).hexdigest()!=want for name,want in pin['sha256'].items())):
            raise ValueError('eCapture enhanced patch identity mismatch')
    return manifest


class ECaptureCollector:
    def __init__(self,subject,profile,executable,pipeline,*,elevate=False):
        self.subject,self.profile,self.executable,self.pipeline=subject,profile,executable,pipeline
        self.ready=threading.Event();self.errors=[];self.process=None;self.threads=[];self.sequence={}
        self.stopping=threading.Event()
        self.elevate=elevate;self.etw_started=False;self.elevation_state='not_requested'

    def line(self,line):
        match=PATTERN.search(line)
        if not match:
            if 'requires administrator privileges' in line:self.errors.append('administrator_privileges_required')
            if line.strip()=='ecapture_etw_session_started':self.etw_started=True
            diagnostic=re.fullmatch(r'enhanced_capture_unavailable: ([a-z_]+)',line.strip())
            if diagnostic:self.errors.append(diagnostic.group(1))
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
        from .windows import identity
        current=identity(self.subject['pid'])
        if current['creation_filetime']!=self.subject['creation_filetime'] or current['image_sha256']!=self.subject['image_sha256']:
            raise ValueError('eCapture target identity changed')
        manifest=verify_build(self.executable)
        enhanced=manifest.get('variant')=='enhanced'
        if enhanced and self.profile.mode!='schannel':raise ValueError('enhanced eCapture only supports Schannel')
        from .elevation import is_elevated,ElevatedCapture
        if self.elevate and not enhanced:raise ValueError('UAC relay requires the verified enhanced eCapture build')
        elevated=is_elevated()
        if not elevated and not self.elevate:
            self.errors.append('administrator_privileges_required')
            self.elevation_state='required'
            raise RuntimeError('eCapture requires elevation; use --elevate-ecapture or an administrator terminal')
        env=dict(os.environ)
        # Never let a parent environment silently switch the stock binary.
        for name in ('TTRACE_ECAPTURE_ENHANCED','TTRACE_ECAPTURE_PID','TTRACE_ECAPTURE_BIRTH'):env.pop(name,None)
        if enhanced:env.update(TTRACE_ECAPTURE_ENHANCED='ECW2',TTRACE_ECAPTURE_PID=str(self.subject['pid']),TTRACE_ECAPTURE_BIRTH=str(self.subject['creation_filetime']))
        if self.elevate and not elevated:
            self.elevation_state='pending'
            self.process=ElevatedCapture(self.executable,self.subject,manifest)
            try:self.process.start()
            except OSError:
                self.errors.extend(self.process.errors)
                self.elevation_state=self.process.errors[0] if self.process.errors else 'failed'
                self.process=None
                raise
            self.elevation_state='collector_elevated'
        else:
            self.elevation_state='already_elevated'
            self.process=subprocess.Popen([str(self.executable.resolve()),"tls","--schannel","--pid",str(self.subject["pid"]),"-m","text"],
                stdin=subprocess.PIPE if enhanced else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=self.executable.parent.resolve(),env=env)
        if enhanced:
            from .ecapture_enhanced import StructuredCapture
            self.structured=StructuredCapture(self.subject,self.profile.application,self.pipeline)
            def frames():
                try:
                    while not self.structured.terminal:
                        self.structured.read(self.process.stdout)
                        if self.structured.ready:self.ready.set()
                except (EOFError,OSError,ValueError):
                    self.errors.append('structured_capture_failed')
                    self.structured.gap('structured_capture_failed')
            thread=threading.Thread(target=frames,daemon=True);thread.start();self.threads.append(thread)
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
        for stream in ((self.process.stderr,) if enhanced else (self.process.stdout,self.process.stderr)):
            thread=threading.Thread(target=read,args=(stream,),daemon=True);thread.start();self.threads.append(thread)
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if self.ready.wait(0.1):return
            if self.process.poll() is not None:
                self.errors.append('ecapture_exited_before_readiness')
                raise RuntimeError("eCapture exited before readiness; verify ETW privileges and build manifest")
        self.errors.append('ecapture_readiness_timeout')
        raise RuntimeError("eCapture readiness unverified")

    def check_health(self):
        if self.process:
            self.errors.extend(e for e in getattr(self.process,'errors',[]) if e not in self.errors)
        if self.process and self.process.poll() is not None and not self.stopping.is_set():
            if 'ecapture_process_exited' not in self.errors:self.errors.append('ecapture_process_exited')
        if self.errors:raise RuntimeError('eCapture collection unavailable')

    def close(self):
        if self.stopping.is_set():return
        try:self.check_health()
        except RuntimeError:pass
        self.stopping.set()
        if self.process and self.process.poll() is None:
            if hasattr(self,'structured'):
                try:
                    self.process.stdin.write(b'X');self.process.stdin.flush();self.process.wait(timeout=7)
                except (OSError,subprocess.TimeoutExpired):
                    self.errors.append('structured_shutdown_failed')
            if self.process.poll() is None:self.process.terminate();self.process.wait(timeout=5)
        for thread in self.threads:thread.join(timeout=2)
        if self.process:
            # Relay terminal/exit is checked separately from the DLL terminal frame.
            relay_thread=getattr(self.process,'thread',None)
            if relay_thread:relay_thread.join(timeout=2)
            self.errors.extend(e for e in getattr(self.process,'errors',[]) if e not in self.errors)
        if hasattr(self,'structured'):
            if not self.structured.terminal:
                self.errors.append('terminal_capture_health_unavailable');self.structured.gap('terminal_capture_health_unavailable')
            elif self.structured.lost:self.errors.append('terminal_capture_loss')
        if self.process:
            for stream in (getattr(self.process,name,None) for name in ('stdin','stdout','stderr')):
                if stream:stream.close()
            if hasattr(self.process,'close'):self.process.close()
