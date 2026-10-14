"""A policy process can implement the named-pipe protocol in any language."""
import json
import os
from pathlib import Path
import subprocess
import threading


AUDIT_FIELDS={"kind","request_id","native_event_id","guard_session_id","pid","tid",
              "protocol","decision","action","reason","policy_version","policy_id",
              "content_sha256","content_bytes","matched_rule_ids","candidate_source_paths",
              "source_confidence","elapsed_ms","action_execution","byte_level_taint_proof",
              "captured_qpc","qpc_frequency","captured_at_unix_ns","engine_language"}
AUDIT_KINDS={"engine.listening","native.initialize","native.ready","native.outcome",
             "model.request","policy.decision"}


def audit_metadata(row):
    if not isinstance(row,dict) or row.get("kind") not in AUDIT_KINDS:return None
    return {key:value for key,value in row.items() if key in AUDIT_FIELDS}


class ExternalEngine:
    def __init__(self,pid:int,command:list[str],audit:Path):
        self.pid,self.command,self.audit=pid,command,audit
        self.ready=threading.Event();self.listening=threading.Event();self.records=[];self.errors=[]
        self.process=None;self.thread=None;self.stderr_thread=None

    def start(self):
        env=dict(os.environ,TTRACE_GUARD_PID=str(self.pid),TTRACE_GUARD_PIPE=rf"\\.\pipe\ttrace-guard-{self.pid}")
        self.audit.parent.mkdir(parents=True,exist_ok=True)
        self.process=subprocess.Popen(self.command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,env=env,text=True,encoding="utf-8")
        def read():
            with self.audit.open("a",encoding="utf-8") as out:
                for line in self.process.stdout:
                    try:row=json.loads(line)
                    except ValueError:continue
                    row=audit_metadata(row)
                    if row is None:continue
                    self.records.append(row);out.write(json.dumps(row)+"\n");out.flush()
                    if row.get("kind")=="engine.listening":self.listening.set()
                    if row.get("kind")=="native.ready":self.ready.set()
        self.thread=threading.Thread(target=read,daemon=True);self.thread.start()
        # Drain diagnostics to avoid pipe backpressure; never persist arbitrary
        # engine output, which may contain inspected payloads or credentials.
        def drain():
            while self.process.stderr.read(4096):pass
        self.stderr_thread=threading.Thread(target=drain,daemon=True);self.stderr_thread.start()
        import ctypes,time
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.WaitNamedPipeW.argtypes=[ctypes.c_wchar_p,ctypes.c_ulong]
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if self.listening.is_set() or kernel.WaitNamedPipeW(env["TTRACE_GUARD_PIPE"],100):return
            if self.process.poll() is not None:raise RuntimeError("External policy process exited before listening")
            time.sleep(0.05)
        raise RuntimeError("External named-pipe engine did not become available")

    def close(self):
        if self.process and self.process.poll() is None:self.process.terminate();self.process.wait(timeout=5)
        if self.thread:self.thread.join(timeout=2)
        if self.stderr_thread:self.stderr_thread.join(timeout=2)
