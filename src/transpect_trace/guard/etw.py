"""Scope ETW metadata before persistence; grade derived source relations only."""
from __future__ import annotations

import hashlib
import json
import ntpath
import os
from pathlib import Path
import subprocess
import threading
import time
from uuid import uuid5,NAMESPACE_URL

from .evidence import evidence_dict

PROCESS="22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"
FILE="edd08927-9cc4-4e65-b970-c2560fb5c289"
NETWORK="7dd42a49-5329-4832-8dfd-43d979153a88"


def canonical_path(path):
    if not isinstance(path,str):return None
    if path.startswith("\\\\?\\"):path=path[4:]
    if os.name=="nt" and path.lower().startswith("\\device\\"):
        import ctypes
        k=ctypes.WinDLL("kernel32",use_last_error=True)
        k.QueryDosDeviceW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_ulong]
        k.QueryDosDeviceW.restype=ctypes.c_ulong
        for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            buffer=ctypes.create_unicode_buffer(32768)
            if k.QueryDosDeviceW(drive+":",buffer,len(buffer)):
                prefix=buffer.value
                if path.casefold().startswith(prefix.casefold()+"\\"):
                    path=drive+":"+path[len(prefix):];break
    return ntpath.normcase(ntpath.normpath(path))


def number(value,default=0):
    try:return int(str(value),0)
    except ValueError:
        try:return int(str(value),10)
        except ValueError:return default


class EtwIndex:
    def __init__(self,pid:int,creation_filetime:int):
        self.root_pid=pid
        identity=f"{pid}-{creation_filetime}"
        self.processes={pid:{"identity":identity,"parent":None,
                        "event_id":str(uuid5(NAMESPACE_URL,f"process-snapshot:{identity}")),"parent_identity":None,
                        "reliable_birth":True}}
        self.root_identity=identity;self.history={identity:self.processes[pid]}
        self.root_retired=False
        self.snapshot={"kind":"system.process.snapshot","event_id":self.processes[pid]["event_id"],
                       "pid":pid,"creation_filetime":creation_filetime,"method":"win32_process_identity",
                       "source_trust":"external","byte_level_taint_proof":False}
        self.threads={};self.files={};self.reads=[];self.writes=set();self.dropped_events=0
        self.clock=None

    def consume(self,row:dict) -> dict|None:
        if row.get("kind")=="etw.ready":self.clock=row;return row
        if row.get("kind")=="etw.stopped":
            self.dropped_events+=sum(row.get(key,0) for key in ("events_lost","buffers_lost","decode_errors"))
            return row
        if row.get("kind")=="etw.unavailable":return row
        if row.get("kind")!="etw.event":return None
        props=row.get("properties",{});provider=row.get("provider","").strip("{}").lower()
        task=row.get("task","").lower();opcode=row.get("opcode",0)
        pid=number(props.get("ProcessID",props.get("ProcessId",row.get("header_pid",0))))
        tid=number(props.get("ThreadID",props.get("ThreadId",props.get("TTID",row.get("header_tid",0)))))
        sequence=row.get("sequence",0);tick=row.get("timestamp_qpc",0)
        eid=str(uuid5(NAMESPACE_URL,f"etw:{self.root_pid}:{sequence}:{provider}:{tick}"))
        if provider==PROCESS and "thread" in task:
            if opcode in (2,4) or "stop" in task:self.threads.pop(tid,None)
            elif pid in self.processes:self.threads[tid]=pid
        if provider==PROCESS and ("process" in task or task==""):
            parent=number(props.get("ParentProcessID",props.get("ParentProcessId",0)))
            if opcode in (1,3) or "start" in task:
                created=number(props.get("CreateTime",0))
                owns=(not self.root_retired and (not created or f"{pid}-{created}"==self.root_identity)) if pid==self.root_pid else parent in self.processes
                if owns:
                    identity=self.root_identity if pid==self.root_pid else f"{pid}-{created}" if created else f"{pid}-qpc:{tick}"
                    self.processes[pid]={"identity":identity,"parent":parent,"event_id":eid,
                                         "parent_identity":self.processes.get(parent,{}).get("identity"),
                                         "reliable_birth":pid==self.root_pid or bool(created)}
                    self.history[identity]=self.processes[pid]
                else:
                    self.processes.pop(pid,None)
                    self.threads={key:owner for key,owner in self.threads.items() if owner!=pid}
                    if pid==self.root_pid:self.root_retired=True
            elif opcode in (2,4) or "stop" in task:
                if pid in self.processes:
                    subject=self.processes.pop(pid)
                    self.threads={key:owner for key,owner in self.threads.items() if owner!=pid}
                    if pid==self.root_pid:self.root_retired=True
                    return {**row,"event_id":eid,"subject_identity":subject["identity"],"pid":pid,"normalized_kind":"system.process.stopped"}
        if provider==FILE:
            pid=self.threads.get(tid,pid)
            key=str(props.get("FileObject",props.get("FileKey","")))
            path=props.get("FileName",props.get("FilePath"))
            if isinstance(path,str) and key:self.files[key]=path
            path=path if isinstance(path,str) else self.files.get(key)
            if "close" in task or "cleanup" in task:self.files.pop(key,None)
            if pid not in self.processes:return None
            kind="system.file.access"
            if "read" in task or opcode==67:kind="system.file.read"
            elif "write" in task or opcode==68:kind="system.file.write"
            normalized={**row,"event_id":eid,"pid":pid,"tid":tid,"path":path,
                        "subject_identity":self.processes[pid]["identity"],"normalized_kind":kind,
                        "read_success":"not_inferred_from_access_event"}
            if kind=="system.file.read":self.reads.append(normalized)
            if kind=="system.file.write" and path:self.writes.add(path.casefold())
            return normalized
        if pid not in self.processes:return None
        kind="system.network.event" if provider==NETWORK else "system.process.event"
        return {**row,"event_id":eid,"pid":pid,"tid":tid,
                "subject_identity":self.processes[pid]["identity"],"normalized_kind":kind}

    def correlate(self,decision:dict) -> dict:
        paths=decision.get("candidate_source_paths",[])
        content_matched=bool(paths)
        # A missing process-start witness or a reused PID cannot earn High.
        def lineage(identity):
            seen=set();events=[]
            while identity in self.history and identity not in seen:
                seen.add(identity);subject=self.history[identity]
                if subject.get("event_id"):events.append(subject["event_id"])
                if identity==self.root_identity:return events
                identity=subject.get("parent_identity")
            return []
        def before_request(read):
            if decision.get("captured_qpc") and decision.get("qpc_frequency"):
                return read["timestamp_qpc"]<=decision["captured_qpc"]
            if not self.clock or not decision.get("captured_at_unix_ns"):return False
            seconds=(read["timestamp_qpc"]-self.clock["clock_qpc"])/self.clock["qpc_frequency"]
            unix_ns=(self.clock["clock_filetime"]-116444736000000000)*100+int(seconds*1e9)
            return unix_ns<=decision["captured_at_unix_ns"]
        eligible=[r for r in self.reads if r.get("path") and lineage(r["subject_identity"]) and before_request(r)]
        if not content_matched:
            # Candidate evidence only: recent reads without matching content
            # cannot earn High or prove that bytes reached this request.
            tick=decision.get("captured_qpc");freq=decision.get("qpc_frequency")
            eligible=[r for r in eligible if tick and freq and 0<=tick-r["timestamp_qpc"]<=5*freq]
            paths=sorted({r["path"] for r in eligible})
        reads=[r for r in eligible if canonical_path(r["path"]) in {canonical_path(p) for p in paths}]
        process_ids=[eid for r in reads for eid in lineage(r["subject_identity"])]
        content_ids=[decision["request_id"]] if content_matched else []
        def reliable(identity):
            seen=set()
            while identity in self.history and identity not in seen:
                seen.add(identity);subject=self.history[identity]
                if not subject.get("reliable_birth"):return False
                if identity==self.root_identity:return True
                identity=subject.get("parent_identity")
            return False
        relation=evidence_dict(paths=paths,file_event_ids=[r["event_id"] for r in reads],
                              process_event_ids=process_ids,content_event_ids=content_ids,
                              reliable_identity=bool(reads) and all(reliable(r["subject_identity"]) for r in reads),time_related=bool(reads),
                              dropped_events=self.dropped_events,
                              snapshot_current=not any(canonical_path(p) in {canonical_path(w) for w in self.writes} for p in paths))
        if not content_matched and paths:
            relation["limitations"]+= ("Candidate reads within 5 seconds; no content match",)
        if any(not reliable(r["subject_identity"]) for r in reads):
            relation["limitations"]+=("Child creation time missing; PID generation uses event QPC",)
        return {"request_id":decision["request_id"],"source_relation":relation}


def collect(executable:Path,pid:int,creation_filetime:int,output:Path):
    index=EtwIndex(pid,creation_filetime);output.parent.mkdir(parents=True,exist_ok=True)
    collector=subprocess.Popen([str(executable)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,text=True,encoding="utf-8",creationflags=0x200)
    with output.open("a",encoding="utf-8") as file:
        file.write(json.dumps(index.snapshot)+"\n");file.flush()
        try:
            for line in collector.stdout:
                try:row=index.consume(json.loads(line))
                except ValueError:continue
                if row is not None:file.write(json.dumps(row,ensure_ascii=False)+"\n");file.flush()
        except KeyboardInterrupt:
            import signal
            collector.send_signal(signal.CTRL_BREAK_EVENT)
            collector.wait(timeout=10)
    return collector.wait(),index


class EtwSession:
    def __init__(self,executable:Path,identity:dict,output:Path):
        self.executable,self.output=executable,output
        self.index=EtwIndex(identity["pid"],identity["creation_filetime"])
        self.state={"state":"initializing","confidence":"Unknown","byte_level_taint_proof":False}
        self.ready=threading.Event();self.lock=threading.Lock();self.process=None;self.thread=None

    def start(self):
        if not self.executable.is_file():self.state.update(state="unavailable",reason="collector_not_built");return
        self.output.parent.mkdir(parents=True,exist_ok=True)
        self.output.write_text(json.dumps(self.index.snapshot)+"\n",encoding="utf-8")
        self.process=subprocess.Popen([str(self.executable)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,text=True,encoding="utf-8",creationflags=0x200)
        def read():
            terminal=False
            with self.output.open("a",encoding="utf-8") as out:
                for line in self.process.stdout:
                    try:
                        with self.lock:row=self.index.consume(json.loads(line))
                    except ValueError:continue
                    if row is None:continue
                    out.write(json.dumps(row,ensure_ascii=False)+"\n");out.flush()
                    if row.get("kind")=="etw.ready":self.state.update(state="ready");self.ready.set()
                    if row.get("kind")=="etw.unavailable":self.state.update(state="unavailable",details=row);self.ready.set()
                    if row.get("kind")=="etw.stopped":
                        terminal=True
                        self.state.update(state="degraded" if self.index.dropped_events or row.get("status") else "stopped",
                                          terminal_observed=True,events_lost=self.index.dropped_events)
            if not terminal and self.state.get("state")!="unavailable":
                self.state.update(state="degraded",reason="collector_exit_without_terminal",terminal_observed=False)
            self.ready.set()
        self.thread=threading.Thread(target=read,daemon=True);self.thread.start()
        if not self.ready.wait(5):self.state.update(state="unavailable",reason="collector_not_ready")

    def close(self,decisions:list[dict],relations:Path):
        if self.process and self.process.poll() is None:
            import signal
            try:self.process.send_signal(signal.CTRL_BREAK_EVENT);self.process.wait(timeout=5)
            except (OSError,subprocess.TimeoutExpired):self.process.terminate();self.process.wait(timeout=5)
        if self.thread:self.thread.join(timeout=2)
        relations.parent.mkdir(parents=True,exist_ok=True)
        with self.lock:
            rows=[self.index.correlate(row) for row in decisions if row.get("kind")=="policy.decision"]
        relations.write_text("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in rows),encoding="utf-8")
        self.state["events_lost"]=self.index.dropped_events
