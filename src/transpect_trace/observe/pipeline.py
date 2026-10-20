from __future__ import annotations

import hashlib
import json
from pathlib import Path
from .assessment import Assessor
from .models import CaptureEvent,SourceRelation
from .protocol import Connection
from .unified import normalize
from .semantics import from_unified


class Pipeline:
    def __init__(self,directory:Path,policy,*,synthetic_bodies=False,semantic_sink=None):
        self.directory=directory;directory.mkdir(parents=True,exist_ok=True)
        self.assessor=Assessor(policy);self.connections={};self.rows=[];self.assessments=[];self.gaps=[]
        self.synthetic_bodies=synthetic_bodies
        self.semantic_sink=semantic_sink

    def write(self,name,row):
        with (self.directory/name).open("a",encoding="utf-8") as out:out.write(json.dumps(row,ensure_ascii=False)+"\n")

    def gap(self,event,reason):
        row={"kind":"coverage_gap","pid":event.pid,"creation_filetime":event.creation_filetime,
             "connection_id":event.connection_id,"provider":event.provider,"reason":reason,"can_enforce":False}
        self.gaps.append(row);self.write("coverage-gaps.jsonl",row)

    def consume(self,event:CaptureEvent):
        # Metadata-only by construction, including for headers and control frames.
        meta=event.model_dump();meta.update(captured_bytes=len(event.data),data_sha256=hashlib.sha256(event.data).hexdigest())
        self.write("capture-metadata.jsonl",meta)
        if event.event=="ready":return
        key=(event.pid,event.creation_filetime,event.connection_id)
        if key not in self.connections:
            if len(self.connections)>=128:self.gap(event,"connection_limit");return
            self.connections[key]=Connection()
        bodies,gaps=self.connections[key].feed(event)
        if sum(state.memory_bytes() for state in self.connections.values())>64*1024*1024:
            self.connections[key].quarantine();bodies=[];gaps.append('aggregate_reassembly_memory_limit')
        for reason in gaps:self.gap(event,reason)
        for body in bodies:
            if len(self.rows)>=10000:
                self.gap(event,'observation_count_limit');break
            obs,risk=self.assessor.assess(event,body)
            row=obs.model_dump();self.rows.append(row);self.assessments.append(risk.model_dump())
            self.write("observations.jsonl",row);self.write("assessments.jsonl",risk.model_dump())
            unified=normalize(event,body,obs)
            self.write("unified-requests.jsonl",unified.model_dump())
            self.write("classifications.jsonl",unified.classification.model_dump())
            semantics=from_unified(unified,body.data,body.headers.get("content-encoding","identity"))
            self.write("request-semantics.jsonl",semantics.model_dump())
            if self.semantic_sink:
                self.semantic_sink(semantics)
            if self.synthetic_bodies:
                # Only fixtures can construct Pipeline with this opt-in.
                folder=self.directory/"synthetic-bodies";folder.mkdir(exist_ok=True)
                (folder/(obs.observation_id+".bin")).write_bytes(body.data)
                (folder/(obs.observation_id+".semantics.json")).write_text(
                    json.dumps(semantics.synthetic_export(),ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        if event.event=="closed":self.connections.pop(key,None)

    def finish(self,etw_index=None):
        for (pid,birth,conn),state in self.connections.items():
            pending=bool(state.buffer or state.pending_ws or (state.parser and state.parser.pending) or (state.ws and state.ws.pending))
            if pending and not state.failed:
                row={"kind":"coverage_gap","pid":pid,"creation_filetime":birth,"connection_id":conn,
                     "reason":"capture_ended_with_incomplete_request","can_enforce":False}
                self.gaps.append(row);self.write("coverage-gaps.jsonl",row)
        for obs,risk in zip(self.rows,self.assessments):
            if etw_index:
                tick=obs['captured_qpc'];frequency=obs['qpc_frequency']
                if etw_index.clock:
                    target_frequency=etw_index.clock['qpc_frequency']
                    tick=tick*target_frequency//frequency;frequency=target_frequency
                decision={"pid":obs["pid"],"request_id":obs["observation_id"],"captured_qpc":obs["captured_qpc"],
                          "qpc_frequency":obs["qpc_frequency"],"candidate_source_paths":risk["candidate_source_paths"]}
                decision.update(captured_qpc=tick,qpc_frequency=frequency)
                relation=etw_index.correlate(decision)["source_relation"]
                relation["evidence_event_ids"]=list(relation["evidence_event_ids"])
                relation["candidate_source_paths"]=list(relation["candidate_source_paths"])
                relation["limitations"]=list(relation["limitations"])
            else:
                relation=dict(confidence="Unknown",method="system_evidence_unavailable",evidence_event_ids=[],
                              candidate_source_paths=risk["candidate_source_paths"],limitations=["ETW evidence unavailable"],byte_level_taint_proof=False)
            source=SourceRelation(observation_id=obs["observation_id"],**relation)
            self.write("source-relations.jsonl",source.model_dump())


def report(directory:Path):
    def read(name):
        path=directory/name
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.is_file() else []
    observations=read("observations.jsonl");risks=read("assessments.jsonl");gaps=read("coverage-gaps.jsonl")
    status=json.loads((directory/"status.json").read_text()) if (directory/"status.json").is_file() else {}
    summary=json.loads((directory/'summary.json').read_text()) if (directory/'summary.json').is_file() else {}
    scope=summary.get('scope')
    variant=summary.get('collector_variant')
    experiment={'scope':scope if isinstance(scope,str) and scope in {'companion_only_no_ETW','controlled_origin','inventory_only'} else 'unspecified',
                'collector_variant':variant if isinstance(variant,str) and variant in {'enhanced-companion','enhanced','upstream'} else 'unknown',
                'runtime_certification':'not_performed_by_this_report'}
    classifications=read("classifications.jsonl");unified=read("unified-requests.jsonl")
    semantics=read("request-semantics.jsonl")
    return {"schema_version":"transpect.observe.report/1.0","status":status,"status_snapshot_only":True,"experiment":experiment,
            "visibility":{"observed_requests":len(observations),"complete_requests":sum(r["completeness"]=="complete" for r in observations),
                          "llm_requests":sum(r["llm_identification"]=="identified" for r in observations),"coverage_gaps":gaps},
            "control":{"can_enforce":False,"blocked_requests":0,"high_risk_recommendations":sum(r["risk"]=="critical" for r in risks)},
            "classification":{"rules_independent_of_policy":True,"counts":{name:sum(r['category']==name for r in classifications) for name in ('LLM','NON_LLM','UNKNOWN')},"results":classifications},
            "unified_requests":unified,
            "request_semantics":{"available":bool(semantics),"results":semantics,
                "counts":{g:sum(len(r.get(g,[])) for r in semantics)
                          for g in ("prompt","context","tool_calls","tool_results")},
                "plaintext_exported":False},
            "source_evidence":read("source-relations.jsonl"),"whole_system_coverage":False,"actual_ai_channel_certified":False}
