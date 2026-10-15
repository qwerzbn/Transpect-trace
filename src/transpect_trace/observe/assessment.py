"""Local-only assessment. Recommendations can never execute a gate action."""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit
from uuid import uuid4
from transpect_trace.guard.policy import PolicyEngine,strings
from .models import CaptureEvent,RequestObservation,RiskAssessment
from .protocol import Body,decode_body


def semantics(value):
    found=set()
    def walk(item):
        if isinstance(item,dict):
            typ=item.get("type");role=item.get("role",item.get("author",{}).get("role") if isinstance(item.get("author"),dict) else None)
            if role=="user":found.add("prompt")
            if isinstance(role,str) and role in {"system","developer"}:found.add("context")
            if role=="tool" or typ=="function_call_output":found.add("tool_result")
            if typ=="function_call" or "tool_calls" in item:found.add("tool_arguments")
            if isinstance(typ,str) and typ in {"input_file","input_image","input_audio","image_url"}:found.add("attachment_reference_or_inline")
            for child in item.values():walk(child)
        elif isinstance(item,list):
            for child in item:walk(child)
    if isinstance(value,dict):
        walk(value.get('input',value.get('messages',[])))
        if isinstance(value.get('instructions'),str):found.add('context')
        if value.get('tools'):found.add('tool_specifications')
    if isinstance(value,dict) and isinstance(value.get("input"),str):found.add("prompt")
    return sorted(found) or ["unknown"]


class Assessor:
    def __init__(self,policy):
        from .policy import ObservationPolicy
        self.config=policy if isinstance(policy,ObservationPolicy) else ObservationPolicy(content_policy=policy)
        self.policy=self.config.content_policy;self.registered=PolicyEngine(self.policy).registered

    def assess(self,event:CaptureEvent,body:Body):
        from transpect_trace.guard.detection import detect_text
        limits=list(body.limitations)
        try:data=decode_body(body.data,body.headers.get("content-encoding",""))
        except Exception:
            data=body.data;limits.append("content_decoding_unavailable")
        content_type=body.headers.get("content-type","unknown").split(";",1)[0].lower()
        value=None
        try:value=json.loads(data.decode("utf-8"))
        except (ValueError,UnicodeError,RecursionError):limits.append("payload_semantics_unknown")
        meaning=semantics(value)
        if 'attachment_reference_or_inline' in meaning:limits.append('attachment_content_not_inspected')
        authority=body.headers.get(":authority",body.headers.get("host"))
        # Do not persist userinfo, query strings, arbitrary paths or headers.
        destination=None
        if authority:
            try:
                parsed=urlsplit("https://"+authority)
                if parsed.hostname and not parsed.username and not parsed.password:
                    destination="https://"+parsed.hostname+(":"+str(parsed.port) if parsed.port else "")
            except ValueError:limits.append("destination_invalid")
        path=body.headers.get(":path","").split("?",1)[0]
        structure=isinstance(value,dict) and ("messages" in value or "input" in value or value.get("type")=="response.create")
        endpoint=path.rstrip("/").endswith(("/responses","/chat/completions","/conversation"))
        known_app=event.application in {"codex-cli","vscode-codex","python-api","chrome-web"}
        identified="identified" if structure and (endpoint or known_app) else "candidate" if structure else "unknown"
        if identified!="identified":limits.append("llm_request_not_confirmed")
        obs=RequestObservation(observation_id=uuid4().hex,provider=event.provider,application=event.application,
            pid=event.pid,creation_filetime=event.creation_filetime,connection_id=event.connection_id,image_sha256=event.image_sha256,
            stream_id=body.stream_id,protocol=body.protocol,destination=destination,
            destination_evidence="http_authority" if destination else "unknown",
            completeness="unknown" if limits else "complete",content_type=content_type,
            content_bytes=len(data),content_sha256=hashlib.sha256(data).hexdigest(),
            llm_identification=identified,semantics=meaning,limitations=limits,
            captured_qpc=event.captured_qpc,qpc_frequency=event.qpc_frequency,
            send_evidence="constructed" if event.capture_point!="tls" else "accepted_by_tls" if event.provider=="native-observer" else "unverified")
        text="\n".join(strings(value)) if value is not None else data.decode("utf-8",errors="replace")
        hits,sources=detect_text(text,self.policy,self.registered)
        soft=[];risk_limits=list(limits)
        if any(word.casefold() in text.casefold() for word in self.config.warning_keywords):soft.append('WARNING_KEYWORD')
        if self.policy.allowed_upstreams:
            if not destination:risk_limits.append('destination_policy_not_evaluable')
            elif urlsplit(destination).hostname not in self.policy.allowed_upstreams:soft.append('UPSTREAM_NOT_ALLOWED')
        if self.config.allowed_application_hashes:
            if not event.image_sha256:risk_limits.append('application_identity_unavailable')
            elif event.image_sha256 not in self.config.allowed_application_hashes:soft.append('APPLICATION_NOT_ALLOWED')
        risk="critical" if hits else "unknown" if risk_limits else "warning" if soft else "no_match"
        score=100 if hits else 50 if any(x in soft for x in ['UPSTREAM_NOT_ALLOWED','APPLICATION_NOT_ALLOWED']) else 10 if soft else 0
        assessment=RiskAssessment(observation_id=obs.observation_id,risk=risk,score=score,
            matched_rule_ids=sorted(set(hits+soft)),candidate_source_paths=sorted(sources),
            recommended_action="block_request" if hits else "warn" if soft else "audit",policy_version=self.policy.version,
            limitations=["Observation only; no request was blocked",*risk_limits])
        return obs,assessment
