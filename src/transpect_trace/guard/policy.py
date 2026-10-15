"""Reference policy implementation; the wire contract is language independent."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


Action = Literal["none", "block_request", "block_session", "terminate_process"]


class GuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_: Literal["transpect.guard.request/1.0"] = Field(alias="schema")
    request_id: str = Field(min_length=1, max_length=64)
    guard_session_id: str = Field(min_length=1, max_length=96)
    pid: int = Field(gt=0)
    tid: int = Field(ge=0)
    kind: Literal["model.request", "native.initialize", "native.ready", "native.outcome"]
    protocol: Literal["http", "wss", "control"]
    destination: str | None = None
    completeness: Literal["complete", "partial", "unknown"]
    payload_utf8: str
    captured_qpc: int | None = None
    qpc_frequency: int | None = None
    outcome_for_request_id: str = ""
    outcome_action: Action = "none"
    outcome_captured_qpc: int = 0

    @model_validator(mode="after")
    def control_shape(self):
        if self.kind != "model.request" and (self.protocol != "control" or self.payload_utf8):
            raise ValueError("control frames cannot carry a model payload")
        if self.kind == "model.request" and self.protocol == "control":
            raise ValueError("model requests require a transport")
        return self


class GuardDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True,
                              json_schema_extra={"required":["schema","request_id","decision","action","reason","policy_version"]})
    schema_: Literal["transpect.guard.decision/1.0"] = Field(default="transpect.guard.decision/1.0", alias="schema")
    request_id: str = Field(min_length=1,max_length=64)
    decision: Literal["allow", "deny", "unknown"]
    action: Action
    reason: str = Field(max_length=1023)
    policy_version: str = Field(max_length=127)

    @model_validator(mode="after")
    def consistent_action(self):
        if self.decision == "allow" and self.action != "none":
            raise ValueError("allow must use action=none")
        if self.decision != "allow" and self.action == "none":
            raise ValueError("non-allow cannot use action=none")
        return self


class Marker(BaseModel):
    marker_id: str
    value: str = Field(min_length=1)
    source_path: str
    classification: str = "sensitive"


class GuardPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_: str = Field(default="transpect.guard.policy/1.0", alias="schema")
    policy_id: str = "local-guard"
    version: str = "1"
    deny_action: Literal["block_request", "block_session", "terminate_process"] = "block_request"
    content_markers: list[Marker] = Field(default_factory=list)
    allowed_source_paths: list[str] = Field(default_factory=list)
    allowed_upstreams: list[str] = Field(default_factory=list)
    registered_files: list[Path] = Field(default_factory=list)
    credential_rules: bool = True

    @model_validator(mode="after")
    def supported_schema(self):
        if self.schema_ not in {"transpect.guard.policy/1.0", "transpect.gateway.policy/1.0"}:
            raise ValueError("unsupported policy schema")
        return self

    @classmethod
    def load(cls, path: Path):
        result = cls.model_validate(json.loads(path.read_text(encoding="utf-8")))
        result.registered_files = [(path.parent / p).resolve() if not p.is_absolute() else p for p in result.registered_files]
        return result


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                yield f"{key}={item}"
            yield from strings(item)


class PolicyEngine:
    def __init__(self, policy: GuardPolicy):
        self.policy = policy
        self.blocked_sessions: set[str] = set()
        self.registered: list[tuple[str, str]] = []
        for file in policy.registered_files:
            if file.stat().st_size>16*1024*1024:raise ValueError(f"registered file exceeds the v1 text limit: {file}")
            data = file.read_text(encoding="utf-8")
            if len(data.strip()) < 32:
                raise ValueError(f"registered file needs at least 32 characters: {file}")
            # Registration snapshots are content evidence, never proof of a read.
            for offset in range(0, len(data), 256):
                chunk = data[offset:offset + 256]
                if len(chunk.strip()) >= 32:
                    self.registered.append((str(file), chunk))

    def evaluate(self, request: GuardRequest) -> tuple[GuardDecision, dict]:
        start = time.monotonic_ns()
        hits: list[str] = []
        sources: set[str] = set()
        state, reason, action = "allow", "POLICY_ALLOW", "none"
        if request.kind != "model.request":
            audit={}
            if request.kind=="native.outcome":
                audit={"kind":"native.outcome","request_id":request.outcome_for_request_id,
                       "native_event_id":request.request_id,"pid":request.pid,"tid":request.tid,
                       "guard_session_id":request.guard_session_id,"action":request.outcome_action,
                       "captured_qpc":request.outcome_captured_qpc,"qpc_frequency":request.qpc_frequency,
                       "action_execution":"native_error_constructed","byte_level_taint_proof":False}
            return GuardDecision(request_id=request.request_id, decision="allow", action="none",
                                 reason="CONTROL_ACK", policy_version=self.policy.version), audit
        if request.guard_session_id in self.blocked_sessions:
            state, reason, action = "deny", "SESSION_BLOCKED", "block_session"
        elif request.completeness != "complete":
            state, reason, action = "unknown", "INCOMPLETE_CONTENT", "block_request"
        else:
            try:
                value = json.loads(request.payload_utf8)
                if not isinstance(value, dict) or not isinstance(value.get("model"), str) or "input" not in value:
                    raise ValueError("not a supported model-request JSON object")
                if request.protocol == "wss" and value.get("type") != "response.create":
                    raise ValueError("unsupported WSS message type")
                def uninspectable(item):
                    if isinstance(item,dict):
                        if item.get("type") in {"input_file","input_image","input_audio","image_url"}:return True
                        return any(uninspectable(v) for v in item.values())
                    if isinstance(item,list):return any(uninspectable(v) for v in item)
                    return False
                if uninspectable(value.get("input")):
                    raise ValueError("binary or referenced attachment not inspected by v1")
                text = "\n".join(strings(value))
                from .detection import detect_text
                hits,sources=detect_text(text,self.policy,self.registered)
                if self.policy.allowed_upstreams:
                    from urllib.parse import urlsplit
                    host = urlsplit(request.destination).hostname if request.destination else None
                    if host is None:
                        state, reason, action = "unknown", "DESTINATION_UNAVAILABLE", "block_request"
                    elif host not in self.policy.allowed_upstreams:
                        hits.append("UPSTREAM_NOT_ALLOWED")
                if hits:
                    state, reason, action = "deny", "CONTENT_POLICY_DENIED", self.policy.deny_action
            except (ValueError, TypeError):
                state, reason, action = "unknown", "UNSUPPORTED_CONTENT", "block_request"
        if action == "block_session":
            self.blocked_sessions.add(request.guard_session_id)
        decision = GuardDecision(request_id=request.request_id, decision=state, action=action,
                                 reason=reason, policy_version=self.policy.version)
        audit = {"kind": "policy.decision", "request_id": request.request_id,
                 "guard_session_id": request.guard_session_id, "pid": request.pid, "tid": request.tid,
                 "protocol": request.protocol, "decision": state, "action": action, "reason": reason,
                 "captured_qpc":request.captured_qpc,"qpc_frequency":request.qpc_frequency,
                 "policy_version": self.policy.version, "policy_id": self.policy.policy_id,
                 "content_sha256": hashlib.sha256(request.payload_utf8.encode()).hexdigest(),
                 "content_bytes": len(request.payload_utf8.encode()), "matched_rule_ids": sorted(set(hits)),
                 "candidate_source_paths": sorted(sources), "source_confidence": "Unknown",
                 "elapsed_ms": (time.monotonic_ns() - start) / 1e6,
                 "action_execution": "not_yet_confirmed", "byte_level_taint_proof": False}
        return decision, audit
