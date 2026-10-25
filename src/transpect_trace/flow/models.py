"""Flow v1 audit contracts. Plaintext is never a serialized model field."""
from __future__ import annotations

from typing import Literal
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator
from transpect_trace.protect.models import DetectionFinding

LIMIT = 1024 * 1024
Confidence = Literal['High', 'Medium', 'Low', 'Unknown']


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid')
    can_enforce: Literal[False] = False


class FlowProcess(Record):
    role: Literal['A', 'B']
    pid: int = Field(gt=0)
    creation_filetime: int = Field(gt=0)
    image_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')

    @property
    def key(self):
        return self.pid, self.creation_filetime


class CollectorHealth(Record):
    ready: bool = False
    terminal: bool = False
    identity_verified: bool = False
    lost_events: int = Field(default=0, ge=0)
    errors: int = Field(default=0, ge=0)
    limitations: list[str] = Field(default_factory=list)

    @property
    def complete(self):
        return self.ready and self.terminal and self.identity_verified and not (self.lost_events or self.errors or self.limitations)


class CrossApplicationSession(Record):
    schema_version: Literal['transpect.flow.session/1.0'] = 'transpect.flow.session/1.0'
    session_id: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:-]+$')
    subjects: list[FlowProcess] = Field(min_length=2, max_length=2)
    scenario: Literal['file', 'pipe'] | None = None
    membership_basis: Literal['explicit_registration_not_lineage'] = 'explicit_registration_not_lineage'
    build_identities: dict[str, str] = Field(default_factory=dict)
    started_at_utc: str | None = None
    ended_at_utc: str | None = None
    health: dict[str, CollectorHealth] = Field(default_factory=dict)
    status: Literal['starting', 'observing', 'complete', 'partial', 'unavailable'] = 'starting'
    limitations: list[str] = Field(default_factory=list)
    byte_level_taint_proof: Literal[False] = False


class TransferObservation(Record):
    schema_version: Literal['transpect.flow.transfer/1.0'] = 'transpect.flow.transfer/1.0'
    observation_id: str = Field(default_factory=lambda: uuid4().hex)
    session_id: str
    process: FlowProcess
    object_kind: Literal['file', 'pipe']
    operation: Literal['read', 'write']
    resource_id: str | None = None
    resource_role: Literal['source', 'transfer', 'pipe', 'unknown'] = 'unknown'
    open_generation: int = Field(ge=0)
    connection_generation: int = Field(default=0, ge=0)
    file_version: str | None = None
    peer_pid: int | None = None
    peer_creation_filetime: int | None = None
    first_qpc: int = Field(ge=0)
    last_qpc: int = Field(ge=0)
    qpc_frequency: int = Field(gt=0)
    first_offset: int | None = None
    completed_bytes: int = Field(ge=0)
    captured_bytes: int = Field(ge=0, le=LIMIT)
    content_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    completeness: Literal['complete', 'partial', 'unknown']
    evidence_event_ids: list[str]
    findings: list[DetectionFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class OutboundContentObservation(Record):
    schema_version: Literal['transpect.flow.outbound/1.0'] = 'transpect.flow.outbound/1.0'
    observation_id: str = Field(default_factory=lambda: uuid4().hex)
    original_observation_id: str
    attempt_id: str = Field(default_factory=lambda: uuid4().hex)
    session_id: str
    process: FlowProcess
    provider: str
    capture_layer: str
    connection_id_sha256: str
    stream_id: int | None = None
    protocol: str
    destination_host: str | None = None
    captured_qpc: int = Field(ge=0)
    qpc_frequency: int = Field(gt=0)
    body_bytes: int = Field(ge=0)
    raw_body_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    decoded_body_sha256: str | None = None
    completeness: Literal['complete', 'partial', 'unknown']
    content_type: Literal['text/plain', 'application/json', 'unsupported']
    encoding_state: Literal['identity', 'unsupported', 'unknown']
    parsing_state: Literal['text', 'json', 'failed', 'unsupported']
    llm_classification: Literal['LLM', 'NON_LLM', 'UNKNOWN']
    detection_status: Literal['matched', 'no_match', 'incomplete']
    findings: list[DetectionFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    send_evidence: Literal['encryption_input_observed', 'request_constructed', 'unverified'] = 'unverified'

    @field_validator('destination_host')
    @classmethod
    def host_only(cls, value):
        import re
        if value is not None and (len(value) > 253 or not re.fullmatch(r'[A-Za-z0-9.:-]+', value)):
            raise ValueError('host must exclude credentials, path and query')
        return value


class PropagationRelation(Record):
    schema_version: Literal['transpect.flow.relation/1.0'] = 'transpect.flow.relation/1.0'
    relation_id: str = Field(default_factory=lambda: uuid4().hex)
    left_id: str
    right_id: str
    relation_kind: Literal['file_handoff_candidate', 'pipe_handoff_candidate', 'within_process_content_candidate', 'outbound_content_candidate']
    confidence: Confidence
    method: str
    evidence_event_ids: list[str]
    limitations: list[str] = Field(default_factory=list)
    byte_level_taint_proof: Literal[False] = False
    unique_source_proven: Literal[False] = False
    merged: Literal[False] = False
