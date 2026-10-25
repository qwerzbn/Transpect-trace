"""Agent flow audit contracts; application identifiers and content are hashed."""
from __future__ import annotations

from typing import Literal
from uuid import uuid4

from pydantic import Field

from transpect_trace.flow.models import Confidence, FlowProcess, Record
from transpect_trace.protect.models import DetectionFinding

class AgentMessageObservation(Record):
    schema_version: Literal['transpect.agent.observation/1.0'] = 'transpect.agent.observation/1.0'
    observation_id: str = Field(default_factory=lambda: uuid4().hex)
    original_observation_id: str
    session_id: str
    stage: Literal['source_read', 'message_write', 'message_read', 'outbound']
    process: FlowProcess
    agent_id: Literal['agent-a', 'agent-b']
    capture_source: Literal['native-io', 'ecapture-windows']
    capture_layer: Literal['io', 'tls']
    protocol_status: Literal['valid', 'invalid', 'not_applicable']
    task_id_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    message_id_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    parent_message_id_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    tool_call_id_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    protocol_attempt_id_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    local_attempt_id: str | None = None
    body_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    body_bytes: int = Field(ge=0, le=1024 * 1024)
    payload_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    payload_bytes: int | None = Field(default=None, ge=0, le=1024 * 1024)
    payload_representation: Literal['text', 'json'] | None = None
    completeness: Literal['complete', 'partial', 'unknown']
    detection_status: Literal['matched', 'no_match', 'incomplete']
    findings: list[DetectionFinding] = Field(default_factory=list)
    sensitivity_labels: list[Literal['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'UNKNOWN']] = Field(default_factory=list)
    llm_classification: Literal['LLM', 'NON_LLM', 'UNKNOWN'] = 'UNKNOWN'
    evidence_event_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    label_basis: Literal['observed_content_detection_only'] = 'observed_content_detection_only'


class AgentPropagationRelation(Record):
    schema_version: Literal['transpect.agent.relation/1.0'] = 'transpect.agent.relation/1.0'
    relation_id: str = Field(default_factory=lambda: uuid4().hex)
    left_id: str
    right_id: str
    relation_kind: Literal['source_message_candidate', 'agent_message_handoff', 'protocol_parent_reference']
    confidence: Confidence
    method: Literal['same_process_registered_content_or_exact_payload', 'observed_protocol_and_native_handoff', 'outbound_declared_parent_identifier']
    content_evidence: Literal['exact_payload', 'registered_content_overlap', 'none'] = 'none'
    shared_registration_ids: list[str] = Field(default_factory=list)
    base_relation_ids: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    protocol_declaration_only: bool = False
    byte_level_taint_proof: Literal[False] = False
    unique_source_proven: Literal[False] = False
    merged: Literal[False] = False


class AgentFlowSession(Record):
    schema_version: Literal['transpect.agent.session/1.0'] = 'transpect.agent.session/1.0'
    session_id: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:-]+$')
    task_id_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    subjects: list[FlowProcess] = Field(min_length=2, max_length=2)
    identity_basis: Literal['explicit_agent_to_process_registration'] = 'explicit_agent_to_process_registration'
    status: Literal['observing', 'complete', 'partial', 'unavailable'] = 'observing'
    base_flow_status: Literal['starting', 'observing', 'complete', 'partial', 'unavailable', 'unknown'] = 'unknown'
    limitations: list[str] = Field(default_factory=list)
    can_enforce: Literal[False] = False
    byte_level_taint_proof: Literal[False] = False
