"""Redacted business evidence contracts, independent of two-party Flow v1."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from transpect_trace.flow.models import CollectorHealth, Confidence
from transpect_trace.protect.models import DetectionFinding

Token = Annotated[str, Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:-]+$')]
Digest = Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
GitObjectId = Annotated[str, Field(pattern=r'^(?:[a-f0-9]{40}|[a-f0-9]{64})$')]
Status = Literal['complete', 'partial', 'unsupported', 'unavailable', 'unknown']
Provenance = Literal['native_io', 'etw', 'ecapture', 'native_request', 'source_receipt',
                     'git_object', 'client_result', 'fixture_truth']


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid')
    can_enforce: Literal[False] = False


class ScenarioProcess(Record):
    role: Token
    pid: int = Field(gt=0)
    creation_filetime: int = Field(gt=0)
    image_sha256: Digest
    parent_pid: int | None = Field(default=None, gt=0)
    parent_creation_filetime: int | None = Field(default=None, gt=0)
    membership_basis: Literal['explicit_registration', 'observed_lineage'] = 'explicit_registration'

    @model_validator(mode='after')
    def parent_identity(self):
        if (self.parent_pid is None) != (self.parent_creation_filetime is None):
            raise ValueError('partial_parent_identity')
        if self.membership_basis == 'observed_lineage' and self.parent_pid is None:
            raise ValueError('lineage_requires_parent_identity')
        return self

    @property
    def key(self):
        return self.pid, self.creation_filetime


class ScenarioEvidence(Record):
    evidence_id: Token
    stage_id: Token
    provenance: Provenance
    process: ScenarioProcess | None = None
    attempt_id: Token | None = None
    body_sha256: Digest | None = None
    body_bytes: int | None = Field(default=None, ge=0)
    complete: bool = False
    success: bool | None = None
    object_id: GitObjectId | None = None
    object_location: Literal['origin', 'sender'] | None = None
    observed_blob_count: int | None = Field(default=None, ge=0)
    content_registration_ids: list[Token] = Field(default_factory=list)
    file_identity: Token | None = None
    io_operation: Literal['read', 'write'] | None = None
    io_offset: int | None = Field(default=None, ge=0)
    io_started_qpc: int | None = Field(default=None, ge=0)
    io_completed_qpc: int | None = Field(default=None, ge=0)
    qpc_frequency: int | None = Field(default=None, gt=0)
    event_ids: list[Token] = Field(default_factory=list)
    limitations: list[Token] = Field(default_factory=list)

    @model_validator(mode='after')
    def body_pair(self):
        if (self.body_sha256 is None) != (self.body_bytes is None):
            raise ValueError('body_hash_length_pair_required')
        if (self.object_id is not None or self.object_location is not None or self.observed_blob_count is not None):
            if self.provenance != 'git_object' or self.object_location is None:
                raise ValueError('git_object_metadata_requires_location')
        if self.file_identity is not None or self.io_operation is not None or self.io_offset is not None:
            if self.provenance != 'native_io' or None in (self.file_identity, self.io_operation, self.io_offset):
                raise ValueError('file_range_requires_native_io_identity')
        clock = (self.io_started_qpc, self.io_completed_qpc, self.qpc_frequency)
        if any(value is not None for value in clock):
            if None in clock or self.file_identity is None or self.io_completed_qpc < self.io_started_qpc:
                raise ValueError('native_io_clock_incomplete_or_invalid')
        return self


class ScenarioStage(Record):
    stage_id: Token
    participant: Token
    state: Status = 'unknown'
    required_provenance: list[Provenance] = Field(default_factory=list)
    evidence_ids: list[Token] = Field(default_factory=list)
    limitations: list[Token] = Field(default_factory=list)


class ScenarioOutbound(Record):
    attempt_id: Token
    process: ScenarioProcess | None = None
    capture_source: Literal['ecapture', 'native_request', 'unavailable']
    capture_layer: Literal['tls', 'request', 'unknown']
    completeness: Literal['complete', 'partial', 'unknown']
    body_sha256: Digest | None = None
    body_bytes: int | None = Field(default=None, ge=0)
    capture_evidence_id: Token | None = None
    receipt_evidence_id: Token | None = None
    detection_status: Literal['matched', 'no_match', 'incomplete', 'unsupported'] = 'incomplete'
    findings: list[DetectionFinding] = Field(default_factory=list)
    source_received: bool | None = None
    receipt_match: bool | None = None
    association_basis: Literal['ordered_body_multiset', 'unknown', 'exact_runtime_id'] = Field(
        default='unknown', description='Ordered hash/length/count pairing is an accounting candidate, not a propagated request identity.')
    limitations: list[Token] = Field(default_factory=list)

    @model_validator(mode='after')
    def scope(self):
        if (self.body_sha256 is None) != (self.body_bytes is None):
            raise ValueError('body_hash_length_pair_required')
        expected = {'ecapture': 'tls', 'native_request': 'request', 'unavailable': 'unknown'}
        if self.capture_layer != expected[self.capture_source]:
            raise ValueError('capture_source_layer_mismatch')
        if self.detection_status == 'matched' and not self.findings:
            raise ValueError('matched_requires_finding')
        if self.completeness != 'complete' and self.detection_status == 'no_match':
            raise ValueError('incomplete_body_cannot_claim_no_match')
        return self


class ScenarioObjectDetection(Record):
    attempt_id: Token
    object_id: GitObjectId
    body_sha256: Digest
    body_bytes: int = Field(ge=0, le=1024 * 1024)
    evidence_id: Token
    detection_status: Literal['matched', 'no_match', 'incomplete'] = 'incomplete'
    findings: list[DetectionFinding] = Field(default_factory=list)
    limitations: list[Token] = Field(default_factory=list)

    @model_validator(mode='after')
    def matched_needs_finding(self):
        if self.detection_status == 'matched' and not self.findings:
            raise ValueError('matched_requires_finding')
        return self


class ScenarioGitObjectScan(Record):
    attempt_id: Token
    evidence_id: Token
    received_blob_count: int = Field(ge=0)
    complete: bool = False
    limitations: list[Token] = Field(default_factory=list)


class ScenarioRelation(Record):
    relation_id: Token
    left_id: Token
    right_id: Token
    confidence: Confidence = 'Unknown'
    method: Literal['content_candidate', 'observed_file_handoff', 'observed_protocol_mapping',
                    'observed_lineage', 'git_object_receipt', 'timing_candidate']
    evidence_ids: list[Token] = Field(default_factory=list)
    limitations: list[Token] = Field(default_factory=list)
    byte_level_taint_proof: Literal[False] = False
    unique_source_proven: Literal[False] = False


class ScenarioCapabilities(Record):
    system_behavior: Status = 'unknown'
    content_detection: Status = 'unknown'
    propagation: Status = 'unknown'
    source_receipt: Status = 'unknown'
    control: Literal['not_applicable'] = 'not_applicable'


class BusinessScenarioReport(Record):
    schema_version: Literal['transpect.business.report/1.0'] = 'transpect.business.report/1.0'
    session_id: Token
    scenario: Literal['webhook', 'git']
    case: Token
    state: Status = 'unknown'
    certified: bool = False
    participants: list[ScenarioProcess] = Field(default_factory=list)
    stages: list[ScenarioStage] = Field(default_factory=list)
    evidence: list[ScenarioEvidence] = Field(default_factory=list)
    outbound: list[ScenarioOutbound] = Field(default_factory=list)
    git_objects: list[ScenarioObjectDetection] = Field(default_factory=list)
    git_scans: list[ScenarioGitObjectScan] = Field(default_factory=list)
    relations: list[ScenarioRelation] = Field(default_factory=list)
    health: dict[Token, CollectorHealth] = Field(default_factory=dict)
    capabilities: ScenarioCapabilities = Field(default_factory=ScenarioCapabilities)
    limitations: list[Token] = Field(default_factory=list)
    byte_level_taint_proof: Literal[False] = False


class BusinessRuntimeStatus(Record):
    schema_version: Literal['transpect.business.runtime/1.0'] = 'transpect.business.runtime/1.0'
    session_id: Token
    scenario: Literal['webhook', 'git']
    state: Literal['initializing', 'observing', 'complete', 'partial', 'unsupported', 'unavailable', 'unknown']
    controller: ScenarioProcess | None = None
    data_released: bool = False
    certified: bool = False
    gaps: list[Token] = Field(default_factory=list)
