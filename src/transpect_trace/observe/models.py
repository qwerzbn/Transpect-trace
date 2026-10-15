from __future__ import annotations

import base64
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

BODY_LIMIT = 16 * 1024 * 1024
FRAME_LIMIT = 1024 * 1024


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CaptureEvent(Record):
    schema_version: Literal["transpect.observe.capture/1.0"] = "transpect.observe.capture/1.0"
    provider: Literal["native-observer", "ecapture-windows", "fixture"]
    capture_point: Literal["tls", "http-body", "wss-message"]
    pid: int = Field(gt=0)
    creation_filetime: int = Field(gt=0)
    tid: int = Field(ge=0)
    connection_id: str = Field(min_length=1,max_length=128)
    direction: Literal["send", "recv"]
    sequence: int = Field(gt=0)
    captured_qpc: int = Field(ge=0)
    qpc_frequency: int = Field(gt=0)
    data_b64: str = Field(default="",exclude=True,repr=False)
    truncated: bool = False
    lost_events: int = Field(default=0,ge=0)
    connection_identity: Literal["stable", "unknown"] = "stable"
    event: Literal["data", "closed", "ready", "gap"] = "data"
    application: str = "unknown"
    image_sha256: str | None = Field(default=None,pattern=r'^[a-f0-9]{64}$')

    @field_validator("data_b64")
    @classmethod
    def bounded_data(cls,value):
        if len(value) > FRAME_LIMIT*4//3+4:raise ValueError("capture frame too large")
        if len(base64.b64decode(value,validate=True)) > FRAME_LIMIT:raise ValueError("capture frame too large")
        return value

    @property
    def data(self):return base64.b64decode(self.data_b64,validate=True)


class RequestObservation(Record):
    schema_version: Literal["transpect.observe.request/1.0"] = "transpect.observe.request/1.0"
    observation_id: str
    provider: str
    application: str
    image_sha256: str | None = None
    pid: int
    creation_filetime: int
    connection_id: str
    stream_id: int | None = None
    protocol: str
    destination: str | None = None
    destination_evidence: Literal["http_authority", "unknown"] = "unknown"
    completeness: Literal["complete", "partial", "unknown"]
    content_type: str
    content_bytes: int
    content_sha256: str
    llm_identification: Literal["identified", "candidate", "unknown"]
    semantics: list[str]
    limitations: list[str]
    captured_qpc: int
    qpc_frequency: int
    send_evidence: Literal["constructed", "accepted_by_tls", "unverified"] = "unverified"
    can_enforce: Literal[False] = False


class RiskAssessment(Record):
    schema_version: Literal["transpect.observe.risk/1.0"] = "transpect.observe.risk/1.0"
    observation_id: str
    risk: Literal["critical", "warning", "no_match", "unknown"]
    score: int = Field(ge=0,le=100)
    matched_rule_ids: list[str]
    candidate_source_paths: list[str]
    source_confidence: Literal["High", "Medium", "Low", "Unknown"] = "Unknown"
    recommended_action: Literal["block_request", "warn", "audit"]
    effective_action: Literal["audit"] = "audit"
    can_enforce: Literal[False] = False
    policy_version: str
    limitations: list[str]


class SourceRelation(Record):
    schema_version: Literal["transpect.observe.source/1.0"] = "transpect.observe.source/1.0"
    observation_id: str
    confidence: Literal["High", "Medium", "Low", "Unknown"]
    method: str
    evidence_event_ids: list[str]
    candidate_source_paths: list[str]
    limitations: list[str]
    byte_level_taint_proof: Literal[False] = False
