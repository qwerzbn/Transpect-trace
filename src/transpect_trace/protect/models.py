"""M4–M6 contracts. Serialization excludes transient inspected content."""
from __future__ import annotations
from typing import Literal
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, model_validator,field_validator

class Record(BaseModel):
    model_config=ConfigDict(extra='forbid')

class AdapterCapability(Record):
    schema_version: Literal['transpect.protect.capability/1.0']='transpect.protect.capability/1.0'
    adapter_id: str
    channel: Literal['cli','ide','api','web']
    image_sha256: str
    module_sha256: dict[str,str]=Field(default_factory=dict)
    entry: str
    protocols: list[str]
    capture_stage: str
    content_scope: list[str]
    verified_actions: list[Literal['block_request','block_session','terminate_process']]=Field(default_factory=list)
    certification: Literal['unverified','controlled_origin','real_client']='unverified'
    can_enforce: bool=False
    limitations: list[str]=Field(default_factory=list)

    @model_validator(mode='after')
    def enforce_requires_proof(self):
        if self.can_enforce and (self.certification=='unverified' or not self.verified_actions):
            raise ValueError('enforcement requires independently verified refusal and scope')
        return self

class SemanticCaptureEvent(Record):
    schema_version: Literal['transpect.protect.semantic/1.0']='transpect.protect.semantic/1.0'
    observation_id: str=Field(default_factory=lambda:uuid4().hex)
    attempt_id: str=Field(default_factory=lambda:uuid4().hex)
    run_id: str
    adapter_id: str
    application: str
    channel: Literal['cli','ide','api','web']
    pid: int=Field(gt=0)
    creation_filetime: int=Field(gt=0)
    image_sha256: str
    connection_id: str|None=None
    connection_identity: Literal['stable','unknown']='unknown'
    stream_id: int|None=None
    captured_qpc: int|None=Field(default=None,gt=0)
    qpc_frequency: int|None=Field(default=None,gt=0)
    protocol: str
    method: str='POST'
    # These must already be sanitized; never accept a full URL in audit output.
    destination_host: str|None=None
    api_path: Literal['/responses','/chat/completions','unknown']='unknown'
    completeness: Literal['complete','partial','unknown']='unknown'
    encoding_state: Literal['identity','decoded','compressed','unsupported','unknown']='identity'
    content_encoding: Literal['identity','gzip','deflate','zstd','unsupported']='identity'
    capture_stage: str='before_transport'
    body_sha256: str=Field(pattern=r'^[a-f0-9]{64}$')
    body_bytes: int=Field(ge=0,le=16*1024*1024)
    body: bytes=Field(default=b'',exclude=True,repr=False)
    gate_owner: str|None=None
    limitations: list[str]=Field(default_factory=list)

    @field_validator('destination_host')
    @classmethod
    def host_only(cls,value):
        import re
        if value is not None and (len(value)>253 or not re.fullmatch(r'[A-Za-z0-9.:-]+',value)):
            raise ValueError('destination must be a host, without URL, userinfo or query')
        return value

    @model_validator(mode='after')
    def immutable_snapshot(self):
        import hashlib
        # Metadata-only round trips are intentionally not gateable.
        if self.body and (len(self.body)!=self.body_bytes or hashlib.sha256(self.body).hexdigest()!=self.body_sha256):
            raise ValueError('snapshot mismatch')
        return self

class RequestRelation(Record):
    schema_version: Literal['transpect.protect.relation/1.0']='transpect.protect.relation/1.0'
    left_id: str
    right_id: str
    grade: Literal['EXACT','STRONG','CANDIDATE','UNKNOWN']
    method: str
    evidence_ids: list[str]
    limitations: list[str]=Field(default_factory=list)

class DetectionFinding(Record):
    schema_version: Literal['transpect.protect.finding/1.0']='transpect.protect.finding/1.0'
    detector_version: str
    rule_id: str
    location: str
    severity: Literal['info','medium','high','critical']
    strength: Literal['weak','contextual','exact']
    sensitivity: Literal['PUBLIC','INTERNAL','CONFIDENTIAL','SECRET','UNKNOWN']='UNKNOWN'
    data_types: list[Literal['credential','private_key','source_code','personal_information','registered_text']]
    evidence_sha256: str
    registration_id: str|None=None
    index_version: str|None=None

class PolicyVerdict(Record):
    schema_version: Literal['transpect.protect.verdict/1.0']='transpect.protect.verdict/1.0'
    attempt_id: str
    decision: Literal['ALLOW','BLOCK','REVIEW','UNKNOWN']
    reason: str
    policy_version: str
    requested_action: Literal['none','block_request','block_session','terminate_process']
    actual_action: Literal['not_confirmed','none','block_request','block_session','terminate_process']='not_confirmed'
    detection_status: Literal['matched','no_match','incomplete']
    findings: list[DetectionFinding]=Field(default_factory=list)

    @model_validator(mode='after')
    def consistent(self):
        if (self.decision=='ALLOW') != (self.requested_action=='none'):
            raise ValueError('only ALLOW may delegate sending')
        return self

class GateRequest(Record):
    schema_version: Literal['transpect.protect.request/1.0']='transpect.protect.request/1.0'
    event: SemanticCaptureEvent
    body_b64: str=Field(max_length=22369624,repr=False,exclude=True)

class GateReply(Record):
    schema_version: Literal['transpect.protect.reply/1.0']='transpect.protect.reply/1.0'
    attempt_id: str=Field(min_length=1,max_length=64)
    decision: Literal['ALLOW','BLOCK','REVIEW','UNKNOWN']
    action: Literal['none','block_request','block_session','terminate_process']
    reason: str=Field(max_length=127)
    policy_version: str=Field(max_length=127)

    @model_validator(mode='after')
    def consistent(self):
        if (self.decision=='ALLOW')!=(self.action=='none'):raise ValueError('invalid decision/action combination')
        return self

class ExecutionEvidence(Record):
    schema_version: Literal['transpect.protect.execution/1.0']='transpect.protect.execution/1.0'
    attempt_id: str=Field(min_length=1,max_length=64)
    pid: int=Field(gt=0)
    action: Literal['none','block_request','block_session']
    result: Literal['transport_authorized','native_rejection']
    qpc: int=Field(gt=0)

    @model_validator(mode='after')
    def consistent(self):
        if (self.action=='none')!=(self.result=='transport_authorized'):raise ValueError('inconsistent execution evidence')
        return self
