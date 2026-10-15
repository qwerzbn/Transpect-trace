"""Observation policy is separate from the unchanged Guard v1 contract."""
import json
from pathlib import Path
from typing import Literal
from pydantic import Field,field_validator
from transpect_trace.guard.policy import GuardPolicy
from .models import Record


class ObservationPolicy(Record):
    schema_version: Literal['transpect.observe.policy/1.0']='transpect.observe.policy/1.0'
    content_policy: GuardPolicy=Field(default_factory=GuardPolicy)
    warning_keywords: list[str]=Field(default_factory=list,max_length=50)
    allowed_application_hashes: list[str]=Field(default_factory=list,max_length=100)

    @field_validator('warning_keywords')
    @classmethod
    def valid_keywords(cls,values):
        if any(not v.strip() or len(v)>256 for v in values):raise ValueError('invalid warning keyword')
        return values

    @field_validator('allowed_application_hashes')
    @classmethod
    def valid_hashes(cls,values):
        import re
        if any(not re.fullmatch('[a-f0-9]{64}',v) for v in values):raise ValueError('invalid application hash')
        return values


def load_policy(path:Path):
    value=json.loads(path.read_text(encoding='utf-8'))
    if value.get('schema_version')!='transpect.observe.policy/1.0':return GuardPolicy.load(path)
    policy=ObservationPolicy.model_validate(value)
    policy.content_policy.registered_files=[(path.parent/p).resolve() if not p.is_absolute() else p for p in policy.content_policy.registered_files]
    return policy
