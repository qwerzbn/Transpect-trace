"""Versioned public experiment report, excluding source/draft/auth content."""
from typing import Literal
from pydantic import Field, model_validator
from transpect_trace.protect.models import Record
from transpect_trace.guard import BINARY_SHA256
from . import CODEX_TOOL_HOST_SHA256


class KnowledgeMailReport(Record):
    schema_version: Literal['transpect.knowledge-mail.report/1.0'] = 'transpect.knowledge-mail.report/1.0'
    state: Literal['starting_services', 'running_codex', 'complete', 'partial', 'unavailable']
    passed: bool = False
    cases: list[dict] = Field(default_factory=list)
    expected_cases: int = Field(ge=3, le=9)
    controller: dict
    real_codex_autonomy: bool
    codex_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    codex_tool_host_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    model: str
    mail_control: str
    llm_guard_rerun: Literal[False] = False
    etw_rerun: Literal[False] = False
    ecapture_rerun: Literal[False] = False
    external_smtp_delivery: Literal[False] = False
    proxy_used: Literal[False] = False
    tls_replaced: Literal[False] = False
    service_transport: str
    scope: str
    errors: list[str] = Field(default_factory=list)
    services: dict | None = None
    service_cleanup_errors: list[str] = Field(default_factory=list)
    service_cleanup_confirmed: bool = False

    @model_validator(mode='after')
    def complete_requires_evidence(self):
        if self.passed and (self.state != 'complete' or len(self.cases) != self.expected_cases
                            or any(c.get('passed') is not True for c in self.cases)
                            or not self.real_codex_autonomy or self.codex_sha256 != BINARY_SHA256
                            or self.codex_tool_host_sha256 != CODEX_TOOL_HOST_SHA256
                            or any(not isinstance(c.get('checks'), dict) or not c['checks']
                                   or any(value is not True for value in c['checks'].values()) for c in self.cases)
                            or self.errors or self.service_cleanup_errors or not self.service_cleanup_confirmed):
            raise ValueError('complete report requires all cases and cleanup')
        if self.state == 'complete' and not self.passed:
            raise ValueError('complete state requires passed evidence')
        return self
