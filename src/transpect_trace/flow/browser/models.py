"""Browser API evidence, independent of TLS and process evidence."""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from transpect_trace.protect.models import DetectionFinding

LIMIT = 1024 * 1024
WIRE_LIMIT = 2 * LIMIT


class BrowserRequestObservation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal['transpect.browser.request/1.0'] = 'transpect.browser.request/1.0'
    can_enforce: Literal[False] = False
    observation_id: str
    browser_run_id: str
    extension_session_id: str
    request_id_sha256: str = Field(pattern='^[a-f0-9]{64}$')
    request_stage: int = Field(ge=1)
    tab_id: int
    frame_id: int
    document_id_sha256: str | None = None
    network_process: None = None
    process_binding: Literal['unknown'] = 'unknown'
    capture_layer: Literal['browser_request_body'] = 'browser_request_body'
    capture_api: Literal['chrome.webRequest'] = 'chrome.webRequest'
    event_phase: Literal['before_send_headers', 'request_aborted_before_headers']
    method: Literal['POST', 'PUT']
    target_origin: str
    target_path_sha256: str = Field(pattern='^[a-f0-9]{64}$')
    content_type: Literal['application/json', 'text/plain', 'unsupported']
    body_bytes: int = Field(ge=0)
    captured_bytes: int = Field(ge=0, le=LIMIT)
    body_sha256: str | None = None
    decoded_body_sha256: str | None = None
    completeness: Literal['complete', 'partial', 'unknown']
    encoding_state: Literal['identity', 'unsupported', 'unknown']
    parsing_state: Literal['json', 'text', 'failed', 'unsupported']
    detection_status: Literal['matched', 'no_match', 'incomplete']
    findings: list[DetectionFinding] = Field(default_factory=list)
    attachment_state: Literal['none', 'reference_content_unchecked', 'unsupported'] = 'none'
    send_evidence: Literal['browser_request_observed_not_delivery'] = 'browser_request_observed_not_delivery'
    limitations: list[str] = Field(default_factory=list)
