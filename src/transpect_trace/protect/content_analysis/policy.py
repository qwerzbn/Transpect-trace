"""Deterministic, fail-closed policy for Chrome file and paste content."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time

from pydantic import Field, field_validator

from transpect_trace.protect.detection import ContentIndex, detect
from transpect_trace.protect.models import Record

from .models import (
    MAX_CONTENT_BYTES,
    ContentAnalysisAudit,
    ContentAnalysisRequest,
    ContentAnalysisVerdict,
)


class ContentAnalysisPolicy(Record):
    version: str = "chrome-content/1"
    allowed_hosts: list[str] = Field(default_factory=list)
    pii_rules: bool = False
    max_content_bytes: int = Field(default=MAX_CONTENT_BYTES, ge=1, le=MAX_CONTENT_BYTES)

    @field_validator("allowed_hosts")
    @classmethod
    def hosts_only(cls, values):
        import re

        if len(values) != len(set(values)) or any(
            not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", value) for value in values
        ):
            raise ValueError("allowed_hosts must contain sanitized unique hosts")
        return values


@dataclass(frozen=True)
class _InspectionField:
    location: str
    value: str
    sha256: str
    inspected: bool = True


class ContentAnalysisEngine:
    def __init__(self, policy: ContentAnalysisPolicy | None = None, index: ContentIndex | None = None):
        self.policy = policy or ContentAnalysisPolicy()
        self.index = index

    def evaluate(
        self, request: ContentAnalysisRequest, *, now: int | None = None
    ) -> tuple[ContentAnalysisVerdict, ContentAnalysisAudit]:
        decision = "UNKNOWN"
        reason = "UNINSPECTABLE_CONTENT"
        detection_status = "incomplete"
        findings = []
        current_time = int(time.time()) if now is None else now

        valid_reasons = {
            "FILE_ATTACHED": {"FILE_PICKER_DIALOG", "CLIPBOARD_PASTE", "DRAG_AND_DROP"},
            "BULK_DATA_ENTRY": {"CLIPBOARD_PASTE", "DRAG_AND_DROP"},
        }
        if request.reason not in valid_reasons[request.connector]:
            reason = "UNSUPPORTED_CONNECTOR_REASON"
        elif request.expires_at is not None and current_time >= request.expires_at:
            reason = "DECISION_DEADLINE_EXPIRED"
        elif self.policy.allowed_hosts and request.destination_host not in self.policy.allowed_hosts:
            reason = "DESTINATION_NOT_ALLOWED_OR_UNKNOWN"
        elif request.completeness != "complete" or request.limitations:
            reason = "INCOMPLETE_CONTENT"
        elif request.encoding_state != "utf8":
            reason = "UNSUPPORTED_CONTENT_ENCODING"
        elif request.body_bytes > self.policy.max_content_bytes:
            reason = "CONTENT_LIMIT_EXCEEDED"
        elif not request.body or len(request.body) != request.body_bytes:
            reason = "CONTENT_SNAPSHOT_UNAVAILABLE"
        elif hashlib.sha256(request.body).hexdigest() != request.body_sha256:
            reason = "CONTENT_SNAPSHOT_MISMATCH"
        else:
            try:
                text = request.body.decode("utf-8-sig")
                field = _InspectionField(
                    location="/content",
                    value=text,
                    sha256=request.body_sha256,
                )
                findings = detect([field], self.index, pii_rules=self.policy.pii_rules)
                detection_status = "matched" if findings else "no_match"
                if any(
                    finding.sensitivity in {"SECRET", "CONFIDENTIAL"}
                    and finding.strength in {"exact", "contextual"}
                    for finding in findings
                ):
                    decision, reason = "BLOCK", "SENSITIVE_CONTENT"
                else:
                    decision, reason = "ALLOW", "REQUIRED_CHECKS_COMPLETE"
            except (UnicodeError, ValueError, TypeError, RecursionError):
                reason = "REQUIRED_CHECK_FAILED"

        action = "allow" if decision == "ALLOW" else "block"
        verdict = ContentAnalysisVerdict(
            attempt_id=request.attempt_id,
            request_token_sha256=request.request_token_sha256,
            decision=decision,
            action=action,
            reason=reason,
            policy_version=self.policy.version,
            detection_status=detection_status,
            findings=findings,
        )
        audit = ContentAnalysisAudit(
            attempt_id=request.attempt_id,
            request_token_sha256=request.request_token_sha256,
            user_action_id_sha256=request.user_action_id_sha256,
            connector=request.connector,
            reason=request.reason,
            destination_host=request.destination_host,
            completeness=request.completeness,
            encoding_state=request.encoding_state,
            body_sha256=request.body_sha256,
            body_bytes=request.body_bytes,
            decision=decision,
            action=action,
            verdict_reason=reason,
            policy_version=self.policy.version,
            rule_ids=sorted({finding.rule_id for finding in findings}),
            registration_ids=sorted(
                {finding.registration_id for finding in findings if finding.registration_id}
            ),
            limitations=sorted(set(request.limitations)),
        )
        return verdict, audit
