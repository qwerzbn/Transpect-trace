"""Privacy-safe contracts for Chrome local content analysis.

Raw browser tokens, user-action identifiers and inspected bytes are transient.
They are excluded from all default serialization and representations.
"""
from __future__ import annotations

import hashlib
import re
from typing import Literal
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from transpect_trace.protect.models import DetectionFinding, Record


MAX_CONTENT_BYTES = 1024 * 1024
Connector = Literal["FILE_ATTACHED", "BULK_DATA_ENTRY"]
Reason = Literal[
    "UNKNOWN",
    "CLIPBOARD_PASTE",
    "DRAG_AND_DROP",
    "FILE_PICKER_DIALOG",
]


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class ContentAnalysisRequest(Record):
    schema_version: Literal["transpect.chrome.content.request/1.0"] = (
        "transpect.chrome.content.request/1.0"
    )
    attempt_id: str = Field(
        default_factory=lambda: uuid4().hex,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )
    connector: Connector
    reason: Reason
    destination_host: str
    completeness: Literal["complete", "partial", "unknown"]
    encoding_state: Literal["utf8", "binary", "unsupported", "unknown"]
    body_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    body_bytes: int = Field(ge=0, le=MAX_CONTENT_BYTES)
    request_token_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    user_action_id_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expires_at: int | None = Field(default=None, ge=0)
    tags: list[str] = Field(default_factory=list, max_length=16)
    limitations: list[str] = Field(default_factory=list, max_length=32)

    # These values are needed only while producing the SDK response.  They are
    # never written into audit JSON or included in repr/model_dump.
    request_token: str = Field(default="", exclude=True, repr=False, max_length=4096)
    user_action_id: str = Field(default="", exclude=True, repr=False, max_length=4096)
    body: bytes = Field(default=b"", exclude=True, repr=False)

    @field_validator("limitations")
    @classmethod
    def safe_limitations(cls, values):
        if len(set(values)) != len(values) or any(
            not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", value) for value in values
        ):
            raise ValueError("invalid limitation identifier")
        return values

    @classmethod
    def from_sdk(
        cls,
        *,
        request_token: str,
        connector: Connector,
        reason: Reason,
        destination_url: str,
        body: bytes,
        completeness: Literal["complete", "partial", "unknown"] = "complete",
        encoding_state: Literal["utf8", "binary", "unsupported", "unknown"] = "utf8",
        user_action_id: str = "",
        expires_at: int | None = None,
        tags: list[str] | None = None,
        limitations: list[str] | None = None,
    ) -> "ContentAnalysisRequest":
        from urllib.parse import urlsplit

        parsed = urlsplit(destination_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("valid HTTP destination required")
        host = parsed.hostname.lower()
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return cls(
            connector=connector,
            reason=reason,
            destination_host=host,
            completeness=completeness,
            encoding_state=encoding_state,
            body_sha256=_digest(body),
            body_bytes=len(body),
            request_token_sha256=_digest(request_token.encode("utf-8")),
            user_action_id_sha256=(
                _digest(user_action_id.encode("utf-8")) if user_action_id else None
            ),
            expires_at=expires_at,
            tags=tags or [],
            limitations=limitations or [],
            request_token=request_token,
            user_action_id=user_action_id,
            body=body,
        )

    @model_validator(mode="after")
    def validate_transient_snapshot(self):
        if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", self.destination_host):
            raise ValueError("destination must be a host, without path or query")
        if len(set(self.tags)) != len(self.tags) or any(
            not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", tag) for tag in self.tags
        ):
            raise ValueError("invalid content-analysis tag")
        if self.body and (
            len(self.body) != self.body_bytes or _digest(self.body) != self.body_sha256
        ):
            raise ValueError("content snapshot mismatch")
        if self.request_token and _digest(self.request_token.encode("utf-8")) != self.request_token_sha256:
            raise ValueError("request token mismatch")
        if self.user_action_id and (
            _digest(self.user_action_id.encode("utf-8")) != self.user_action_id_sha256
        ):
            raise ValueError("user action mismatch")
        return self


class ContentAnalysisVerdict(Record):
    schema_version: Literal["transpect.chrome.content.verdict/1.0"] = (
        "transpect.chrome.content.verdict/1.0"
    )
    attempt_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    request_token_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: Literal["ALLOW", "BLOCK", "UNKNOWN"]
    action: Literal["allow", "block"]
    reason: str = Field(min_length=1, max_length=127)
    policy_version: str = Field(min_length=1, max_length=127)
    detection_status: Literal["matched", "no_match", "incomplete"]
    findings: list[DetectionFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def fail_closed(self):
        if (self.decision == "ALLOW") != (self.action == "allow"):
            raise ValueError("only ALLOW may authorize content use")
        return self


class ContentAnalysisAudit(Record):
    schema_version: Literal["transpect.chrome.content.audit/1.0"] = (
        "transpect.chrome.content.audit/1.0"
    )
    attempt_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    request_token_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    user_action_id_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    connector: Connector
    reason: Reason
    destination_host: str
    completeness: Literal["complete", "partial", "unknown"]
    encoding_state: Literal["utf8", "binary", "unsupported", "unknown"]
    body_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    body_bytes: int = Field(ge=0, le=MAX_CONTENT_BYTES)
    decision: Literal["ALLOW", "BLOCK", "UNKNOWN"]
    action: Literal["allow", "block"]
    verdict_reason: str
    policy_version: str
    rule_ids: list[str] = Field(default_factory=list)
    registration_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
