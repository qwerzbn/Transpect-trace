from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field


class ContentMarker(BaseModel):
    model_config = ConfigDict(extra="forbid")

    marker_id: str = Field(min_length=1)
    value: str = Field(min_length=1)
    source_path: str = Field(min_length=1)
    classification: str = "sensitive"


class GatewayPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_: Literal["transpect.gateway.policy/1.0"] = Field(
        default="transpect.gateway.policy/1.0", alias="schema"
    )
    policy_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    allowed_upstreams: list[str] = Field(default_factory=list)
    allowed_source_paths: list[str] = Field(default_factory=list)
    content_markers: list[ContentMarker] = Field(default_factory=list)


@dataclass(frozen=True)
class PolicyDecision:
    decision: Literal["allow", "deny"]
    rule_id: str
    reason: str
    requested_upstream: str
    matched_marker_ids: tuple[str, ...] = ()
    matched_source_paths: tuple[str, ...] = ()
    matched_marker_sha256: tuple[str, ...] = ()


def load_policy(path: Path | str) -> GatewayPolicy:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return GatewayPolicy.model_validate(value)


def upstream_identity(url: str) -> str:
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower()


def evaluate_policy(policy: GatewayPolicy, body: bytes, upstream: str) -> PolicyDecision:
    requested_upstream = upstream_identity(upstream)
    allowed_upstreams = {upstream_identity(value) for value in policy.allowed_upstreams}
    if allowed_upstreams and requested_upstream not in allowed_upstreams:
        return PolicyDecision(
            decision="deny",
            rule_id="UPSTREAM_NOT_ALLOWED",
            reason="The configured model upstream is outside the task allowlist.",
            requested_upstream=requested_upstream,
        )

    allowed_sources = set(policy.allowed_source_paths)
    matched = [marker for marker in policy.content_markers if marker.value.encode("utf-8") in body]
    denied = [marker for marker in matched if marker.source_path not in allowed_sources]
    if denied:
        return PolicyDecision(
            decision="deny",
            rule_id="DATA_OUT_OF_SCOPE",
            reason="The model request contains data mapped to a source outside the task allowlist.",
            requested_upstream=requested_upstream,
            matched_marker_ids=tuple(marker.marker_id for marker in denied),
            matched_source_paths=tuple(marker.source_path for marker in denied),
            matched_marker_sha256=tuple(
                f"sha256:{hashlib.sha256(marker.value.encode('utf-8')).hexdigest()}" for marker in denied
            ),
        )

    return PolicyDecision(
        decision="allow",
        rule_id="POLICY_ALLOW",
        reason="The request satisfies the configured task data and upstream policy.",
        requested_upstream=requested_upstream,
        matched_marker_ids=tuple(marker.marker_id for marker in matched),
        matched_source_paths=tuple(marker.source_path for marker in matched),
        matched_marker_sha256=tuple(
            f"sha256:{hashlib.sha256(marker.value.encode('utf-8')).hexdigest()}" for marker in matched
        ),
    )
