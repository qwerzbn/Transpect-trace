from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator


TRACE_EVENT_SCHEMA = "transpect.trace.event/1.0"
MANIFEST_SCHEMA = "transpect.trace.manifest/1.0"
EVENT_NAMESPACE = UUID("ac8f588a-f658-45e2-8d57-65c45ec51332")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def stable_event_id(run_id: str, collector: str, collector_seq: int, kind: str) -> str:
    return str(uuid5(EVENT_NAMESPACE, f"{run_id}\0{collector}\0{collector_seq}\0{kind}"))


class EventTime(BaseModel):
    model_config = ConfigDict(extra="forbid")
    wall: str
    monotonic_ns: int = Field(ge=0)


class EventSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collector: str = Field(min_length=1)
    version: str = Field(min_length=1)
    trust: Literal["external", "kernel", "instrumented", "application", "derived"]


class Correlation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str | None = None
    turn_id: str | None = None
    request_id: str | None = None
    tool_call_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    pid: int | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    tid: int | None = Field(default=None, ge=0)
    fd: int | None = None


class Operation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    target: str | None = None


class ContentRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bytes: int = Field(ge=0)
    sha256: str | None = None
    blob_ref: str | None = None
    media_type: str | None = None
    encoding: str | None = None
    payload_status: Literal["full", "redacted", "hash_only", "unavailable"] = "unavailable"

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str | None) -> str | None:
        if value is not None and (not value.startswith("sha256:") or len(value) != 71):
            raise ValueError("sha256 must use the sha256:<64 hex characters> form")
        return value


class EventLink(BaseModel):
    model_config = ConfigDict(extra="forbid")
    relation: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)


class TraceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, serialize_by_alias=True)
    schema_: Literal["transpect.trace.event/1.0"] = Field(default=TRACE_EVENT_SCHEMA, alias="schema")
    event_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    collector_seq: int = Field(ge=1)
    ingest_seq: int = Field(ge=1)
    time: EventTime
    plane: Literal["run", "client", "model", "system"]
    kind: str = Field(min_length=1)
    source: EventSource
    correlation: Correlation = Field(default_factory=Correlation)
    operation: Operation
    content: ContentRef = Field(default_factory=lambda: ContentRef(bytes=0))
    attributes: dict[str, Any] = Field(default_factory=dict)
    links: list[EventLink] = Field(default_factory=list)


class CollectorState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    version: str = "unknown"
    started: bool = False
    stopped: bool = False
    dropped_events: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list)


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, serialize_by_alias=True)
    schema_: Literal["transpect.trace.manifest/1.0"] = Field(default=MANIFEST_SCHEMA, alias="schema")
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    status: Literal["running", "complete", "incomplete", "failed"] = "running"
    started_at: str = Field(default_factory=utc_now)
    ended_at: str | None = None
    client: str
    client_version: str = "unknown"
    provider: str
    model: str
    workspace: str
    host: dict[str, Any] = Field(default_factory=dict)
    container: dict[str, Any] = Field(default_factory=dict)
    collectors: list[CollectorState] = Field(default_factory=list)
    configuration: dict[str, Any] = Field(default_factory=dict)
    failure: dict[str, Any] | None = None
