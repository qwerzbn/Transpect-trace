from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ProcessIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pid: int = Field(gt=0)
    creation_filetime: int = Field(gt=0)
    image_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    image_name: str | None = Field(default=None, max_length=260)

    @property
    def key(self) -> str:
        return f"{self.pid}-{self.creation_filetime}"


class BehaviorEvent(BaseModel):
    """Metadata only; no command line, payload or arbitrary ETW properties."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["transpect.codex.behavior/1.0"] = "transpect.codex.behavior/1.0"
    run_id: str
    event_id: str
    kind: Literal["process.snapshot", "process.start", "process.exit", "file.access", "file.read", "file.write", "network.activity"]
    subject: ProcessIdentity
    parent_identity: str | None = None
    timestamp_qpc: int = Field(ge=0)
    evidence_method: str
    provider: str | None = None
    opcode: int | None = None
    path: str | None = None
    destination_address: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Literal["tcp", "udp", "unknown"] = "unknown"
    reported_size: int | None = Field(default=None, ge=0)
    limitations: list[str] = Field(default_factory=list)
    read_success: Literal["unknown"] = "unknown"
    payload_sent: Literal["unknown"] = "unknown"
    byte_level_taint_proof: Literal[False] = False


class EgressRule(BaseModel):
    """Observation rule. It never installs a filter or implies execution."""
    model_config = ConfigDict(extra="forbid")
    rule_id: str
    image_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    destination_address: str
    destination_port: int = Field(gt=0, le=65535)
    protocol: Literal["tcp", "udp"]
    action: Literal["audit", "recommend_block"] = "audit"
