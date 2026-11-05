"""Synchronous DLP gate for the Codex client's own command-hook contract.

Codex writes one JSON event to stdin and reads one JSON decision from stdout.
This module implements only the output shapes the pinned client accepts, because
an output the client rejects is discarded -- a malformed reply would fail open.

Enforcement reach, verified per event rather than assumed:

| event             | role     | effect                                      |
| ----------------- | -------- | ------------------------------------------- |
| `UserPromptSubmit`| enforce  | `decision: block` stops the submitted text  |
| `PreToolUse`      | enforce  | `permissionDecision: deny` stops the call   |
| `PreModelRequest` | observe  | fires before each request, carries no body  |

`PreModelRequest` is observe-only: the client reports `Completed` for a block
decision and sends the request anyway. Attachments have no hook event at all, so
files added in the desktop UI are outside this gate.

The gate fails closed on every enforceable event: an unreadable event, an
inspection error, an archive failure or an unknown event all deny.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

from .archive import EncryptedRequestArchive
from .content_dlp import ContentDLPEngine, DLPVerdict, decide, fuse

CONFIG_SCHEMA = "transpect.codex-hook-gate/1.0"
AUDIT_SCHEMA = "transpect.codex-hook-gate.decision/1.0"
CONFIG_ENV = "TRANSPECT_CODEX_GATE_CONFIG"
MAX_EVENT_BYTES = 8 * 1024 * 1024
MAX_AUDIT_BYTES = 64 * 1024 * 1024
MODES = frozenset(("enforce", "observe"))

# Events this gate answers. `enforce` marks the ones whose denial the pinned
# client actually honors; everything else is recorded and allowed through.
ENFORCED_EVENTS = frozenset(("UserPromptSubmit", "PreToolUse"))
OBSERVED_EVENTS = frozenset(("PreModelRequest", "SessionStart", "SessionEnd"))
DENY_MESSAGE = {
    "UserPromptSubmit": "本地 DLP 拒绝发送该输入",
    "PreToolUse": "本地 DLP 拒绝该工具调用",
}

# A coding assistant legitimately receives source code, so the structural
# code heuristic is advisory by default: it is recorded but does not deny.
# A fingerprint hit on *registered* source code keeps denying, because that is
# the signal that proprietary code is leaving. Change these in the gate config
# when a deployment wants a stricter or looser action per category.
#
# `ENTROPY_TOKEN` is advisory for the same reason: an uncorroborated
# high-entropy string is usually a commit SHA or package hash in developer
# traffic. `ENTROPY_TOKEN_CONTEXT`, which needs a secret-ish word nearby, still
# denies. Both defaults were chosen from a measured run over this machine's own
# prompt history; see scripts/measure_codex_gate_false_positives.py.
DEFAULT_ENFORCED_CATEGORIES = ("SECRET", "PII", "INTERNAL_DOC", "SOURCE_CODE",
                               "INSPECTION_ERROR")
DEFAULT_ADVISORY_RULE_IDS = ("CODE_STRUCTURE", "ENTROPY_TOKEN")


@dataclass(frozen=True)
class GateConfig:
    mode: str
    archive_directory: Path
    audit_file: Path
    registration_directory: Path | None
    enforced_categories: frozenset[str] = frozenset(DEFAULT_ENFORCED_CATEGORIES)
    advisory_rule_ids: frozenset[str] = frozenset(DEFAULT_ADVISORY_RULE_IDS)

    @classmethod
    def load(cls, path: Path) -> "GateConfig":
        raw = Path(path).read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError("gate configuration exceeds limit")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema") != CONFIG_SCHEMA:
            raise ValueError("unsupported gate configuration")
        unknown = set(value) - {"schema", "mode", "archive_directory", "audit_file",
                                "registration_directory", "enforced_categories",
                                "advisory_rule_ids"}
        if unknown:
            raise ValueError(f"unknown gate configuration fields: {sorted(unknown)}")
        mode = value.get("mode")
        if mode not in MODES:
            raise ValueError("gate mode must be enforce or observe")
        base = Path(path).resolve().parent
        registration = value.get("registration_directory")
        return cls(
            mode=mode,
            archive_directory=cls._resolve(base, value["archive_directory"]),
            audit_file=cls._resolve(base, value["audit_file"]),
            registration_directory=(cls._resolve(base, registration)
                                    if registration is not None else None),
            enforced_categories=cls._names(value.get("enforced_categories"),
                                           DEFAULT_ENFORCED_CATEGORIES),
            advisory_rule_ids=cls._names(value.get("advisory_rule_ids"),
                                         DEFAULT_ADVISORY_RULE_IDS),
        )

    @staticmethod
    def _resolve(base: Path, value: object) -> Path:
        if not isinstance(value, str) or not value:
            raise ValueError("gate path must be a non-empty string")
        candidate = Path(value)
        return candidate if candidate.is_absolute() else (base / candidate).resolve()

    @staticmethod
    def _names(value: object, default: tuple[str, ...]) -> frozenset[str]:
        if value is None:
            return frozenset(default)
        if (not isinstance(value, list) or len(value) > 256
                or any(not isinstance(item, str) or not item for item in value)):
            raise ValueError("category and rule lists must hold non-empty strings")
        return frozenset(value)


@dataclass(frozen=True)
class GateOutcome:
    event: str
    allowed: bool
    reason: str
    response: dict
    audit: dict


def _inspection_target(event: dict) -> tuple[str, str]:
    """Return (label, text) for the bytes this event is able to put on the wire."""
    name = event["hook_event_name"]
    if name == "UserPromptSubmit":
        prompt = event.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError("user prompt text is unavailable")
        return "prompt", prompt
    if name == "PreToolUse":
        tool = event.get("tool_name")
        if not isinstance(tool, str) or not tool:
            raise ValueError("tool name is unavailable")
        if "tool_input" not in event:
            raise ValueError("tool input is unavailable")
        # Serialize deterministically so nested argument values are inspected as
        # text, including values the model placed in object fields.
        arguments = json.dumps(event["tool_input"], ensure_ascii=False,
                               sort_keys=True, separators=(",", ":"))
        return "tool_call", f"tool_name={tool}\n{arguments}"
    raise ValueError(f"event carries no inspectable content: {name}")


def _deny_response(event_name: str, reason: str) -> dict:
    """Build only the fields the pinned client accepts for a denial."""
    message = DENY_MESSAGE[event_name] + f"（{reason}）"
    if event_name == "UserPromptSubmit":
        return {"decision": "block", "reason": message}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": message}}


class CodexHookGate:
    """Decide one hook event; construct the engine lazily so observe stays cheap."""

    def __init__(self, config: GateConfig):
        self.config = config
        self._archive: EncryptedRequestArchive | None = None
        self._engine: ContentDLPEngine | None = None
        self._policy_version = "codex-hook-gate/1"

    def _prepare(self) -> tuple[EncryptedRequestArchive, ContentDLPEngine]:
        if self._archive is None or self._engine is None:
            archive = EncryptedRequestArchive(self.config.archive_directory)
            if self.config.registration_directory is None:
                engine = ContentDLPEngine()
            else:
                from .desktop_registration import load_desktop_registration
                engine, self._policy_version, _ = load_desktop_registration(
                    self.config.registration_directory, archive)
            self._archive, self._engine = archive, engine
        return self._archive, self._engine

    def actionable(self, verdict: DLPVerdict) -> str:
        """Re-decide using only evidence this deployment acts on.

        Advisory rules and unenforced categories stay in the audit row but do
        not deny, so a policy change never needs a second inspection pass.
        """
        if verdict.reason in {"INSPECTION_FAILED", "TEXT_UNINSPECTABLE",
                              "FILE_UNINSPECTABLE"}:
            return "BLOCK"
        acted = tuple(item for item in verdict.evidence
                      if item[0] in self.config.enforced_categories
                      and item[1] not in self.config.advisory_rule_ids)
        return decide(max(fuse(acted).values(), default=0.0))

    def decide(self, event: object) -> GateOutcome:
        began = time.monotonic()
        name = event.get("hook_event_name") if isinstance(event, dict) else None
        if not isinstance(name, str) or name not in ENFORCED_EVENTS | OBSERVED_EVENTS:
            # An unknown event cannot be reasoned about. Only an enforceable one
            # can be denied, and an unknown name is not enforceable, so record it.
            return self._outcome("unknown", True, "UNSUPPORTED_HOOK_EVENT", {},
                                 began, None, None)
        if name not in ENFORCED_EVENTS:
            return self._outcome(name, True, "OBSERVED_NOT_ENFORCEABLE", {},
                                 began, None, None)

        record_id: str | None = None
        verdict: DLPVerdict | None = None
        try:
            label, text = _inspection_target(event)
            archive, engine = self._prepare()
            payload = json.dumps({"event": name, "label": label, "text": text},
                                 ensure_ascii=False).encode("utf-8")
            # The inspected bytes are durable before any send is authorized.
            record_id = archive.save("model_request", payload).record_id
            verdict = engine.inspect_text(text)
            reason = ("REQUIRED_CHECKS_COMPLETE"
                      if self.actionable(verdict) == "ALLOW"
                      else "SENSITIVE_OR_AMBIGUOUS_CONTENT")
        except Exception as error:
            reason = f"GATE_FAILED_{type(error).__name__}"

        denied = reason != "REQUIRED_CHECKS_COMPLETE"
        if denied and self.config.mode == "enforce":
            return self._outcome(name, False, reason, _deny_response(name, reason),
                                 began, record_id, verdict)
        return self._outcome(name, not denied, reason, {}, began, record_id, verdict)

    def _outcome(self, name: str, allowed: bool, reason: str, response: dict,
                 began: float, record_id: str | None,
                 verdict: DLPVerdict | None) -> GateOutcome:
        audit = {
            "schema": AUDIT_SCHEMA,
            "decided_at": datetime.now(timezone.utc).isoformat(),
            "hook_event_name": name,
            "mode": self.config.mode,
            "role": "enforce" if name in ENFORCED_EVENTS else "observe",
            "allowed": allowed,
            "enforced": bool(response),
            "reason": reason,
            "policy_version": self._policy_version,
            "dlp_decision": verdict.decision if verdict else None,
            "actionable_decision": self.actionable(verdict) if verdict else None,
            "matched_rule_ids": sorted(verdict.rule_ids) if verdict else [],
            "categories": sorted(verdict.categories) if verdict else [],
            "category_scores": dict(verdict.category_scores) if verdict else {},
            "archive_record_id": record_id,
            "elapsed_ms": round((time.monotonic() - began) * 1000, 3),
        }
        return GateOutcome(name, allowed, reason, response, audit)

    def append_audit(self, audit: dict) -> None:
        path = self.config.audit_file
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > MAX_AUDIT_BYTES:
            raise ValueError("gate audit log exceeds limit")
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(audit, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def _read_event(stream) -> dict:
    raw = stream.read(MAX_EVENT_BYTES + 1)
    if not raw or len(raw) > MAX_EVENT_BYTES:
        raise ValueError("hook event is empty or exceeds the inspection limit")
    return json.loads(raw.decode("utf-8"))


def _fallback_denial(raw_event_name: str | None) -> dict:
    """Deny without a loaded config when the event name is still recoverable."""
    if raw_event_name in ENFORCED_EVENTS:
        return _deny_response(raw_event_name, "GATE_UNAVAILABLE")
    return {}


def main(argv: list[str] | None = None, stdin=None, stdout=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout.buffer if stdout is None else stdout
    event: dict | None = None
    try:
        event = _read_event(stdin)
        config_path = os.environ.get(CONFIG_ENV) or (argv[0] if argv else None)
        if not config_path:
            raise ValueError(f"set {CONFIG_ENV} or pass the configuration path")
        gate = CodexHookGate(GateConfig.load(Path(config_path)))
        outcome = gate.decide(event)
        try:
            gate.append_audit(outcome.audit)
        except Exception:
            # An unwritable audit log must not silently authorize a send.
            if outcome.event in ENFORCED_EVENTS and gate.config.mode == "enforce":
                outcome = GateOutcome(
                    outcome.event, False, "AUDIT_UNAVAILABLE",
                    _deny_response(outcome.event, "AUDIT_UNAVAILABLE"),
                    {**outcome.audit, "reason": "AUDIT_UNAVAILABLE", "allowed": False})
        response = outcome.response
    except Exception:
        name = event.get("hook_event_name") if isinstance(event, dict) else None
        response = _fallback_denial(name if isinstance(name, str) else None)
    if response:
        stdout.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
