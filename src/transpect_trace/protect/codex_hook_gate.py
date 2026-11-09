"""Synchronous DLP gate for the Codex client's own command-hook contract.

Codex writes one JSON event to stdin and reads one JSON decision from stdout.
This module implements only the output shapes the pinned client accepts, because
an output the client rejects is discarded -- a malformed reply would fail open.

Enforcement reach, verified per event against a scripted local origin that
records what actually arrives upstream (scripts/probe_codex_hook_coverage.py):

| event             | role     | inspected bytes          | denial effect                    |
| ----------------- | -------- | ------------------------ | -------------------------------- |
| `UserPromptSubmit`| enforce  | `prompt`                 | turn stops, zero model requests  |
| `PreToolUse`      | enforce  | tool name + arguments    | call does not run                |
| `PostToolUse`     | enforce  | `tool_response`          | output replaced by the reason    |
| `PreModelRequest` | observe  | metadata + transcript    | none -- the client sends anyway  |

`PostToolUse` closes the path a coding agent leaks through most: a harmless
command (`Get-Content .env`) whose *output* goes to the model in the next
request. A block there replaces the output with the gate's fixed reason before
the request is built. Two limits were measured, not assumed: a long-running
command's output already returned before its yield window is sent before
`PostToolUse` fires, and attachments (`-i` images, desktop file uploads) never
reach any enforceable hook. `PreModelRequest` records the latter from the
transcript so they are at least visible in the audit.

The gate fails closed on every enforceable event: an unreadable or oversized
event, an inspection error, an archive or audit failure all deny.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time

from .archive import ArchiveReceipt, EncryptedRequestArchive
from . import collection as col
from .content_dlp import ContentDLPEngine, DLPVerdict, decide, fuse
from .tool_policy import DEFAULT_ALLOWED_HOSTS, ToolPolicy

CONFIG_SCHEMA = "transpect.codex-hook-gate/1.0"
AUDIT_SCHEMA = "transpect.codex-hook-gate.decision/1.1"
CONFIG_ENV = "TRANSPECT_CODEX_GATE_CONFIG"
MAX_EVENT_BYTES = 8 * 1024 * 1024
MAX_AUDIT_BYTES = 64 * 1024 * 1024
MAX_ROTATED_AUDITS = 32
MAX_TRANSCRIPT_TAIL = 8 * 1024 * 1024
MODES = frozenset(("enforce", "observe"))

# `enforce` marks the events whose denial the pinned client honors.
ENFORCED_EVENTS = frozenset(("UserPromptSubmit", "PreToolUse", "PostToolUse"))
OBSERVED_EVENTS = frozenset(("PreModelRequest", "SessionStart", "SessionEnd"))
TOOL_EVENTS = frozenset(("PreToolUse", "PostToolUse"))
DENY_MESSAGE = {
    "UserPromptSubmit": "本地 DLP 拒绝发送该输入",
    "PreToolUse": "本地 DLP 拒绝该工具调用",
    "PostToolUse": "本地 DLP 已拦截该工具输出，未发送给模型",
}

# A coding assistant legitimately receives source code, so the structural
# code heuristic is advisory by default: it is recorded but does not deny.
# A fingerprint hit on *registered* source code keeps denying, because that is
# the signal that proprietary code is leaving. `ENTROPY_TOKEN` is advisory for
# the same reason: an uncorroborated high-entropy string is usually a commit
# SHA or package hash. `IMAGE_UNINSPECTED` records an image the engine cannot
# read; add it to the enforced set to deny every image a tool returns.
DEFAULT_ENFORCED_CATEGORIES = ("SECRET", "PII", "INTERNAL_DOC", "SOURCE_CODE",
                               "INSPECTION_ERROR", "SENSITIVE_PATH",
                               "NETWORK_EGRESS", "GATE_TAMPER")
DEFAULT_ADVISORY_RULE_IDS = ("CODE_STRUCTURE", "ENTROPY_TOKEN", "IMAGE_UNINSPECTED")
DEFAULT_OVERRIDE_TTL = 600
_UNINSPECTABLE = {"INSPECTION_FAILED", "TEXT_UNINSPECTABLE", "FILE_UNINSPECTABLE"}
_EVENT_NAME = re.compile(rb'"hook_event_name"\s*:\s*"([A-Za-z]{1,64})"')
_DATA_URL = re.compile(r"^data:[\w.+/-]+;base64,", re.I)
_META_FIELDS = ("session_id", "turn_id", "tool_use_id", "tool_name", "agent_id",
                "agent_type", "permission_mode")


@dataclass(frozen=True)
class GateConfig:
    mode: str
    archive_directory: Path
    audit_file: Path
    registration_directory: Path | None
    enforced_categories: frozenset[str] = frozenset(DEFAULT_ENFORCED_CATEGORIES)
    advisory_rule_ids: frozenset[str] = frozenset(DEFAULT_ADVISORY_RULE_IDS)
    # 0 disables REVIEW approval codes entirely.
    review_override_ttl_seconds: int = DEFAULT_OVERRIDE_TTL
    override_directory: Path | None = None
    egress_allowed_hosts: frozenset[str] = frozenset(DEFAULT_ALLOWED_HOSTS)
    protected_paths: tuple[str, ...] = ()
    # `transpect.codex-collection/1.0` rows; None disables collection.
    collection_file: Path | None = None

    _FIELDS = frozenset(("schema", "mode", "archive_directory", "audit_file",
                         "registration_directory", "enforced_categories",
                         "advisory_rule_ids", "review_override_ttl_seconds",
                         "override_directory", "egress_allowed_hosts",
                         "protected_paths", "collection_file"))

    @classmethod
    def load(cls, path: Path) -> "GateConfig":
        raw = Path(path).read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError("gate configuration exceeds limit")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema") != CONFIG_SCHEMA:
            raise ValueError("unsupported gate configuration")
        unknown = set(value) - cls._FIELDS
        if unknown:
            raise ValueError(f"unknown gate configuration fields: {sorted(unknown)}")
        mode = value.get("mode")
        if mode not in MODES:
            raise ValueError("gate mode must be enforce or observe")
        base = Path(path).resolve().parent
        registration = value.get("registration_directory")
        audit_file = cls._resolve(base, value["audit_file"])
        ttl = value.get("review_override_ttl_seconds", DEFAULT_OVERRIDE_TTL)
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 0 <= ttl <= 86_400:
            raise ValueError("review_override_ttl_seconds must be 0..86400")
        override = value.get("override_directory")
        # Absent means next to the audit file; an explicit null disables it.
        collection = value.get("collection_file", audit_file.parent / "collection.jsonl")
        if isinstance(collection, str):
            collection = cls._resolve(base, collection)
        elif collection is not None and "collection_file" in value:
            raise ValueError("collection_file must be a path or null")
        return cls(
            mode=mode,
            archive_directory=cls._resolve(base, value["archive_directory"]),
            audit_file=audit_file,
            registration_directory=(cls._resolve(base, registration)
                                    if registration is not None else None),
            enforced_categories=cls._names(value.get("enforced_categories"),
                                           DEFAULT_ENFORCED_CATEGORIES),
            advisory_rule_ids=cls._names(value.get("advisory_rule_ids"),
                                         DEFAULT_ADVISORY_RULE_IDS),
            review_override_ttl_seconds=ttl,
            override_directory=(cls._resolve(base, override) if override is not None
                                else audit_file.parent / "review-overrides"),
            egress_allowed_hosts=cls._names(value.get("egress_allowed_hosts"),
                                            DEFAULT_ALLOWED_HOSTS),
            protected_paths=tuple(sorted(cls._names(value.get("protected_paths"), ()))),
            collection_file=collection,
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
            raise ValueError("category, rule, host and path lists must hold non-empty strings")
        return frozenset(value)


@dataclass(frozen=True)
class GateOutcome:
    event: str
    allowed: bool
    reason: str
    response: dict
    audit: dict
    # `transpect.codex-collection/1.0` rows, written before the audit row.
    collection: tuple[dict, ...] = ()

@dataclass
class InspectionTarget:
    """The bytes one event can put on the wire, plus evidence the engine cannot see."""
    label: str
    text: str
    # Content an approval code binds to; equal content yields an equal binding.
    binding: str
    findings: list[tuple[str, str, float]] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    approvals: list = field(default_factory=list)


def leaves(value: object, *, images: list | None = None, depth: int = 0) -> list[str]:
    """Every string a JSON value carries, keys included, in document order.

    Inspecting the leaves rather than a JSON serialization matters: serializing
    turns `password="x"` into `password=\\"x\\"`, which the rules missed. Image
    data URLs are counted into `images` and not returned, since base64 pixels
    are neither inspectable text nor useful entropy evidence.
    """
    if depth > 64:
        raise ValueError("tool value nesting exceeds limit")
    out: list[str] = []
    if isinstance(value, str):
        if _DATA_URL.match(value):
            if images is not None:
                images.append(len(value))
        else:
            out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            out.extend(leaves(item, images=images, depth=depth + 1))
    elif isinstance(value, list):
        for item in value:
            out.extend(leaves(item, images=images, depth=depth + 1))
    elif value is not None:
        out.append(str(value))
    return out


def inspection_target(event: dict, policy: ToolPolicy | None = None) -> InspectionTarget:
    """Return what this event is able to send, without touching archive or engine."""
    name = event["hook_event_name"]
    if name == "UserPromptSubmit":
        prompt = event.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError("user prompt text is unavailable")
        from .review_override import split_approvals
        stripped, approvals = split_approvals(prompt)
        # Justifications are user text the model will read, so they are inspected.
        extra = "\n".join(item.justification for item in approvals if item.justification)
        text = stripped + ("\n" + extra if extra else "")
        return InspectionTarget("prompt", text, stripped, approvals=approvals,
                                meta={"approval_lines": len(approvals)})
    tool = event.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise ValueError("tool name is unavailable")
    if "tool_input" not in event:
        raise ValueError("tool input is unavailable")
    binding = f"tool_name={tool}\n" + json.dumps(event["tool_input"], ensure_ascii=False,
                                                 sort_keys=True, separators=(",", ":"))
    if name == "PreToolUse":
        values = leaves(event["tool_input"])
        target = InspectionTarget("tool_call", f"tool_name={tool}\n" + "\n".join(values),
                                  binding)
        if policy is not None:
            target.findings.extend(policy.inspect(tool, values))
        return target
    if name == "PostToolUse":
        if "tool_response" not in event:
            raise ValueError("tool response is unavailable")
        images: list[int] = []
        values = leaves(event["tool_response"], images=images)
        target = InspectionTarget("tool_output", "\n".join(values), binding,
                                  meta={"image_items": len(images)})
        if images:
            target.findings.append(("INSPECTION_GAP", "IMAGE_UNINSPECTED", 0.60))
        return target
    raise ValueError(f"event carries no inspectable content: {name}")


def _deny_response(event_name: str, reason: str, hint: str = "") -> dict:
    """Build only the fields the pinned client accepts for a denial."""
    message = DENY_MESSAGE[event_name] + f"（{reason}）" + hint
    if event_name == "PreToolUse":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                       "permissionDecision": "deny",
                                       "permissionDecisionReason": message}}
    # UserPromptSubmit and PostToolUse share `decision: block` plus `reason`;
    # for PostToolUse the client sends that reason in place of the output.
    return {"decision": "block", "reason": message}


def _override_hint(event_name: str, code: str, ttl: int) -> str:
    minutes = max(1, ttl // 60)
    if event_name == "UserPromptSubmit":
        return (f"。如确认不含敏感信息，在原文末尾另起一行写 `#dlp-approve {code} <理由>` "
                f"后重新发送（{minutes} 分钟内有效，仅一次）")
    return (f"。如确认可以放行，请用户回复 `#dlp-approve {code} <理由>`，再让 Agent 重试同一操作"
            f"（{minutes} 分钟内有效，仅一次）")


def _metadata(event: dict) -> dict:
    return {key: event[key][:256] for key in _META_FIELDS
            if isinstance(event.get(key), str)}


class CodexHookGate:
    """Decide one hook event; construct the engine lazily so observe stays cheap."""

    def __init__(self, config: GateConfig):
        self.config = config
        self._archive: EncryptedRequestArchive | None = None
        self._engine: ContentDLPEngine | None = None
        self._overrides = None
        self._policy_version = "codex-hook-gate/2"
        self.policy = ToolPolicy(allowed_hosts=config.egress_allowed_hosts,
                                 protected_paths=config.protected_paths)

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

    def overrides(self):
        if self.config.review_override_ttl_seconds <= 0:
            return None
        if self._overrides is None:
            from .review_override import OverrideStore
            self._overrides = OverrideStore(self.config.override_directory,
                                            self.config.review_override_ttl_seconds)
        return self._overrides

    def actionable(self, verdict: DLPVerdict,
                   extra: tuple[tuple[str, str, float], ...] = ()) -> str:
        """Re-decide using only evidence this deployment acts on.

        Advisory rules and unenforced categories stay in the audit row but do
        not deny, so a policy change never needs a second inspection pass.
        """
        if verdict.reason in _UNINSPECTABLE:
            return "BLOCK"
        acted = tuple(item for item in tuple(verdict.evidence) + tuple(extra)
                      if item[0] in self.config.enforced_categories
                      and item[1] not in self.config.advisory_rule_ids)
        return decide(max(fuse(acted).values(), default=0.0))

    def decide(self, event: object) -> GateOutcome:
        began = time.perf_counter()
        name = event.get("hook_event_name") if isinstance(event, dict) else None
        if not isinstance(name, str) or name not in ENFORCED_EVENTS | OBSERVED_EVENTS:
            # An unknown event cannot be reasoned about. Only an enforceable one
            # can be denied, and an unknown name is not enforceable, so record it.
            return self._outcome("unknown", {}, True, "UNSUPPORTED_HOOK_EVENT", {},
                                 began)
        if name not in ENFORCED_EVENTS:
            extra = self._observe(event) if name == "PreModelRequest" else {}
            records: tuple[dict, ...] = ()
            if name == "PreModelRequest" and self.config.collection_file is not None:
                try:
                    records = self._metadata_records(event, extra, began)
                except Exception as error:
                    extra = {**extra, "collection_error": type(error).__name__}
            return self._outcome(name, event, True, "OBSERVED_NOT_ENFORCEABLE", {},
                                 began, extra=extra, collection=records)

        record_id = None
        receipt: ArchiveReceipt | None = None
        payload = b""
        images: list[tuple[ArchiveReceipt, str]] = []
        action = None
        verdict = None
        target = None
        override: dict = {}
        hint = ""
        try:
            target = inspection_target(event, self.policy)
            archive, engine = self._prepare()
            payload = json.dumps({"event": name, "label": target.label,
                                  "text": target.text}, ensure_ascii=False).encode("utf-8")
            # The inspected bytes are durable before any send is authorized.
            receipt = archive.save("model_request", payload)
            record_id = receipt.record_id
            verdict = engine.inspect_text(target.text)
            action = self.actionable(verdict, tuple(target.findings))
            if action == "ALLOW":
                reason = "REQUIRED_CHECKS_COMPLETE"
            else:
                reason = "SENSITIVE_OR_AMBIGUOUS_CONTENT"
            session = event.get("session_id") if isinstance(event.get("session_id"), str) else ""
            store = self.overrides()
            if name == "UserPromptSubmit" and store is not None and target.approvals:
                override = self._apply_prompt_approvals(store, target, session, action)
                if override.get("redeemed"):
                    reason = "REVIEW_APPROVED_BY_USER"
            elif name in TOOL_EVENTS and store is not None and action == "REVIEW":
                code = store.redeem_tool(name, session, target.binding)
                if code:
                    reason = "REVIEW_APPROVED_BY_USER"
                    override = {"redeemed": True}
            if (reason == "SENSITIVE_OR_AMBIGUOUS_CONTENT" and action == "REVIEW"
                    and store is not None and self.config.mode == "enforce"):
                code = store.issue(name, session, target.binding)
                hint = _override_hint(name, code, self.config.review_override_ttl_seconds)
                override = {**override, "issued": True}
        except Exception as error:
            reason = f"GATE_FAILED_{type(error).__name__}"

        allowed = reason in {"REQUIRED_CHECKS_COMPLETE", "REVIEW_APPROVED_BY_USER"}
        records = ()
        if self.config.collection_file is not None and receipt is not None:
            try:
                if name == "PostToolUse":
                    images = self._archive_images(event["tool_response"])
                records = self._collection_records(name, event, target, payload, receipt,
                                                   images, verdict, action, allowed, began)
            except Exception:
                # An item that cannot be recorded is not authorized to leave.
                allowed, reason = False, "COLLECTION_UNAVAILABLE"
        extra = {"override": override} if override else {}
        if target is not None and target.meta:
            extra.update(target.meta)
        if not allowed and self.config.mode == "enforce":
            return self._outcome(name, event, False, reason,
                                 _deny_response(name, reason, hint), began,
                                 record_id, verdict, target, extra, records)
        return self._outcome(name, event, allowed, reason, {}, began, record_id,
                             verdict, target, extra, records)

    def _archive_images(self, value: object) -> list[tuple[ArchiveReceipt, str]]:
        """Archive each base64 data URL as collected content, after the verdict, so
        collection never changes what is inspected. A payload that is not valid
        base64 is archived as the URL text the client sends."""
        archive, images = self._archive, []
        for url in col.data_urls(value):
            if url.base64:
                data = url.data or url.url.encode("utf-8")
                images.append((archive.save("attachment", data), archive.keyed_digest(data)))
        return images

    def _collection_records(self, name: str, event: dict, target: InspectionTarget,
                            payload: bytes, receipt: ArchiveReceipt,
                            images: list[tuple[ArchiveReceipt, str]],
                            verdict: DLPVerdict | None, action: str | None,
                            allowed: bool, began: float) -> tuple[dict, ...]:
        """Rows for the content one enforced event archived. No I/O."""
        category, point, match = {
            "UserPromptSubmit": ("user_prompt", "before_upstream", target.binding),
            # Hook and wire tool arguments differ in shape (Bash/command vs
            # exec_command/cmd), so they are joined by call id, not digest.
            "PreToolUse": ("tool_call_args", "before_execution", None),
            "PostToolUse": ("tool_output", "after_execution_before_upstream", target.text),
        }[name]
        observe = self.config.mode == "observe"
        common = {
            "route": "hook", "route_event": name, "protocol": "hook", "collection": "content",
            "decision_point": point, "actionable": action,
            "route_decision": "observe_allow" if observe else "allow" if allowed else "deny",
            "released_by_route": observe or allowed, "correlation": col.hook_correlation(event),
            "policy_version": self._policy_version, "gate_mode": self.config.mode,
            "elapsed_ms": (time.perf_counter() - began) * 1000,
        }
        archive = self._archive
        field_name = {"user_prompt": "prompt", "tool_call_args": "tool_input"}.get(
            category, "tool_response")
        rows = [col.build_record(
            **common, category=category, location=f"hook:{name}/{field_name}",
            receipt=receipt, content_hmac=archive.keyed_digest(payload),
            match_hmac=(archive.keyed_digest(col.normalize_match_text(category, match)
                                             .encode("utf-8")) if match is not None else None),
            inspected=verdict is not None, verdict=verdict,
            findings=tuple(item for item in target.findings if item[1] != "IMAGE_UNINSPECTED"),
            extra={"image_items": len(images)} if images else None)]
        for index, (image, digest) in enumerate(images):
            # The route acts on the whole output, so an image carries the event's action.
            rows.append(col.build_record(
                **common, category="tool_output_image",
                location=f"hook:{name}/tool_response/image/{index}", receipt=image,
                content_hmac=digest, match_hmac=digest, inspected=False, verdict=None,
                findings=(col.IMAGE_GAP,)))
        return tuple(rows)

    def _metadata_records(self, event: dict, observed: dict, began: float) -> tuple[dict, ...]:
        """PreModelRequest cannot deny, so it records only what will be sent, not content."""
        common = {
            "route": "hook", "route_event": "PreModelRequest", "protocol": "hook",
            "collection": "metadata_only", "receipt": None, "content_hmac": None,
            "match_hmac": None, "inspected": False, "decision_point": "none", "verdict": None,
            "actionable": None, "route_decision": "not_enforceable", "released_by_route": True,
            "correlation": col.hook_correlation(event), "policy_version": self._policy_version,
            "gate_mode": self.config.mode, "elapsed_ms": (time.perf_counter() - began) * 1000,
        }
        attachments = observed.get("ungated_attachments", 0)
        rows = [col.build_record(**common, category="request_metadata",
                                 location="hook:PreModelRequest", extra=observed)]
        if attachments:
            rows.append(col.build_record(
                **common, category="user_attachment", location="hook:PreModelRequest/transcript",
                extra={"ungated_attachments": attachments}))
        return tuple(rows)

    def _apply_prompt_approvals(self, store, target: InspectionTarget, session: str,
                                action: str) -> dict:
        granted, redeemed = 0, False
        for approval in target.approvals:
            if store.grant(approval.code, session):
                granted += 1
            elif (action == "REVIEW" and not redeemed
                  and store.redeem_prompt(approval.code, session, target.binding)):
                redeemed = True
        # A BLOCK verdict is never approved, even with a valid code.
        return {"granted_tool_codes": granted, "redeemed": redeemed and action == "REVIEW"}

    def _observe(self, event: dict) -> dict:
        """Count attachments in this turn that no enforceable hook could inspect."""
        path = event.get("transcript_path")
        turn = event.get("turn_id")
        if not isinstance(path, str) or not isinstance(turn, str):
            return {}
        try:
            return {"ungated_attachments": transcript_attachments(Path(path), turn)}
        except Exception as error:
            return {"transcript_error": type(error).__name__}

    def _outcome(self, name: str, event: dict, allowed: bool, reason: str,
                 response: dict, began: float, record_id: str | None = None,
                 verdict: DLPVerdict | None = None,
                 target: InspectionTarget | None = None, extra: dict | None = None,
                 collection: tuple[dict, ...] = ()) -> GateOutcome:
        findings = tuple(target.findings) if target else ()
        rule_ids = set(verdict.rule_ids) if verdict else set()
        rule_ids.update(item[1] for item in findings)
        categories = set(verdict.categories) if verdict else set()
        categories.update(item[0] for item in findings)
        scores = dict(verdict.category_scores) if verdict else {}
        for category, score in fuse(findings).items():
            scores[category] = round(1 - (1 - scores.get(category, 0.0)) * (1 - score), 4)
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
            "actionable_decision": self.actionable(verdict, findings) if verdict else None,
            "matched_rule_ids": sorted(rule_ids),
            "categories": sorted(categories),
            "category_scores": scores,
            "archive_record_id": record_id,
            "elapsed_ms": round((time.perf_counter() - began) * 1000, 3),
            **_metadata(event if isinstance(event, dict) else {}),
            **(extra or {}),
        }
        return GateOutcome(name, allowed, reason, response, audit, collection)

    def append_audit(self, audit: dict) -> None:
        append_audit_line(self.config.audit_file,
                          json.dumps(audit, ensure_ascii=False, sort_keys=True))

    def append_collection(self, records: tuple[dict, ...]) -> None:
        if self.config.collection_file is not None and records:
            col.CollectionWriter(self.config.collection_file).write(records)


def transcript_attachments(path: Path, turn_id: str) -> int:
    """Count image/file inputs the user attached in this turn, from the transcript.

    The client writes the user message with its attachments to the rollout
    before the model request, so `PreModelRequest` can see what
    `UserPromptSubmit` could not. Only the tail is read.
    """
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - MAX_TRANSCRIPT_TAIL))
        data = stream.read()
    in_turn, count = False, 0
    for line in data.splitlines():
        if not line.startswith(b"{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        payload = row.get("payload") if isinstance(row, dict) else None
        if not isinstance(payload, dict):
            continue
        if row.get("type") == "event_msg" and payload.get("type") == "task_started":
            in_turn = payload.get("turn_id") == turn_id
        elif (in_turn and row.get("type") == "response_item"
              and payload.get("type") == "message" and payload.get("role") == "user"):
            count += sum(1 for item in payload.get("content") or []
                         if isinstance(item, dict)
                         and item.get("type") in {"input_image", "input_file", "image"})
    return count


# ---- audit log: rotation plus an inter-process lock ----

class _FileLock:
    """Exclusive lock on a sidecar file; hook processes run concurrently."""

    def __init__(self, path: Path, timeout: float = 10.0):
        self.path, self.timeout, self.stream = path, timeout, None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = open(self.path, "a+b")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    self.stream.seek(0)
                    msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() > deadline:
                    self.stream.close()
                    raise TimeoutError("audit lock timeout")
                time.sleep(0.01)

    def __exit__(self, *_exc):
        try:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.stream.close()


def append_audit_line(path: Path, line: str, *, max_bytes: int = MAX_AUDIT_BYTES,
                      keep: int = MAX_ROTATED_AUDITS) -> None:
    """Append one row; rotate instead of failing when the file is full.

    The previous behavior raised once the file passed its limit, and the caller
    turns an audit failure into a denial -- so a full log denied every prompt.
    Rotation keeps the newest `keep` files and drops older ones.
    """
    path = Path(path)
    with _FileLock(path.with_name(path.name + ".lock")):
        if path.exists() and path.stat().st_size >= max_bytes:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            os.replace(path, path.with_name(f"{path.stem}-{stamp}{path.suffix}"))
            rotated = sorted(path.parent.glob(f"{path.stem}-*{path.suffix}"))
            for old in rotated[:max(0, len(rotated) - keep)]:
                old.unlink(missing_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def audit_files(path: Path) -> list[Path]:
    """The live audit file and its rotations, oldest first."""
    path = Path(path)
    rotated = sorted(path.parent.glob(f"{path.stem}-*{path.suffix}"))
    return rotated + ([path] if path.exists() else [])


# ---- process entry ----

def read_event(stream) -> tuple[dict | None, str | None]:
    """Return (event, recoverable name). An oversized event still yields its name."""
    raw = stream.read(MAX_EVENT_BYTES + 1)
    match = _EVENT_NAME.search(raw[:65536]) if raw else None
    name = match.group(1).decode("ascii") if match else None
    if not raw or len(raw) > MAX_EVENT_BYTES:
        return None, name
    try:
        event = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None, name
    return (event if isinstance(event, dict) else None), name


def fallback_denial(raw_event_name: str | None, reason: str = "GATE_UNAVAILABLE") -> dict:
    """Deny without a loaded config when the event name is still recoverable."""
    if raw_event_name in ENFORCED_EVENTS:
        return _deny_response(raw_event_name, reason)
    return {}


def run_event(event: dict | None, name: str | None, config_path: str | None,
              gate: "CodexHookGate | None" = None) -> dict:
    """Decide one event end to end and return the reply object ({} = allow).

    A resident service passes its already-loaded `gate`; the per-event process
    builds one from `config_path`. Both take the same decision path.
    """
    try:
        if event is None:
            # Unparseable or oversized: nothing can be inspected, so an
            # enforceable event denies.
            return fallback_denial(name, "EVENT_UNINSPECTABLE")
        if gate is None:
            if not config_path:
                raise ValueError(f"set {CONFIG_ENV} or pass the configuration path")
            gate = CodexHookGate(GateConfig.load(Path(config_path)))
        outcome = gate.decide(event)
        enforcing = outcome.event in ENFORCED_EVENTS and gate.config.mode == "enforce"
        try:
            # Collected before audited: an item without a record is not released.
            gate.append_collection(outcome.collection)
        except Exception as error:
            outcome.audit["collection_error"] = type(error).__name__
            if enforcing and not outcome.response:
                outcome.audit.update(allowed=False, enforced=True,
                                     reason="COLLECTION_UNAVAILABLE")
                try:
                    gate.append_audit(outcome.audit)
                except Exception:
                    pass
                return _deny_response(outcome.event, "COLLECTION_UNAVAILABLE")
        try:
            gate.append_audit(outcome.audit)
        except Exception:
            # An unwritable audit log must not silently authorize a send.
            if enforcing:
                try:  # the collection rows already said allow
                    gate.append_collection(tuple(col.supersede(outcome.collection,
                                                               "AUDIT_UNAVAILABLE")))
                except Exception:
                    pass
                return _deny_response(outcome.event, "AUDIT_UNAVAILABLE")
        return outcome.response
    except Exception:
        event_name = event.get("hook_event_name") if isinstance(event, dict) else name
        return fallback_denial(event_name if isinstance(event_name, str) else None)


def main(argv: list[str] | None = None, stdin=None, stdout=None) -> int:
    """Always exit 0 with a parseable reply: a non-zero exit makes the client
    report `Failed` and send anyway, which is fail-open."""
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout.buffer if stdout is None else stdout
    name = None
    try:
        event, name = read_event(stdin)
        config_path = os.environ.get(CONFIG_ENV) or (argv[0] if argv else None)
        response = run_event(event, name, config_path)
    except Exception:
        response = fallback_denial(name)
    if response:
        stdout.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
