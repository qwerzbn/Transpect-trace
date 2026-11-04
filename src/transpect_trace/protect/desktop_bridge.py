"""Synchronous desktop model and attachment policy behind a pinned native gate.

This is the decision service, not a claim that the desktop upload Hook is
installed. The desktop controller must attest that separate Hook before it
opens any network permit.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import threading
import time
from uuid import uuid4

from transpect_trace.guard.detection import inspection_text
from transpect_trace.guard.policy import GuardDecision
from .archive import ArchiveReceipt, EncryptedRequestArchive, MAX_SNAPSHOT_BYTES
from .content_dlp import ContentDLPEngine, DLPVerdict


_REFERENCE = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_DATA_URL = re.compile(r"data:[^\s,]{0,256};base64,", re.I)
_ANY_DATA_URL = re.compile(r"data:[^\s,]{0,1024},", re.I)
_ATTACHMENT_TYPES = frozenset(("input_file", "file", "input_image", "image_url", "input_audio"))
_FILE_KEYS = frozenset(("file_id", "file_data", "file_url", "file_path", "image_url", "image_base64"))
_UNVERIFIED_HISTORY_KEYS = frozenset(("previous_response_id", "conversation_id", "conversation"))
_SENSITIVE_FIELD = re.compile(r"(?i)(?:password|passwd|api[_-]?key|secret|access[_-]?token|client_secret|credential|密钥|口令)")
PENDING_APPROVAL_TTL = timedelta(minutes=5)
MAX_PENDING_APPROVALS = 1024


def _nested_field_context(value: object) -> str:
    """Keep parent field names visible when a request nests scalar values."""
    parts: list[str] = []
    size = 0
    stack: list[tuple[object, str | None]] = [(value, None)]
    while stack:
        item, sensitive_parent = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                # JSON keys are bytes on the wire even if the value is a map.
                parts.append(key)
                size += len(key.encode("utf-8")) + 1
                parent = key if _SENSITIVE_FIELD.search(key) else sensitive_parent
                stack.append((child, parent))
        elif isinstance(item, list):
            stack.extend((child, sensitive_parent) for child in item)
        elif sensitive_parent is not None and (isinstance(item, str) or type(item) in (int, float)):
            part = sensitive_parent + "=" + str(item)
            parts.append(part)
            size += len(part.encode("utf-8")) + 1
        if size > MAX_SNAPSHOT_BYTES:
            raise ValueError("nested context exceeds inspection limit")
    return "\n".join(parts)


@dataclass(frozen=True)
class AttachmentApproval:
    approval_id: str
    filename: str
    receipt: ArchiveReceipt
    decision: str
    reason: str
    rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class _ApprovedReference:
    receipt: ArchiveReceipt
    filename: str
    policy_version: str


class DesktopDLPBridge:
    """Fail-closed bridge for the existing six-field Guard decision protocol."""

    def __init__(self, subject: dict, archive: EncryptedRequestArchive,
                 dlp: ContentDLPEngine | None = None, *, policy_version: str = "desktop-dlp/1"):
        from types import SimpleNamespace
        self.subject = subject
        self.archive = archive
        self.dlp = dlp or ContentDLPEngine()
        self.policy = SimpleNamespace(version=policy_version)
        self._pending: dict[str, AttachmentApproval] = {}
        self._references: dict[str, _ApprovedReference] = {}
        self._lock = threading.RLock()
        self._last_prune = datetime.now(timezone.utc)
        self.archive.prune(now=self._last_prune)

    @classmethod
    def from_registration(cls, subject: dict, archive: EncryptedRequestArchive,
                          directory: Path) -> "DesktopDLPBridge":
        from .desktop_registration import load_desktop_registration
        engine, policy_version, _ = load_desktop_registration(directory, archive)
        return cls(subject, archive, engine, policy_version=policy_version)

    def _retention_check(self) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._expire_pending_locked(now)
        if now - self._last_prune >= timedelta(hours=24):
            self.archive.prune(now=now)
            with self._lock:
                cutoff = now - self.archive.retention
                self._references = {name: entry for name, entry in self._references.items()
                                    if datetime.fromisoformat(entry.receipt.saved_at) > cutoff}
            self._last_prune = now

    def _expire_pending_locked(self, now: datetime) -> None:
        cutoff = now - PENDING_APPROVAL_TTL
        self._pending = {name: entry for name, entry in self._pending.items()
                         if datetime.fromisoformat(entry.receipt.saved_at) > cutoff}

    def evaluate_attachment(self, filename: str, data: bytes) -> AttachmentApproval:
        """Called by the *actual upload* Hook on the exact bytes it will send."""
        if (not isinstance(filename, str) or not 1 <= len(filename) <= 255
                or any(char in filename for char in ("/", "\\", "\0"))):
            raise ValueError("invalid attachment filename")
        self._retention_check()
        with self._lock:
            if len(self._pending) >= MAX_PENDING_APPROVALS:
                raise ValueError("pending upload approval capacity reached")
        receipt = self.archive.save("attachment", data)
        verdict = self.dlp.inspect_file_bytes(filename, data)
        approval = AttachmentApproval(uuid4().hex, filename, receipt, verdict.decision,
                                      verdict.reason, verdict.rule_ids)
        if verdict.decision == "ALLOW":
            with self._lock:
                self._expire_pending_locked(datetime.now(timezone.utc))
                if len(self._pending) >= MAX_PENDING_APPROVALS:
                    raise ValueError("pending upload approval capacity reached")
                self._pending[approval.approval_id] = approval
        return approval

    def bind_reference(self, approval_id: str, reference_id: str, filename: str,
                       body_sha256: str) -> None:
        """Bind a returned file ID only to the exact previously approved snapshot."""
        if (not isinstance(reference_id, str) or not _REFERENCE.fullmatch(reference_id)
                or not isinstance(filename, str) or not 1 <= len(filename) <= 255):
            raise ValueError("invalid file reference")
        with self._lock:
            self._expire_pending_locked(datetime.now(timezone.utc))
            approval = self._pending.get(approval_id)
            if (approval is None or approval.decision != "ALLOW"
                    or approval.filename != filename
                    or approval.receipt.body_sha256 != body_sha256
                    or datetime.fromisoformat(approval.receipt.saved_at)
                    <= datetime.now(timezone.utc) - PENDING_APPROVAL_TTL
                    or reference_id in self._references):
                raise ValueError("file reference has no matching approved upload")
            # A deleted or tampered encrypted snapshot cannot authorize a new ID.
            stored, _ = self.archive.read(approval.receipt.record_id)
            if stored != approval.receipt:
                raise ValueError("approved upload archive mismatch")
            self._pending.pop(approval_id)
            self._references[reference_id] = _ApprovedReference(
                approval.receipt, filename, self.policy.version)

    def _inline(self, item: dict) -> DLPVerdict:
        name = item.get("filename")
        field_name = "file_data" if "file_data" in item else "data"
        encoded = item[field_name]
        if not isinstance(name, str) or not isinstance(encoded, str):
            raise ValueError("inline file name or data unavailable")
        match = _DATA_URL.match(encoded)
        if not match or len(encoded) > MAX_SNAPSHOT_BYTES * 2:
            raise ValueError("unsupported inline file data")
        try:
            raw = base64.b64decode(encoded[match.end():], validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("invalid inline file data") from error
        if not 0 < len(raw) <= MAX_SNAPSHOT_BYTES:
            raise ValueError("inline file exceeds limit")
        self.archive.save("attachment", raw)
        return self.dlp.inspect_file_bytes(name, raw)

    def _attachments(self, value: object) -> tuple[object, list[DLPVerdict]]:
        """Replace only attachment bytes while retaining their visible metadata."""
        verdicts: list[DLPVerdict] = []
        nodes = 0

        def walk(item: object, depth: int = 0) -> object:
            nonlocal nodes
            nodes += 1
            if nodes > 200_000 or depth > 64:
                raise ValueError("request structure exceeds inspection limit")
            if isinstance(item, list):
                return [walk(child, depth + 1) for child in item]
            if isinstance(item, str) and _ANY_DATA_URL.search(item):
                raise ValueError("untyped inline file content")
            if not isinstance(item, dict):
                return item
            if _UNVERIFIED_HISTORY_KEYS.intersection(item):
                raise ValueError("unverified server-side history reference")
            kind = item.get("type")
            if kind in _ATTACHMENT_TYPES:
                if kind not in {"input_file", "file"}:
                    raise ValueError("unsupported attachment type")
                if set(item) - {"type", "filename", "file_id", "file_data", "data", "detail"}:
                    raise ValueError("unrecognized attachment field")
                if "detail" in item and item["detail"] not in {"auto", "low", "high"}:
                    raise ValueError("unsupported file detail")
                if "file_data" in item and "data" in item:
                    raise ValueError("ambiguous inline file data")
                has_inline = "file_data" in item or "data" in item
                if "file_id" in item and has_inline:
                    raise ValueError("ambiguous attachment source")
                if has_inline:
                    verdicts.append(self._inline(item))
                    filename = item["filename"]
                else:
                    reference = item.get("file_id")
                    if not isinstance(reference, str) or not _REFERENCE.fullmatch(reference):
                        raise ValueError("unresolved file reference")
                    with self._lock:
                        approved = self._references.get(reference)
                    if (approved is None or approved.policy_version != self.policy.version
                            or datetime.fromisoformat(approved.receipt.saved_at)
                            <= datetime.now(timezone.utc) - self.archive.retention):
                        raise ValueError("unapproved file reference")
                    if "filename" in item and item["filename"] != approved.filename:
                        raise ValueError("file reference filename mismatch")
                    stored, _ = self.archive.read(approved.receipt.record_id)
                    if stored != approved.receipt:
                        raise ValueError("approved file archive mismatch")
                    verdicts.append(DLPVerdict("ALLOW", "APPROVED_FILE_REFERENCE"))
                    filename = approved.filename
                return {"type": kind, "filename": filename, "detail": item.get("detail", "auto")}
            if _FILE_KEYS.intersection(item):
                raise ValueError("unrecognized attachment shape")
            return {key: walk(child, depth + 1) for key, child in item.items()}

        return walk(value), verdicts

    def evaluate(self, request) -> tuple[GuardDecision, dict]:
        if request.kind != "model.request":
            audit = {}
            if request.kind == "native.outcome":
                audit = {"kind": "native.outcome", "request_id": request.outcome_for_request_id,
                         "native_event_id": request.request_id, "pid": request.pid,
                         "tid": request.tid, "guard_session_id": request.guard_session_id,
                         "action": request.outcome_action,
                         "captured_qpc": request.outcome_captured_qpc,
                         "qpc_frequency": request.qpc_frequency,
                         "action_execution": "native_error_constructed",
                         "byte_level_taint_proof": False}
            return GuardDecision(request_id=request.request_id, decision="allow",
                                 action="none", reason="CONTROL_ACK",
                                 policy_version=self.policy.version), audit
        began = time.monotonic()
        raw = b""
        receipt = None
        reason = "REQUIRED_CHECKS_FAILED"
        verdict: DLPVerdict | None = None
        attachments: list[DLPVerdict] = []
        try:
            if request.pid != self.subject.get("pid"):
                raise ValueError("desktop process identity mismatch")
            raw = request.payload_utf8.encode("utf-8")
            self._retention_check()
            # The complete wire body is durable before parsing or authorizing.
            receipt = self.archive.save("model_request", raw)
            if request.completeness != "complete" or len(raw) > MAX_SNAPSHOT_BYTES:
                raise ValueError("incomplete request")
            def no_duplicate_fields(pairs):
                fields = {}
                for key, item in pairs:
                    if key in fields:
                        raise ValueError("duplicate JSON field")
                    fields[key] = item
                return fields

            value = json.loads(raw, object_pairs_hook=no_duplicate_fields)
            if not isinstance(value, dict):
                raise ValueError("unsupported model request")
            if request.protocol == "wss" and value.get("type") != "response.create":
                raise ValueError("unsupported WSS message")
            response = value.get("response", value) if value.get("type") == "response.create" else value
            if not isinstance(response, dict) or not isinstance(response.get("model"), str):
                raise ValueError("model request shape unavailable")
            if "input" not in response and "messages" not in response:
                raise ValueError("model request input unavailable")
            if "input" in response and (not isinstance(response["input"], (str, list)) or not response["input"]):
                raise ValueError("model request input shape unavailable")
            if "messages" in response and (not isinstance(response["messages"], list) or not response["messages"]):
                raise ValueError("model request messages shape unavailable")
            # Inspect the entire serialized message, including WSS envelope
            # fields outside `response`; those bytes also cross the wire.
            redacted, attachments = self._attachments(value)
            text = inspection_text(redacted) + "\n" + _nested_field_context(redacted)
            verdict = self.dlp.inspect_text(text)
            if verdict.decision != "ALLOW" or any(item.decision != "ALLOW" for item in attachments):
                reason = "SENSITIVE_OR_UNINSPECTABLE_CONTENT"
            else:
                reason = "REQUIRED_CHECKS_COMPLETE"
        except Exception:
            reason = "ARCHIVE_OR_INSPECTION_FAILED" if receipt is None else "UNINSPECTABLE_CONTENT"
        allowed = reason == "REQUIRED_CHECKS_COMPLETE"
        decision = GuardDecision(request_id=request.request_id,
                                 decision="allow" if allowed else "deny",
                                 action="none" if allowed else "block_request",
                                 reason=reason, policy_version=self.policy.version)
        rule_ids = set(verdict.rule_ids if verdict else ())
        rule_ids.update(rule for item in attachments for rule in item.rule_ids)
        row = {"kind": "policy.decision", "request_id": request.request_id,
               "guard_session_id": request.guard_session_id,
               "pid": request.pid, "tid": request.tid,
               "protocol": request.protocol, "decision": decision.decision,
               "action": decision.action, "reason": reason,
               "policy_version": self.policy.version,
               "body_sha256": hashlib.sha256(raw).hexdigest(), "body_bytes": len(raw),
               "archive_record_id": receipt.record_id if receipt else None,
               "matched_rule_ids": sorted(rule_ids),
               "elapsed_ms": (time.monotonic() - began) * 1000,
               "action_execution": "not_yet_confirmed"}
        return decision, row
