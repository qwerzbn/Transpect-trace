"""Route N collection: archive and decide each new content item of a model request.

The native guard hands the policy service the complete serialized request
(`transpect.guard.request/1.0`). Codex resends the whole context every turn
(`store=false`), and the guard calls the HTTP gate twice per body about 55 ms
apart, so this collector works on items, not bodies: an item already archived
in this guard session reuses its decision, and only new items are inspected
and recorded. In the ordinary mode they are also archived separately. In the
shared-request mode one durable full-body snapshot backs every item record.
A request is released only if every item is.

Every failure blocks, as the probe engine does; observe mode records the same
rows but always allows.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace

from transpect_trace.guard.policy import GuardDecision, GuardRequest
from .archive import ArchiveReceipt, EncryptedRequestArchive
from .codex_hook_gate import MODES, CodexHookGate, GateConfig, leaves
from .collection import (CollectedItem, CollectionWriter, build_record, data_urls,
                         normalize_match_text, supersede)
from .content_dlp import DLPVerdict
from .wire_items import (WireRequest, data_url_item, item_identity, metadata_view,
                         parse_wire_request)

DUPLICATE_WINDOW_SECONDS = 10.0
# guard/pipe.py blocks a model request whose decision takes longer than this.
DECISION_DEADLINE_SECONDS = 2.0
# Decided past this, the collector blocks itself, leaving time to write the rows.
_DECISION_BUDGET_SECONDS = 1.75
_RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}
_NOT_INSPECTED = DLPVerdict("ALLOW", "NOT_INSPECTED")
_PARSE_FAILED = ("INSPECTION_ERROR", "WIRE_PARSE_FAILED", 1.0)
_DEADLINE = "DECISION_DEADLINE_EXCEEDED"


@dataclass(frozen=True)
class CachedItem:
    archive_record_id: str
    content_hmac: str
    actionable: str
    first_request_id: str


class SessionItemCache:
    """Decided items per guard session, LRU-bounded. Eviction only re-archives."""

    def __init__(self, max_items: int = 65_536, max_sessions: int = 64):
        self.max_items, self.max_sessions = max_items, max_sessions
        self._items: OrderedDict[str, OrderedDict[bytes, CachedItem]] = OrderedDict()
        self._bodies: dict[str, dict[str, tuple[str, str, float]]] = {}
        self._lock = threading.Lock()

    def _session(self, session: str) -> OrderedDict[bytes, CachedItem]:
        items = self._items.setdefault(session, OrderedDict())
        self._items.move_to_end(session)
        while len(self._items) > self.max_sessions:
            evicted, _ = self._items.popitem(last=False)
            self._bodies.pop(evicted, None)
        return items

    def get(self, session: str, key: bytes) -> CachedItem | None:
        with self._lock:
            items = self._session(session)
            if key in items:
                items.move_to_end(key)
            return items.get(key)

    def put(self, session: str, key: bytes, item: CachedItem) -> None:
        with self._lock:
            items = self._session(session)
            items[key] = item
            items.move_to_end(key)
            while len(items) > self.max_items:
                items.popitem(last=False)

    def recent_body(self, session: str, sha256: str) -> tuple[str, str] | None:
        """(action, request_id) of the same body seen in this session within the window."""
        with self._lock:
            seen = self._bodies.get(session, {}).get(sha256)
            if seen is None or time.monotonic() - seen[2] > DUPLICATE_WINDOW_SECONDS:
                return None
            return seen[0], seen[1]

    def remember_body(self, session: str, sha256: str, action: str, request_id: str) -> None:
        with self._lock:
            now = time.monotonic()
            bodies = self._bodies.setdefault(session, {})
            for key in [key for key, seen in bodies.items()
                        if now - seen[2] > DUPLICATE_WINDOW_SECONDS]:
                del bodies[key]
            bodies[sha256] = (action, request_id, now)


@dataclass
class CollectionResult:
    action: str                 # ALLOW | REVIEW | BLOCK
    reason: str
    records: list[dict]
    envelope: dict


@dataclass
class _Decided:
    item: CollectedItem
    receipt: ArchiveReceipt
    content_hmac: str
    match_hmac: str | None
    verdict: DLPVerdict | None
    findings: tuple
    actionable: str
    elapsed_ms: float


class NativeRequestCollector:
    def __init__(self, gate: CodexHookGate, writer: CollectionWriter, *,
                 archive_full_body: bool = False, cache: SessionItemCache | None = None,
                 capture_only: bool = False, shared_request_archive: bool = False):
        self.gate, self.writer = gate, writer
        self.archive_full_body = archive_full_body
        self.capture_only = capture_only
        self.shared_request_archive = shared_request_archive
        self.cache = cache or SessionItemCache()

    @property
    def policy_version(self) -> str:
        return f"native-collection/1:{self.gate._policy_version}"[:127]

    def collect(self, request: GuardRequest) -> CollectionResult:
        began = time.perf_counter()
        # A lone surrogate must not escape the fail-closed path below: kept as
        # bytes, it makes the body invalid UTF-8, so parsing fails and it blocks.
        raw = request.payload_utf8.encode("utf-8", "surrogatepass")
        sha = hashlib.sha256(raw).hexdigest()
        try:
            return self._collect(request, raw, sha, began)
        except Exception as error:  # fail closed
            return CollectionResult("BLOCK", f"COLLECTION_FAILED_{type(error).__name__}", [], {
                "request_id": request.request_id, "guard_session_id": request.guard_session_id,
                "request_sha256": sha, "content_bytes": len(raw),
                "elapsed_ms": round((time.perf_counter() - began) * 1000, 3)})

    def _collect(self, request: GuardRequest, raw: bytes, sha: str,
                 began: float) -> CollectionResult:
        session = request.guard_session_id
        ids = {"guard_session_id": session, "request_id": request.request_id,
               "request_sha256": sha}
        archive, _ = self.gate._prepare()
        # One flushed snapshot is sufficient to recover every parsed item by
        # location and keyed digest. It also bounds durable writes for long
        # desktop contexts with hundreds of items.
        body_receipt = (archive.save("model_request", raw)
                        if self.shared_request_archive else None)
        if request.completeness != "complete":
            # A partial capture must not inherit a cached allow for identical
            # bytes, nor seed the cache for a later complete capture.
            receipt = body_receipt
            if receipt is None and self.archive_full_body:
                receipt = archive.save("model_request", raw)
            envelope = self._envelope(
                request, raw, archive, receipt, {**ids, "first_request_id": request.request_id},
                "BLOCK", began,
                {"capture_completeness": request.completeness,
                 "limitations": ["capture_incomplete"]},
                fail_closed=True,
            )
            self.writer.write([envelope])
            return CollectionResult("BLOCK", "INCOMPLETE_CONTENT", [envelope], envelope)
        seen = self.cache.recent_body(session, sha)
        if seen is not None:
            action, first = seen
            receipt = body_receipt
            if receipt is None and self.capture_only and self.archive_full_body:
                receipt = archive.save("model_request", raw)
            envelope = self._envelope(request, raw, archive, receipt, {**ids, "first_request_id": first},
                                      action, began, {"duplicate_invocation": True})
            self.writer.write([envelope])
            return CollectionResult(action, "DUPLICATE_INVOCATION", [envelope], envelope)

        wire, items, failed = self._items(raw, request.protocol)
        correlation = {**ids, **(wire.correlation if wire else {}),
                       "first_request_id": request.request_id}
        decided: dict[bytes, _Decided] = {}
        actions, cached = [], 0
        for item in items:
            key = item_identity(item)
            hit = decided.get(key) or self.cache.get(session, key)
            if hit is not None:
                actions.append(hit.actionable)
                cached += 1
                continue
            decided[key] = self._decide(item, archive, failed, body_receipt)
            actions.append(decided[key].actionable)
        action = max(actions, key=_RANK.__getitem__, default="ALLOW")
        reason = ("WIRE_PARSE_FAILED" if failed else "REQUIRED_CHECKS_COMPLETE"
                  if action == "ALLOW" else "SENSITIVE_OR_AMBIGUOUS_CONTENT")
        late = not self.capture_only and time.perf_counter() - began > _DECISION_BUDGET_SECONDS
        if late:  # the pipe would block it anyway; record that, not an allow
            action, reason = "BLOCK", _DEADLINE
        records = [self._record(request, result, correlation, action, late)
                   for result in decided.values()]
        if body_receipt is None and self.archive_full_body:
            body_receipt = archive.save("model_request", raw)
        extra = {"items_total": len(items), "items_new": len(decided), "items_cached": cached,
                 "incremental": bool(wire and wire.incremental),
                 "format": wire.format if wire else "unparsed",
                 "limitations": (wire.limitations if wire else ["wire_parse_failed"])[:64],
                 **({"deadline_exceeded": True} if late else {})}
        envelope = self._envelope(request, raw, archive, body_receipt, correlation, action,
                                  began, extra, late)
        records.append(envelope)
        self.writer.write(records)
        # Cached only once recorded, so a failed write never hides an item later.
        for key, result in decided.items():
            self.cache.put(session, key, CachedItem(result.receipt.record_id, result.content_hmac,
                                                    result.actionable, request.request_id))
        self.cache.remember_body(session, sha, action, request.request_id)
        return CollectionResult(action, reason, records, envelope)

    def supersede(self, result: CollectionResult, reason: str) -> None:
        """The pipe overrode an allow: record the denial and answer the guard's
        second call on the same body with it."""
        if self.capture_only:
            raise ValueError("capture-only observations cannot be superseded as enforcement")
        envelope = result.envelope
        self.writer.write(supersede(result.records, reason))
        self.cache.remember_body(envelope["guard_session_id"], envelope["request_sha256"],
                                 "BLOCK", envelope["request_id"])

    @staticmethod
    def _items(raw: bytes, protocol: str) -> tuple[WireRequest | None, list[CollectedItem], bool]:
        """Items to decide. A delta (`previous_response_id`) carries only new items,
        which are itemized like a full body and flagged incremental on the
        envelope; an unparsed body is one whole-body `unknown` item, plus one item
        per inline base64 payload, which that text omits."""
        try:
            wire = parse_wire_request(raw, protocol=protocol)
        except ValueError:
            return None, [CollectedItem("unknown", "/", raw, "", None, inspectable=False)], True
        if wire.format != "unknown":
            return wire, wire.items, False
        body = json.loads(raw)
        view = metadata_view(body) if isinstance(body, dict) else body
        urls = [url for url in data_urls(body) if url.base64]
        return wire, [CollectedItem("unknown", "/", raw, "\n".join(leaves(view)), None),
                      *(data_url_item("unknown", f"/#{index}", url)
                        for index, url in enumerate(urls))], False

    def _decide(self, item: CollectedItem, archive, failed: bool,
                body_receipt: ArchiveReceipt | None = None) -> _Decided:
        began = time.perf_counter()
        receipt = body_receipt or archive.save(item.archive_kind, item.payload)
        content_hmac = archive.keyed_digest(item.payload)
        if item.archive_kind == "attachment":
            match_hmac = content_hmac
        elif item.match_text is not None:
            match_hmac = archive.keyed_digest(
                normalize_match_text(item.category, item.match_text).encode("utf-8"))
        else:
            match_hmac = None
        _, engine = self.gate._prepare()
        verdict = (None if not item.inspectable
                   else engine.inspect_file_bytes(item.file_name, item.payload) if item.file_name
                   else engine.inspect_text(item.inspect_text))
        findings: list = list(item.findings)
        if item.category == "tool_call_args" and item.tool_name:
            # inspect_text is "tool_name=<name>\n" + the argument leaves, as on the hook.
            findings.extend(self.gate.policy.inspect(item.tool_name,
                                                     [item.inspect_text.partition("\n")[2]]))
        if failed:
            findings.append(_PARSE_FAILED)
        actionable = ("BLOCK" if failed
                      else self.gate.actionable(verdict or _NOT_INSPECTED, tuple(findings)))
        return _Decided(item, receipt, content_hmac, match_hmac, verdict, tuple(findings),
                        actionable, (time.perf_counter() - began) * 1000)

    def _route(self, action: str, late: bool = False,
               fail_closed: bool = False) -> tuple[str, bool | None]:
        if self.capture_only:
            return "not_enforceable", None
        if late or fail_closed:  # capture failures and deadlines block in either mode
            return "deny", False
        if self.gate.config.mode == "observe":
            return "observe_allow", True
        return ("allow", True) if action == "ALLOW" else ("deny", False)

    def _record(self, request: GuardRequest, result: _Decided, correlation: dict,
                action: str, late: bool = False) -> dict:
        item = result.item
        route_decision, released = self._route(action, late)
        extra = {"tool_executed_before_decision": True} if item.category == "tool_output" else {}
        if self.shared_request_archive:
            extra["shared_request_archive"] = True
        return build_record(
            route="native", route_event="model.request", protocol=request.protocol,
            category=item.category, location=item.location, collection="content",
            receipt=result.receipt, content_hmac=result.content_hmac,
            match_hmac=result.match_hmac, inspected=result.verdict is not None,
            decision_point="none" if self.capture_only else "before_upstream", verdict=result.verdict,
            actionable=result.actionable, route_decision=route_decision,
            released_by_route=released,
            correlation={**correlation, "call_id": item.call_id, "tool_name": item.tool_name},
            policy_version=self.policy_version,
            gate_mode="observe" if self.capture_only else self.gate.config.mode,
            elapsed_ms=result.elapsed_ms, extra=extra, findings=result.findings,
            content_bytes=len(item.payload))

    def _envelope(self, request: GuardRequest, raw: bytes, archive, receipt, correlation: dict,
                  action: str, began: float, extra: dict, late: bool = False,
                  fail_closed: bool = False) -> dict:
        route_decision, released = self._route(action, late, fail_closed)
        return build_record(
            route="native", route_event="model.request", protocol=request.protocol,
            category="request_envelope", location="/",
            collection="content" if receipt else "metadata_only", receipt=receipt,
            content_hmac=archive.keyed_digest(raw), match_hmac=None, inspected=False,
            decision_point="none" if self.capture_only else "before_upstream",
            verdict=None, actionable=action,
            route_decision=route_decision, released_by_route=released,
            correlation=correlation, policy_version=self.policy_version,
            gate_mode="observe" if self.capture_only else self.gate.config.mode,
            elapsed_ms=(time.perf_counter() - began) * 1000,
            extra=extra, content_bytes=len(raw))


class NativeCollectionEngine:
    """Native pipe policy engine, or a post-capture lab collector without enforcement."""

    def __init__(self, config: GateConfig, *, mode: str | None = None,
                 collection_file: Path | None = None, archive_full_body: bool = False,
                 capture_only: bool = False, shared_request_archive: bool = False):
        if capture_only and not archive_full_body:
            raise ValueError("capture_only requires archive_full_body")
        if shared_request_archive and not archive_full_body:
            raise ValueError("shared_request_archive requires archive_full_body")
        if mode is not None:
            if mode not in MODES:
                raise ValueError("mode must be enforce or observe")
            config = replace(config, mode=mode)
        path = (collection_file or getattr(config, "collection_file", None)
                or config.audit_file.parent / "collection.jsonl")
        self.gate = CodexHookGate(config)
        self.capture_only = capture_only
        # The pipe path has a 2 s deadline; the capture-only path still benefits
        # from a prepared archive and engine before its first observation.
        self.gate._prepare()
        self.collector = NativeRequestCollector(self.gate, CollectionWriter(path),
                                                archive_full_body=archive_full_body,
                                                capture_only=capture_only,
                                                shared_request_archive=shared_request_archive)
        self.policy = SimpleNamespace(version=self.collector.policy_version)

    def evaluate(self, request) -> tuple[GuardDecision, dict | None]:
        if self.capture_only:
            raise ValueError("capture_only cannot serve pipe enforcement decisions")
        if request.kind != "model.request":
            return GuardDecision(request_id=request.request_id, decision="allow", action="none",
                                 reason="CONTROL", policy_version=self.policy.version), None
        began = time.perf_counter()
        result = self.collector.collect(request)
        # Observe mode allows, except past the deadline, where the pipe blocks anyway.
        allowed = result.action == "ALLOW" or (self.gate.config.mode == "observe"
                                               and result.reason not in (_DEADLINE, "INCOMPLETE_CONTENT"))
        if allowed and time.perf_counter() - began > DECISION_DEADLINE_SECONDS:
            try:  # the rows were written in time, the decision was not
                self.collector.supersede(result, _DEADLINE)
            except Exception:
                pass
        decision = "allow" if allowed else "deny"
        row = {**result.envelope, "decision": decision, "action": result.action,
               "reason": result.reason}
        return GuardDecision(request_id=request.request_id, decision=decision,
                             action="none" if allowed else "block_request",
                             reason=result.reason[:1023],
                             policy_version=self.policy.version), row


def read_shared_request_item(archive: EncryptedRequestArchive, record: dict) -> bytes:
    """Recover an item referenced by a durable full-request snapshot.

    The category and JSON location select the item, while its keyed digest
    verifies the exact bytes. A repeated location with distinct content is
    therefore never accepted merely because the path matches.
    """
    if (record.get("extra", {}).get("shared_request_archive") is not True
            or record.get("archive_kind") != "model_request"):
        raise ValueError("record is not backed by a shared request archive")
    receipt, raw = archive.read(record["archive_record_id"])
    if (receipt.kind != "model_request"
            or hashlib.sha256(raw).hexdigest() != record.get("request_sha256")):
        raise ValueError("shared request archive does not match the record")
    _, items, _ = NativeRequestCollector._items(raw, record["protocol"])
    for item in items:
        if (item.category == record.get("category")
                and item.location == record.get("location")
                and len(item.payload) == record.get("content_bytes")
                and archive.keyed_digest(item.payload) == record.get("content_hmac")):
            return item.payload
    raise ValueError("shared request item is absent or differs")
