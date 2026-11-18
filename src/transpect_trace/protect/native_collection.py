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

from collections import Counter, OrderedDict
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import re
import threading
import time
from types import SimpleNamespace

from transpect_trace.guard.policy import GuardDecision, GuardRequest
from .archive import ArchiveReceipt, EncryptedRequestArchive
from .codex_hook_gate import MODES, CodexHookGate, GateConfig, leaves
from .collection import (CollectedItem, CollectionWriter, build_record, data_urls,
                         normalize_match_text, supersede)
from .content_dlp import DLPVerdict
from .redact import redact_raw_json
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


def _content_position(location: str) -> tuple[int, int] | None:
    parts = location.split("/")
    if len(parts) < 3 or parts[1] != "messages" or not parts[2].isdigit():
        return None
    content = int(parts[4]) if len(parts) > 4 and parts[3] == "content" and parts[4].isdigit() else -1
    return int(parts[2]), content


_CODEX_INPUT_POSITION = re.compile(
    r"(?:/response)?/input/(\d+)/(?:content(?:/\d+(?:/text)?)?|output)$"
)
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def _codex_input_position(location: str) -> tuple[int, int] | None:
    # All text parts of one message share the same ordering position. A benign
    # sibling part never establishes a subsequent user message.
    match = _CODEX_INPUT_POSITION.fullmatch(location)
    return (int(match[1]), -1) if match else None


def _wss_message_anchors(raw: bytes) -> tuple[dict[int, bytes], set[int], int]:
    """Stable Codex message IDs let a denied delta be found after its input index moves.

    Bind the whole user message (including ID, role, all keys and part order).
    An ID repeated anywhere in the request is ambiguous, even across roles.
    """
    body = json.loads(raw)
    entries = body.get("response", body).get("input")
    if not isinstance(entries, list):
        return {}, set(), 0
    ids = Counter(x["id"] for x in entries if isinstance(x, dict) and isinstance(x.get("id"), str))
    anchors, ambiguous = {}, set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("type") != "message" or entry.get("role") != "user":
            continue
        ident = entry.get("id")
        if not isinstance(ident, str) or not ident.startswith("msg_") or not _UUID.fullmatch(ident[4:]):
            continue
        if ids[ident] != 1:
            ambiguous.add(index)
        else:
            encoded = json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
            anchors[index] = hashlib.sha256(encoded).digest()
    return anchors, ambiguous, len(entries)


@dataclass(frozen=True)
class CachedItem:
    archive_record_id: str
    content_hmac: str
    actionable: str
    first_request_id: str
    first_location: str
    deny_boundary: tuple[int, int] | None = None
    deny_turn: str | None = None


class SessionItemCache:
    """Decided items per guard session, LRU-bounded. Eviction only re-archives."""

    def __init__(self, max_items: int = 65_536, max_sessions: int = 64):
        self.max_items, self.max_sessions = max_items, max_sessions
        self._items: OrderedDict[str, OrderedDict[bytes, CachedItem]] = OrderedDict()
        self._bodies: dict[str, dict[str, tuple[str, str, float, str | None]]] = {}
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

    def recent_body(self, session: str, sha256: str) -> tuple[str, str, str | None] | None:
        """(action, request_id, redacted_payload) of the same body seen in this
        session within the window. redacted_payload replays the cleaned body so
        a client retry of a redact-allowed request never falls back to a deny."""
        with self._lock:
            seen = self._bodies.get(session, {}).get(sha256)
            if seen is None or time.monotonic() - seen[2] > DUPLICATE_WINDOW_SECONDS:
                return None
            return seen[0], seen[1], seen[3]

    def remember_body(self, session: str, sha256: str, action: str, request_id: str,
                      redacted_payload: str | None = None) -> None:
        with self._lock:
            now = time.monotonic()
            bodies = self._bodies.setdefault(session, {})
            for key in [key for key, seen in bodies.items()
                        if now - seen[2] > DUPLICATE_WINDOW_SECONDS]:
                del bodies[key]
            bodies[sha256] = (action, request_id, now, redacted_payload)


@dataclass
class CollectionResult:
    action: str                 # ALLOW | REVIEW | BLOCK
    reason: str
    records: list[dict]
    envelope: dict
    # Cleaned body for a recovered historical denial or legacy redact mode.
    redacted_payload: str | None = None


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
                 capture_only: bool = False, shared_request_archive: bool = False,
                 allowed_formats: frozenset[str] | None = None,
                 redact_on_block: bool = False,
                 scrub_denied_history: bool = False,
                 scrub_codex_denied_history: bool = False):
        self.gate, self.writer = gate, writer
        self.archive_full_body = archive_full_body
        self.capture_only = capture_only
        self.shared_request_archive = shared_request_archive
        self.allowed_formats = allowed_formats
        self.redact_on_block = redact_on_block
        self.scrub_denied_history = scrub_denied_history
        self.scrub_codex_denied_history = scrub_codex_denied_history
        if scrub_codex_denied_history and (redact_on_block or capture_only or gate.config.mode != "enforce"):
            raise ValueError("Codex history recovery requires enforce mode and direct denial")
        self.cache = cache or SessionItemCache()

    @property
    def policy_version(self) -> str:
        return f"native-collection/1:{self.gate._policy_version}"[:127]

    def _cache_key(self, item: CollectedItem, codex_thread: str | None = None) -> bytes:
        key = item_identity(item)
        if self.scrub_codex_denied_history:
            return hashlib.sha256(key + b"\0" + (codex_thread or "").encode("ascii")
                                  + b"\0" + item.location.encode("utf-8")).digest()
        if self.scrub_denied_history:
            # The same secret submitted at a later message location is a new
            # blocked turn, not previously denied history.
            return hashlib.sha256(key + b"\0" + item.location.encode("utf-8")).digest()
        return key

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
        body_key = f"{request.protocol}:{sha}" if self.scrub_codex_denied_history else sha
        seen = self.cache.recent_body(session, body_key)
        if seen is not None:
            action, first, cached_redacted = seen
            receipt = body_receipt
            if receipt is None and self.capture_only and self.archive_full_body:
                receipt = archive.save("model_request", raw)
            extra = {"duplicate_invocation": True}
            duplicate_reason = "DUPLICATE_INVOCATION"
            if cached_redacted is not None and self.scrub_codex_denied_history:
                # A duplicate still authorizes only the cleaned body. Preserve
                # the forwarding proof and policy reason on this attempt.
                extra.update(history_scrubbed=True,
                             forwarded_body_hmac=archive.keyed_digest(cached_redacted.encode("utf-8")))
                duplicate_reason = "HISTORICAL_BLOCK_SCRUBBED"
            envelope = self._envelope(request, raw, archive, receipt, {**ids, "first_request_id": first},
                                      action, began, extra)
            self.writer.write([envelope])
            return CollectionResult(action, duplicate_reason, [envelope], envelope,
                                    cached_redacted)

        wire, items, failed = self._items(raw, request.protocol)
        if self.allowed_formats is not None and (wire is None or wire.format not in self.allowed_formats):
            wire, items, failed = (None, [CollectedItem("unknown", "/", raw, "", None,
                                                       inspectable=False)], True)
        correlation = {**ids, **(wire.correlation if wire else {}),
                       "first_request_id": request.request_id}
        codex = (self.scrub_codex_denied_history and wire is not None
                 and wire.format in ("responses", "wss_response_create"))
        valid_ids = codex and all(_UUID.fullmatch(correlation.get(key) or "")
                                  for key in ("thread_id", "turn_id"))
        thread_id = correlation["thread_id"] if valid_ids else None
        turn_id = correlation["turn_id"] if valid_ids else None
        locate = _codex_input_position if codex else _content_position
        wss = valid_ids and wire.format == "wss_response_create"
        anchors, ambiguous, input_count = _wss_message_anchors(raw) if wss else ({}, set(), 0)
        # Exact-position keys for deltas always use a separate namespace.
        # Only an individually denied, ID-bound message can cross into full history.
        delta_keys: dict[bytes, bytes] = {}
        claude_history = (self.scrub_denied_history and wire is not None
                          and wire.format == "anthropic_messages" and request.protocol == "http")
        decided: dict[bytes, _Decided] = {}
        actions, cached = [], 0
        blocked_items: list[tuple[CollectedItem, tuple[str, ...]]] = []
        historical_blocked: list[tuple[CollectedItem, tuple[str, ...]]] = []
        historical_boundaries: list[tuple[int, int]] = []
        fresh_nonallow = False
        safe_user_positions: list[tuple[int, int]] = []
        for item in items:
            key = self._cache_key(item, thread_id)
            position = locate(item.location)
            ambiguous_message = bool(position and position[0] in ambiguous)
            anchor = anchors.get(position[0]) if position and item.category == "user_prompt" else None
            delta_key = None
            if anchor is not None:
                key = hashlib.sha256(key + anchor).digest()
                suffix = item.location[_CODEX_INPUT_POSITION.fullmatch(item.location).end(1):]
                delta_key = hashlib.sha256(b"wss-denied-delta\0" + thread_id.encode("ascii")
                                           + anchor + suffix.encode("ascii") + item_identity(item)).digest()
            if codex and wire.incremental:
                key = hashlib.sha256(b"incremental\0" + key).digest()
                if delta_key is not None and input_count == 1:
                    delta_keys[key] = delta_key
            same_body = decided.get(key)
            hit = same_body or self.cache.get(session, key)
            if hit is None and delta_key is not None and not wire.incremental:
                candidate = self.cache.get(session, delta_key)
                if candidate is not None and candidate.actionable in ("BLOCK", "REVIEW"):
                    hit = replace(candidate, first_location=item.location, deny_boundary=position)
            if (hit is None and claude_history
                    and item.category in ("user_prompt", "tool_output")
                    and item.payload.rstrip(b" \t\r\n") != item.payload):
                canonical = replace(item, payload=item.payload.rstrip(b" \t\r\n"))
                candidate = self.cache.get(session, self._cache_key(canonical))
                if (candidate is not None and candidate.actionable == "BLOCK"
                        and candidate.first_location == item.location):
                    hit = candidate
            if hit is not None:
                actions.append(hit.actionable)
                if hit.actionable != "ALLOW":
                    rules = (tuple(rule for _, rule, _ in hit.findings)
                             if isinstance(hit, _Decided) else ("SENSITIVE",))
                    blocked_items.append((item, rules))
                    if same_body is not None or ambiguous_message:
                        fresh_nonallow = True
                    elif (hit.actionable in ("BLOCK", "REVIEW")
                          and hit.first_location == item.location
                          and (not codex or (turn_id and hit.deny_turn and hit.deny_turn != turn_id
                                            and item.category in ("user_prompt", "tool_output")))
                          and hit.deny_boundary is not None):
                        historical_blocked.append((item, rules))
                        historical_boundaries.append(hit.deny_boundary)
                    else:
                        fresh_nonallow = True
                elif item.category == "user_prompt":
                    position = locate(item.location)
                    if position is not None:
                        safe_user_positions.append(position)
                cached += 1
                continue
            decided[key] = self._decide(item, archive, failed, body_receipt)
            actions.append(decided[key].actionable)
            if decided[key].actionable != "ALLOW":
                fresh_nonallow = True
                blocked_items.append(
                    (item, tuple(rule for _, rule, _ in decided[key].findings)))
            elif item.category == "user_prompt":
                position = locate(item.location)
                if position is not None:
                    safe_user_positions.append(position)
        action = max(actions, key=_RANK.__getitem__, default="ALLOW")
        reason = ("WIRE_PARSE_FAILED" if failed else "REQUIRED_CHECKS_COMPLETE"
                  if action == "ALLOW" else "SENSITIVE_OR_AMBIGUOUS_CONTENT")
        late = not self.capture_only and time.perf_counter() - began > _DECISION_BUDGET_SECONDS
        if late:  # the pipe would block it anyway; record that, not an allow
            action, reason = "BLOCK", _DEADLINE
        # A denied turn must never reach the model. On a later, safe user turn,
        # old blocked items may be replaced in that new request's history. A
        # fresh non-ALLOW item still denies the entire request.
        history_recovery = ((claude_history or (valid_ids and not wire.incremental)) and not self.redact_on_block
                            and action in ("BLOCK", "REVIEW") and not failed and not late
                            and historical_blocked
                            and not fresh_nonallow
                            and all(locate(item.location) is not None
                                    for item, _ in historical_blocked)
                            and any(position > max(historical_boundaries)
                                    for position in safe_user_positions))
        # Redact mode: a BLOCK verdict becomes an allow of the cleaned body.
        # Item-level records keep the BLOCK truth; the envelope carries the
        # cleaned payload for the decision layer. Unresolvable redaction or a
        # payload that still contains blocked item bytes keeps the deny.
        redacted_payload: str | None = None
        if (history_recovery or
                (self.redact_on_block and action == "BLOCK" and not failed and not late
                 and request.protocol == "http")):
            try:
                targets = [(item.location.removesuffix("#base64-decoded"), rules) for item, rules in
                           (historical_blocked if history_recovery else blocked_items)]
                if targets:
                    serialized = redact_raw_json(raw, targets, strings_only=bool(codex))
                    clean_wire, clean_items, clean_failed = self._items(serialized, request.protocol)
                    _, clean_engine = self.gate._prepare()
                    complete_verdict = clean_engine.inspect_text(serialized.decode("utf-8"))
                    if (not clean_failed and clean_wire is not None
                            and (self.allowed_formats is None
                                 or clean_wire.format in self.allowed_formats)
                            and self.gate.actionable(complete_verdict) == "ALLOW"
                            and all(self._decide(item, archive, False, body_receipt).actionable
                                    == "ALLOW" for item in clean_items)):
                        redacted_payload = serialized.decode("utf-8")
            except (KeyError, ValueError, TypeError, UnicodeError):
                redacted_payload = None
        if history_recovery and redacted_payload is not None:
            action, reason = "ALLOW", "HISTORICAL_BLOCK_SCRUBBED"
            if time.perf_counter() - began > _DECISION_BUDGET_SECONDS:
                late, action, reason, redacted_payload = True, "BLOCK", _DEADLINE, None
        records = [self._record(request, result, correlation, action, late)
                   for result in decided.values()]
        if body_receipt is None and self.archive_full_body:
            body_receipt = archive.save("model_request", raw)
        extra = {"items_total": len(items), "items_new": len(decided), "items_cached": cached,
                 "history_scrubbed": bool(history_recovery and redacted_payload is not None),
                 "incremental": bool(wire and wire.incremental),
                 "format": wire.format if wire else "unparsed",
                 "limitations": (wire.limitations if wire else ["wire_parse_failed"])[:64],
                 **({"deadline_exceeded": True} if late else {})}
        if history_recovery and redacted_payload is not None:
            extra["forwarded_body_hmac"] = archive.keyed_digest(redacted_payload.encode("utf-8"))
            extra["history_replacement_count"] = len(historical_blocked)
        envelope = self._envelope(request, raw, archive, body_receipt, correlation, action,
                                  began, extra, late)
        records.append(envelope)
        self.writer.write(records)
        # Cached only once recorded, so a failed write never hides an item later.
        user_positions = [locate(item.location) for item in items
                          if item.category == "user_prompt"]
        known_positions = [position for position in user_positions if position is not None]
        for key, result in decided.items():
            item_position = locate(result.item.location)
            boundary = (max([*known_positions, item_position] if item_position is not None
                            else known_positions, default=None)
                        if result.actionable != "ALLOW" else None)
            cached_item = CachedItem(result.receipt.record_id, result.content_hmac,
                                     result.actionable, request.request_id,
                                     result.item.location, boundary, turn_id)
            self.cache.put(session, key, cached_item)
            if key in delta_keys and result.actionable in ("BLOCK", "REVIEW") and not failed and not late:
                self.cache.put(session, delta_keys[key], cached_item)
            if (claude_history and result.actionable != "ALLOW"
                    and result.item.category in ("user_prompt", "tool_output")
                    and result.item.payload.rstrip(b" \t\r\n") != result.item.payload):
                canonical = replace(result.item,
                                    payload=result.item.payload.rstrip(b" \t\r\n"))
                self.cache.put(session, self._cache_key(canonical), cached_item)
        self.cache.remember_body(session, body_key, action, request.request_id, redacted_payload)
        return CollectionResult(action, reason, records, envelope, redacted_payload)

    def supersede(self, result: CollectionResult, reason: str) -> None:
        """The pipe overrode an allow: record the denial and answer the guard's
        second call on the same body with it."""
        if self.capture_only:
            raise ValueError("capture-only observations cannot be superseded as enforcement")
        envelope = result.envelope
        self.writer.write(supersede(result.records, reason))
        key = envelope["request_sha256"]
        if self.scrub_codex_denied_history:
            key = f"{envelope['protocol']}:{key}"
        self.cache.remember_body(envelope["guard_session_id"], key,
                                 "BLOCK", envelope["request_id"])

    @staticmethod
    def _items(raw: bytes, protocol: str) -> tuple[WireRequest | None, list[CollectedItem], bool]:
        """Items to decide. A delta (`previous_response_id`) carries only new items,
        which are itemized like a full body and flagged incremental on the
        envelope; an unparsed body is one whole-body `unknown` item, plus one item
        per inline base64 payload, which that text omits."""
        try:
            # JSON libraries normally keep the last duplicate key. An earlier
            # shadowed value would still go on the wire but vanish from the
            # itemized view, so reject duplicate keys at every nesting level.
            def unique_pairs(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate JSON key")
                    value[key] = item
                return value

            json.loads(raw, object_pairs_hook=unique_pairs)
            wire = parse_wire_request(raw, protocol=protocol)
        except (ValueError, UnicodeError):
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
        claude_uninspectable = any(rule == "CLAUDE_ATTACHMENT_UNINSPECTABLE"
                                   for _, rule, _ in findings)
        actionable = ("BLOCK" if failed or claude_uninspectable
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
                 capture_only: bool = False, shared_request_archive: bool = False,
                 allowed_formats: frozenset[str] | None = None,
                 scrub_denied_history: bool = False,
                 scrub_codex_denied_history: bool = False):
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
                                                shared_request_archive=shared_request_archive,
                                                allowed_formats=allowed_formats,
                                                redact_on_block=getattr(config, "redact_on_block", False),
                                                scrub_denied_history=scrub_denied_history,
                                                scrub_codex_denied_history=scrub_codex_denied_history)
        self.policy = SimpleNamespace(version=self.collector.policy_version)

    def evaluate(self, request) -> tuple[GuardDecision, dict | None]:
        if self.capture_only:
            raise ValueError("capture_only cannot serve pipe enforcement decisions")
        if request.kind != "model.request":
            return GuardDecision(request_id=request.request_id, decision="allow", action="none",
                                 reason="CONTROL", policy_version=self.policy.version), None
        began = time.perf_counter()
        result = self.collector.collect(request)
        redacted = result.redacted_payload
        # Observe mode allows, except past the deadline, where the pipe blocks anyway.
        # Redact mode allows with the cleaned payload attached.
        allowed = (result.action == "ALLOW"
                   or (self.gate.config.mode == "observe"
                       and result.reason not in (_DEADLINE, "INCOMPLETE_CONTENT"))
                   or redacted is not None)
        if allowed and time.perf_counter() - began > DECISION_DEADLINE_SECONDS:
            allowed, redacted = False, None
            try:  # the rows were written in time, the decision was not
                self.collector.supersede(result, _DEADLINE)
            except Exception:
                pass
            result = replace(result, action="BLOCK", reason=_DEADLINE,
                             envelope={**result.envelope, "route_decision": "deny",
                                       "released_by_route": False,
                                       "extra": {**result.envelope.get("extra", {}),
                                                 "superseded_reason": _DEADLINE}})
        decision = "allow" if allowed else "deny"
        row = {**result.envelope, "decision": decision, "action": result.action,
               "reason": result.reason}
        reason = ("REDACTED_SENSITIVE_CONTENT" if redacted is not None
                  and result.reason != "HISTORICAL_BLOCK_SCRUBBED"
                  else result.reason)[:1023]
        return GuardDecision(request_id=request.request_id, decision=decision,
                             action="none" if allowed else "block_request",
                             reason=reason,
                             policy_version=self.policy.version,
                             redacted_payload=redacted if decision == "allow" else None), row


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
