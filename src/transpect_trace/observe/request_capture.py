"""Versioned request snapshots; never describe request-layer bytes as TLS capture.

TTQ1 is deliberately independent from legacy TTO1 and eCapture ECW2. Each
request is framed on one authenticated pipe connection, with ordered offsets,
an explicit end, process birth and a SHA-256 over the immutable full snapshot.
Plaintext stays in bounded memory; default artifacts contain hashes only.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import threading
from urllib.parse import urlsplit

from .models import BODY_LIMIT, CaptureEvent
from .protocol import Body

REQUEST_HEADER = struct.Struct("<4sIIIQQQQQII")
REQUEST_MAGIC = b"TTQ1"
CHUNK_LIMIT = 65536
FIRST = 256
END = 512


@dataclass(repr=False)
class RequestSnapshot:
    request_id: str
    pid: int
    creation_filetime: int
    tid: int
    protocol: str
    payload: bytes
    qpc: int
    frequency: int
    source: str
    completeness: str = "complete"
    destination: str | None = None


class SnapshotAssembler:
    """One connection carries one request; any framing error quarantines it."""
    def __init__(self, subject, *, frequency, callback, gap):
        self.subject, self.frequency, self.callback, self.gap = subject, frequency, callback, gap
        self.state = None
        self.failed = False
        self.pending = None

    def feed(self, values, digest: bytes, payload: bytes):
        if self.failed:
            return
        magic, pid, tid, direction, request_id, total, offset, birth, qpc, length, flags = values
        protocol = flags & 255
        identity = (pid, birth, tid, request_id, total, qpc, protocol, digest)
        try:
            if self.pending is not None:
                raise ValueError("request_snapshot_data_after_end")
            if (magic != REQUEST_MAGIC or pid != self.subject["pid"] or birth != self.subject["creation_filetime"]
                    or direction != 0 or not request_id or not 0 < total <= BODY_LIMIT or length != len(payload)
                    or not 0 < length <= CHUNK_LIMIT or len(digest) != 32 or protocol not in {16, 32}
                    or flags & ~(255 | FIRST | END)):
                raise ValueError("request_snapshot_invalid_header")
            if self.state is None:
                if not flags & FIRST or offset != 0:
                    raise ValueError("request_snapshot_missing_start")
                self.state = (identity, bytearray())
            elif flags & FIRST:
                raise ValueError("request_snapshot_duplicate_start")
            saved, data = self.state
            if saved != identity or offset != len(data) or offset + length > total:
                raise ValueError("request_snapshot_identity_or_sequence_gap")
            data.extend(payload)
            if flags & END:
                if len(data) != total or hashlib.sha256(data).digest() != digest:
                    raise ValueError("request_snapshot_end_or_digest_mismatch")
                self.pending = RequestSnapshot(str(request_id), pid, birth, tid,
                    "wss" if protocol == 32 else "http", bytes(data), qpc, self.frequency,
                    "ecapture-codex-request/native-observer")
                self.state = None
            elif len(data) == total:
                raise ValueError("request_snapshot_missing_end")
        except ValueError as error:
            self.failed = True
            self.state = None
            self.gap(str(error))

    def finish(self, *, clean_eof=True):
        if self.pending is not None:
            pending,self.pending=self.pending,None
            if not clean_eof or self.failed:
                self.gap("request_snapshot_connection_end_unconfirmed")
            else:
                self.callback(pending)
        if self.state is not None:
            self.state = None
            self.failed = True
            self.gap("request_snapshot_connection_ended_incomplete")
        self.failed=True


class RequestCaptureSink:
    """Feed full request-layer snapshots into existing Observe normalization."""
    def __init__(self, pipeline, subject):
        self.pipeline, self.subject = pipeline, subject
        self.completed = 0

    def gap(self, reason):
        row = dict(kind="coverage_gap", provider="ecapture-codex-request", capture_layer="request-body",
            pid=self.subject["pid"], creation_filetime=self.subject["creation_filetime"],
            connection_id="unknown", reason=reason, can_enforce=False)
        self.pipeline.gaps.append(row)
        self.pipeline.write("coverage-gaps.jsonl", row)

    def __call__(self, snapshot):
        from .semantics import from_unified
        from .unified import normalize
        if snapshot.pid != self.subject["pid"] or snapshot.creation_filetime != self.subject["creation_filetime"]:
            self.gap("request_snapshot_process_identity_mismatch")
            return
        if len(self.pipeline.rows) >= 10000:
            self.gap("request_snapshot_observation_count_limit")
            return
        event = CaptureEvent(provider="native-observer", capture_point="wss-message" if snapshot.protocol == "wss" else "http-body",
            pid=snapshot.pid, creation_filetime=snapshot.creation_filetime, tid=snapshot.tid,
            connection_id="request:" + snapshot.request_id, direction="send", sequence=1,
            connection_identity="unknown",
            captured_qpc=snapshot.qpc, qpc_frequency=snapshot.frequency, application="codex-cli",
            image_sha256=self.subject.get("image_sha256"), truncated=snapshot.completeness == "partial")
        headers = {"content-type": "application/json"}
        if snapshot.destination:
            try:
                target = urlsplit(snapshot.destination)
                if target.hostname and not target.username and not target.password:
                    headers[":authority"] = target.hostname + (":" + str(target.port) if target.port else "")
                    headers[":path"] = target.path
            except ValueError:
                pass
        body = Body(snapshot.payload, headers, "wss" if snapshot.protocol == "wss" else "http-json",
                    limitations=[] if snapshot.completeness == "complete" else ["request_snapshot_not_complete"])
        observation, risk = self.pipeline.assessor.assess(event, body)
        observation.provider = snapshot.source
        unified = normalize(event, body, observation)
        unified.capture_source = snapshot.source
        # TTQ1 proves the request boundary, not a socket/connection mapping.
        # Keep the unknown connection limitation while reporting the separately
        # verified snapshot completeness and classifying only that snapshot.
        unified.completeness = snapshot.completeness
        from .classification import classify
        try:
            import json
            parsed=json.loads(snapshot.payload.decode('utf-8'))
            unified.classification=classify(observation.observation_id,parsed,headers,'codex-cli',
                complete=snapshot.completeness=='complete',decoded=True,empty=not snapshot.payload)
        except (ValueError,UnicodeError,RecursionError):
            pass
        semantics = from_unified(unified, body.data, "identity")
        self.pipeline.rows.append(observation.model_dump())
        self.pipeline.assessments.append(risk.model_dump())
        for name, row in (("observations.jsonl", observation.model_dump()), ("assessments.jsonl", risk.model_dump()),
                ("unified-requests.jsonl", unified.model_dump()), ("classifications.jsonl", unified.classification.model_dump()),
                ("request-semantics.jsonl", semantics.model_dump())):
            self.pipeline.write(name, row)
        self.pipeline.write("request-snapshots.jsonl", dict(schema_version="transpect.observe.request-snapshot/1.0",
            request_id=snapshot.request_id, observation_id=observation.observation_id, pid=snapshot.pid,
            creation_filetime=snapshot.creation_filetime, capture_source=snapshot.source, capture_layer="request-body",
            protocol=snapshot.protocol, payload_bytes=len(snapshot.payload), payload_sha256=hashlib.sha256(snapshot.payload).hexdigest(),
            network_connection_identity="unknown",
            completeness=snapshot.completeness, boundary_evidence="versioned_immutable_request_snapshot",
            send_evidence="constructed", can_enforce=False))
        if self.pipeline.semantic_sink:
            self.pipeline.semantic_sink(semantics)
        self.completed += 1


class GuardRequestTap:
    """Best-effort observation tap; its failure cannot change Guard decisions.

The caller may execute this synchronously before policy evaluation. It only
copies/queues a bounded immutable UTF-8 snapshot; parsing and persistence run
on an independent worker. No second Native Hook is installed.
"""
    def __init__(self, directory: Path, subject, policy=None, *, pipeline=None,
                 queue_limit_bytes=32 * 1024 * 1024, semantic_sink=None):
        from .pipeline import Pipeline
        from transpect_trace.guard.policy import GuardPolicy
        if not BODY_LIMIT <= queue_limit_bytes <= 64 * 1024 * 1024:
            raise ValueError("request tap queue must be bounded between 16 and 64 MiB")
        self.directory, self.subject = Path(directory), subject
        self.pipeline = pipeline or Pipeline(self.directory, policy or GuardPolicy(), semantic_sink=semantic_sink)
        self.sink = RequestCaptureSink(self.pipeline, subject)
        self.limit, self.queued, self.queue = queue_limit_bytes, 0, deque()
        self.condition = threading.Condition()
        self.closed = False
        self.errors = []
        self.dropped = 0
        self.worker = threading.Thread(target=self._work, name="codex-request-capture", daemon=True)
        self.worker.start()
        self.pipeline.write("capture-health.jsonl", self.status())

    def __call__(self, request):
        try:
            if request.kind != "model.request":
                return
            if request.pid != self.subject["pid"]:
                raise ValueError("request_tap_identity_mismatch")
            if len(request.payload_utf8) > BODY_LIMIT:
                raise ValueError("request_tap_body_limit")
            data = request.payload_utf8.encode("utf-8")
            if not data or len(data) > BODY_LIMIT:
                raise ValueError("request_tap_body_limit")
            snapshot = RequestSnapshot(request.request_id, request.pid, self.subject["creation_filetime"],
                request.tid, request.protocol, data, request.captured_qpc or 0,
                request.qpc_frequency or 1, "ecapture-codex-request/native-guard-tap",
                request.completeness, request.destination)
            with self.condition:
                if self.closed or self.queued + len(data) > self.limit or len(self.queue) >= 128:
                    self.dropped += 1
                    return
                self.queue.append(snapshot)
                self.queued += len(data)
                self.condition.notify()
        except Exception:
            with self.condition:
                self.dropped += 1

    def _work(self):
        while True:
            with self.condition:
                self.condition.wait_for(lambda: self.queue or self.closed)
                if not self.queue:
                    return
                snapshot = self.queue.popleft()
            try:
                self.sink(snapshot)
            except Exception:
                self.errors.append("request_tap_processing_failure")
            finally:
                with self.condition:
                    self.queued -= len(snapshot.payload)

    def status(self):
        return dict(adapter="codex-request", capture_layer="request-body", hook_owner="native-guard",
            state="degraded" if self.errors or self.dropped else "stopped" if self.closed else "observing",
            observed_requests=self.sink.completed, dropped_snapshots=self.dropped,
            errors=sorted(set(self.errors)), terminal_health=self.closed and not self.worker.is_alive(),
            can_enforce=False, tls_plaintext_capture=False,
            assessment_authority='observation_only; execution verdict is in Guard audit')

    def check_health(self):
        if self.errors or self.dropped or (not self.closed and not self.worker.is_alive()):
            raise RuntimeError("Codex request observation degraded")

    def close(self):
        with self.condition:
            if self.closed:
                return
            self.closed = True
            self.condition.notify_all()
        self.worker.join(timeout=10)
        if self.worker.is_alive():
            self.errors.append("request_tap_shutdown_unconfirmed")
            return
        if self.dropped:
            self.sink.gap("request_tap_queue_loss_or_invalid_snapshot")
        if self.errors:
            self.sink.gap("request_tap_processing_failure")
        self.pipeline.write("capture-health.jsonl", self.status())
        self.pipeline.finish()
