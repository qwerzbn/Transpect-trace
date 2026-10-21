import hashlib
import json
import threading
from types import SimpleNamespace

import pytest

from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.policy import GuardPolicy, GuardRequest
from transpect_trace.observe.adapters import capability, create_collector
from transpect_trace.observe.pipeline import Pipeline
from transpect_trace.observe.request_capture import (
    BODY_LIMIT, CHUNK_LIMIT, END, FIRST, GuardRequestTap, RequestCaptureSink,
    SnapshotAssembler,
)


SUBJECT = dict(pid=42, creation_filetime=123, image_sha256=BINARY_SHA256)


def chunks(body, **changes):
    digest = hashlib.sha256(body).digest()
    for offset in range(0, len(body), CHUNK_LIMIT):
        payload = body[offset:offset+CHUNK_LIMIT]
        flags = 16 | (FIRST if offset == 0 else 0) | (END if offset+len(payload) == len(body) else 0)
        fields = dict(magic=b"TTQ1", pid=42, tid=4, direction=0, request_id=1,
            total=len(body), offset=offset, birth=123, qpc=55, length=len(payload), flags=flags)
        fields.update(changes)
        yield tuple(fields.values()), digest, payload


def test_one_mib_native_snapshot_is_complete_without_persisting_plaintext(tmp_path):
    body = json.dumps(dict(model="fixture", input="fake-private-marker-" + "中" * 400000,
        instructions="context", tools=[dict(type="function", name="not_a_call")]), ensure_ascii=False).encode()
    assert len(body) > 1024 * 1024
    pipeline = Pipeline(tmp_path, GuardPolicy())
    sink = RequestCaptureSink(pipeline, SUBJECT)
    assembler = SnapshotAssembler(SUBJECT, frequency=1000, callback=sink, gap=sink.gap)
    for frame in chunks(body):
        assembler.feed(*frame)
    assembler.finish()
    assert not pipeline.gaps and sink.completed == 1
    row = json.loads((tmp_path / "unified-requests.jsonl").read_text())
    assert row["completeness"] == "complete"
    assert row["raw_payload_bytes"] == len(body)
    assert row["raw_payload_sha256"] == hashlib.sha256(body).hexdigest()
    assert row["transport_protocol"] == "unknown" and row["capture_point"] == "http-body"
    assert "native-observer" in row["capture_source"] and "ecapture-codex-request" in row["capture_source"]
    assert "fake-private-marker-" not in "".join(p.read_text() for p in tmp_path.glob("*.jsonl"))
    assert "tool_call" not in {f["kind"] for f in row["fields"]}


@pytest.mark.parametrize("fault", ["duplicate", "missing", "reorder", "digest", "identity", "overflow", "no-end", "after-end"])
def test_snapshot_gaps_never_produce_complete_requests(fault):
    body = b"x" * (CHUNK_LIMIT * 2 + 10)
    frames = list(chunks(body))
    if fault == "duplicate": frames.insert(1, frames[0])
    if fault == "missing": del frames[1]
    if fault == "reorder": frames.reverse()
    if fault == "digest": frames[-1] = (frames[-1][0], b"\0" * 32, frames[-1][2])
    if fault == "identity": frames = list(chunks(body, birth=456))
    if fault == "overflow": frames = list(chunks(body, total=BODY_LIMIT+1))
    if fault == "no-end": frames = frames[:-1]
    if fault == "after-end": frames.append(frames[-1])
    results, gaps = [], []
    assembler = SnapshotAssembler(SUBJECT, frequency=1000, callback=results.append, gap=gaps.append)
    for frame in frames: assembler.feed(*frame)
    assembler.finish()
    assert not results and gaps


def test_snapshot_complete_end_requires_verified_connection_eof():
    results,gaps=[],[]
    assembler=SnapshotAssembler(SUBJECT,frequency=1000,callback=results.append,gap=gaps.append)
    for frame in chunks(b'{}'):assembler.feed(*frame)
    assert not results
    assembler.finish(clean_eof=False)
    assert not results and gaps==['request_snapshot_connection_end_unconfirmed']


def request(**changes):
    fields = dict(schema="transpect.guard.request/1.0", request_id="r", guard_session_id="s",
        pid=42, tid=4, kind="model.request", protocol="http", completeness="complete",
        payload_utf8='{"model":"fixture","input":"private-test-marker"}', captured_qpc=55, qpc_frequency=1000)
    fields.update(changes)
    return GuardRequest.model_validate(fields)


def test_guard_tap_reuses_same_snapshot_and_preserves_real_provenance(tmp_path):
    tap = GuardRequestTap(tmp_path, SUBJECT)
    tap(request())
    tap.close()
    assert tap.status()["terminal_health"] and tap.status()["observed_requests"] == 1
    assert not tap.status()["tls_plaintext_capture"] and not tap.status()["can_enforce"]
    row = json.loads((tmp_path / "request-snapshots.jsonl").read_text())
    assert row["capture_layer"] == "request-body" and row["send_evidence"] == "constructed"
    assert row["payload_sha256"] == hashlib.sha256(request().payload_utf8.encode()).hexdigest()
    assert "private-test-marker" not in "".join(p.read_text() for p in tmp_path.glob("*.jsonl"))


def test_tap_errors_are_observation_gaps_and_never_escape_guard_caller(tmp_path):
    tap = GuardRequestTap(tmp_path, SUBJECT)
    tap(request(pid=999))
    tap.close()
    assert tap.status()["state"] == "degraded"
    assert tap.status()["dropped_snapshots"] == 1
    with pytest.raises(RuntimeError): tap.check_health()
    assert "request_tap_queue_loss_or_invalid_snapshot" in (tmp_path / "coverage-gaps.jsonl").read_text()


def test_snapshot_accepts_exact_sixteen_mib_and_releases_buffer():
    body = b"x" * BODY_LIMIT
    results, gaps = [], []
    assembler = SnapshotAssembler(SUBJECT, frequency=1000, callback=results.append, gap=gaps.append)
    for frame in chunks(body): assembler.feed(*frame)
    assembler.finish()
    assert not gaps and len(results) == 1 and results[0].payload == body and assembler.state is None


def test_guard_tap_queue_counts_active_snapshot_and_drops_without_blocking(tmp_path):
    tap = GuardRequestTap(tmp_path, SUBJECT, queue_limit_bytes=BODY_LIMIT)
    entered, release = threading.Event(), threading.Event()
    original = tap.sink
    class SlowSink:
        completed = 0
        def __call__(self, snapshot):
            entered.set()
            assert release.wait(5)
            original(snapshot)
            self.completed += 1
        def gap(self, reason): original.gap(reason)
    tap.sink = SlowSink()
    body = json.dumps(dict(input="x" * (9*1024*1024)))
    tap(request(payload_utf8=body))
    assert entered.wait(2)
    tap(request(payload_utf8=body, request_id="second"))
    assert tap.dropped == 1 and tap.queued == len(body)
    release.set(); tap.close()
    assert tap.status()["observed_requests"] == 1
    assert tap.status()["state"] == "degraded"


def test_ecapture_routing_does_not_certify_codex_tls_or_install_second_hook(tmp_path):
    assert capability("schannel")["tls_plaintext_capture"]
    assert not capability("codex-request", protection=True)["tls_plaintext_capture"]
    pipeline = Pipeline(tmp_path, GuardPolicy())
    profile = SimpleNamespace(application="codex-cli", mode="codex-json")
    tap = create_collector("codex-request", SUBJECT, profile, pipeline=pipeline, protection=True)
    assert isinstance(tap, GuardRequestTap)
    tap.close()
    with pytest.raises(ValueError):
        create_collector("codex-request", {**SUBJECT, "image_sha256":"a"*64}, profile,
                         pipeline=pipeline, protection=True)
