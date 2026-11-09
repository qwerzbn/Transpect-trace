"""Test-only thread scope must not inspect or archive other chats."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import threading
import ctypes
from ctypes import wintypes
import struct

import transpect_trace.guard.pipe as pipe_module

from transpect_trace.guard.pipe import PipeServer, SecurityAttributes, _wire_thread_ids
from transpect_trace.guard.policy import GuardDecision, GuardRequest


TARGET = "01a1b9f0-f1d8-7f82-af4e-2e437f6c605a"
OTHER = "01a1b9ea-610e-79a1-ae74-0de36c1a71fa"
CACHE = "01a1b6d5-e9c5-7d01-b983-5630a1bae1bf"


def _request(body: str, *, request_id: str = "1234-3") -> GuardRequest:
    return GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": request_id,
        "guard_session_id": "1234-42", "pid": 1234, "tid": 7,
        "kind": "model.request", "protocol": "http", "destination": None,
        "completeness": "complete", "payload_utf8": body})


def _server(tmp_path: Path, target: str | None = TARGET):
    server = object.__new__(PipeServer)
    calls = []

    def evaluate(request):
        calls.append(request.request_id)
        return (GuardDecision(request_id=request.request_id, decision="deny",
                              action="block_request", reason="TEST_DENY",
                              policy_version="test/1"), None)

    server.engine = SimpleNamespace(policy=SimpleNamespace(version="test/1"),
                                    evaluate=evaluate)
    server.lock = threading.Lock()
    server.scope_lock = threading.Lock()
    server.scope_counts = {"target": 0, "bypassed": 0,
                           "unidentified_scope_bypass": 0}
    server.decision_delivery = []
    server.pending_outcomes = {}
    server.target_thread_id = target
    server.audit = tmp_path / "audit.jsonl"
    server.records = []
    server.errors = []
    server.validation_error_count = 0
    server.validation_errors = []
    return server, calls


def test_target_thread_is_normalized_and_inspected(tmp_path):
    server, calls = _server(tmp_path)
    body = json.dumps({"client_metadata": {"thread_id": TARGET.upper()},
                       "prompt_cache_key": CACHE, "input": "normal"})
    assert _wire_thread_ids(body) == frozenset({TARGET})
    decision, row = server._evaluate_request(_request(body))
    assert decision.decision == "deny" and row is None
    assert calls == ["1234-3"]
    assert server.scope_counts == {"target": 1, "bypassed": 0,
                                   "unidentified_scope_bypass": 0}


def test_other_thread_large_request_bypasses_engine_and_held_lock(tmp_path):
    server, calls = _server(tmp_path)
    body = json.dumps({"client_metadata": {"thread_id": OTHER},
                       "prompt_cache_key": CACHE,
                       "input": [{"text": "x" * 1800} for _ in range(530)]})
    assert len(body) > 950_000
    result = []
    server.lock.acquire()
    try:
        worker = threading.Thread(
            target=lambda: result.append(server._evaluate_request(_request(body))),
            daemon=True)
        worker.start()
        worker.join(timeout=2)
        assert not worker.is_alive(), "non-target chat waited for the policy lock"
    finally:
        server.lock.release()
    decision, row = result[0]
    assert decision.decision == "allow" and decision.action == "none"
    assert row is None and calls == []
    assert not server.audit.exists()
    assert server.scope_counts == {"target": 0, "bypassed": 1,
                                   "unidentified_scope_bypass": 0}


def test_unidentified_payload_passes_without_collection(tmp_path):
    server, calls = _server(tmp_path)
    for index, body in enumerate(("{", json.dumps({"client_metadata": {"thread_id": "bad"}}))):
        decision, row = server._evaluate_request(_request(body, request_id=f"1234-{index}"))
        assert decision.decision == "allow" and row is None
    assert calls == [] and not server.audit.exists()
    assert server.scope_counts == {"target": 0, "bypassed": 0,
                                   "unidentified_scope_bypass": 2}


def test_prompt_cache_key_alone_is_not_a_thread_identity(tmp_path):
    server, calls = _server(tmp_path)
    body = json.dumps({"prompt_cache_key": TARGET, "input": []})
    decision, _ = server._evaluate_request(_request(body))
    assert decision.decision == "allow" and calls == []
    assert server.scope_counts["unidentified_scope_bypass"] == 1


def test_explicit_other_thread_wins_over_matching_session_key(tmp_path):
    server, calls = _server(tmp_path)
    body = json.dumps({"client_metadata": {"thread_id": OTHER},
                       "prompt_cache_key": TARGET, "input": []})
    decision, _ = server._evaluate_request(_request(body))
    assert decision.decision == "allow" and calls == []


def test_unscoped_server_preserves_engine_path(tmp_path):
    server, calls = _server(tmp_path, target=None)
    decision, _ = server._evaluate_request(_request("{}"))
    assert decision.decision == "deny" and calls == ["1234-3"]


def test_concurrent_safe_engine_does_not_serialize_inspection(tmp_path):
    server, _ = _server(tmp_path, target=None)
    slow_entered, release_slow, fast_entered = (threading.Event() for _ in range(3))

    def evaluate(request):
        if request.request_id == "1234-1":
            slow_entered.set()
            assert release_slow.wait(1)
        else:
            fast_entered.set()
        return (GuardDecision(request_id=request.request_id, decision="allow",
                              action="none", reason="TEST_ALLOW",
                              policy_version="test/1"), None)

    server.engine = SimpleNamespace(policy=SimpleNamespace(version="test/1"),
                                    evaluate=evaluate, concurrent_safe=True)
    results = {}
    slow = threading.Thread(target=lambda: results.update(
        slow=server._evaluate_request(_request("{}", request_id="1234-1"))))
    fast = threading.Thread(target=lambda: results.update(
        fast=server._evaluate_request(_request("{}", request_id="1234-2"))))
    slow.start()
    try:
        assert slow_entered.wait(1)
        fast.start()
        assert fast_entered.wait(0.5), "fast request waited for slow inspection"
        fast.join(timeout=0.5)
        assert not fast.is_alive()
        assert results["fast"][0].decision == "allow"
    finally:
        release_slow.set()
        slow.join(timeout=1)
        if fast.ident is not None:
            fast.join(timeout=1)
    assert not slow.is_alive() and not fast.is_alive()


def test_generic_engine_keeps_serialized_session_state(tmp_path):
    server, _ = _server(tmp_path, target=None)
    slow_entered, release_slow, fast_entered = (threading.Event() for _ in range(3))

    def evaluate(request):
        if request.request_id == "1234-1":
            slow_entered.set()
            assert release_slow.wait(1)
        else:
            fast_entered.set()
        return (GuardDecision(request_id=request.request_id, decision="allow",
                              action="none", reason="TEST_ALLOW",
                              policy_version="test/1"), None)

    server.engine.evaluate = evaluate
    slow = threading.Thread(target=lambda: server._evaluate_request(
        _request("{}", request_id="1234-1")))
    fast = threading.Thread(target=lambda: server._evaluate_request(
        _request("{}", request_id="1234-2")))
    slow.start()
    try:
        assert slow_entered.wait(1)
        fast.start()
        assert not fast_entered.wait(0.05)
    finally:
        release_slow.set()
        slow.join(timeout=1)
        if fast.ident is not None:
            fast.join(timeout=1)
    assert not slow.is_alive() and not fast.is_alive()
    assert fast_entered.is_set()


def _wire_frame(kind: str, *, request_id: str, protocol: str = "control",
                action: str = "none", outcome_for: str = "") -> bytes:
    return json.dumps({
        "schema": "transpect.guard.request/1.0", "request_id": request_id,
        "guard_session_id": "1234-42", "pid": 1234, "tid": 7,
        "kind": kind, "protocol": protocol, "destination": None,
        "completeness": "complete", "payload_utf8": "" if kind != "model.request"
        else json.dumps({"client_metadata": {"thread_id": OTHER}}),
        "outcome_action": action,
        "outcome_for_request_id": outcome_for,
    }).encode()


def _serve_frames(server: PipeServer, frames: list[bytes]) -> list[bytes]:
    """Exercise the pipe loop without opening a process or named pipe."""
    writes = []

    class Kernel:
        def CreateNamedPipeW(self, *args):
            return 1

        def ConnectNamedPipe(self, *args):
            return True

        def GetNamedPipeClientProcessId(self, handle, output):
            ctypes.cast(output, ctypes.POINTER(wintypes.ULONG)).contents.value = 1234
            return True

        def WriteFile(self, handle, data, length, output, overlap):
            writes.append(bytes(data[:length]))
            ctypes.cast(output, ctypes.POINTER(wintypes.DWORD)).contents.value = length
            return True

        def FlushFileBuffers(self, *args):
            return True

        def DisconnectNamedPipe(self, *args):
            return True

        def CloseHandle(self, *args):
            return True

    server.k = Kernel()
    server.name = "isolated-fake-pipe"
    server.pid = 1234
    server.workers = 1
    server.stop = threading.Event()
    server.listening = threading.Event()
    server.security = SecurityAttributes()
    server.request_tap = None
    chunks = iter(chunk for frame in frames
                  for chunk in (struct.pack("<I", len(frame)), frame))

    def read(handle, size):
        chunk = next(chunks)
        assert len(chunk) == size
        if chunk is frames[-1]:
            server.stop.set()
        return chunk

    server._read = read
    server._serve()
    assert server.listening.is_set()
    return writes


def test_malformed_outcome_is_diagnostic_and_later_model_request_is_allowed(tmp_path):
    server, calls = _server(tmp_path)
    first = _wire_frame("model.request", request_id="1234-1", protocol="http")
    malformed = _wire_frame("native.outcome", request_id="1234-2", action="invalid",
                            outcome_for="1234-1")
    last = _wire_frame("model.request", request_id="1234-3", protocol="http")
    writes = _serve_frames(server, [first, malformed, last])
    assert len(writes) == 2  # malformed telemetry receives no decision
    assert server.scope_counts["bypassed"] == 2
    assert calls == [] and server.errors == []
    assert server.validation_snapshot() == {
        "count": 1, "recent": [{"kind_hint": "native.outcome",
                              "frame_bytes": len(malformed),
                              "issues": [{"field": "outcome_action",
                                          "type": "literal_error"}]}]}
    delivery = server.decision_delivery_snapshot()
    assert [item["request_id"] for item in delivery] == ["1234-1", "1234-3"]
    assert delivery[0]["decision"] == "allow"
    assert delivery[0]["server_reply_write_complete"] is True
    assert delivery[0]["native_outcome_action"] == "invalid_outcome_frame"
    assert delivery[0]["native_acceptance_attested"] is False
    assert OTHER not in json.dumps(delivery)
    assert not server.audit.exists()


def test_bypassed_allow_and_valid_native_deny_are_separately_visible(tmp_path):
    server, calls = _server(tmp_path)
    model = _wire_frame("model.request", request_id="1234-1", protocol="http")
    outcome = _wire_frame("native.outcome", request_id="1234-2",
                          action="block_request", outcome_for="1234-1")
    writes = _serve_frames(server, [model, outcome])
    assert len(writes) == 2 and calls == ["1234-2"] and server.errors == []
    trace, = server.decision_delivery_snapshot()
    assert trace["decision"] == "allow"
    assert trace["server_reply_write_complete"] is True
    assert trace["native_outcome_action"] == "block_request"
    assert trace["native_acceptance_attested"] is False


def test_server_delivery_timing_uses_native_qpc_without_claiming_ack(
        tmp_path, monkeypatch):
    server, _ = _server(tmp_path)
    frame = json.loads(_wire_frame("model.request", request_id="1234-1",
                                   protocol="http"))
    frame["captured_qpc"] = 1000
    frame["qpc_frequency"] = 1000
    samples = iter((1010, 1020, 1030))
    monkeypatch.setattr(pipe_module, "_qpc_now", lambda: next(samples))
    _serve_frames(server, [json.dumps(frame).encode()])
    trace, = server.decision_delivery_snapshot()
    assert (trace["age_at_frame_read_ms"], trace["age_at_decision_ms"],
            trace["age_at_reply_write_ms"]) == (10, 20, 30)
    assert trace["server_reply_write_complete"] is True
    assert trace["server_flush_complete"] is True
    assert trace["native_acceptance_attested"] is False


def test_outcome_before_delivery_is_correlated_and_requires_parsed_allow(tmp_path):
    server, _ = _server(tmp_path, target=None)
    request = _request("{}", request_id="1234-1")
    decision = GuardDecision(request_id="1234-1", decision="allow",
                             action="none", reason="TEST_ALLOW", policy_version="test/1")
    server._note_native_outcome("1234-1", "none", valid_frame=True,
                                stage="parsed_allow")
    assert "1234-1" in server.pending_outcomes
    server._record_decision_delivery(request, decision, 100, None, None, None,
                                     True, True)
    trace, = server.decision_delivery_snapshot()
    assert trace["native_acceptance_attested"] is True
    assert trace["native_diagnostic_stage"] == "parsed_allow"
    assert server.pending_outcomes == {}

    server._note_native_outcome("1234-1", "none", valid_frame=True,
                                stage="io_failed")
    assert server.decision_delivery_snapshot()[0]["native_acceptance_attested"] is False
    server._note_native_outcome("1234-1", "none", valid_frame=True)
    assert server.decision_delivery_snapshot()[0]["native_acceptance_attested"] is False


def test_unmatched_outcomes_are_bounded(tmp_path):
    server, _ = _server(tmp_path, target=None)
    for number in range(100):
        server._note_native_outcome(f"1234-{number}", "none", valid_frame=True,
                                    stage="parsed_allow")
    assert len(server.pending_outcomes) == 64
    assert "1234-0" not in server.pending_outcomes
    assert "1234-99" in server.pending_outcomes


def test_malformed_model_frame_gets_no_allow_reply_and_server_continues(tmp_path):
    server, calls = _server(tmp_path)
    malformed = _wire_frame("model.request", request_id="1234-1",
                            protocol="control")
    valid = _wire_frame("model.request", request_id="1234-2", protocol="http")
    writes = _serve_frames(server, [malformed, valid])
    assert len(writes) == 1  # no reply means the Native caller blocks the bad request
    assert server.scope_counts["bypassed"] == 1
    assert calls == [] and server.errors == []
    snapshot = server.validation_snapshot()
    assert snapshot["count"] == 1
    assert snapshot["recent"][0]["kind_hint"] == "model.request"
    assert snapshot["recent"][0]["issues"][0]["type"] == "value_error"
