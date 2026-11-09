"""The route comparison is judged against origin bytes, joined without plaintext."""
import hashlib
import hmac
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from transpect_trace.protect import collection
from transpect_trace.protect import collection_eval as ev
from transpect_trace.protect.archive import ArchiveReceipt
from transpect_trace.protect.collection import CollectedItem

FAKE_KEY = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
MARKER = "TTRACE_SYNTHETIC_MARKER_5521"
PROMPT = "summarize the project"


class FakeArchive:
    """Keyed digests and decryption without DPAPI; one key per route."""

    def __init__(self, key: bytes = b"route-key", payloads: dict | None = None):
        self.key, self.payloads = key, payloads or {}

    def keyed_digest(self, data: bytes) -> str:
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def read(self, record_id: str):
        if record_id not in self.payloads:
            raise ValueError("unknown record")
        payload = self.payloads[record_id]
        receipt = ArchiveReceipt(record_id, "model_request", hashlib.sha256(payload).hexdigest(),
                                 len(payload), "2026-11-06T00:00:00+00:00")
        return receipt, payload


def _row(category, *, route="hook", decision="allow", record_id="1" * 32, match=None,
         call_id=None, session="s-1", turn="t-1", kind="content"):
    receipt = (ArchiveReceipt(record_id, "model_request", "a" * 64, 10, "2026-11-06T00:00:00+00:00")
               if record_id and kind == "content" else None)
    return collection.build_record(
        route=route, route_event="UserPromptSubmit" if route == "hook" else "model.request",
        protocol="hook" if route == "hook" else "http", category=category, location="loc",
        collection=kind, receipt=receipt, content_hmac="0" * 64 if receipt else None,
        match_hmac=match, inspected=True, decision_point="before_upstream", verdict=None,
        actionable="ALLOW" if decision != "deny" else "BLOCK", route_decision=decision,
        released_by_route=decision != "deny",
        correlation={"session_id": session, "turn_id": turn, "call_id": call_id},
        policy_version="p", gate_mode="enforce", elapsed_ms=1.0)


def _item(category, text, call_id=None):
    return CollectedItem(category, "/input/0", text.encode(), text, text, call_id=call_id)


@pytest.fixture
def fake_wire(monkeypatch):
    """Stand-in for WP1's wire parser: one item per JSON body field."""
    calls = []

    def parse_wire_request(raw, *, protocol):
        calls.append(protocol)
        body = json.loads(raw)
        items = [_item(category, text) for category, text in body["items"]]
        return SimpleNamespace(items=items, correlation={"turn_id": body.get("turn")})

    module = ModuleType("transpect_trace.protect.wire_items")
    module.parse_wire_request = parse_wire_request
    monkeypatch.setitem(sys.modules, "transpect_trace.protect.wire_items", module)
    return calls


def _body(*items, turn="t-1"):
    return json.dumps({"items": [list(item) for item in items], "turn": turn}).encode()


def test_ground_truth_uses_wire_parser(fake_wire):
    bodies = [_body(("user_prompt", PROMPT)),
              _body(("user_prompt", PROMPT), ("tool_output", MARKER), turn="t-2")]
    items = ev.ground_truth(bodies)
    assert fake_wire == ["http", "http"]
    assert [(item.category, item.inspect_text) for item in items] == [
        ("user_prompt", PROMPT), ("tool_output", MARKER)]  # repeated history counted once
    assert ev.origin_turns(bodies) == {"t-1", "t-2"}


def test_cell_collected_by_digest_under_the_routes_own_key():
    archive = FakeArchive()
    gt = [_item("user_prompt", PROMPT)]
    row = _row("user_prompt", match=archive.keyed_digest(PROMPT.encode()))
    found = ev.assess("user_prompt", [row], gt, {}, archive, b"", turns=frozenset({"t-1"}))
    assert found == {"cell": "COLLECTED_RELEASED", "match_quality": "id_and_digest",
                     "leaked": False, "records": 1}
    # The other route's key yields a different digest: no match, so not collected.
    assert ev.cell("user_prompt", [row], gt, {}, FakeArchive(b"other"), b"") == "NOT_COLLECTED"


def test_cell_leaked_when_planted_token_at_origin():
    archive = FakeArchive(payloads={"1" * 32: f"deploy with {FAKE_KEY}".encode()})
    planted = {"user_prompt": FAKE_KEY.encode()}
    blob = ev.origin_bytes([json.dumps({"input": f"deploy with {FAKE_KEY}"}).encode()])
    found = ev.assess("user_prompt", [_row("user_prompt")], [], planted, archive, blob)
    assert (found["cell"], found["match_quality"], found["leaked"]) == (
        "COLLECTED_LEAKED", "planted", True)
    # A benign control's token is expected upstream: proof of collection, not a leak.
    assert ev.cell("user_prompt", [_row("user_prompt")], [], planted, archive, blob,
                   sensitive=False) == "COLLECTED_RELEASED"


def test_token_inside_an_image_counts_as_reaching_origin():
    import base64
    png = b"\x89PNG" + MARKER.encode()
    body = json.dumps({"output": [{"image_url": "data:image/png;base64,"
                                   + base64.b64encode(png).decode()}]}).encode()
    assert MARKER.encode() not in body
    assert MARKER.encode() in ev.origin_bytes([body])


def test_cell_blocked_when_denied_and_absent():
    archive = FakeArchive(payloads={"1" * 32: FAKE_KEY.encode()})
    rows = [_row("tool_output", decision="deny")]
    assert ev.cell("tool_output", rows, [], {"tool_output": FAKE_KEY.encode()}, archive,
                   b"nothing sensitive") == "COLLECTED_BLOCKED"


def test_shared_item_does_not_claim_token_only_present_elsewhere_in_request():
    from transpect_trace.protect.native_collection import NativeRequestCollector

    body = json.loads((Path(__file__).parent / "fixtures/codex_collection/http_turn1.json")
                      .read_text(encoding="utf-8"))
    body["input"][2]["content"][0]["text"] += "\nSynthetic secret " + FAKE_KEY
    raw = json.dumps(body).encode()
    archive_id = "a" * 32
    archive = FakeArchive(payloads={archive_id: raw})
    _, items, failed = NativeRequestCollector._items(raw, "http")
    assert not failed
    prompt = next(item for item in items if item.category == "user_prompt")
    row = _row("user_prompt", route="native", record_id=archive_id)
    row.update(location=prompt.location, content_bytes=len(prompt.payload),
               content_hmac=archive.keyed_digest(prompt.payload),
               request_sha256=hashlib.sha256(raw).hexdigest(),
               extra={"shared_request_archive": True})
    collection.validate_record(row)
    assert ev._archived_contains(archive, row, prompt.payload)
    assert not ev._archived_contains(archive, row, FAKE_KEY.encode())
    assert ev.cell("user_prompt", [row], [], {"user_prompt": FAKE_KEY.encode()},
                   archive, b"") == "NOT_COLLECTED"


def test_hook_cannot_cover_client_instructions_cell():
    planted = {"client_instructions": FAKE_KEY.encode()}
    gt = [_item("client_instructions", f"# AGENTS.md instructions for x\n{FAKE_KEY}"),
          _item("user_prompt", PROMPT)]
    hook_rows = [_row("user_prompt")]
    found = ev.assess("client_instructions", hook_rows, gt, planted, FakeArchive(),
                      FAKE_KEY.encode())
    assert found["cell"] == "NOT_COLLECTED" and found["leaked"] is True
    assert ev.cell("tool_definitions", hook_rows, [], {}, FakeArchive(), b"") == "NOT_APPLICABLE"
    assert ev.cell("user_attachment", [_row("user_attachment", kind="metadata_only")], [], {},
                   FakeArchive(), b"") == "METADATA_ONLY"


def test_tool_rows_join_by_call_id_when_texts_differ():
    gt = [_item("tool_call_args", '{"cmd":"Get-Content notes.txt"}', call_id="call_0")]
    row = _row("tool_call_args", call_id="call_0")
    found = ev.assess("tool_call_args", [row], gt, {}, FakeArchive(), b"")
    assert (found["cell"], found["match_quality"]) == ("COLLECTED_RELEASED", "id_only")
    other = _row("tool_call_args", call_id="call_9")
    assert ev.cell("tool_call_args", [other], gt, {}, FakeArchive(), b"") == "NOT_COLLECTED"


def test_coverage_matrix_marks_probe_errors(fake_wire):
    archive = FakeArchive()
    cases = [{"case": "benign", "planted": {}, "sensitive": False, "runs": {
        "hook": {"records": [_row("user_prompt", match=archive.keyed_digest(PROMPT.encode()))],
                 "origin_bodies": [_body(("user_prompt", PROMPT))], "archive": archive},
        "native": {"error": "RuntimeError: native hooks did not attest readiness"}}}]
    matrix = ev.coverage_matrix(cases)
    assert matrix["cells"]["benign"]["user_prompt"]["hook"]["cell"] == "COLLECTED_RELEASED"
    assert matrix["cells"]["benign"]["user_prompt"]["native"]["cell"] == "PROBE_ERROR"
    assert matrix["summary"]["native"]["user_prompt"] == {"PROBE_ERROR": 1}


def test_judge_and_metrics():
    case = ev.Case("benign", "read", (["exec_command", {}],), {"tool_output": MARKER},
                   sensitive=False)
    assert ev.judge(case, 2, MARKER.encode()) == "ALLOWED"
    assert ev.judge(case, 1, MARKER.encode()) == "BROKEN"
    secret = ev.Case("secret_prompt", FAKE_KEY, (), {"user_prompt": FAKE_KEY})
    assert ev.judge(secret, 0, b"") == "STOPPED"
    assert ev.judge(secret, 1, FAKE_KEY.encode()) == "LEAKED"
    image = ev.Case("image", "look", (), {"tool_output_image": MARKER})
    assert ev.judge(image, 2, MARKER.encode()) == "SENT_UNINSPECTED"
    assert ev.percentile([5.0, 1.0, 3.0, 2.0], 0.95) == 5.0 and ev.percentile([], 0.5) is None
    envelope = _row("request_envelope", route="native", record_id=None)
    envelope["request_sha256"] = "b" * 64
    assert ev.allowed_bytes_equal_origin([envelope], ["b" * 64]) is True
    assert ev.allowed_bytes_equal_origin([envelope], ["c" * 64]) is False
    assert ev.latency([envelope, _row("user_prompt", route="native")], "native")["decisions"] == 1


def _matrix(native_cell="COLLECTED_BLOCKED", hook_cell="NOT_COLLECTED"):
    return {"cells": {"agents_md_secret": {"client_instructions": {
        "hook": {"cell": hook_cell}, "native": {"cell": native_cell}}}}}


GOOD = {"broken_benign": 0, "benign_non_allow": 0, "latency_p95_ms": 300.0,
        "allowed_bytes_equal_origin": True}


def test_recommend_hook_only_when_native_unvalidated():
    portability = {"builds": {
        "0.166": {"hook_route": "available", "native_route": "pinned_unvalidated"},
        "0.162": {"hook_route": "available", "native_route": "validated"}}}
    result = ev.recommend(_matrix(), portability, quality=GOOD)
    assert result["builds"]["0.166"]["verdict"] == "hook_only"
    assert "client_instructions" in result["builds"]["0.166"]["reasons"][0]
    assert result["builds"]["0.162"]["verdict"] == "hook_plus_native"
    slow = ev.recommend(_matrix(), portability, quality={**GOOD, "latency_p95_ms": 1600.0})
    assert slow["builds"]["0.162"]["verdict"] == "hook_only"
    assert ev.recommend(_matrix(), portability)["builds"]["0.162"]["verdict"] == "hook_only"



def test_recommend_scopes_live_quality_to_measured_build():
    portability = {"builds": {
        "0.162": {"hook_route": "available", "native_route": "validated", "sha256": "d139"},
        "0.162-copy": {"hook_route": "available", "native_route": "validated",
                       "sha256": "f552"}}}
    result = ev.recommend(_matrix(), portability, quality={**GOOD, "backend_sha256": "d139"})
    assert result["builds"]["0.162"]["verdict"] == "hook_plus_native"
    assert result["builds"]["0.162-copy"]["verdict"] == "hook_only"
    assert "not measured on this build" in result["builds"]["0.162-copy"]["reasons"][0]

def test_recommend_native_only_when_hooks_unavailable():
    portability = {"builds": {
        "a": {"hook_route": "unavailable(features.hooks=false)", "native_route": "validated"},
        "b": {"hook_route": "unavailable(features.hooks=false)", "native_route": "locator_only"}}}
    result = ev.recommend(_matrix(), portability)
    assert result["builds"]["a"]["verdict"] == "native_only"
    assert result["builds"]["b"]["verdict"] == "uncollected"


def test_health_check_session_excluded(tmp_path):
    path = tmp_path / "collection.jsonl"
    rows = [_row("user_prompt"), _row("user_prompt", session=ev.HEALTH_SESSION)]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    loaded = ev.load_route_records(path)
    assert [row["session_id"] for row in loaded] == ["s-1"]
    path.write_text(json.dumps({**rows[0], "prompt": PROMPT}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        ev.load_route_records(path)  # a row with free text is rejected, not skipped


def _envelope(request_id, *, duplicate=False, superseded=False, released=True, ms=100.0,
              sha=None):
    row = _row("request_envelope", route="native", record_id=None,
               decision="allow" if released else "deny")
    extra = {"duplicate_invocation": True} if duplicate else {}
    if superseded:
        extra["superseded_reason"] = "DECISION_DEADLINE_EXCEEDED"
    return {**row, "request_id": request_id, "request_sha256": (sha or request_id[-1]) * 64,
            "elapsed_ms": ms, "extra": extra}


def test_reused_and_superseding_rows_are_not_decisions():
    rows = [_envelope("r-a", ms=120.0), _envelope("r-b", duplicate=True, ms=0.2, sha="a"),
            _envelope("r-c", ms=180.0)]
    assert ev.latency(rows, "native") == {"decisions": 2, "p50_ms": 120.0, "p95_ms": 180.0}
    assert ev.allowed_bytes_equal_origin(rows, ["a" * 64, "c" * 64]) is True
    # The pipe blocked r-a after its rows said allow: its bytes were never released.
    late = [rows[0], _envelope("r-a", superseded=True, released=False),
            _envelope("r-b", duplicate=True, released=False, sha="a"), rows[2]]
    assert ev.latency(late, "native")["decisions"] == 2
    assert ev.allowed_bytes_equal_origin(late, ["c" * 64]) is True


def test_output_of_a_denied_call_is_not_applicable(fake_wire):
    archive = FakeArchive()
    denied = _row("tool_call_args", decision="deny", call_id="call_1")
    case = {"case": "sensitive_path_call", "planted": {"tool_output": MARKER.encode()},
            "sensitive": True, "runs": {"hook": {
                "records": [denied], "archive": archive,
                "origin_bodies": [_body(("tool_output", "denied by policy"))]}}}
    cell = ev.coverage_matrix([case])["cells"]["sensitive_path_call"]["tool_output"]["hook"]
    assert (cell["cell"], cell["match_quality"]) == ("NOT_APPLICABLE", "prevented_by_route")


def test_lost_async_rows_are_probe_errors_not_gaps(fake_wire):
    archive = FakeArchive()
    run = {"records": [], "archive": archive, "unmeasured": ["request_metadata"],
           "origin_bodies": [_body(("request_metadata", "{}"), ("user_prompt", PROMPT))]}
    matrix = ev.coverage_matrix([{"case": "c", "planted": {}, "sensitive": False,
                                  "runs": {"hook": run}}])
    cells = matrix["cells"]["c"]
    assert cells["request_metadata"]["hook"]["cell"] == "PROBE_ERROR"
    assert cells["user_prompt"]["hook"]["cell"] == "NOT_COLLECTED"
    cells["request_metadata"]["native"] = {"cell": "COLLECTED_RELEASED"}
    matrix["cells"]["c"] = {"user_attachment": cells["request_metadata"]}
    assert ev.recommend(matrix, {"builds": {}})["native_gains"] == ["user_attachment"]


def test_tool_output_not_a_native_gain_when_hook_denied_the_call():
    cells = {"sensitive_path_call": {
        "tool_call_args": {"hook": {"cell": "COLLECTED_BLOCKED"},
                           "native": {"cell": "COLLECTED_BLOCKED"}},
        "tool_output": {"hook": {"cell": "NOT_COLLECTED"}, "native": {"cell": "COLLECTED_BLOCKED"}}}}
    assert ev.recommend({"cells": cells}, {"builds": {}})["native_gains"] == []
