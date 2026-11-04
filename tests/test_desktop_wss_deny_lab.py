"""Origin evidence must gate synthetic fixed-backend denial claims."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from probe_desktop_wss_deny_lab import _report  # noqa: E402


BODY = b'{"type":"response.create","model":"fixture","input":"synthetic"}'
DIGEST = hashlib.sha256(BODY).hexdigest()
BASE = {"kind": "marker_buffer", "hook": "model.wss", "bytes": len(BODY),
        "sha256": DIGEST, "request_shape": "response.create-input",
        "raw_body": "PRIVATE"}
WARMUP = {"protocol": "websocket", "payload_bytes": 10,
          "payload_sha256": hashlib.sha256(b"warmup-123").hexdigest(),
          "marker_in_origin_payload": False, "wss_wire_body_bytes_received": 18}
MARKED = {"protocol": "websocket", "payload_bytes": len(BODY),
          "payload_sha256": DIGEST, "marker_in_origin_payload": True,
          "wss_wire_body_bytes_received": len(BODY) + 8,
          "payload_utf8": "PRIVATE"}
EMPTY_WSS = {"protocol": "websocket", "wss_wire_body_bytes_received": 0,
             "error": "EOFError: client closed"}
DENIED_WSS = {"kind": "synthetic_denied", "hook": "model.wss"}
DENIED_HTTP = {"kind": "synthetic_http_denied_owned", "hook": "model.http"}
HTTP_HIT = {"kind": "marker_buffer", "hook": "model.http", "bytes": len(BODY),
            "sha256": DIGEST}
HOOKS = [{"kind": "hook_installed", "hook": hook}
         for hook in ("model.http", "model.wss")]


def report(events, origin, mode="all", exit_code=1, errors=None):
    return _report(HOOKS + events, origin, mode=mode, target_sha256="a" * 64,
                   marker_sha256="b" * 64, exit_code=exit_code,
                   errors=errors or [])


def test_allow_requires_exact_origin_payload_hash_and_does_not_persist_body():
    accepted = report([BASE], [WARMUP, MARKED], mode="allow", exit_code=0)
    assert accepted["passed"] and accepted["status"] == "exact_wss_payload_match"
    assert "PRIVATE" not in str(accepted)
    changed = {**MARKED, "payload_sha256": "0" * 64}
    assert report([BASE], [WARMUP, changed], mode="allow", exit_code=0)["passed"] is False


def test_wss_only_denial_is_a_bypass_when_http_fallback_reaches_origin():
    fallback = {"protocol": "http", "payload_bytes": len(BODY),
                "payload_sha256": DIGEST, "marker_in_origin_payload": True}
    observed = report([BASE, DENIED_WSS, HTTP_HIT], [WARMUP, EMPTY_WSS, fallback],
                      mode="wss-only")
    assert observed["status"] == "wss_denied_http_fallback_leaked"
    assert observed["origin_marked_payload_count"] == 1
    assert observed["wss_zero_frame_connection_count"] == 1


def test_all_denial_requires_both_hooks_normal_exit_and_zero_marked_origin():
    complete = report([BASE, DENIED_WSS, HTTP_HIT, DENIED_HTTP],
                      [WARMUP, EMPTY_WSS])
    assert complete["status"] == "synthetic_marker_denied_all_observed_paths"
    assert complete["origin_marked_payload_count"] == 0
    assert complete["total_origin_body_bytes"] == WARMUP["payload_bytes"]
    assert complete["unmarked_warmup_body_bytes"] == WARMUP["payload_bytes"]
    assert "PRIVATE" not in str(complete)
    unmarked_fallback = {"protocol": "http", "payload_bytes": len(BODY),
                         "payload_sha256": DIGEST, "marker_in_origin_payload": False}
    for events, origin, exit_code, errors in (
            ([BASE, DENIED_WSS, HTTP_HIT], [WARMUP, EMPTY_WSS], 1, []),
            ([BASE, DENIED_WSS, HTTP_HIT, DENIED_HTTP], [WARMUP, EMPTY_WSS, MARKED], 1, []),
            ([BASE, DENIED_WSS, HTTP_HIT, DENIED_HTTP],
             [WARMUP, EMPTY_WSS, unmarked_fallback], 1, []),
            ([BASE, DENIED_WSS, HTTP_HIT, DENIED_HTTP], [WARMUP, EMPTY_WSS], -1, []),
            ([BASE, DENIED_WSS, HTTP_HIT, DENIED_HTTP], [WARMUP, EMPTY_WSS], 1,
             ["frida_script_error"]),
    ):
        assert report(events, origin, exit_code=exit_code, errors=errors)["passed"] is False
