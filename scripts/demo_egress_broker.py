"""Demo: egress boundary prototype -- why the boundary, not the detector, is the
un-bypassable control.

A controlled broker is the *only* reachable network egress for the controlled
identity. It inspects the full request body before forwarding to a single
allowlisted upstream, refuses arbitrary URLs/tunneling, and fails closed when
the policy service is unavailable. The upstream is a real loopback origin that
records exactly which bytes reached it, so "0 bytes reached the origin on deny"
is a measured oracle, not a claim.

What is really enforced here (by the broker code, on loopback):
  * content inspection before forward (ProtectionEngine),
  * single-allowlisted-destination (arbitrary URL refused),
  * fail-closed on policy-service loss.
What is *modeled* and labeled, not enforced here:
  * default-deny egress for the controlled identity (the "a tool uses its own
    client / connects directly" case). Real enforcement needs WFP or an
    isolated low-privilege identity at the OS level -- see
    docs/development/fixed-codex-io-egress.md. In this demo it is an explicit,
    labeled policy check, not an OS filter.

Honest limit demonstrated on purpose: a semantically transformed secret passes
the broker's content check (the detector misses it) and reaches the upstream.
That is exactly why read-access restriction + approval -- not content matching --
must guard data that truly must not leave.

Synthetic fake secrets only; every endpoint is 127.0.0.1 loopback.
"""
from __future__ import annotations

import argparse
import http.client
import json
import sys
import threading
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from transpect_trace.protect.policy import ProtectionEngine, ProtectionPolicy  # noqa: E402
from transpect_trace.protect.models import SemanticCaptureEvent  # noqa: E402

MAX_BODY = 4 * 1024 * 1024


def event_from_body(raw: bytes, run_id: str) -> SemanticCaptureEvent:
    """Build a before-send snapshot from a raw request body the broker received."""
    return SemanticCaptureEvent(
        run_id=run_id, adapter_id="broker-demo/1", application="broker-demo", channel="api",
        pid=1, creation_filetime=1, image_sha256="0" * 64, protocol="http",
        destination_host="localhost", api_path="/responses", method="POST", completeness="complete",
        content_encoding="identity", encoding_state="identity",
        body_sha256=sha256(raw).hexdigest(), body_bytes=len(raw), body=raw,
        gate_owner="broker-demo/1")


class _Upstream(BaseHTTPRequestHandler):
    received: list[bytes] = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(min(length, MAX_BODY))
        type(self).received.append(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):  # silence
        pass


def _make_broker_handler(engine: ProtectionEngine, upstream_host: str, upstream_port: int, state: dict):
    allowed_target = f"http://{upstream_host}:{upstream_port}/responses"

    class _Broker(BaseHTTPRequestHandler):
        def _deny(self, code: int, reason: str):
            self.send_response(code)
            self.end_headers()
            self.wfile.write(json.dumps({"forwarded": False, "reason": reason}).encode())

        def do_POST(self):  # noqa: N802
            # Always drain the request body first so a deny cannot reset the
            # client connection (and so oversize is rejected after a bounded read).
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(min(length, MAX_BODY))
            # Fail-closed: no policy service -> never forward.
            if not state.get("policy_available", True):
                return self._deny(503, "policy_service_unavailable_fail_closed")
            target = self.headers.get("X-Target-Url", "")
            # Single allowlisted destination: no arbitrary URL, no tunneling.
            if target != allowed_target:
                return self._deny(403, "destination_not_allowlisted")
            if length > MAX_BODY:
                return self._deny(413, "oversize_body_fail_closed")
            verdict = engine.evaluate(event_from_body(raw, state["run_id"]))
            if verdict.decision != "ALLOW":
                return self._deny(403, f"content_denied:{verdict.reason}")
            # Only now does any byte leave toward the single upstream.
            conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=5)
            try:
                conn.request("POST", "/responses", body=raw)
                upstream_response = conn.getresponse()
                upstream_response.read()
            finally:
                conn.close()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"forwarded": True, "reason": "allowed"}).encode())

        def log_message(self, *args):
            pass

    return _Broker


def _post(host: str, port: int, raw: bytes, target_url: str | None) -> dict:
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Content-Length": str(len(raw))}
    if target_url is not None:
        headers["X-Target-Url"] = target_url
    try:
        conn.request("POST", "/forward", body=raw, headers=headers)
        response = conn.getresponse()
        return {"status": response.status, **json.loads(response.read() or b"{}")}
    finally:
        conn.close()


def _body(text: str) -> bytes:
    return json.dumps({"model": "fixture", "input": text}, ensure_ascii=False).encode()


# Synthetic fake secret and a semantically transformed variant of it.
SECRET = "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=" + "A" * 40
SEMANTIC = ("my aws access key id begins with the letters A K I A then A B C D, "
            "and the secret is forty capital A characters in a row")
BENIGN = "请总结这段公开文档的要点。"


def run_scenarios() -> dict:
    engine = ProtectionEngine(ProtectionPolicy())
    state = {"policy_available": True, "run_id": sha256(b"broker-demo").hexdigest()[:32]}

    upstream = HTTPServer(("127.0.0.1", 0), _Upstream)
    uh, up = upstream.server_address
    broker_handler = _make_broker_handler(engine, uh, up, state)
    broker = HTTPServer(("127.0.0.1", 0), broker_handler)
    bh, bp = broker.server_address
    allowed_target = f"http://{uh}:{up}/responses"
    for server in (upstream, broker):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    # The modeled OS default-deny: the only destination the controlled identity
    # may reach is the broker. Anything else is refused *before* a socket opens.
    def egress_allowed(host: str, port: int) -> bool:
        return (host, port) == (bh, bp)

    rows: list[dict] = []

    def scenario(name, technique, send, expect_upstream_bytes, control, honest_note=None):
        _Upstream.received.clear()
        result = send()
        reached = sum(len(b) for b in _Upstream.received)
        row = {"case": name, "technique": technique, "control": control,
               "upstream_bytes": reached, "expected_upstream_bytes": expect_upstream_bytes,
               "pass": reached == expect_upstream_bytes, "result": result}
        if honest_note:
            row["honest_note"] = honest_note
        rows.append(row)

    # 1. Tool uses its own client and dials the upstream directly, bypassing the
    #    broker. Under default-deny the socket never opens -> 0 bytes. Modeled.
    def direct_bypass():
        if egress_allowed(uh, up):
            return _post(uh, up, _body(SECRET), None)  # would reach upstream
        return {"status": "blocked_before_connect", "reason": "os_default_deny_modeled"}
    scenario("direct_to_upstream", "bypass broker with own client", direct_bypass,
             0, "os_default_deny (modeled; real = WFP/isolated identity)")

    # 2. Benign body through the broker -> forwarded, upstream receives it.
    scenario("broker_benign", "normal request via broker",
             lambda: _post(bh, bp, _body(BENIGN), allowed_target),
             len(_body(BENIGN)), "broker content inspection (allow)")

    # 3. Regex-detectable secret via broker -> denied, upstream receives nothing.
    scenario("broker_sensitive", "plain secret via broker",
             lambda: _post(bh, bp, _body(SECRET), allowed_target),
             0, "broker content inspection (deny)")

    # 4. Arbitrary URL / tunneling attempt -> refused structurally.
    scenario("broker_arbitrary_url", "exfil to attacker URL via broker",
             lambda: _post(bh, bp, _body(BENIGN), "http://attacker.example/collect"),
             0, "single-allowlisted-destination")

    # 5. Policy service down -> fail closed, nothing forwarded.
    def policy_down():
        state["policy_available"] = False
        try:
            return _post(bh, bp, _body(BENIGN), allowed_target)
        finally:
            state["policy_available"] = True
    scenario("broker_policy_down", "benign request while policy engine unavailable",
             policy_down, 0, "fail-closed on policy loss")

    # 6. HONEST MISS: semantically transformed secret passes the content check
    #    and reaches the upstream. The boundary is not a content guarantee.
    scenario("broker_semantic_miss", "paraphrased/spelled-out secret via broker",
             lambda: _post(bh, bp, _body(SEMANTIC), allowed_target),
             len(_body(SEMANTIC)), "broker content inspection (MISS)",
             honest_note="content detection cannot catch semantic transforms; "
                         "data that must not leave requires read-access restriction + approval, "
                         "not content matching")

    broker.shutdown()
    upstream.shutdown()

    structural = [r for r in rows if r["case"] != "broker_semantic_miss"]
    return {"allowed_target": allowed_target,
            "structural_controls_pass": all(r["pass"] for r in structural),
            "semantic_miss_demonstrated": rows[-1]["upstream_bytes"] > 0,
            "rows": rows}


def main():
    argparse.ArgumentParser(description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    report = run_scenarios()
    print("== 出口边界原型 Demo（环回 broker + 默认拒绝建模）==")
    print(f"唯一允许上游: {report['allowed_target']}")
    for row in report["rows"]:
        mark = "OK" if row["pass"] else "FAIL"
        print(f"[{mark}] {row['case']:22s} 到达上游字节={row['upstream_bytes']:>6} "
              f"(期望={row['expected_upstream_bytes']}) 控制={row['control']}")
        if row.get("honest_note"):
            print(f"       诚实边界: {row['honest_note']}")
    print(f"\n结构性控制全部达标: {report['structural_controls_pass']}")
    print(f"语义绕过(内容检测漏检)已演示: {report['semantic_miss_demonstrated']} "
          f"-> 边界保证 != 内容保证")
    raise SystemExit(0 if report["structural_controls_pass"] else 1)


if __name__ == "__main__":
    main()
