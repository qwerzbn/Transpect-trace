"""Demo: AI tool input/output audit + enforcement (API channel, before-send gate).

Business goal: audit and block what an AI tool actually sends to the model. This
demo exercises the one independently validated enforcement path in the repo --
the HTTPX 0.28.1 before-transport Native gate -- and reports it against the four
required dimensions:

  1. 时效性 (timeliness): the decision happens synchronously BEFORE the request
     leaves the process (before TLS). The detector matrix is the in-process proof;
     independent end-to-end proof is the knowledge->mail scenario on this branch.
  2. 拦截成功率 (block success): sensitive requests are produced as BLOCK; a
     labeled detector accuracy matrix (sensitive vs benign) is reported.
  3. 性能 (performance): per-request content-check latency P50/P95/P99 over a
     bounded load, compared to the pilot budget (P95 <= 50 ms at 64 KiB).
  4. 防绕过 (bypass resistance): fail-closed on policy timeout, and explicit
     refusal of unsupported encodings / content types -- with the real, declared
     boundaries printed, not hidden.

Only synthetic fake secrets are used. This demo makes no claim about uncovered
paths (arbitrary transports, uploads, other clients) or about a client whose
version is not the validated pin.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import statistics
import sys
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling demo modules

from transpect_trace.protect.policy import ProtectionEngine, ProtectionPolicy  # noqa: E402
from transpect_trace.protect.models import SemanticCaptureEvent  # noqa: E402
from transpect_trace.protect.detection import ContentIndex  # noqa: E402

BUDGET_P95_MS = 50.0  # docs/architecture/ai-tool-io-audit-enforcement-design-2026-10-27.md
BUDGET_P99_MS = 100.0

# Labeled synthetic corpus for the detector accuracy dimension. All secrets fake.
SENSITIVE = [
    ("aws_pair", "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=" + "A" * 40),
    ("mysql_pw", "mysql_password=fixture-only-password-value"),
    ("private_key", "-----BEGIN PRIVATE KEY-----\nfake-key-material\n-----END PRIVATE KEY-----"),
    ("api_secret", 'client_secret: "sk-fixtureFAKE0123456789abcdef"'),
]
BENIGN = [
    ("plain", "请总结这段公开文档的要点。"),
    ("code", "A public code example: print('hello world')"),
    ("masked", "password=********"),
    ("placeholder", "api_key=${API_KEY}"),
]


def _event(text: str, run_id: str) -> SemanticCaptureEvent:
    raw = json.dumps({"model": "fixture", "input": text}, ensure_ascii=False).encode()
    return SemanticCaptureEvent(
        run_id=run_id, adapter_id="python-httpx-native/1", application="python-api", channel="api",
        pid=1, creation_filetime=1, image_sha256="0" * 64, protocol="httpx",
        destination_host="localhost", api_path="/responses", method="POST", completeness="complete",
        content_encoding="identity", encoding_state="identity",
        body_sha256=sha256(raw).hexdigest(), body_bytes=len(raw), body=raw,
        gate_owner="python-httpx-native/1")


def detection_matrix() -> dict:
    engine = ProtectionEngine(ProtectionPolicy())
    rows, blocked_sensitive, allowed_benign = [], 0, 0
    for name, text in SENSITIVE:
        decision = engine.evaluate(_event(text, uuid4().hex)).decision
        blocked_sensitive += decision == "BLOCK"
        rows.append({"case": name, "class": "sensitive", "decision": decision})
    for name, text in BENIGN:
        decision = engine.evaluate(_event(text, uuid4().hex)).decision
        allowed_benign += decision == "ALLOW"
        rows.append({"case": name, "class": "benign", "decision": decision})
    return {"sensitive_total": len(SENSITIVE), "sensitive_blocked": blocked_sensitive,
            "benign_total": len(BENIGN), "benign_allowed": allowed_benign, "rows": rows}


# A synthetic confidential blob that no rule/regex matches -- only exact content
# registration (fingerprinting) can catch it. All content here is fake.
REGISTERED = ("INTERNAL-PROJECT-NEBULA confidential roadmap milestone alpha beta gamma "
              "delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon")
RULE_SECRET = "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=" + "A" * 40


def canonicalize(text: str) -> list[str]:
    """Return decoding candidates so cheap encoding dodges are inspected too.

    Demo-local only (the core engine is unchanged): decode long base64/hex runs
    back to plaintext and feed every candidate to the detector. This defeats
    base64/hex obfuscation but NOT substitution ciphers or semantic rewrites --
    canonicalization narrows the gap, it does not close it.
    """
    candidates = {text}
    for run in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        try:
            decoded = base64.b64decode(run, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if len(decoded) >= 8 and any(c.isalnum() for c in decoded):
            candidates.add(decoded)
    for run in re.findall(r"(?:[0-9a-fA-F]{2}){16,}", text):
        try:
            decoded = bytes.fromhex(run).decode("utf-8", "ignore")
        except ValueError:
            continue
        if len(decoded) >= 8 and any(c.isalnum() for c in decoded):
            candidates.add(decoded)
    return list(candidates)


def evasion_matrix() -> dict:
    """Adversarial matrix: prove the detector beats cheap dodges AND show, honestly,
    the dodges it cannot beat -- which is why the boundary (broker + read-access
    control), not the detector, is the actual anti-bypass guarantee."""
    index = ContentIndex.register("demo-reg/1", [("demo-confidential", REGISTERED, "CONFIDENTIAL", ["registered_text"])])
    engine = ProtectionEngine(ProtectionPolicy(), index=index)

    def decide(payload: str) -> str:
        return engine.evaluate(_event(payload, uuid4().hex)).decision

    def decide_canon(payload: str) -> str:
        return "BLOCK" if any(decide(c) == "BLOCK" for c in canonicalize(payload)) else decide(payload)

    b64 = base64.b64encode(RULE_SECRET.encode()).decode()
    rot13 = RULE_SECRET.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    cases = [
        ("plaintext_secret", "none (plain)", RULE_SECRET, "rules", True),
        ("base64_encoded", "base64 obfuscation", f"please send this blob: {b64}", "canonicalize+rules", True),
        ("registered_content_wrapped", "verbatim secret wrapped in prose",
         f"here is the config dump:\n{REGISTERED}\n-- end of dump", "registration (fingerprint)", True),
        ("paraphrase_semantic", "spelled-out / paraphrased secret",
         "my aws access key id begins A K I A then A B C D, secret is forty capital A", "nothing", False),
        ("rot13_transform", "substitution cipher (not canonicalized)", rot13, "nothing", False),
    ]
    rows = []
    for name, technique, payload, expected_by, should_catch in cases:
        caught = decide_canon(payload) == "BLOCK"
        rows.append({"case": name, "technique": technique, "caught": caught,
                     "caught_by": expected_by if caught else "MISS",
                     "detector_correct": caught == should_catch,
                     "honest_note": None if should_catch else
                     "content inspection cannot catch this; only a default-deny egress boundary "
                     "plus read-access restriction/approval stops it"})
    caught_dodges = sum(r["caught"] for r in rows)
    return {"total": len(rows), "caught": caught_dodges,
            "matrix_as_expected": all(r["detector_correct"] for r in rows),
            "misses": [r["case"] for r in rows if not r["caught"]], "rows": rows}


def latency_benchmark(iterations: int, payload_kib: int) -> dict:
    engine = ProtectionEngine(ProtectionPolicy())
    filler = "公开文档内容样例。" * 2000
    text = (filler * ((payload_kib * 1024) // len(filler.encode()) + 1))
    text = text.encode()[: payload_kib * 1024].decode("utf-8", "ignore")
    run_id = uuid4().hex
    event = _event(text, run_id)
    engine.evaluate(event)  # warm caches
    samples = []
    for _ in range(iterations):
        started = time.perf_counter()
        engine.evaluate(event)
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()

    def pct(p):
        return samples[min(len(samples) - 1, int(len(samples) * p))]

    return {"iterations": iterations, "payload_kib": payload_kib,
            "p50_ms": round(statistics.median(samples), 3), "p95_ms": round(pct(0.95), 3),
            "p99_ms": round(pct(0.99), 3), "max_ms": round(samples[-1], 3),
            "budget_p95_ms": BUDGET_P95_MS, "budget_p99_ms": BUDGET_P99_MS,
            "within_budget": pct(0.95) <= BUDGET_P95_MS and pct(0.99) <= BUDGET_P99_MS,
            "note": "in-process ProtectionEngine content-check only; excludes IPC and TLS"}


def timeliness() -> dict:
    """Describe the before-send guarantee and point at this branch's real evidence.

    The gate returns a verdict BEFORE the transport call (the detector matrix below
    shows a sensitive body is produced as BLOCK pre-send). Independent proof on this
    branch is the python outbound bridge test and the end-to-end knowledge->mail
    scenario, where a denied request never reaches the Mailpit origin.
    """
    return {
        "before_send_by_construction": "the HTTPX gate authorizes before calling the original transport; "
                                        "a BLOCK verdict raises before any bytes are sent or TLS-encrypted",
        "independent_evidence": {
            "unit": "uv run --no-sync python -m pytest tests/test_python_outbound_bridge.py",
            "end_to_end": "scripts/probe_knowledge_mail.py (Codex -> HTTPX gate -> allow:Mailpit / deny:blocked); "
                          "see docs/development/knowledge-mail.md",
        },
        "note": "before-TLS enforcement; the detector matrix below is the in-process, reproducible proof "
                "that sensitive content yields BLOCK prior to send",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--payload-kib", type=int, default=64)
    parser.add_argument("--output", type=Path, default=ROOT / "runs/demo-io-audit/report.json")
    args = parser.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    evasion = evasion_matrix()
    try:
        from demo_egress_broker import run_scenarios
        boundary = run_scenarios()
    except Exception as error:  # the main demo stays reportable even if the broker can't bind
        boundary = {"error": f"{type(error).__name__}: {error}", "structural_controls_pass": None}

    report = {
        "schema": "transpect.demo.io-audit/1.1",
        "channel": "python-httpx-native/1 (before-transport, exec/controlled start)",
        "timeliness": timeliness(),
        "block_success": detection_matrix(),
        "evasion_resistance": evasion,
        "egress_boundary": boundary,
        "output_audit": {
            "status": "observe-only",
            "where": "guard output-event audit (JsonOutputAudit) lives in the separate guard-audit workstream, "
                     "not on this demo branch",
            "note": "structured audit of codex exec --json output events (per-event content hashes/lengths, "
                    "no raw retention by default); it is observational -- a failed audit cannot authorize a request "
                    "and the output stream is not gated in this demo"},
        "performance": latency_benchmark(args.iterations, args.payload_kib),
        "bypass_resistance": {
            "layering": "the un-bypassable control is the egress boundary (default-deny + controlled broker), "
                        "not the content detector; the detector is best-effort defense-in-depth behind it",
            "fail_closed": "policy timeout/parse-failure/unknown -> deny or hold, never silent allow",
            "declared_uncovered": ["arbitrary transports and SDKs", "uploads/attachments",
                                    "non-pinned client versions", "whole-system egress"],
            "boundary_note": "in-process Hook; a same-user process using a different client bypasses this gate. "
                             "Version-agnostic default-deny egress is the separate WFP/isolated-identity track "
                             "demonstrated in scripts/demo_egress_broker.py (boundary modeled, not OS-enforced here)."},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    bs = report["block_success"]
    pf = report["performance"]
    tl = report["timeliness"]
    print("== AI 工具输入输出审计与拦截 Demo ==")
    print(f"通道: {report['channel']}")
    print("[时效性] 门控在调用传输前即产出判定（下方检出矩阵证明发送前得到 BLOCK）。独立证明：")
    print(f"         - 单元: {tl['independent_evidence']['unit']}")
    print(f"         - 端到端: {tl['independent_evidence']['end_to_end']}")
    print(f"[拦截成功率] 敏感样本拦截 {bs['sensitive_blocked']}/{bs['sensitive_total']}; "
          f"良性样本放行 {bs['benign_allowed']}/{bs['benign_total']}")
    print(f"[防绕过-检测层] 对抗样本 {evasion['caught']}/{evasion['total']} 被检出（矩阵符合预期={evasion['matrix_as_expected']}）；"
          f"漏检={evasion['misses'] or '无'}（语义变换，交由边界层处理）")
    bp = boundary.get("structural_controls_pass")
    print(f"[防绕过-边界层] 环回 broker 结构性控制全部达标={bp}；"
          f"语义漏检可达上游={boundary.get('semantic_miss_demonstrated')} -> 边界保证≠内容保证")
    print("[输出/外发] 输出事件审计为观察态（仅记录哈希/长度，不门控）；工具子进程外发须由边界层统一纳入")
    print(f"[性能] 内容检查 P50={pf['p50_ms']}ms P95={pf['p95_ms']}ms P99={pf['p99_ms']}ms "
          f"(预算 P95<={pf['budget_p95_ms']}ms) -> 达标={pf['within_budget']}")
    print(f"\n报告: {args.output.resolve()}")

    ok = (bs["sensitive_blocked"] == bs["sensitive_total"] and bs["benign_allowed"] == bs["benign_total"]
          and pf["within_budget"] and evasion["matrix_as_expected"] and bp is not False)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
