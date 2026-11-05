"""Four-dimension report for the local content-recognition DLP engine.

Dimensions: timeliness, block success, performance, evasion resistance. The
engine under test is the production one in
`transpect_trace.protect.content_dlp` -- this script owns no detection logic of
its own, so the numbers below describe the same code the desktop gate calls.

This is an offline sample evaluation. It starts no Codex client and proves no
live enforcement; see `docs/development/desktop-current-mainline.md` for the
gate itself. Every secret, record and document here is a synthetic fake.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from transpect_trace.protect.content_dlp import (  # noqa: E402
    ContentDLPEngine, EDMIndex, FingerprintIndex,
)

# Budgets are per payload size and were measured on this engine, not inherited
# from the deleted prototype: that prototype had no EDM layer and keyed its
# shingles on process-local `hash()`, so its figures are not comparable.
# Measured p95 on this engine is ~3 ms at 8 KiB and ~60 ms at 64 KiB; the
# budgets below leave headroom so a loaded machine does not fail the guard.
PAYLOAD_BUDGETS_MS = {8: 20.0, 64: 90.0}
BUDGET_P95_MS = PAYLOAD_BUDGETS_MS[64]
_FAKE_SECRET = "Ab3x7Q2m9Pv4Na6Ty8Rz0Ls5Kb1Dc3Fh"
_NOVEL_SECRET = "xqeF7P2mZk9Lw3Rt8Vb1Nc6Hy4Jd0Gs5Pa2"
_KNOWN_DOC = (
    "Project Nebula confidential roadmap phase alpha ships the internal review "
    "workflow phase beta adds the redaction service phase gamma delivers audit "
    "controls for all agents."
)
_KNOWN_CODE = (
    "def rotate_signing_key(tenant_id, kms_client):\n"
    "    current = kms_client.get_active_key(tenant_id)\n"
    "    new_key = kms_client.create_key(tenant_id)\n"
    "    return new_key.fingerprint"
)

# (case, expected category, text). Expected categories are the developer's
# policy intent for these fixtures, not an independent blind label set.
SENSITIVE = (
    ("aws_key_pair", "SECRET",
     f"aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key={_FAKE_SECRET}"),
    ("private_key_block", "SECRET",
     "-----BEGIN PRIVATE KEY-----\nMIIFakeKeyMaterial\n-----END PRIVATE KEY-----"),
    ("novel_format_token", "SECRET", f"here is the deploy token: {_NOVEL_SECRET}"),
    ("internal_doc_fragment", "INTERNAL_DOC",
     "FYI quoting our plan: phase beta adds the redaction service phase gamma "
     "delivers audit controls for all agents. Please review."),
    ("registered_source_code", "SOURCE_CODE", _KNOWN_CODE),
    ("corroborated_pii", "PII", "员工 Zhang Wei (E10293) 需要报销。"),
)
BENIGN = (
    ("public_request", "请总结这段公开文档的要点，谢谢。"),
    ("masked_secret", "password=********"),
    ("placeholder_secret", "api_key=${API_KEY}"),
    ("reference_uuid", "Reference UUID 550e8400-e29b-41d4-a716-446655440000"),
)


def build_engine() -> ContentDLPEngine:
    """Register the same synthetic EDM records and documents the fixtures use."""
    key = hashlib.sha256(b"demo-io-audit-edm-fixture").digest()
    return ContentDLPEngine(
        index=FingerprintIndex.from_documents({
            "fake-roadmap": ("INTERNAL_DOC", _KNOWN_DOC),
            "fake-source": ("SOURCE_CODE", _KNOWN_CODE),
        }),
        edm_index=EDMIndex.from_records(
            {"fake-employee-1": {"name": "Zhang Wei", "employee_id": "E10293"}}, key),
    )


def detection_matrix() -> dict:
    engine = build_engine()
    rows = []
    for case, expected_category, text in SENSITIVE:
        verdict = engine.inspect_text(text)
        rows.append({
            "case": case, "class": "sensitive", "expected_category": expected_category,
            "decision": verdict.decision, "categories": list(verdict.categories),
            "rule_ids": list(verdict.rule_ids),
            "detected": verdict.decision != "ALLOW" and expected_category in verdict.categories,
        })
    for case, text in BENIGN:
        verdict = engine.inspect_text(text)
        rows.append({"case": case, "class": "benign", "decision": verdict.decision,
                     "categories": list(verdict.categories),
                     "rule_ids": list(verdict.rule_ids)})
    sensitive = [row for row in rows if row["class"] == "sensitive"]
    benign = [row for row in rows if row["class"] == "benign"]
    return {
        "sensitive_total": len(sensitive),
        "sensitive_blocked": sum(row["decision"] == "BLOCK" for row in sensitive),
        "benign_total": len(benign),
        "benign_allowed": sum(row["decision"] == "ALLOW" for row in benign),
        "all_sensitive_caught": all(row["detected"] for row in sensitive),
        "rows": rows,
    }


def evasion_matrix() -> dict:
    engine = build_engine()
    secret = f"aws_secret_access_key={_FAKE_SECRET}"
    cases = (
        ("plaintext_secret", "none", secret, True, "rules+context"),
        ("base64_encoded_secret", "base64 obfuscation",
         "blob: " + base64.b64encode(secret.encode()).decode(), True, "decode then rules"),
        ("hex_encoded_secret", "hex obfuscation", "blob: " + secret.encode().hex(),
         True, "decode then rules"),
        ("novel_format_secret", "unknown key format", f"token {_NOVEL_SECRET}",
         True, "entropy"),
        ("known_doc_fragment", "partial copy of a registered document",
         "see: phase gamma delivers audit controls for all agents", True, "fingerprint"),
        ("paraphrased_internal_doc", "semantic rewrite of a registered document",
         "Heads up: the upcoming work first ships an internal review flow, then a "
         "service that removes sensitive values, and finally a data-flow guard.",
         False, "declared miss: layers are lexical/structural"),
    )
    rows = []
    for case, technique, payload, should_catch, mechanism in cases:
        verdict = engine.inspect_text(payload)
        caught = verdict.decision != "ALLOW"
        rows.append({
            "case": case, "technique": technique, "caught": caught,
            "mechanism": mechanism, "decision": verdict.decision,
            "as_expected": caught == should_catch,
            "honest_note": None if should_catch else
            "a pure paraphrase changes every surface token, so only a semantic "
            "layer catches it; that layer is not implemented",
        })
    return {"total": len(rows), "caught": sum(row["caught"] for row in rows),
            "matrix_as_expected": all(row["as_expected"] for row in rows),
            "misses": [row["case"] for row in rows if not row["caught"]],
            "rows": rows}


def file_upload_sample(directory: Path) -> dict:
    engine = build_engine()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "uploaded_sample.py"
    payload = (_KNOWN_CODE + f"\n# config\nAPI_TOKEN = '{_NOVEL_SECRET}'\n").encode("utf-8")
    path.write_bytes(payload)
    verdict = engine.inspect_file_bytes(path.name, payload)
    return {"file": path.name, "decision": verdict.decision, "reason": verdict.reason,
            "categories": list(verdict.categories), "rule_ids": list(verdict.rule_ids),
            "payload_sha256": hashlib.sha256(payload).hexdigest()}


def latency(iterations: int, payload_kib: int) -> dict:
    if iterations < 1 or payload_kib < 1:
        raise ValueError("iterations and payload size must be positive")
    engine = build_engine()
    filler = "公开文档内容样例。This is public filler text. " * 200
    raw = (filler * ((payload_kib * 1024) // len(filler.encode("utf-8")) + 1))
    text = raw.encode("utf-8")[:payload_kib * 1024].decode("utf-8", "ignore")
    engine.inspect_text(text)
    samples = []
    for _ in range(iterations):
        started = time.perf_counter()
        engine.inspect_text(text)
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()

    def percentile(fraction: float) -> float:
        return round(samples[min(len(samples) - 1, int(len(samples) * fraction))], 3)

    budget = PAYLOAD_BUDGETS_MS.get(payload_kib)
    result = {"iterations": iterations, "payload_kib": payload_kib,
              "p50_ms": round(statistics.median(samples), 3),
              "p95_ms": percentile(0.95), "p99_ms": percentile(0.99),
              "budget_p95_ms": budget,
              "note": "local inspection only; excludes capture, archive, IPC and transport"}
    result["within_budget"] = budget is None or result["p95_ms"] <= budget
    return result


def build_report(iterations: int, payload_kib: int, directory: Path) -> dict:
    detection = detection_matrix()
    evasion = evasion_matrix()
    upload = file_upload_sample(directory)
    typical = latency(max(1, iterations // 4), 8)
    performance = latency(iterations, payload_kib)
    performance["typical_prompt_8kib"] = typical
    return {
        "schema": "transpect.demo.io-audit/3.0",
        "engine": "transpect_trace.protect.content_dlp.ContentDLPEngine",
        "live_enforcement_verified": False,
        "blind_holdout": False,
        "timeliness": {
            "synchronous_verdict": True,
            "before_send_enforcement_proved_here": False,
            "enforcement_entry_points": [
                "src/transpect_trace/protect/codex_hook_gate.py (supported Codex hooks)",
                "src/transpect_trace/protect/desktop_bridge.py (pinned desktop research probe)",
            ],
        },
        "block_success": detection,
        "evasion_resistance": evasion,
        "file_upload": upload,
        "performance": performance,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--payload-kib", type=int, default=64)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "runs/demo-io-audit/report.json")
    args = parser.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    report = build_report(args.iterations, args.payload_kib, args.output.parent)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")

    detection, evasion = report["block_success"], report["evasion_resistance"]
    performance, upload = report["performance"], report["file_upload"]
    print("== 本地内容识别 DLP 四维度报告（离线样本，不含实际发送）==")
    print(f"[时效性] 同步判定；本报告不证明发送前门控已部署。")
    print(f"[拦截成功率] 敏感 BLOCK {detection['sensitive_blocked']}/"
          f"{detection['sensitive_total']}，期望类别全部命中="
          f"{detection['all_sensitive_caught']}；良性放行 "
          f"{detection['benign_allowed']}/{detection['benign_total']}")
    for row in detection["rows"]:
        if row["class"] == "sensitive":
            print(f"            {row['case']:24s} {row['decision']:6s} "
                  f"类别={row['categories']}")
    print(f"[防绕过] {evasion['caught']}/{evasion['total']} 命中（符合预期="
          f"{evasion['matrix_as_expected']}）；诚实漏检={evasion['misses']}")
    print(f"[上传样本] {upload['file']} {upload['decision']} 类别={upload['categories']}")
    typical = performance["typical_prompt_8kib"]
    print(f"[性能] 8KiB  P50={typical['p50_ms']}ms P95={typical['p95_ms']}ms"
          f"（预算 {typical['budget_p95_ms']}ms）达标={typical['within_budget']}")
    print(f"       {performance['payload_kib']}KiB P50={performance['p50_ms']}ms "
          f"P95={performance['p95_ms']}ms P99={performance['p99_ms']}ms"
          f"（预算 {performance['budget_p95_ms']}ms）达标={performance['within_budget']}")
    print(f"\n报告: {args.output.resolve()}")

    passed = (detection["all_sensitive_caught"]
              and detection["benign_allowed"] == detection["benign_total"]
              and evasion["matrix_as_expected"]
              and upload["decision"] == "BLOCK"
              and performance["within_budget"]
              and performance["typical_prompt_8kib"]["within_budget"])
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
