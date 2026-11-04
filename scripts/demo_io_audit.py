"""Demo: AI-tool outbound content audit + block (content-recognition DLP, before-send).

Business goal: identify enterprise-sensitive data -- source code, secrets/keys, internal
documents, PII -- in the OUTBOUND prompt text and uploaded files, and block it BEFORE it
leaves the enterprise boundary. Detection is content recognition, not minimal-privilege:
a local, multi-layer ensemble (rules+validators+context, entropy, exact-data-match,
fingerprint) fused into per-category confidence. See scripts/demo_content_dlp.py.

Reported against the four required dimensions:

  1. 时效性 (timeliness): the detector returns a synchronous verdict in an offline
     sample run. The separately tested HTTPX gate uses the older ProtectionEngine;
     this four-layer detector is not wired into a live outbound path.
  2. 拦截成功率 (block success): sensitive samples are blocked, benign allowed; a labeled
     per-category matrix is reported.
  3. 性能 (performance): per-inspection latency P50/P95/P99 vs the pilot budget.
  4. 防绕过 (bypass resistance): base64/hex are canonicalized, unknown-format secrets caught
     by entropy, partial document copies by fingerprint; a PURE semantic paraphrase is an
     honestly-declared MISS deferred to the next-round semantic layer. Fail-closed on error.

Only synthetic fake secrets/records/documents are used.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling demo modules

from demo_content_dlp import (  # noqa: E402
    detection_matrix, evasion_matrix, file_upload_demo, latency)

BUDGET_P95_MS = 50.0
BUDGET_P99_MS = 100.0


def timeliness() -> dict:
    return {
        "before_send_by_construction": False,
        "enforcement_channel": {
            "unit": "uv run --no-sync python -m pytest tests/test_python_outbound_bridge.py",
            "end_to_end": "scripts/probe_knowledge_mail.py validates the separate HTTPX gate; "
                          "it does not use this four-layer detector",
        },
        "note": "this report checks synthetic text and a locally created file; no live Codex "
                "or HTTPX request is supplied to ContentDLPEngine",
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

    detect = detection_matrix()
    evade = evasion_matrix()
    upload = file_upload_demo()
    perf = latency(args.iterations, args.payload_kib)
    perf["budget_p95_ms"] = BUDGET_P95_MS
    perf["budget_p99_ms"] = BUDGET_P99_MS
    perf["within_budget"] = perf["p95_ms"] <= BUDGET_P95_MS and perf["p99_ms"] <= BUDGET_P99_MS

    report = {
        "schema": "transpect.demo.io-audit/2.0",
        "channel": "content-recognition DLP (offline sample evaluation)",
        "timeliness": timeliness(),
        "block_success": detect,
        "evasion_resistance": evade,
        "file_upload": upload,
        "performance": perf,
        "recognition_layers": {
            "1_rules_validators_context": "regex for well-formed identifiers + Luhn validator + "
                                          "nearby-keyword boosting; base64/hex canonicalized first",
            "2_entropy": "long high-entropy tokens flagged as likely keys even with no known format",
            "3_exact_data_match": "enterprise records hashed locally; corroborative evidence across "
                                  "fields of one record raises confidence / cuts false positives",
            "4_fingerprint": "k-gram shingles catch partial copies of known internal docs/source; "
                             "a structural heuristic flags novel source code",
            "fusion": "noisy-OR per category -> BLOCK/REVIEW/ALLOW; fail-closed on inspector error",
            "deferred_semantic_layer": "embedding similarity / local fine-tuned LLM classifier catches "
                                        "pure paraphrase; NOT in this round (declared MISS in evasion)",
            "locality": "all inspection is local -- content is never shipped to a cloud classifier "
                        "(avoids the data-exposure paradox)",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("== AI 工具外发内容识别与拦截 Demo（内容识别 DLP，本地多层）==")
    print(f"通道: {report['channel']}")
    print("[时效性] 检测器同步返回判定；本 Demo 尚未接入真实请求的发送前门控。")
    print(f"         - 单元: {report['timeliness']['enforcement_channel']['unit']}")
    print(f"         - 端到端: {report['timeliness']['enforcement_channel']['end_to_end']}")
    print(f"[拦截成功率] 敏感 BLOCK {detect['sensitive_blocked']}/{detect['sensitive_total']}，"
          f"全部敏感被识别={detect['all_sensitive_caught']}；良性放行 {detect['benign_allowed']}/{detect['benign_total']}")
    for row in detect["rows"]:
        if row["class"] == "sensitive":
            print(f"            敏感 {row['case']:20s} 动作={row['action']:6s} 类别={list(row['scores'])}")
    print(f"[防绕过] 对抗样本 {evade['caught']}/{evade['total']} 命中（符合预期={evade['matrix_as_expected']}）；"
          f"漏检={evade['misses']}（纯语义改写 -> 待语义层）")
    print(f"[本地文件样本] {upload['file']} 动作={upload['action']} 命中层={upload['layers_fired']}")
    print(f"[性能] 内容识别 P50={perf['p50_ms']}ms P95={perf['p95_ms']}ms P99={perf['p99_ms']}ms "
          f"(预算 P95<={BUDGET_P95_MS}ms) -> 达标={perf['within_budget']}")
    print(f"\n报告: {args.output.resolve()}")

    ok = (detect["all_sensitive_caught"] and detect["benign_allowed"] == detect["benign_total"]
          and evade["matrix_as_expected"] and upload["action"] == "BLOCK" and perf["within_budget"])
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
