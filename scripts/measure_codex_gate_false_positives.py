"""Measure the gate's action rate on this machine's own Codex prompt history.

A gate that denies ordinary developer prompts is unusable, so the rate has to be
measured on real traffic before `enforce` is switched on. This reads local
rollout transcripts, replays the `role=user` texts through the same engine and
policy the gate uses, and reports counts only.

No prompt text, and no excerpt of one, is written to the report: each row is a
salted digest plus the rule identifiers that fired. The salt is random per run
unless `--salt` is given, so digests cannot be correlated across runs by
default. Nothing is sent anywhere; the whole pass is local.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect.codex_hook_gate import (  # noqa: E402
    CodexHookGate, GateConfig,
)

import install_codex_hook_gate as installer  # noqa: E402

SCHEMA = "transpect.codex-gate-false-positive/1.0"
MAX_PROMPT_BYTES = 1024 * 1024
MAX_LINE_BYTES = 8 * 1024 * 1024


def user_prompts(session_root: Path, limit: int):
    """Yield (session, ordinal, text) for every role=user transcript message."""
    files = sorted(session_root.rglob("*.jsonl"))
    seen = 0
    for path in files:
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for line in handle:
                if len(line) > MAX_LINE_BYTES:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("type") != "response_item":
                    continue
                payload = row.get("payload")
                if (not isinstance(payload, dict) or payload.get("type") != "message"
                        or payload.get("role") != "user"):
                    continue
                parts = [item.get("text") for item in payload.get("content") or []
                         if isinstance(item, dict) and isinstance(item.get("text"), str)]
                text = "\n".join(parts)
                if not text.strip() or len(text.encode("utf-8")) > MAX_PROMPT_BYTES:
                    continue
                yield path.name, row.get("ordinal"), text
                seen += 1
                if limit and seen >= limit:
                    return


def measure(session_root: Path, gate: CodexHookGate, limit: int, salt: bytes) -> dict:
    decisions = Counter()
    actions = Counter()
    rules = Counter()
    categories = Counter()
    denied_rows = []
    timings = []
    sessions = set()
    for session, ordinal, text in user_prompts(session_root, limit):
        sessions.add(session)
        started = time.perf_counter()
        verdict = gate._prepare()[1].inspect_text(text)
        timings.append((time.perf_counter() - started) * 1000)
        actionable = gate.actionable(verdict)
        decisions[verdict.decision] += 1
        actions[actionable] += 1
        for rule in verdict.rule_ids:
            rules[rule] += 1
        for category in verdict.categories:
            categories[category] += 1
        if actionable != "ALLOW":
            denied_rows.append({
                "session": session, "ordinal": ordinal,
                "prompt_bytes": len(text.encode("utf-8")),
                "prompt_digest": hashlib.blake2b(
                    salt + text.encode("utf-8"), digest_size=12).hexdigest(),
                "engine_decision": verdict.decision,
                "actionable_decision": actionable,
                "rule_ids": list(verdict.rule_ids),
                "category_scores": dict(verdict.category_scores),
            })
    total = sum(actions.values())
    timings.sort()
    return {
        "schema": SCHEMA,
        "session_root": str(session_root),
        "sessions_seen": len(sessions),
        "prompts_evaluated": total,
        "engine_decisions": dict(decisions),
        "policy_actions": dict(actions),
        "policy_deny_rate": round((total - actions["ALLOW"]) / total, 5) if total else None,
        "enforced_categories": sorted(gate.config.enforced_categories),
        "advisory_rule_ids": sorted(gate.config.advisory_rule_ids),
        "rule_hit_counts": dict(rules.most_common()),
        "category_hit_counts": dict(categories.most_common()),
        "latency_ms": {
            "p50": round(timings[len(timings) // 2], 3) if timings else None,
            "p95": round(timings[min(len(timings) - 1, int(len(timings) * .95))], 3)
            if timings else None,
        },
        "prompt_text_in_report": False,
        "digest_salt_is_random_per_run": True,
        "interpretation": (
            "These are real prompts this machine already sent, so a deny here is a "
            "candidate false positive, not a confirmed one: a prompt may legitimately "
            "have carried a secret. Rows list rule identifiers so each deny can be "
            "reviewed against the original session by session name and ordinal."),
        "denied": denied_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sessions", type=Path, default=None,
                        help="defaults to <CODEX_HOME>/sessions")
    parser.add_argument("--gate-directory", type=Path,
                        default=ROOT / "runs" / "codex-gate-false-positives" / "gate")
    parser.add_argument("--registration", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=0, help="0 reads every prompt")
    parser.add_argument("--salt", default=None,
                        help="hex salt for prompt digests; random when omitted")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "runs" / "codex-gate-false-positives" / "report.json")
    args = parser.parse_args()

    codex_home = Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex"))
    session_root = (args.sessions or codex_home / "sessions").resolve(strict=True)
    config = GateConfig.load(installer.write_gate_config(
        args.gate_directory.resolve(), "observe", args.registration))
    salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(16)
    report = measure(session_root, CodexHookGate(config), args.limit, salt)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(json.dumps({key: report[key] for key in (
        "sessions_seen", "prompts_evaluated", "engine_decisions", "policy_actions",
        "policy_deny_rate", "latency_ms")}, indent=2))
    print("top rules:", json.dumps(dict(list(report["rule_hit_counts"].items())[:12]),
                                   ensure_ascii=False))
    print(args.output)


if __name__ == "__main__":
    main()
