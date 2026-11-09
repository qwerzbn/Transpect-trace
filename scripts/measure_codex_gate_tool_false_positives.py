"""Measure the gate's action rate on this machine's own Codex *tool* history.

The prompt measurement (measure_codex_gate_false_positives.py) covers
`UserPromptSubmit`. This one covers the two tool events, which see far more
traffic and far noisier text -- source code, logs, hashes:

* `PreToolUse`: each recorded tool call is rebuilt as the hook event the client
  sends. `exec_command` becomes `Bash {command}` (the hook's own naming, checked
  against live events). The desktop's code-mode `exec` tool is a JavaScript
  wrapper; the client fires one hook per nested call, so the nested `cmd`
  literals are extracted and replayed as separate `Bash` events.
* `PostToolUse`: each recorded tool output is replayed as `tool_response`.

Both go through `codex_hook_gate.inspection_target` and the gate's own
`actionable` decision, so the policy measured is the policy that runs. Reports
counts, salted digests and rule IDs only -- never a command or output excerpt.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect.codex_hook_gate import (  # noqa: E402
    CodexHookGate, GateConfig, inspection_target,
)

import install_codex_hook_gate as installer  # noqa: E402

SCHEMA = "transpect.codex-gate-tool-false-positive/1.0"
MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_ITEM_BYTES = 2 * 1024 * 1024
_JS_CMD = re.compile(r'\bcmd\s*:\s*("(?:[^"\\]|\\.){1,65536}")')


def _hook_tool(name: str, arguments: object) -> tuple[str, object]:
    if name in {"exec_command", "shell", "local_shell", "shell_command"}:
        if isinstance(arguments, dict):
            command = arguments.get("cmd", arguments.get("command"))
            return "Bash", {"command": command}
    return name, arguments


def tool_events(session_root: Path, limit: int):
    """Yield (session, kind, event) rebuilt from rollout transcripts."""
    seen = 0
    for path in sorted(session_root.rglob("*.jsonl")):
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names: dict[str, tuple[str, object]] = {}
        with handle:
            for line in handle:
                if len(line) > MAX_LINE_BYTES:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                payload = row.get("payload")
                if row.get("type") != "response_item" or not isinstance(payload, dict):
                    continue
                kind = payload.get("type")
                events = []
                if kind == "function_call":
                    try:
                        arguments = json.loads(payload.get("arguments") or "{}")
                    except ValueError:
                        arguments = {"raw": payload.get("arguments")}
                    tool, tool_input = _hook_tool(payload.get("name") or "", arguments)
                    names[payload.get("call_id")] = (tool, tool_input)
                    events.append(("PreToolUse", tool, tool_input, None))
                elif kind == "custom_tool_call":
                    source = payload.get("input") or ""
                    nested = []
                    for match in _JS_CMD.finditer(source):
                        try:
                            nested.append(json.loads(match.group(1)))
                        except ValueError:
                            continue
                    names[payload.get("call_id")] = ("Bash", {"command": "\n".join(nested)})
                    events += [("PreToolUse", "Bash", {"command": command}, None)
                               for command in nested]
                elif kind in {"function_call_output", "custom_tool_call_output"}:
                    tool, tool_input = names.get(payload.get("call_id"), ("unknown", {}))
                    events.append(("PostToolUse", tool, tool_input, payload.get("output")))
                for name, tool, tool_input, response in events:
                    event = {"hook_event_name": name, "tool_name": tool or "unknown",
                             "tool_input": tool_input, "session_id": path.stem,
                             "turn_id": "t", "tool_use_id": "u"}
                    if name == "PostToolUse":
                        event["tool_response"] = response
                    if len(json.dumps(event, ensure_ascii=False)) > MAX_ITEM_BYTES:
                        continue
                    yield path.name, name, event
                    seen += 1
                    if limit and seen >= limit:
                        return


def measure(session_root: Path, gate: CodexHookGate, limit: int, salt: bytes) -> dict:
    engine = gate._prepare()[1]
    stats = {name: {"actions": Counter(), "rules": Counter(), "categories": Counter(),
                    "timings": []} for name in ("PreToolUse", "PostToolUse")}
    denied = []
    sessions = set()
    for session, name, event in tool_events(session_root, limit):
        sessions.add(session)
        bucket = stats[name]
        started = time.perf_counter()
        try:
            target = inspection_target(event, gate.policy)
        except ValueError:
            bucket["actions"]["UNBUILDABLE"] += 1
            continue
        verdict = engine.inspect_text(target.text)
        action = gate.actionable(verdict, tuple(target.findings))
        bucket["timings"].append((time.perf_counter() - started) * 1000)
        bucket["actions"][action] += 1
        rules = set(verdict.rule_ids) | {item[1] for item in target.findings}
        for rule in rules:
            bucket["rules"][rule] += 1
        for category in set(verdict.categories) | {item[0] for item in target.findings}:
            bucket["categories"][category] += 1
        if action != "ALLOW":
            denied.append({
                "event": name, "session": session, "tool_name": event["tool_name"][:64],
                "bytes": len(target.text.encode("utf-8")),
                "digest": hashlib.blake2b(salt + target.text.encode("utf-8"),
                                          digest_size=12).hexdigest(),
                "actionable_decision": action,
                "rule_ids": sorted(rules),
            })
    report = {"schema": SCHEMA, "session_root": str(session_root),
              "sessions_seen": len(sessions),
              "enforced_categories": sorted(gate.config.enforced_categories),
              "advisory_rule_ids": sorted(gate.config.advisory_rule_ids),
              "content_in_report": False, "events": {}, "denied": denied}
    for name, bucket in stats.items():
        total = sum(bucket["actions"].values())
        timings = sorted(bucket["timings"])
        denies = total - bucket["actions"]["ALLOW"] - bucket["actions"]["UNBUILDABLE"]
        report["events"][name] = {
            "evaluated": total,
            "policy_actions": dict(bucket["actions"]),
            "policy_deny_rate": round(denies / total, 5) if total else None,
            "rule_hit_counts": dict(bucket["rules"].most_common()),
            "category_hit_counts": dict(bucket["categories"].most_common()),
            "latency_ms": {
                "p50": round(timings[len(timings) // 2], 3) if timings else None,
                "p95": round(timings[min(len(timings) - 1, int(len(timings) * .95))], 3)
                if timings else None},
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sessions", type=Path, default=None)
    parser.add_argument("--gate-directory", type=Path,
                        default=ROOT / "runs" / "codex-gate-false-positives" / "tool-gate")
    parser.add_argument("--registration", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--salt", default=None)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "runs" / "codex-gate-false-positives" / "tool-report.json")
    args = parser.parse_args()
    codex_home = Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex"))
    session_root = (args.sessions or codex_home / "sessions").resolve(strict=True)
    config = GateConfig.load(installer.write_gate_config(
        args.gate_directory.resolve(), "observe", args.registration, codex_home=codex_home))
    salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(16)
    report = measure(session_root, CodexHookGate(config), args.limit, salt)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    for name, row in report["events"].items():
        print(name, json.dumps({key: row[key] for key in
                                ("evaluated", "policy_actions", "policy_deny_rate",
                                 "latency_ms")}))
        print("  top rules:", json.dumps(dict(list(row["rule_hit_counts"].items())[:14]),
                                         ensure_ascii=False))
    print(args.output)


if __name__ == "__main__":
    main()
