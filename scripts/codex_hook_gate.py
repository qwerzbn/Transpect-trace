"""Entry point Codex invokes for each hook event.

Codex tokenizes a hook `command` on whitespace and does not honor quotes, so
every path in the configured command line must be free of spaces. The installer
checks that; this file only wires stdin/stdout to the gate.

It must never exit non-zero or print nothing for an enforceable event because
it failed to start: the client treats a failed hook as `Failed` and sends the
request anyway. So the event is read with the standard library first, and if
the gate package cannot even be imported, a stdlib-only denial is written.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import re
import sys

_MAX = 8 * 1024 * 1024
_NAME = re.compile(rb'"hook_event_name"\s*:\s*"([A-Za-z]{1,64})"')
# Kept identical to codex_hook_gate._deny_response; the contract test checks both.
_FALLBACK = {
    "UserPromptSubmit": {"decision": "block",
                         "reason": "本地 DLP 拒绝发送该输入（GATE_UNAVAILABLE）"},
    "PostToolUse": {"decision": "block",
                    "reason": "本地 DLP 已拦截该工具输出，未发送给模型（GATE_UNAVAILABLE）"},
    "PreToolUse": {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": "本地 DLP 拒绝该工具调用（GATE_UNAVAILABLE）"}},
}


def _fallback(raw: bytes) -> int:
    match = _NAME.search(raw[:65536])
    reply = _FALLBACK.get(match.group(1).decode("ascii")) if match else None
    if reply:
        sys.stdout.buffer.write((json.dumps(reply, ensure_ascii=False) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


def run() -> int:
    raw = sys.stdin.buffer.read(_MAX + 1)
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from transpect_trace.protect.codex_hook_gate import main
    except BaseException:
        return _fallback(raw)
    try:
        return main(sys.argv[1:], io.BytesIO(raw), sys.stdout.buffer)
    except BaseException:
        return _fallback(raw)


if __name__ == "__main__":
    raise SystemExit(run())
