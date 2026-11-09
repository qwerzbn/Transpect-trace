"""Check that the Codex DLP gate is installed, trusted, unmodified and *actually running*.

Codex fails open in three silent ways: an untrusted hook is skipped without a
message, a hook process that cannot start is reported `Failed` and the request
is sent, and a user (or agent) can edit or delete `hooks.json`. None of these
leave an error anywhere a user would look. This script looks for each one:

* `install`   -- every gate event has its group in hooks.json, with the command
                 recorded at install time;
* `trust`     -- config.toml holds a trust entry for each of those groups;
* `integrity` -- every gate source file still has its install-time SHA-256
                 (the trust hash covers the hooks.json entry, not the code it runs);
* `tamper`    -- whether the current user can write the gate's code, interpreter,
                 config or hooks.json (if yes, the gate is policy, not a boundary);
* `service`   -- the resident service answers on its pipe (optional);
* `coverage`  -- reconciliation: every turn in the Codex transcripts since the
                 gate began recording turn IDs must have a gate audit row for its
                 prompt, and every tool call one for the call (and its output, when
                 PostToolUse is installed). A turn without one is a turn the gate
                 did not see.

Exit code 0 only when every check that ran is OK. Prints counts and IDs only.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect.codex_hook_gate import (  # noqa: E402
    AUDIT_SCHEMA, GateConfig, audit_files,
)

import install_codex_hook_gate as installer  # noqa: E402

SCHEMA = "transpect.codex-gate-health/1.0"
# Turns a person starts. Sub-agent and async-question turns carry no composer
# prompt, so UserPromptSubmit is not expected for them.
PROMPT_TRIGGERS = frozenset(("composer", "exec", "remote_android"))
TOOL_ITEMS = frozenset(("function_call", "custom_tool_call", "local_shell_call"))
TOOL_OUTPUT_ITEMS = frozenset(("function_call_output", "custom_tool_call_output",
                               "local_shell_call_output"))
_TRUST_KEY = re.compile(r"^\[hooks\.state\.'(?P<path>.+?):(?P<event>[a-z_]+):(?P<group>\d+):(?P<handler>\d+)'\]\s*$")


def _check(name: str, ok: bool | None, **detail) -> dict:
    return {"check": name, "status": "OK" if ok else ("SKIPPED" if ok is None else "FAIL"),
            **detail}


def check_install(codex_home: Path, manifest: dict | None) -> tuple[dict, dict[str, int]]:
    path = codex_home / "hooks.json"
    if not path.is_file():
        return _check("install", False, reason="hooks.json missing", path=str(path)), {}
    document = json.loads(path.read_text(encoding="utf-8"))
    events = (document.get("hooks") or {}) if isinstance(document, dict) else {}
    expected = manifest["events"] if manifest else list(installer.INSTALLED_EVENTS)
    missing, wrong_command, indexes = [], [], {}
    for event in expected:
        groups = events.get(event) or []
        found = [index for index, group in enumerate(groups)
                 if isinstance(group, dict) and group.get("description") == installer.GATE_MARKER]
        if not found:
            missing.append(event)
            continue
        indexes[event] = found[-1]
        handler = (groups[found[-1]].get("hooks") or [{}])[0]
        if manifest and handler.get("command") != manifest["command"]:
            wrong_command.append(event)
    return _check("install", not missing and not wrong_command, path=str(path),
                  missing_events=missing, command_differs_from_install=wrong_command), indexes


def check_trust(codex_home: Path, indexes: dict[str, int]) -> dict:
    config = codex_home / "config.toml"
    if not indexes:
        return _check("trust", None, reason="no gate groups installed")
    if not config.is_file():
        return _check("trust", False, reason="config.toml missing")
    hooks_path = str((codex_home / "hooks.json").resolve()).casefold()
    trusted = set()
    current = None
    for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _TRUST_KEY.match(line.strip())
        if match:
            current = match
            continue
        if current and line.strip().startswith("trusted_hash"):
            if current["path"].casefold() == hooks_path:
                trusted.add((current["event"], int(current["group"])))
            current = None
    untrusted = [event for event, group in indexes.items()
                 if (installer._TOML_EVENT_KEY.get(event), group) not in trusted]
    return _check("trust", not untrusted, untrusted_events=untrusted,
                  note="presence of a trust entry only; the client re-prompts if the "
                       "hooks.json entry changes, but not if the code behind it does")


def check_integrity(manifest: dict | None) -> dict:
    if manifest is None:
        return _check("integrity", None, reason="no install manifest; reinstall to record one")
    changed, missing = [], []
    for entry in manifest["files"]:
        path = Path(entry["path"])
        if not path.is_file():
            missing.append(path.name)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            changed.append(path.name)
    return _check("integrity", not changed and not missing, changed=changed, missing=missing,
                  files=len(manifest["files"]))


def _writable(path: Path) -> bool:
    """Can this user modify `path` (a file) or create files in it (a directory)?"""
    try:
        if path.is_dir():
            with tempfile.NamedTemporaryFile(dir=path, prefix=".ttrace-w-", delete=True):
                return True
        if path.is_file():
            with path.open("r+b"):
                return True
    except OSError:
        return False
    return False


def check_tamper(codex_home: Path, config_path: Path, manifest: dict | None) -> dict:
    command = (manifest or {}).get("command", "")
    targets = {"hooks.json": codex_home / "hooks.json", "gate_config": config_path,
               "gate_directory": config_path.parent}
    for token in command.split():
        candidate = Path(token)
        if candidate.suffix.lower() in {".exe", ".py"} and candidate.is_file():
            targets[candidate.name] = candidate
            targets[candidate.name + " (directory)"] = candidate.parent
    writable = sorted(name for name, path in targets.items() if _writable(path))
    # Writable is the *expected* state for a user-layer demo; the check fails so
    # the report never reads as "tamper-proof" while it is not.
    return _check("tamper", not writable, user_writable=writable,
                  meaning="the current user, and any agent running as that user, can "
                          "disable or alter the gate" if writable else
                          "gate files are not writable by the current user")


def check_service(config_path: Path, enabled: bool) -> dict:
    if not enabled:
        return _check("service", None, reason="not requested")
    from transpect_trace.protect.codex_gate_service import pipe_name, query
    name = pipe_name(config_path)
    probe = json.dumps({"hook_event_name": "PreModelRequest", "session_id": "transpect-health-check",
                        "turn_id": "transpect-health-check"}).encode("utf-8")
    try:
        reply = query(name, probe, timeout_ms=2000)
    except OSError as error:
        return _check("service", False, pipe=name, error=type(error).__name__,
                      effect="the native client falls back to the per-event gate (slower, still fail-closed)")
    return _check("service", reply == b"", pipe=name)


def _audit_rows(config: GateConfig):
    for path in audit_files(config.audit_file):
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    yield row


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def transcript_turns(sessions: Path, since: datetime):
    """Yield one record per turn that started at or after `since`."""
    cutoff = since.timestamp()
    for path in sessions.rglob("*.jsonl"):
        try:
            if path.stat().st_mtime < cutoff:
                continue
            stream = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with stream:
            turn = None
            for line in stream:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                payload = row.get("payload") if isinstance(row, dict) else None
                if not isinstance(payload, dict):
                    continue
                if row.get("type") == "event_msg" and payload.get("type") == "task_started":
                    if turn:
                        yield turn
                    started = _parse_time(row.get("timestamp"))
                    attribution = payload.get("turn_attribution") or {}
                    turn = None
                    if started and started >= since:
                        turn = {"session": path.name, "turn_id": payload.get("turn_id"),
                                "trigger": attribution.get("turn_trigger"),
                                "user_messages": 0, "tool_calls": 0, "tool_outputs": 0}
                    continue
                if turn is None or row.get("type") != "response_item":
                    continue
                kind = payload.get("type")
                if kind == "message" and payload.get("role") == "user":
                    turn["user_messages"] += 1
                elif kind in TOOL_ITEMS:
                    turn["tool_calls"] += 1
                elif kind in TOOL_OUTPUT_ITEMS:
                    turn["tool_outputs"] += 1
            if turn:
                yield turn


def check_coverage(codex_home: Path, config: GateConfig, indexes: dict[str, int],
                   since: datetime | None) -> dict:
    seen: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    first_with_ids = None
    for row in _audit_rows(config):
        if row.get("schema") != AUDIT_SCHEMA or not row.get("turn_id"):
            continue
        if row.get("session_id") == "transpect-health-check":
            continue
        decided = _parse_time(row.get("decided_at"))
        if decided and (first_with_ids is None or decided < first_with_ids):
            first_with_ids = decided
        seen[row["turn_id"]][row.get("hook_event_name")] += 1
        if row.get("hook_event_name") == "PreToolUse" and row.get("allowed"):
            seen[row["turn_id"]]["PreToolUse_allowed"] += 1
    start = since or first_with_ids
    if start is None:
        return _check("coverage", None,
                      reason="no audit row carries a turn ID yet; reconciliation starts "
                             "with the first event decided by this gate version")
    sessions = codex_home / "sessions"
    if not sessions.is_dir():
        return _check("coverage", None, reason="no transcripts", sessions=str(sessions))
    post_installed = "PostToolUse" in indexes
    totals = defaultdict(int)
    gaps = []
    for turn in transcript_turns(sessions, start):
        rows = seen.get(turn["turn_id"], {})
        totals["turns"] += 1
        problems = []
        if turn["trigger"] in PROMPT_TRIGGERS and turn["user_messages"]:
            totals["prompt_turns"] += 1
            if not rows.get("UserPromptSubmit"):
                problems.append("PROMPT_NOT_GATED")
        if turn["tool_calls"]:
            totals["tool_turns"] += 1
            if not rows.get("PreToolUse"):
                problems.append("TOOL_CALLS_NOT_GATED")
            # A call the gate denied never runs, so it has no PostToolUse; the
            # client writes the denial as the output. Only allowed calls owe one.
            if (post_installed and turn["tool_outputs"] and rows.get("PreToolUse_allowed")
                    and not rows.get("PostToolUse")):
                problems.append("TOOL_OUTPUT_NOT_GATED")
        if problems:
            gaps.append({"session": turn["session"], "turn_id": turn["turn_id"],
                         "trigger": turn["trigger"], "problems": problems})
    return _check("coverage", not gaps, since=start.isoformat(), **totals,
                  ungated_turns=len(gaps), gaps=gaps[:50],
                  meaning="each gap is a turn whose content reached the model without "
                          "the gate deciding on it" if gaps else None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--codex-home", type=Path, default=None)
    parser.add_argument("--gate-directory", type=Path, default=ROOT / "runs" / "codex-hook-gate")
    parser.add_argument("--since", default=None,
                        help="ISO time to reconcile from; default: first audit row with turn IDs")
    parser.add_argument("--service", action="store_true", help="also probe the resident service")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    codex_home = (args.codex_home or installer.default_codex_home()).resolve()
    gate_directory = args.gate_directory.resolve()
    config_path = gate_directory / "gate-config.json"
    manifest_path = gate_directory / installer.MANIFEST_NAME
    manifest = (json.loads(manifest_path.read_text(encoding="utf-8"))
                if manifest_path.is_file() else None)
    config = GateConfig.load(config_path)
    install, indexes = check_install(codex_home, manifest)
    checks = [install, check_trust(codex_home, indexes), check_integrity(manifest),
              check_tamper(codex_home, config_path, manifest),
              check_service(config_path, args.service),
              check_coverage(codex_home, config, indexes, _parse_time(args.since))]
    report = {"schema": SCHEMA, "checked_at": datetime.now(timezone.utc).isoformat(),
              "codex_home": str(codex_home), "gate_config": str(config_path),
              "mode": config.mode, "healthy": all(c["status"] != "FAIL" for c in checks),
              "checks": checks}
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
