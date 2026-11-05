"""Drive the real local Codex client through the hook DLP gate and record it.

Each case runs the pinned `codex exec` backend in a private `CODEX_HOME` with
only this gate installed, then correlates three independent facts per case:

* the client's own `hook: <event> Blocked|Completed` line,
* the gate's audit row, and
* whether a `PreModelRequest` event was recorded at all -- the client fires that
  before every model request, so its absence is this probe's evidence that no
  request left for a blocked prompt.

Only synthetic fake secrets are submitted. Every prompt is sent to a private
CODEX_HOME with no credentials unless `--codex-home` points elsewhere, so a
benign case normally ends in an authentication error after the gate allowed it;
that is expected and is recorded as `allowed_then_unauthenticated`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from transpect_trace.protect.codex_hook_gate import AUDIT_SCHEMA  # noqa: E402

import install_codex_hook_gate as installer  # noqa: E402

SCHEMA = "transpect.codex-hook-gate-live/1.0"
PINNED_BACKEND_SHA256 = (
    "925c7d0665ffa49b0dcf748e034a805a04da984164ac92301432073b47789b99")
PINNED_BACKEND_VERSION = "codex-cli 0.166.0-alpha.6"
FAKE_SECRET = "password=Ab3x7Q2m9Pv4Na6Ty8Rz0Ls5Kb1Dc3Fh"
_HOOK_LINE = re.compile(r"^hook: (\w+)(?: (Blocked|Completed|Failed))?$", re.M)
CASES = (
    ("synthetic_secret_prompt", f"deploy with {FAKE_SECRET}", "blocked"),
    ("benign_prompt", "请简短回复 OK。", "allowed"),
)


def verify_backend(backend: Path) -> dict:
    digest = hashlib.sha256()
    with backend.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    actual = digest.hexdigest()
    version = subprocess.run([str(backend), "--version"], capture_output=True,
                             text=True, timeout=180).stdout.strip()
    if actual != PINNED_BACKEND_SHA256 or version != PINNED_BACKEND_VERSION:
        raise ValueError(f"backend is not the pinned build: {version} {actual}")
    return {"path": str(backend), "sha256": actual, "version": version}


def _hook_events(output: str) -> list[dict]:
    return [{"event": match.group(1), "status": match.group(2) or "started"}
            for match in _HOOK_LINE.finditer(output)]


def _audit_rows(path: Path, seen: int) -> tuple[list[dict], int]:
    if not path.exists():
        return [], seen
    lines = path.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines[seen:] if line.strip()]
    for row in rows:
        if row.get("schema") != AUDIT_SCHEMA:
            raise ValueError("unexpected gate audit schema")
    return rows, len(lines)


def run_case(backend: Path, codex_home: Path, work: Path, audit: Path,
             prompt: str, seen: int, timeout: int) -> tuple[dict, int]:
    environment = {**os.environ, "CODEX_HOME": str(codex_home)}
    began = time.monotonic()
    completed = subprocess.run(
        [str(backend), "exec", "--dangerously-bypass-hook-trust",
         "--skip-git-repo-check", prompt],
        cwd=str(work), env=environment, capture_output=True, text=True,
        encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
        timeout=timeout)
    elapsed = (time.monotonic() - began) * 1000
    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    # The PreModelRequest handler is async, so its row can land just after the
    # client exits. Let it settle before the audit slice is read.
    time.sleep(2.0)
    rows, seen = _audit_rows(audit, seen)
    events = _hook_events(output)
    return {
        "client_hook_events": events,
        "client_blocked_prompt": any(event == {"event": "UserPromptSubmit",
                                               "status": "Blocked"}
                                     for event in events),
        "client_hook_failures": [event for event in events
                                 if event["status"] == "Failed"],
        # Counted from the gate's own audit rows: the client prints nothing for
        # an async handler, so console lines would undercount.
        "model_request_events": sum(row["hook_event_name"] == "PreModelRequest"
                                    for row in rows),
        "origin_returned_401": "401 Unauthorized" in output,
        "gate_audit_rows": rows,
        "exit_code": completed.returncode,
        "elapsed_ms": round(elapsed, 1),
    }, seen


def classify(case: str, expected: str, observed: dict) -> dict:
    enforced = [row for row in observed["gate_audit_rows"]
                if row["hook_event_name"] == "UserPromptSubmit"]
    row = enforced[0] if len(enforced) == 1 else None
    if expected == "blocked":
        # Three independent facts: the client reports the block, the gate's own
        # pre-request handler never fired, and the origin was never reached.
        verified = bool(
            row and row["allowed"] is False and row["enforced"] is True
            and row["dlp_decision"] == "BLOCK" and row["matched_rule_ids"]
            and observed["client_blocked_prompt"]
            and observed["model_request_events"] == 0
            and observed["origin_returned_401"] is False
            and not observed["client_hook_failures"])
        status = ("blocked_with_no_model_request_and_no_origin_contact" if verified
                  else "unverified_block")
    else:
        # The control case must show the opposite: the request did go out and
        # the real origin answered, so the blocked case is not a dead setup.
        verified = bool(
            row and row["allowed"] is True and row["enforced"] is False
            and row["dlp_decision"] == "ALLOW"
            and not observed["client_blocked_prompt"]
            and observed["model_request_events"] > 0
            and not observed["client_hook_failures"])
        status = (("allowed_and_origin_rejected_unauthenticated"
                   if observed["origin_returned_401"] else "allowed_and_sent")
                  if verified else "unverified_allow")
    return {"case": case, "expected": expected, "status": status,
            "verified": verified,
            "gate_decision": {key: row[key] for key in
                              ("allowed", "enforced", "reason", "dlp_decision",
                               "matched_rule_ids", "elapsed_ms")} if row else None,
            **{key: observed[key] for key in
               ("client_blocked_prompt", "model_request_events",
                "origin_returned_401", "client_hook_failures", "exit_code",
                "elapsed_ms")}}


def run_probe(args) -> dict:
    backend = args.backend.resolve(strict=True)
    attested = verify_backend(backend)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    codex_home = args.codex_home.resolve() if args.codex_home else output / "codex-home"
    work = output / "work"
    work.mkdir()
    gate_directory = output / "gate"
    config = installer.write_gate_config(gate_directory, "enforce", args.registration)
    command = installer.build_command(
        Path(sys.executable).resolve(strict=True),
        (ROOT / "scripts" / "codex_hook_gate.py").resolve(strict=True), config)
    codex_home.mkdir(parents=True, exist_ok=True)
    installed = installer.install_user_layer(codex_home, command, dry_run=False)
    audit = gate_directory / "audit.jsonl"

    cases, seen = [], 0
    for case, prompt, expected in CASES:
        observed, seen = run_case(backend, codex_home, work, audit, prompt, seen,
                                  args.timeout)
        cases.append(classify(case, expected, observed))

    report = {
        "schema": SCHEMA,
        "backend": attested,
        "mode": "enforce",
        "hooks_file": installed["path"],
        "hook_trust_bypassed_for_this_probe": True,
        "scope": "codex exec in a private CODEX_HOME; not the desktop UI",
        "desktop_ui_prompt_verified": False,
        "attachment_upload_covered": False,
        "attachment_has_no_hook_event": True,
        "pre_model_request_can_block": False,
        "remote_origin_zero_bytes_verified": False,
        "origin_contact_inferred_from_client_error_not_from_the_server": True,
        "cases": cases,
        "all_cases_verified": all(case["verified"] for case in cases),
        "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
        "audit_rows": sum(1 for _ in audit.open(encoding="utf-8")) if audit.exists() else 0,
    }
    (output / "summary.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.clean_codex_home and not args.codex_home:
        shutil.rmtree(codex_home, ignore_errors=True)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", type=Path, required=True,
                        help="pinned codex.exe used by the installed desktop client")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--codex-home", type=Path, default=None,
                        help="reuse an existing CODEX_HOME instead of a private one")
    parser.add_argument("--registration", type=Path, default=None)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--clean-codex-home", action="store_true")
    args = parser.parse_args()
    report = run_probe(args)
    print(json.dumps({key: report[key] for key in
                      ("all_cases_verified", "scope", "cases")},
                     indent=2, ensure_ascii=False))
    raise SystemExit(0 if report["all_cases_verified"] else 2)


if __name__ == "__main__":
    main()
