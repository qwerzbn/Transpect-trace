"""验收门禁：候选 pin 的确定性全绿判定（版本自动适配第③环）。

流程：
  1. 前置：监管器互斥锁被持有则拒绝运行（探针需要独占子进程管道）；
  2. 校验：候选 pin 结构 + 二进制 SHA/入口字节一致 + 构建专用 DLL；
  3. 探针套件（quick/full）逐个执行，全部 PASS 才算验收通过；
  4. --deploy：把带 accepted 印章的 pin 写入 deploy/claude-guard-lab/，
     监管器此后会对该 SHA-256 热切换接入（fail-closed 之外的首条路径）。

用法：
  uv run --no-sync python scripts/accept_pin.py --pin <pin.json> --suite full --deploy
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from _build_support import ROOT  # noqa: E402

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import claude_service as lab  # noqa: E402

SUPERVISOR_MUTEX = "Local\\ttrace-claude-guard-supervisor"
EVIDENCE_DIR = ROOT / "runs" / "accept"
LIVE_PROVIDERS = frozenset(("claude_account", "anthropic_api", "bedrock",
                            "vertex", "foundry", "relay"))
TUI_CASES = frozenset(("hello", "sensitive", "attachment", "tool_result",
                       "continuation"))
EGRESS_CASES = frozenset(("curl", "powershell", "python", "node", "mcp",
                          "nested_child", "crash_closed"))
SUITE_VERSION = lab.ACCEPTANCE_SUITE_VERSION

QUICK = [
    ("scripts/probe_claude_inprocess_lab.py", ["--case", "short_bearer_allow"], {}),
    ("scripts/probe_claude_inprocess_lab.py", ["--case", "long_key_deny"], {}),
    ("scripts/probe_claude_pii_scenarios.py", ["--case", "pii_deny"], {}),
    ("scripts/probe_claude_multiturn.py", ["--test", "anthropic_prefix_allow",
                                           "--deny-mode", "returnfail"], {}),
]
FULL = ([("scripts/probe_claude_inprocess_lab.py", ["--case", name], {})
         for name in ("short_bearer_allow", "long_bearer_allow", "long_bearer_deny",
                      "short_key_allow", "long_key_allow", "long_key_deny")]
        + [("scripts/probe_claude_pii_scenarios.py", ["--case", "pii_deny"], {})]
        + [("scripts/probe_claude_multiturn.py", ["--test", name,
                                                  "--deny-mode", "returnfail"], {})
           for name in ("abi_session", "scenario4_tool_result",
                        "scenario4_block_continue", "scenario5_base64",
                        "realistic_benign_allow",
                        "anthropic_prefix_allow")]
        + [("scripts/probe_claude_gzip_exact.py", [], {})]
        + [("-m", ["pytest", "-q", "tests/test_claude_redact.py"], {})]
        + [("-m", ["pytest", "-q", "tests/test_content_dlp_core.py"], {})]
        + [("-m", ["pytest", "-q", "tests/test_claude_accept_pin.py"], {})])


def supervisor_running() -> bool:
    handle = ctypes.windll.kernel32.CreateMutexW(None, False, SUPERVISOR_MUTEX)
    if not handle:
        return False
    exists = ctypes.windll.kernel32.GetLastError() == 183  # ERROR_ALREADY_EXISTS
    ctypes.windll.kernel32.CloseHandle(handle)
    return exists


def verify_live_evidence(path: Path, binary_sha256: str,
                         dll_sha256: str) -> tuple[str, dict[str, str]]:
    """Require completed host evidence before a pin can enter resident service."""
    raw = path.read_bytes()
    report = json.loads(raw)
    if (report.get("schema") != "transpect.claude.live-acceptance/1.0"
            or report.get("binary_sha256") != binary_sha256
            or report.get("dll_sha256") != dll_sha256):
        raise ValueError("live evidence identity does not match the candidate")
    providers = report.get("providers", {})
    tui = report.get("tui", {})
    egress = report.get("egress", {})
    if (set(providers) != LIVE_PROVIDERS or set(tui) != TUI_CASES
            or set(egress) != EGRESS_CASES):
        raise ValueError("live evidence matrix is incomplete")
    artifact_hashes: dict[str, str] = {}
    def artifact(row: dict, stem: str) -> bytes:
        name = row.get(stem + "_file")
        digest = row.get(stem + "_sha256")
        if (not isinstance(name, str) or Path(name).name != name
                or not isinstance(digest, str) or not lab.SHA256.fullmatch(digest)):
            raise ValueError(f"missing {stem} artifact and SHA-256")
        source = path.parent / name
        raw_artifact = source.read_bytes()
        if hashlib.sha256(raw_artifact).hexdigest() != digest:
            raise ValueError(f"{stem} artifact SHA-256 mismatch")
        if name in artifact_hashes and artifact_hashes[name] != digest:
            raise ValueError(f"conflicting artifact identity: {name}")
        artifact_hashes[name] = digest
        return raw_artifact

    def check_audit(row: dict) -> None:
        lines = artifact(row, "native_audit").splitlines()
        audits = [json.loads(line) for line in lines if line.strip()]
        if not audits or not any(item.get("route_event") == "model.request"
                                 or item.get("kind") == "tool.exec" for item in audits):
            raise ValueError("native audit contains no request decision")

    def check_origin(row: dict, *, provider: str | None = None) -> None:
        receipt = json.loads(artifact(row, "origin_receipt"))
        if provider is None:
            if (receipt.get("schema") != "transpect.claude.local-origin-receipt/1.0"
                    or receipt.get("mode") != "no_forward"):
                raise ValueError("origin receipt is not a no-forward capture")
            records = receipt.get("records", [])
            posts = ([item for item in records if item.get("starts_post")]
                     if isinstance(records, list) else [])
            if (not posts or any(not item.get("complete") or item.get("app_bytes", 0) <= 0
                                 or item.get("marker_offset", -2) != -1
                                 or any(offset != -1 for offset in
                                        item.get("secondary_marker_offsets", []))
                                 for item in posts)):
                raise ValueError("origin receipt lacks complete marker evidence")
        else:
            if (receipt.get("schema") != "transpect.claude.provider-request-log/1.0"
                    or receipt.get("provider") != provider
                    or not receipt.get("source_export_id")
                    or not isinstance(receipt.get("records"), list)
                    or not receipt["records"]
                    or any(item.get("marker_at_origin") is not False
                           for item in receipt["records"])):
                raise ValueError(f"provider request log is incomplete: {provider}")
    for name, row in providers.items():
        if (row.get("benign") != "PASS" or row.get("sensitive") != "PASS"
                or row.get("marker_at_origin") is not False
                or not row.get("native_audit_sha256")
                or not row.get("origin_receipt_sha256")):
            raise ValueError(f"provider evidence incomplete: {name}")
        check_audit(row)
        check_origin(row, provider=name)
    for name, row in tui.items():
        if (row.get("result") != "PASS" or not row.get("native_audit_sha256")
                or not row.get("origin_receipt_sha256")):
            raise ValueError(f"TUI evidence incomplete: {name}")
        check_audit(row)
        check_origin(row)
    for name, row in egress.items():
        if (row.get("result") != "PASS" or row.get("marker_at_origin") is not False
                or not row.get("origin_receipt_sha256")):
            raise ValueError(f"egress evidence incomplete: {name}")
        check_audit(row)
        check_origin(row)
    return hashlib.sha256(raw).hexdigest(), artifact_hashes


def run_case(script: str, args: list[str], extra_env: dict[str, str],
             env: dict[str, str]) -> dict:
    started = datetime.datetime.now().isoformat(timespec="seconds")
    uv = shutil.which("uv")
    if not uv:
        return {"script": script, "args": args, "result": "FAIL",
                "error": "uv executable not found", "started": started}
    try:
        proc = subprocess.run(
            [uv, "run", "--no-sync", "python", script, *args],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=1800, env=env)
    except subprocess.TimeoutExpired:
        return {"script": script, "args": args, "result": "FAIL",
                "error": "TIMEOUT", "started": started}
    result = {"script": script, "args": args, "result": "FAIL",
              "exit": proc.returncode, "started": started,
              "stdout_sha256": hashlib.sha256(proc.stdout.encode("utf-8")).hexdigest(),
              "stderr_sha256": hashlib.sha256(proc.stderr.encode("utf-8")).hexdigest()}
    if script == "-m":
        result["result"] = "PASS" if proc.returncode == 0 else "FAIL"
        result["evidence"] = {"test_file": args[-1], "exit": proc.returncode}
        return result
    if script == "scripts/probe_claude_gzip_exact.py":
        try:
            parsed = json.loads(proc.stdout.strip().splitlines()[-1])
            result["result"] = ("PASS" if proc.returncode == 0
                                and parsed.get("result") == "PASS"
                                and parsed.get("cases") == 4 else "FAIL")
            result["evidence"] = {"cases": parsed.get("cases")}
        except (IndexError, ValueError):
            pass
        return result
    for line in reversed(proc.stdout.strip().splitlines()):
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict) and "result" in parsed:
            valid = (proc.returncode == 0 and parsed["result"] == "PASS"
                     and ("decision" in parsed or "decisions" in parsed)
                     and ("upstream_app_bytes" in parsed or "blocked_items" in parsed))
            if "decision" in parsed and "upstream_app_bytes" in parsed:
                if parsed["decision"] == "deny":
                    valid = valid and parsed["upstream_app_bytes"] == 0
                elif parsed["decision"] == "allow":
                    valid = valid and parsed["upstream_app_bytes"] > 0
                    if "upstream_sha256" in parsed:
                        valid = (valid and parsed.get("upstream_sha256")
                                 == parsed.get("archive_sha256")
                                 == parsed.get("audit_sha256"))
            result["result"] = "PASS" if valid else "FAIL"
            result["evidence"] = {k: v for k, v in parsed.items()
                                  if k in ("decision", "case", "test", "decisions",
                                           "blocked_items", "exit", "body_bytes",
                                           "upstream_app_bytes", "marker_offset",
                                           "upstream_sha256", "archive_sha256",
                                           "audit_sha256", "post_count", "sink_bodies")}
            break
    if result["result"] != "PASS":
        result["error"] = "probe assertion or process exit failed; inspect isolated probe locally"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", required=True, type=Path)
    parser.add_argument("--exe", default=None)
    parser.add_argument("--suite", choices=("quick", "full"), default="quick")
    parser.add_argument("--deploy", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--live-evidence", type=Path)
    args = parser.parse_args()
    if args.deploy and args.suite != "full":
        print("FAIL: 只允许完整套件部署验收印章", file=sys.stderr)
        return 2
    if args.deploy and args.live_evidence is None:
        print("FAIL: 部署需要完整 TUI、提供商和工具出口实测证据 --live-evidence",
              file=sys.stderr)
        return 2
    if supervisor_running():
        print("FAIL: 常驻监管器正在运行。验收探针需要独占子进程管道，请先停止防护。",
              file=sys.stderr)
        return 2
    pin = lab.load_pin(args.pin)
    binary = Path(args.exe or lab.installed_claude()).resolve(strict=True)
    try:
        lab.check_binary(pin, binary)
    except ValueError as error:
        print(f"FAIL: 二进制与 pin 不符：{error}", file=sys.stderr)
        return 2
    print(f"pin ok: version={pin['claude_code_version']} sha={pin['binary']['sha256'][:12]}…")
    dll = lab.ensure_dll(pin, binary)
    print(f"dll ok: {dll.name}")
    live_sha256 = None
    live_artifacts = {}
    if args.deploy:
        try:
            live_sha256, live_artifacts = verify_live_evidence(
                args.live_evidence, pin["binary"]["sha256"], lab.common.file_sha256(dll))
        except (OSError, ValueError, TypeError, AttributeError) as error:
            print(f"FAIL: 实机证据未通过核对：{error}", file=sys.stderr)
            return 2
    env = dict(os.environ)
    env["TTRACE_PIN"] = str(Path(args.pin).resolve())
    env.pop("TTRACE_CLAUDE_REDACT", None)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    evidence = EVIDENCE_DIR / f"{pin['binary']['sha256'][:12]}-"
    evidence = evidence.with_name(evidence.name + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".jsonl")
    passed, failed = 0, 0
    with open(evidence, "w", encoding="utf-8") as out:
        for script, case_args, extra in (FULL if args.suite == "full" else QUICK):
            case_env = {**env, **extra}
            record = run_case(script, case_args, extra, case_env)
            record["extra_env"] = sorted(extra)
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            out.flush()
            mark = "PASS" if record["result"] == "PASS" else "FAIL"
            if record["result"] == "PASS":
                passed += 1
            else:
                failed += 1
            print(f"  [{mark}] {script} {' '.join(case_args)}")
            if record["result"] != "PASS":
                for line in record.get("error_tail", []):
                    print(f"      {line}")
    verdict = failed == 0
    print(f"verdict: {'ACCEPT' if verdict else 'REJECT'} ({passed} passed, {failed} failed)")
    print(f"evidence: {evidence}")
    if verdict and args.deploy:
        for name, digest in live_artifacts.items():
            source = args.live_evidence.parent / name
            target_artifact = EVIDENCE_DIR / name
            if source.resolve() != target_artifact.resolve():
                shutil.copy2(source, target_artifact)
            if hashlib.sha256(target_artifact.read_bytes()).hexdigest() != digest:
                print(f"FAIL: 实机附件摘要不一致：{name}", file=sys.stderr)
                return 2
        live_copy = EVIDENCE_DIR / args.live_evidence.name
        if args.live_evidence.resolve() != live_copy.resolve():
            shutil.copy2(args.live_evidence, live_copy)
        if hashlib.sha256(live_copy.read_bytes()).hexdigest() != live_sha256:
            print("FAIL: 实机证据复制后摘要不一致", file=sys.stderr)
            return 2
        sources = lab.acceptance_source_hashes(ROOT)
        accepted = {
            "schema": "transpect.claude-guard-lab.accepted/2.0",
            "at": datetime.datetime.now().isoformat(timespec="seconds"),
            "suite": args.suite, "suite_version": SUITE_VERSION,
            "passed": passed, "failed": failed,
            "evidence": evidence.name,
            "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
            "dll": dll.name,
            "dll_sha256": lab.common.file_sha256(dll),
            "pin_core_sha256": pin["_sha256"], "sources": sources,
            "live_evidence": args.live_evidence.name,
            "live_evidence_sha256": live_sha256,
            "live_artifacts": live_artifacts,
            "binary_sha256": pin["binary"]["sha256"],
        }
        target = lab.pin_directory() / f"{pin['claude_code_version']}.json"
        deployed = {k: v for k, v in pin.items()
                    if not k.startswith("_") and k != "accepted"}
        deployed["accepted"] = accepted
        target.write_text(json.dumps(deployed, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
        print(f"deployed (accepted stamped): {target}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
