"""Claude Code 固定版门控：CodeX 场景映射验收（PII 输入 / AGENTS.md 注入）。

在 probe_claude_inprocess_lab 的隔离框架上新增两个场景：
  pii_deny     — 用户输入含姓名、身份证号、银行卡号、手机号、地址，发送前拒绝；
  agents_md_deny — 工作目录 AGENTS.md 含合成 GitHub 令牌，项目指令随 system
                 条目上行时被识别，发送前拒绝。

验收口径与基线探针一致：DLP 判定、加密归档、本地不转发源站三方核对；
拒绝样本要求源站应用字节为 0，普通样本要求三方摘要一致。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import probe_claude_inprocess_lab as base  # noqa: E402  (scripts 目录同层)
from _build_support import ROOT  # noqa: E402

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import claude_service as lab  # noqa: E402
from transpect_trace.protect.archive import EncryptedRequestArchive  # noqa: E402

FAKE_KEY = "ghp_" + "a1B2c3D4e5F6g7H8iJ9J0k1L2m3N4o5P6q7R8"
ID_CARD = "11010519491231002X"  # GB 11643 校验位有效的公开测试样例
BANK_CARD = "4111111111111111"  # Luhn 有效
PHONE = "13800138000"
PII_PROMPT = (
    "请原样回复以下信息。我的姓名是张三，身份证号是{id}，"
    "银行卡号是{card}，手机号是{phone}，家庭住址是北京市朝阳区建国路88号。"
).format(id=ID_CARD, card=BANK_CARD, phone=PHONE)
AGENTS_MD = "# 内部项目说明\n\n部署令牌：{key}\n\n请勿将令牌外传或写入代码。".format(key=FAKE_KEY)


@dataclass(frozen=True)
class Case:
    name: str
    auth: str
    system: str
    marker: str
    prompt: str
    denied: bool
    agents_md: str | None = None


CASES = (
    Case("pii_deny", "bearer", "You are concise.", ID_CARD, PII_PROMPT, True),
    Case("agents_md_deny", "bearer", "You are concise.", FAKE_KEY,
         "Reply briefly. OK", True, agents_md=AGENTS_MD),
)


def run_case(case: Case, binary: Path, openssl: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="ttrace-cc-lab-") as temp:
        directory = Path(temp)
        system = directory / "system.txt"
        system.write_text(case.system, encoding="utf-8")
        if case.agents_md is not None:
            (directory / "AGENTS.md").write_text(case.agents_md, encoding="utf-8")
        origin = base.LocalTlsOrigin(directory, openssl, case.auth, case.marker)
        try:
            env = base.isolated_env(directory, origin, case.auth)
            prompt = case.prompt.encode("utf-8")
            state = directory / "state"
            exit_code = lab.run_print(
                prompt, binary=binary, state_dir=state, child_env=env,
                child_cwd=directory,
                child_args=("--tools", "", "--system-prompt-file", str(system)))
            origin.close()
            records = origin.snapshot()
            run_dirs = list((state / "runs").iterdir())
            if len(run_dirs) != 1:
                raise AssertionError(f"expected one native run directory, found {len(run_dirs)}")
            run_dir = run_dirs[0]
            audit = run_dir / "native-audit.jsonl"
            rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            envelopes = [row for row in rows if row.get("route_event") == "model.request"
                         and row.get("category") == "request_envelope"]
            if len(envelopes) != 1:
                raise AssertionError(f"expected one DLP envelope, found {len(envelopes)}")
            row = envelopes[0]
            receipt, archived = EncryptedRequestArchive(run_dir / "archive").read(
                row["archive_record_id"])
            digest = hashlib.sha256(archived).hexdigest()
            marker_offset = archived.find(case.marker.encode())
            expected_decision = "deny" if case.denied else "allow"
            if row["decision"] != expected_decision:
                collection = run_dir / "collection.jsonl"
                blocked = []
                if collection.exists():
                    for line in collection.read_text(encoding="utf-8").splitlines():
                        item = json.loads(line)
                        if item.get("actionable_decision") == "BLOCK":
                            blocked.append({"category": item.get("category"),
                                            "location": item.get("location"),
                                            "rules": item.get("matched_rule_ids")})
                raise AssertionError(f"DLP decision was {row['decision']} "
                                     f"({row.get('reason')}), expected {expected_decision}; "
                                     f"blocked={blocked[:4]}")
            if digest != row["request_sha256"] or digest != receipt.body_sha256:
                raise AssertionError("DLP audit and encrypted archive hashes differ")
            if len(archived) != row["content_bytes"]:
                raise AssertionError("DLP body length differs from encrypted archive")
            if marker_offset < 0:
                raise AssertionError("synthetic marker is absent from the captured body")
            if case.denied:
                if any(record["app_bytes"] for record in records):
                    raise AssertionError("denied request sent TLS application bytes upstream")
            return {"case": case.name, "exit": exit_code, "decision": row["decision"],
                    "body_bytes": len(archived), "marker_offset": marker_offset,
                    "audit_sha256": row["request_sha256"], "archive_sha256": digest,
                    "upstream_app_bytes": sum(record["app_bytes"] for record in records)}
        finally:
            origin.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--case", action="append", choices=[c.name for c in CASES])
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("the native guard and encrypted archive require Windows")
    openssl = shutil.which("openssl")
    if not openssl:
        parser.error("openssl is required for the isolated HTTPS certificate")
    binary = (args.binary or lab.installed_claude()).resolve(strict=True)
    lab.check_binary(lab.load_pin(), binary)
    selected = [c for c in CASES if not args.case or c.name in args.case]
    failed = False
    for case in selected:
        try:
            result = run_case(case, binary, openssl)
            print(json.dumps({"result": "PASS", **result}, sort_keys=True), flush=True)
        except Exception as error:
            failed = True
            print(json.dumps({"result": "FAIL", "case": case.name,
                              "error": f"{type(error).__name__}: {error}"}),
                  file=sys.stderr, flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
