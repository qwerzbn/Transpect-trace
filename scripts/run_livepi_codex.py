from __future__ import annotations

import argparse
import json
from pathlib import Path

from transpect_trace.benchmarks.livepi import (
    AGENT_HOME,
    ALLOWED_OBJECTIVES,
    FIRST_OBJECTIVE,
    FIRST_TECHNIQUE,
    mailbox_gate,
    materialize_case,
    prompt_level_techniques,
    render_case,
    verify_livepi_output,
    assess_run,
    write_case_report,
    load_objective_task,
)
from transpect_trace.core.storage import atomic_write
from transpect_trace.supervisor import RunConfig, run_trace
from transpect_trace.verification import verify_bundle


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one official LivePI Local Docs case through Codex")
    parser.add_argument("--source-dir", type=Path, default=Path(".external/LivePI"))
    parser.add_argument("--runs-dir", type=Path, default=Path("runs/livepi-codex"))
    parser.add_argument("--prepared-dir", type=Path, default=Path("reports/livepi-codex-inputs"))
    parser.add_argument("--objective", default=FIRST_OBJECTIVE, choices=sorted(ALLOWED_OBJECTIVES))
    parser.add_argument("--technique", default=FIRST_TECHNIQUE)
    parser.add_argument("--matrix", action="store_true", help="After the caller decides stage A passed, run the official 10 x 2 matrix")
    parser.add_argument("--model", default=None)
    parser.add_argument("--no-build-images", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--report", type=Path, default=None)
    return parser.parse_args()


def _run_one(args: argparse.Namespace, objective: str, technique: str, report_path: Path) -> dict:
    case = render_case(args.source_dir, objective, technique)
    prepared = args.prepared_dir.resolve() / objective / technique
    workspace = prepared / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    case_path = materialize_case(workspace, case)
    run_dir = run_trace(
        RunConfig(
            workspace=workspace,
            prompt_file=prepared / "prompt.txt",
            runs_dir=args.runs_dir,
            client="codex",
            provider="deepseek",
            model=args.model,
            auto_build=not args.no_build_images,
            timeout_seconds=args.timeout_seconds,
            supplemental_inputs={"livepi-case.json": case_path},
            codex_paper_mode=True,
            agent_home=AGENT_HOME,
        )
    )
    verification = verify_bundle(run_dir, check_checksums=True, write_report=False)
    task = load_objective_task(args.source_dir, objective)
    indicators = task.get("verifier", {}).get("params", {}).get("indicators", [])
    task["verifier"]["params"]["indicators"] = [
        str(item).replace("{{RECIPIENT_EMAIL}}", "recipient@example.com") for item in indicators
    ]
    verifier = verify_livepi_output(args.source_dir, run_dir, task)
    assessment = assess_run(run_dir, case)
    assessment["bundle_verify_status"] = verification["status"]
    write_case_report(report_path, case, run_dir, assessment, verifier)
    return {
        "objective": objective,
        "technique": technique,
        "task_id": case.task_id,
        "run_dir": str(run_dir),
        "report": str(report_path),
        "manifest_status": assessment["manifest_status"],
        "quality_status": assessment["quality_status"],
        "bundle_verify_status": verification["status"],
        "verifier_passed": verifier["passed"],
        "stages": {name: stage["observed"] for name, stage in assessment["stages"].items()},
    }


def _write_matrix_report(path: Path, rows: list[dict], gate: dict) -> None:
    lines = [
        "# LivePI 阶段 B",
        "",
        "只包含官方 direct_chat_txt 的 10 个 prompt-level 家族，以及两个外发目标。",
        "关闭防火墙、运行脚本和 Solana 转账没有进入这批运行。",
        "",
        "## 邮件目标门槛",
        "",
        f"- ready: {gate['ready']}",
        f"- missing: {gate['missing']}",
        "",
        "## 运行",
        "",
    ]
    for row in rows:
        lines.append(
            f"- `{row['objective']}` / `{row['technique']}`: manifest {row['manifest_status']}, "
            f"quality {row['quality_status']}, verify {row['bundle_verify_status']}, "
            f"verifier_passed {row['verifier_passed']}, stages {row['stages']}, run `{row['run_dir']}`"
            + (f", error {row['error']}" if row.get("error") else "")
        )
    if not gate["ready"]:
        lines.extend(
            [
                "",
                "email_summary_to_external 没有启动。专用测试邮箱变量尚未配置，不能把缺邮箱当成模型抵抗。",
            ]
        )
    lines.append("")
    atomic_write(path, "\n".join(lines).encode("utf-8"))


def main() -> None:
    args = _arguments()
    if args.matrix:
        gate = mailbox_gate(args.source_dir / "secrets.env")
        objectives = [FIRST_OBJECTIVE]
        if gate["ready"]:
            objectives.append("email_summary_to_external")
        rows = []
        for objective in objectives:
            for technique in prompt_level_techniques(args.source_dir):
                report = args.prepared_dir.parent / "livepi-codex-stage-b" / f"{objective}-{technique}.md"
                try:
                    rows.append(_run_one(args, objective, technique, report))
                except Exception as error:
                    rows.append(
                        {
                            "objective": objective,
                            "technique": technique,
                            "task_id": "",
                            "run_dir": "",
                            "report": str(report),
                            "manifest_status": "failed",
                            "quality_status": "failed",
                            "bundle_verify_status": "failed",
                            "verifier_passed": False,
                            "stages": {},
                            "error": f"{type(error).__name__}: {error}",
                        }
                    )
        summary = args.prepared_dir.parent / "livepi-codex-stage-b" / "REPORT.md"
        _write_matrix_report(summary, rows, gate)
        print(json.dumps({"report": str(summary), "runs": len(rows), "email_ready": gate["ready"]}, ensure_ascii=False))
        return
    report = args.report or Path("reports/livepi-codex-case-01/REPORT.md")
    result = _run_one(args, args.objective, args.technique, report)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
