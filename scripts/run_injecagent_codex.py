from __future__ import annotations

import argparse
import json
from pathlib import Path

from transpect_trace.benchmarks.injecagent import build_case_bundle, case_prompt, select_diverse_cases
from transpect_trace.core.storage import atomic_write
from transpect_trace.supervisor import RunConfig, run_trace


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run official InjecAgent cases through Codex and Transpect Trace")
    parser.add_argument("--source-dir", type=Path, default=Path(".external/InjecAgent"))
    parser.add_argument("--runs-dir", type=Path, default=Path("runs/injecagent-codex"))
    parser.add_argument("--prepared-dir", type=Path, default=Path("reports/injecagent-codex-inputs"))
    parser.add_argument("--case", type=int, default=1, help="1-based case within the reproducible diverse-20 selection")
    parser.add_argument("--model", default=None)
    parser.add_argument("--no-build-images", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    selected = select_diverse_cases(args.source_dir, 20)
    if not 1 <= args.case <= len(selected):
        raise SystemExit(f"--case must be between 1 and {len(selected)}")
    case = selected[args.case - 1]
    prepared = args.prepared_dir.resolve() / f"case-{args.case:02d}"
    workspace = prepared / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    atomic_write(workspace / "README.txt", b"Isolated InjecAgent MCP benchmark workspace.\n")
    prompt_file = prepared / "prompt.txt"
    case_file = prepared / "injecagent-case.json"
    atomic_write(prompt_file, (case_prompt(case) + "\n").encode("utf-8"))
    atomic_write(
        case_file,
        (json.dumps(build_case_bundle(args.source_dir, case, args.case), ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    run_dir = run_trace(
        RunConfig(
            workspace=workspace,
            prompt_file=prompt_file,
            runs_dir=args.runs_dir,
            client="codex",
            provider="deepseek",
            model=args.model,
            auto_build=not args.no_build_images,
            timeout_seconds=args.timeout_seconds,
            benchmark_case_file=case_file,
        )
    )
    print(run_dir)


if __name__ == "__main__":
    main()

