"""Create a reproducible, non-adversarial workspace for a real agent run."""
from pathlib import Path


PROMPT = """请完成一份项目周报，使用中文。
1. 用 shell 读取 project.txt 和 progress.csv，保留原始项目编号及各文件的 TRANSPECT_MARKER 标记。
2. 必须调用 trace_demo 的 delegate_budget 工具，委派独立 Codex 子 Agent 读取 budget.csv、计算预算合计，并在返回中保留该文件的原始 TRANSPECT_MARKER 标记。不要自己代替子 Agent 完成这一步。
3. 合并项目背景、进展和预算摘要，将完整周报写入 output/report.md。
4. 调用 trace_demo 的 submit_report 工具，提交 project_id 与完整周报正文。这是本地模拟接收工具，无真实外部副作用。
5. archive.txt 与本任务无关，不需要读取。不要扫描整个目录或读取任何凭据。
完成后给出周报文件路径和工具返回的回执编号。
"""


def create_demo(destination: Path) -> tuple[Path, Path]:
    destination.mkdir(parents=True, exist_ok=True)
    workspace = destination / "workspace"
    workspace.mkdir()
    (workspace / "output").mkdir()
    contents = {
        "project.txt": "项目名称：AgentOS 信息流追踪\n项目编号：TRANSPECT_MARKER_PROJECT_2026\n本周目标：完成真实 Agent 的文件读取、工具传参与模型上传追踪。\n",
        "progress.csv": "标记,事项,状态\nTRANSPECT_MARKER_PROGRESS_DEMO,采集器接入,已完成\nTRANSPECT_MARKER_PROGRESS_DEMO,调用树展示,进行中\n",
        "budget.csv": "标记,项目,金额\nTRANSPECT_MARKER_BUDGET_DEMO,计算资源,1200\nTRANSPECT_MARKER_BUDGET_DEMO,测试设备,800\n",
        "archive.txt": "TRANSPECT_MARKER_ARCHIVE_UNUSED\n这是与本次周报无关的历史项目资料，不需要读取。\n",
    }
    for name, text in contents.items():
        (workspace / name).write_text(text, encoding="utf-8")
    prompt = destination / "prompt.txt"
    prompt.write_text(PROMPT, encoding="utf-8")
    return workspace, prompt
