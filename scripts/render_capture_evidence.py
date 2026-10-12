"""Render screenshots of real Gateway captures for the progress report.

Every value on the cards is read from an evidence bundle under runs/; nothing is typed in.
Usage: uv run python scripts/render_capture_evidence.py
"""

from __future__ import annotations

import html
import json
import subprocess
from pathlib import Path
from typing import Any

from transpect_trace.core.storage import TraceBundle

ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "docs" / "figures"
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")

CARDS = [
    {
        "file": "capture-codex-desktop",
        "title": "Codex 桌面版 · Windows",
        "run": ROOT / "runs/desktop-gateway/desktop-gateway-20261012",
        "match": lambda row: "Codex Desktop" in row["headers"].get("user-agent", "") and row["method"] == "POST",
        "evidence": "runs/desktop-gateway/desktop-gateway-20261012",
    },
    {
        "file": "capture-codex-cli-windows",
        "title": "Codex 命令行 · Windows 原生",
        "run": ROOT / "runs/host/2d394a68-3354-427f-bd88-af2212b6c680",
        "match": lambda row: row["method"] == "POST",
        "evidence": "runs/host/2d394a68-3354-427f-bd88-af2212b6c680",
    },
    {
        "file": "capture-claude-code",
        "title": "Claude Code · Linux 容器",
        "run": ROOT / "runs/1249df72-32b8-4f8a-81aa-64679957c29f",
        "match": lambda row: row["method"] == "POST",
        "evidence": "runs/1249df72-32b8-4f8a-81aa-64679957c29f",
    },
]


def _rows(run: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (run / "raw/gateway/events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def _user_text(body: dict[str, Any]) -> str:
    for item in reversed(body.get("input") or body.get("messages") or []):
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content")
        if isinstance(content, str):
            return content
        texts = [part.get("text", "") for part in content or [] if isinstance(part, dict) and part.get("type") in {"input_text", "text"}]
        if texts:
            return texts[-1]
    return ""


def _tool_output(body: dict[str, Any]) -> str:
    for item in reversed(body.get("input") or []):
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            output = item.get("output")
            return output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
    for message in reversed(body.get("messages") or []):
        for part in message.get("content") or [] if isinstance(message.get("content"), list) else []:
            if isinstance(part, dict) and part.get("type") == "tool_result":
                content = part.get("content")
                if isinstance(content, list):
                    return "\n".join(str(block.get("text", "")) for block in content if isinstance(block, dict))
                return str(content)
    return ""


def _readable_lines(text: str, needles: tuple[str, ...]) -> str:
    # The PowerShell error was GBK text decoded as UTF-8 by the client, so it reached
    # the request as mojibake; show only the lines a reader can check.
    lines = [line.rstrip() for line in text.splitlines()]
    picked = [line for line in lines if any(needle in line for needle in needles)]
    return "\n…\n".join(dict.fromkeys(picked))


def _tool_names(body: dict[str, Any]) -> list[str]:
    names = []
    for tool in body.get("tools") or []:
        names.append(str(tool.get("name") or (tool.get("function") or {}).get("name") or tool.get("type")))
    return names


def _answer(raw: bytes) -> str:
    parts: list[str] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.startswith("data:"):
            continue
        try:
            data = json.loads(line[5:])
        except ValueError:
            continue
        if data.get("type") == "response.output_text.delta":
            parts.append(str(data.get("delta", "")))
        elif data.get("type") == "content_block_delta" and (data.get("delta") or {}).get("type") == "text_delta":
            parts.append(str(data["delta"].get("text", "")))
    return "".join(parts)


def _clip(text: str, limit: int) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + " …"


def _requests(card: dict[str, Any]) -> list[dict[str, Any]]:
    bundle = TraceBundle(card["run"], initialize=False)
    rows = _rows(card["run"])
    endings = {row["request_id"]: row for row in rows if row["kind"] in {"model.response.completed", "model.request.failed"}}
    selected = []
    for row in rows:
        if row["kind"] != "model.request" or not card["match"](row):
            continue
        body = json.loads(bundle.read_blob(row["content"]))
        ending = endings.get(row["request_id"], {})
        selected.append({
            "row": row,
            "body": body,
            "status": ending.get("status"),
            "chunks": ending.get("chunks"),
            "answer": _answer(bundle.read_blob(ending["content"])) if ending.get("content") else "",
        })
    return selected


def _kv(label: str, value: str, mono: bool = True) -> str:
    cls = "v mono" if mono else "v"
    return f'<div class="k">{html.escape(label)}</div><div class="{cls}">{html.escape(value)}</div>'


def _request_block(
    item: dict[str, Any],
    heading: str,
    *,
    tool_needles: tuple[str, ...] = (),
    user_tail: bool = False,
    user_limit: int = 160,
) -> str:
    row, body = item["row"], item["body"]
    tools = _tool_names(body)
    user = _user_text(body).strip()
    user = ("… " + user[-user_limit:]) if user_tail and len(user) > user_limit else _clip(user, user_limit)
    parts = [
        f'<div class="req"><div class="reqhead">{html.escape(heading)}</div><div class="grid">',
        _kv("时间", row["captured_at"]),
        _kv("请求", f'{row["method"]} {row["path"]}'),
        _kv("User-Agent", row["headers"].get("user-agent", "")),
        _kv("正文", f'{row["content"]["bytes"]:,} 字节 · {row["content"]["sha256"][:23]}…'),
        _kv("模型", str(body.get("model"))),
        _kv("工具定义", f'{len(tools)} 个' + (f'：{", ".join(tools[:6])}{" …" if len(tools) > 6 else ""}' if tools else "")),
        _kv("用户输入", user, mono=False),
    ]
    if tool_needles:
        parts.append(_kv("工具返回（摘录，原样进入请求）", _readable_lines(_tool_output(body), tool_needles)))
    status = f'HTTP {item["status"]} · {item["chunks"]} 个流式分片' if item["status"] else "无返回"
    parts.append(_kv("返回", status))
    if item["answer"]:
        parts.append(_kv("模型回答", _clip(item["answer"], 160), mono=False))
    parts.append("</div></div>")
    return "".join(parts)


STYLE = """
body{margin:0;background:#f4f6fa;font-family:'Microsoft YaHei','Segoe UI',sans-serif;color:#1d2a3a}
.card{margin:22px;background:#fff;border:1px solid #d5dde8;border-radius:10px;padding:22px 26px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:#5a6b80;font-size:13px;margin-bottom:14px}
.req{border-top:1px solid #e3e8ef;padding-top:12px;margin-top:12px}
.reqhead{font-weight:bold;font-size:15px;margin-bottom:8px;color:#21456e}
.grid{display:grid;grid-template-columns:230px 1fr;row-gap:6px;column-gap:14px;font-size:13px}
.k{color:#5a6b80}
.v{white-space:pre-wrap;word-break:break-all}
.mono{font-family:Consolas,'Cascadia Mono',monospace;font-size:12.5px}
.note{margin-top:14px;font-size:12.5px;color:#5a6b80}
"""


def _page(card: dict[str, Any], blocks: list[str], note: str) -> str:
    return (
        f"<!doctype html><html><head><meta charset='utf-8'><style>{STYLE}</style></head><body><div class='card'>"
        f"<h1>{html.escape(card['title'])}</h1>"
        f"<div class='sub'>Gateway 在转发前记录的真实请求 · 证据目录 {html.escape(card['evidence'])}</div>"
        + "".join(blocks)
        + f"<div class='note'>{html.escape(note)}</div></div></body></html>"
    )


def _screenshot(page: Path, png: Path, height: int) -> None:
    subprocess.run(
        [str(EDGE), "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--window-size=1200,{height}",
         f"--screenshot={png}", page.as_uri()],
        check=True, capture_output=True, timeout=120,
    )


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    desktop, cli, claude = CARDS
    desktop_requests = _requests(desktop)
    chat = next(item for item in desktop_requests if item["status"] == 200)
    title = next(item for item in desktop_requests if item is not chat)
    pages = [
        (desktop, [
            _request_block(chat, "对话请求"),
            _request_block(title, "生成标题的辅助请求（同一句输入再次发出）", user_tail=True, user_limit=110),
        ], "用户只发了一条消息，Gateway 抓到两次请求；标题请求使用桌面版固定的 gpt-6-luna，DeepSeek 不认识该模型，返回 400。", 720),
        (cli, [
            _request_block(_requests(cli)[-1], "第二次请求：带着工具读取的文件内容",
                           tool_needles=("Process exited", "WindowsPowerShell\\profile.ps1 :", "DotSourceNotSupported",
                                         "TRANSPECT_MARKER", "This file contains")),
        ], "Codex 在只读沙箱里用 PowerShell 读取 public.txt。命令输出里既有文件内容，也有本机 PowerShell 配置文件路径和报错，两者一起进入了模型请求。", 600),
        (claude, [
            _request_block(_requests(claude)[-1], "最后一次请求：带着工具读取的文件内容",
                           tool_needles=("TRANSPECT_MARKER", "This file contains")),
        ], "Claude Code 通过 ANTHROPIC_BASE_URL 指向 Gateway，请求为 Anthropic Messages 格式。", 470),
    ]
    for card, blocks, note, height in pages:
        page = FIGURES / f"{card['file']}.html"
        page.write_text(_page(card, blocks, note), encoding="utf-8")
        png = FIGURES / f"{card['file']}.png"
        _screenshot(page, png, height)
        print(png)


if __name__ == "__main__":
    main()
