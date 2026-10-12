"""File-first projections shared by controlled runs and desktop listeners."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from transpect_trace.core.storage import atomic_write


def tree_text(nodes: list[dict[str, Any]], title: str) -> str:
    by_id = {n["id"]: n for n in nodes}
    children: dict[str | None, list[dict[str, Any]]] = {}
    for n in nodes:
        parent = n.get("parent") if n.get("parent") in by_id else None
        children.setdefault(parent, []).append(n)
    lines = [title]
    seen: set[str] = set()
    def walk(n: dict[str, Any], prefix: str, last: bool) -> None:
        if n["id"] in seen:
            lines.append(prefix + "└── [cycle] " + n["id"])
            return
        seen.add(n["id"])
        lines.append(prefix + ("└── " if last else "├── ") + n["label"].replace("\n", " "))
        nested = children.get(n["id"], [])
        for index, child in enumerate(nested):
            walk(child, prefix + ("    " if last else "│   "), index == len(nested) - 1)
    roots = children.get(None, [])
    for index, root in enumerate(roots):
        walk(root, "", index == len(roots) - 1)
    for n in nodes:
        if n["id"] not in seen:
            walk(n, "", True)
    return "\n".join(lines) + "\n"


def export_data(data: dict[str, Any], directory: Path, *, html: bool = False) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    data = dict(data)
    if data.get('revision') is None:
        data['revision'] = time.time_ns()
    status = dict(revision=data['revision'], run_id=data.get('manifest', {}).get('run_id'),
                  status=data.get('manifest', {}).get('status'), coverage=data.get('coverage', {}))
    atomic_write(directory / 'status.json', json.dumps(dict(status, phase='writing')).encode())
    agents = [{**a, "kind": "agent"} for a in data.get("agents", [])]
    agent_ids = {a["id"].removeprefix("agent:"): a["id"] for a in agents}
    call_nodes = agents + [{**t, "kind": "tool", "parent": agent_ids.get(t.get("agent_id"), "agent:main")} for t in data.get("tools", [])]
    processes = data.get("processes", [])
    coverage = data.get("coverage", {})
    documents = {
        "trace.json": data,
        "agent-tree.json": {"schema": "transpect.tree/1.0", "kind": "agent_calls", "coverage": coverage, "nodes": call_nodes},
        "process-tree.json": {"schema": "transpect.tree/1.0", "kind": "os_processes", "coverage": coverage, "nodes": processes},
        "data-flow.json": {"schema": "transpect.flow/1.0", "coverage": coverage, "nodes": data.get("nodes", []), "edges": data.get("edges", []),
                           "provenance": data.get("provenance", {}), "limits": data.get("limits", [])},
    }
    # status is the last-written commit marker. Readers comparing revisions
    # can retry if a multi-file generation was in progress.
    for name, value in documents.items():
        atomic_write(directory / name, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
    atomic_write(directory / "agent-tree.txt", tree_text(call_nodes, "Agent 调用树").encode())
    atomic_write(directory / "process-tree.txt", tree_text(processes, "系统进程树（含线程；采集范围见 process-tree.json）").encode())
    if html:
        template = Path(__file__).with_name("report.html").read_text(encoding="utf-8")
        payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
        atomic_write(directory / "index.html", template.replace("__TRACE_DATA__", payload).encode())
    atomic_write(directory / 'status.json', (json.dumps(dict(status, phase='ready'), ensure_ascii=False, indent=2) + '\n').encode())
    return directory


def export_run(root: Path, *, html: bool = False) -> Path:
    from transpect_trace.reporting import project_report, report_path
    return export_data(project_report(root), report_path(root).parent, html=html)
