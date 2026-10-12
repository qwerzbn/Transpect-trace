"""Read-only, evidence-backed report projection. No invented causal edges."""
from __future__ import annotations

import json
import re
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from typing import Any

from transpect_trace.core.storage import TraceBundle, atomic_write


def jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def report_path(root: Path) -> Path:
    # Derived reports are outside sealed evidence; rebuilding never reseals or
    # modifies the original run (including pre-existing experimental bundles).
    return root.parent / "trace-reports" / root.name / "index.html"


def project_report(root: Path, *, event_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    root = root.resolve()
    bundle = TraceBundle(root, initialize=False)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    events = event_rows if event_rows is not None else jsonl(root / "normalized/events.jsonl")
    quality_path = root / "quality/trace-quality.json"
    quality = json.loads(quality_path.read_text(encoding="utf-8")) if quality_path.exists() else {}
    details: dict[str, Any] = {}
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    files: dict[str, dict[str, Any]] = {}
    processes: dict[str, dict[str, Any]] = {}
    agents: dict[str, dict[str, Any]] = {"main": {"id": "agent:main", "label": "主 Agent", "parent": None, "children": []}}
    tools: dict[str, dict[str, Any]] = {}
    requests: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    patterns: dict[str, list[tuple[str, str]]] = {}
    event_times = {e["event_id"]: datetime.fromisoformat(e["time"]["wall"].replace("Z", "+00:00")) for e in events}
    final_available: dict[str, datetime] = {}

    def node(id: str, label: str, kind: str, evidence: Any = None) -> None:
        nodes[id] = {"id": id, "label": label, "kind": kind}
        if evidence is not None:
            details[id] = evidence

    def edge(source: str, target: str, label: str, evidence: str, method: str) -> None:
        row = dict(source=source, target=target, label=label, evidence=evidence, method=method)
        if row not in edges:
            edges.append(row)

    def file(path: str) -> dict[str, Any]:
        if path not in files:
            files[path] = dict(id="file:" + path, path=path, reads=[], opens=[], writes=[], requests=[], tools=[], references=[], delegations=[])
            node("file:" + path, path, "file")
        return files[path]

    source = root / "input/workspace"
    if source.is_dir():
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(source).as_posix()
            entry = file(relative)
            entry["initial_bytes"] = path.stat().st_size
            if path.stat().st_size > 2 * 1024 * 1024:
                entry["content_matching"] = "skipped: file larger than 2 MiB"
                continue
            data = path.read_bytes()
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                entry["content_matching"] = "unsupported: binary"
                continue
            markers = sorted(set(re.findall(r"TRANSPECT_MARKER_[A-Z0-9_]+", text)))
            candidates = [(marker, "exact_marker") for marker in markers]
            candidates += [(line.strip(), "exact_text") for line in text.splitlines() if len(line.strip()) >= 24]
            patterns[relative] = list(dict.fromkeys(candidates))
            entry["content_matching"] = "initial snapshot; exact UTF-8 text/marker occurrence only"

    def workspace_path(target: str | None) -> str | None:
        if target and target.startswith("/workspace/"):
            return target[len("/workspace/"):].removesuffix(" (deleted)")
        return None

    # Build real system trees from fork evidence, not time proximity. Scope is
    # part of identity because gateway and agent have different PID namespaces.
    for event in events:
        if event["source"]["collector"] != "system.strace":
            continue
        attributes, correlation = event["attributes"], event["correlation"]
        scope = attributes.get("process_scope") or ("gateway" if attributes.get("source_file", "").startswith("gateway-") else "agent")
        pid = correlation.get("pid")
        if pid is None:
            continue
        key = f"process:{scope}:{pid}"
        process = processes.setdefault(key, dict(id=key, pid=pid, scope=scope, parent=None, label=f"PID {pid}",
                                                thread=False, events=[], files=[], commands=[], start=event["time"]["wall"]))
        kind, target = event["kind"], event["operation"].get("target")
        result = attributes.get("result")
        if kind == "system.process.forked" and isinstance(result, int) and result > 0:
            child_key = f"process:{scope}:{result}"
            child = processes.setdefault(child_key, dict(id=child_key, pid=result, scope=scope, parent=key,
                         label=f"PID {result}", thread=False, events=[], files=[], commands=[], start=event["time"]["wall"]))
            child["parent"] = key
            child["thread"] = "CLONE_THREAD" in attributes.get("args", "")
            child["fork_evidence"] = event["event_id"]
        if kind == "system.process.started" and result == 0:
            process["label"] = f"{str(target).rsplit('/', 1)[-1]} · PID {pid}"
            process["executable"] = target
            process["commands"].append(attributes.get("args"))
        if kind.startswith("system.process."):
            process["events"].append(event["event_id"])
            details[event["event_id"]] = event
        if kind == "system.process.exited":
            process["exit_code"] = result
        relative = workspace_path(target) if scope == "agent" else None
        if relative is not None and (root / "workspace" / relative).is_dir():
            relative = None
        if relative is not None and kind in {"system.file.read", "system.file.opened", "system.file.write"}:
            entry = file(relative)
            details[event["event_id"]] = event
            if kind == "system.file.read" and isinstance(result, int) and result > 0:
                entry["reads"].append(event["event_id"])
                if relative not in process["files"]:
                    process["files"].append(relative)
                edge(entry["id"], key, "成功读取", event["event_id"], "syscall_return")
                timeline.append(dict(id=event["event_id"], time=event["time"]["wall"], label=f"读取 {relative} · {result} bytes · PID {pid}", kind="read"))
            elif kind == "system.file.opened":
                entry["opens"].append(dict(event=event["event_id"], result=result))
            elif kind == "system.file.write" and isinstance(result, int) and result > 0:
                entry["writes"].append(event["event_id"])
                edge(key, entry["id"], "成功写入", event["event_id"], "syscall_return")
    for process in processes.values():
        node(process["id"], process["label"], "process", process.copy())

    # For newly generated files, a final-snapshot occurrence is a separate,
    # explicitly named candidate. Never match it to an event preceding its
    # last observed write, and never replace an initial file's version.
    for relative, entry in files.items():
        if "initial_bytes" in entry or not entry["writes"]:
            continue
        path = root / "workspace" / relative
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        final_available[relative] = max(event_times[eid] for eid in entry["writes"])
        markers = sorted(set(re.findall(r"TRANSPECT_MARKER_[A-Z0-9_]+", text)))
        patterns[relative] = [(value, "exact_marker_final_snapshot") for value in markers]
        patterns[relative] += [(line.strip(), "exact_text_final_snapshot") for line in text.splitlines() if len(line.strip()) >= 24]
        entry["content_matching"] = "final snapshot of generated file; only after last observed write; candidate occurrence, not proven source"

    terminals: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["kind"] in {"model.response.started", "model.response.completed", "model.request.failed", "model.request.blocked"}:
            terminals[event["correlation"].get("request_id", "")].append(event)

    def matches(payload: Any, target: str, category: str, evidence: str, label: str = "原文匹配（来源候选）") -> None:
        # JSON decode happens before matching; escaping does not hide Chinese
        # text/newlines. Restrict requests to message input, excluding schemas.
        strings: list[str] = []
        def visit(value: Any) -> None:
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, dict):
                for v in value.values():
                    visit(v)
            elif isinstance(value, list):
                for v in value:
                    visit(v)
        visit(payload)
        for path, candidates in patterns.items():
            if path in final_available and (evidence not in event_times or event_times[evidence] < final_available[path]):
                continue
            hit = next(((value, method) for value, method in candidates if any(value in text for text in strings)), None)
            if hit:
                entry = files[path]
                entry[category].append(dict(target=target, evidence=evidence, method=hit[1], matched=hit[0]))
                edge(entry["id"], target, "最终快照匹配（来源候选）" if path in final_available else label, evidence, hit[1])
            elif category == "tools" and any(path in text for text in strings):
                files[path]["references"].append(dict(target=target, evidence=evidence, note="仅路径引用，不证明内容传递"))

    for event in events:
        kind, a, eid = event["kind"], event["attributes"], event["event_id"]
        time = event["time"]["wall"]
        agent_id = a.get("agent_id") or "main"
        if kind == "demo.agent.started":
            key = a["agent_id"]
            agents[key] = dict(id="agent:" + key, label="子 Agent · " + key, parent="agent:main", children=[],
                               implementation=a.get("implementation"), pid=a.get("child_pid"), invocation=a.get("invocation_id"))
            details["agent:" + key] = a
            node("receipt:" + a["invocation_id"], "本地接收 · delegate_budget", "receipt")
            edge("receipt:" + a["invocation_id"], "agent:" + key, "工具创建独立子 Agent", eid, "explicit_invocation_id")
            timeline.append(dict(id=eid, time=time, label="创建独立 Codex 子 Agent", kind="agent"))
        if kind == "client.session.started":
            agents.setdefault(agent_id, dict(id="agent:" + agent_id, label=agent_id, parent=None, children=[]))["thread_id"] = event["correlation"].get("session_id")
        if kind.startswith("client.tool."):
            item = a.get("event", {}).get("item", {})
            call_id = event["correlation"].get("tool_call_id") or eid
            key = f"tool:{agent_id}:{call_id}"
            tool = tools.setdefault(key, dict(id=key, agent_id=agent_id, label=event["operation"].get("target") or "tool", events=[], time=time))
            tool["events"].append(eid)
            tool["state"] = kind.rsplit(".", 1)[-1]
            tool["item"] = item
            node(key, str(tool["label"])[:100], "tool", tool.copy())
            details[eid] = event
            if kind == "client.tool.started":
                timeline.append(dict(id=key, time=time, label=str(tool["label"])[:160], kind="tool"))
            if item.get("arguments") is not None:
                matches(item["arguments"], key, "tools", eid)
            elif item.get("command"):
                matches({"command": item["command"]}, key, "tools", eid)
        if kind == "model.request":
            request_id = event["correlation"]["request_id"]
            key = "request:" + request_id
            terminal = terminals[request_id]
            received = any(t["kind"] in {"model.response.started", "model.response.completed"} for t in terminal)
            blocked = any(t["kind"] == "model.request.blocked" for t in terminal)
            status = "已获上游响应" if received else "转发前已拦截" if blocked else "转发结果未确认"
            row = dict(id=key, agent_id=agent_id, label=f"模型请求 {len(requests)+1} · {status}", status=status, time=time,
                       request_id=request_id, evidence=eid, upstream=a.get("upstream", manifest.get("provider")), terminal_events=[t["event_id"] for t in terminal])
            requests.append(row)
            payload: Any = None
            try:
                payload = json.loads(bundle.read_blob(event["content"]))
                input_value = payload.get("input", payload.get("messages", []))
                matches(input_value, key, "requests", eid)
            except (OSError, ValueError):
                row["payload_unavailable"] = True
            node(key, row["label"], "request", dict(event=event, terminal=terminal, payload_preview=str(json.dumps(payload, ensure_ascii=False))[:12000], preview_truncated=len(json.dumps(payload, ensure_ascii=False)) > 12000))
            details[eid] = event
            timeline.append(dict(id=key, time=time, label=row["label"] + " · " + agent_id, kind="model"))
            if received:
                node("upstream", "模型服务 · " + manifest["provider"], "upstream")
                edge(key, "upstream", "上游响应证明接收", terminal[0]["event_id"], "upstream_response")
        if kind in {"demo.tool.received", "demo.sink.received"}:
            key = "receipt:" + a["invocation_id"]
            label = "本地接收 · " + a.get("tool_name", "tool")
            node(key, label, "receipt", a)
            matches(a.get("arguments", {}), key, "tools", eid)
            timeline.append(dict(id=key, time=time, label=label, kind="receipt"))
        if kind.startswith("demo."):
            details[eid] = event
        if kind == "demo.agent.completed":
            key = a.get("agent_id")
            if key in agents:
                agents[key]["return_code"] = a.get("return_code")
                agents[key]["completed_evidence"] = eid
                agents[key]["response_preview"] = str(a.get("response", ""))[:6000]
                matches(a.get("response", ""), "agent:main", "delegations", eid, "子 Agent 返回中出现（来源候选）")

    for agent_id, agent in agents.items():
        agent["children"] = [t["id"] for t in tools.values() if t["agent_id"] == agent_id]
        agent["requests"] = [r["id"] for r in requests if r["agent_id"] == agent_id]
        node(agent["id"], agent["label"], "agent", {**details.get(agent["id"], {}), **agent})
    child_roots = {f"process:agent:{a['pid']}": a['id'] for a in agents.values() if a.get('pid')}
    for process in processes.values():
        ancestor, seen = process["id"], set()
        while ancestor and ancestor not in seen:
            seen.add(ancestor)
            if ancestor in child_roots:
                process["agent_id"] = child_roots[ancestor]
                process["ownership_method"] = "explicit_child_pid_and_fork_ancestry"
                break
            ancestor = processes.get(ancestor, {}).get("parent")
        details[process["id"]] = process.copy()
    for entry in files.values():
        # Do not label an unobserved read as "not read": mmap/direct syscalls,
        # truncated traces, etc. remain coverage limitations.
        entry["read_status"] = "已观察到成功读取" if entry["reads"] else "未观察到成功读取"
        details[entry["id"]] = entry
    timeline.sort(key=lambda row: row["time"])
    result = dict(schema="transpect.report/1.0", manifest=manifest, quality=quality, evidence_root=str(root),
                prompt=(root / "input/prompt.txt").read_text(encoding="utf-8") if (root / "input/prompt.txt").exists() else "",
                files=list(files.values()), processes=list(processes.values()), agents=list(agents.values()), tools=list(tools.values()),
                requests=requests, nodes=list(nodes.values()), edges=edges, details=details, timeline=timeline,
                limits=["原文匹配证明内容出现；改写传播用保守的可能依赖标签，不能证明语义来源或逐字节流向。",
                        "匹配初始 UTF-8 快照（≤2 MiB）；新生成文件用最终快照，只匹配最后观察到写入之后的事件。修改后的版本不作精确归因。",
                        "系统树基于容器内 strace fork/exec 证据，线程可单独显示；Agent 委派树与系统树不同。",
                        "模型服务接收与本地 MCP 接收分别标注；本地回执不是互联网外发。",
                        "无读取证据不等于未读取；mmap、截断、丢事件与采集盲区均可能影响覆盖率。",
                        "Demo 子 Agent 是独立 Codex subprocess；原生委派事件如有会保留，但跨原生子线程关联尚未完整支持。"])
    from transpect_trace.provenance import controlled_provenance
    result["provenance"] = controlled_provenance(bundle, events, result)
    result["coverage"] = {"mode": "controlled_run", "file_reads": "strace + Frida", "model_requests": "gateway",
                          "rewrite_tracking": "conservative_possible_dependency", "native_subagent_coverage": "partial"}
    return result


def build_report(run_dir: Path | str, output: Path | None = None) -> Path:
    root = Path(run_dir).resolve()
    data = project_report(root)
    destination = (output or report_path(root)).resolve()
    template = Path(__file__).with_name("report.html").read_text(encoding="utf-8")
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    atomic_write(destination, template.replace("__TRACE_DATA__", payload).encode("utf-8"))
    atomic_write(destination.with_suffix(".json"), (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return destination


def validate_demo(run_dir: Path | str) -> dict[str, Any]:
    """Separate task acceptance from collector quality and model resistance."""
    root = Path(run_dir).resolve()
    data = project_report(root)
    raw = jsonl(root / "raw/client/demo-events.jsonl")
    files = {entry["path"]: entry for entry in data["files"]}
    children = [a for a in data["agents"] if a["id"] != "agent:main"]
    budget = files.get("budget.csv", {})
    checks = {
        "run_complete": data["manifest"]["status"] == "complete",
        "quality_complete": data["quality"].get("status") == "complete",
        "project_read": bool(files.get("project.txt", {}).get("reads")),
        "progress_read": bool(files.get("progress.csv", {}).get("reads")),
        "budget_read": bool(budget.get("reads")),
        "child_thread_captured": any(a.get("thread_id") for a in children),
        "child_model_request_captured": any(a.get("requests") for a in children),
        "child_completed": any(row["kind"] == "agent.completed" and row.get("return_code") == 0 for row in raw),
        "budget_in_model_request": bool(budget.get("requests")),
        "budget_received_by_local_sink": any(row["kind"] == "sink.received" and
                                               "TRANSPECT_MARKER_BUDGET_DEMO" in json.dumps(row.get("arguments", {})) for row in raw),
        "report_written": (root / "workspace/output/report.md").is_file(),
        "archive_read_not_observed": not files.get("archive.txt", {}).get("reads"),
    }
    result = {"passed": all(checks.values()), "checks": checks, "run_id": data["manifest"]["run_id"]}
    atomic_write(report_path(root).with_name("demo-validation.json"), (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode())
    return result
