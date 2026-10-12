from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from transpect_trace.core.models import Manifest, TraceEvent
from transpect_trace.core.storage import TraceBundle, atomic_write


SECRET_PATTERNS = [
    re.compile(rb"(?i)authorization\s*[:=]\s*bearer\s+[A-Za-z0-9._-]+"),
    re.compile(rb"(?i)(deepseek_api_key|transpect_model_api_key)\s*[:=]\s*[^\s,}\"]+"),
    re.compile(rb"(?i)(anthropic_api_key|x-api-key)\s*[:=]\s*[^\s,}\"]+"),
]


def _jsonl(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    if not path.is_file():
        return rows, [f"missing file: {path.name}"]
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            errors.append(f"{path.name}:{line_number}: {error.msg}")
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            errors.append(f"{path.name}:{line_number}: row is not an object")
    return rows, errors


def _check_checksums(root: Path) -> list[str]:
    path = root / "checksums.sha256"
    if not path.is_file():
        return ["checksums.sha256 is missing"]
    errors: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        digest, separator, relative = line.partition("  ")
        target = (root / relative).resolve()
        if not separator or root != target and root not in target.parents:
            errors.append(f"checksums.sha256:{line_number}: invalid entry")
            continue
        if not target.is_file():
            errors.append(f"missing checksummed file: {relative}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest:
            errors.append(f"checksum mismatch: {relative}")
    return errors


def _scan_secrets(root: Path) -> list[str]:
    findings: list[str] = []
    ignored = {"checksums.sha256"}
    for path in root.rglob("*"):
        if not path.is_file() or path.name in ignored or "blobs" in path.parts:
            continue
        data = path.read_bytes()
        if any(pattern.search(data) for pattern in SECRET_PATTERNS):
            findings.append(path.relative_to(root).as_posix())
    for variable in ("DEEPSEEK_API_KEY", "TRANSPECT_MODEL_API_KEY", "ANTHROPIC_API_KEY", "API_KEY"):
        secret = os.environ.get(variable, "").encode()
        if not secret:
            continue
        for path in root.rglob("*"):
            if path.is_file() and secret in path.read_bytes():
                findings.append(path.relative_to(root).as_posix())
    return sorted(set(findings))


def verify_bundle(run_dir: Path | str, *, check_checksums: bool = True, write_report: bool = True) -> dict[str, Any]:
    bundle = TraceBundle(run_dir)
    errors: list[str] = []
    try:
        manifest = Manifest.model_validate_json((bundle.root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        manifest = None
        errors.append(f"invalid manifest: {error}")

    rows, json_errors = _jsonl(bundle.root / "normalized/events.jsonl")
    errors.extend(json_errors)
    events: list[TraceEvent] = []
    schema_errors: list[str] = []
    for index, row in enumerate(rows, start=1):
        try:
            events.append(TraceEvent.model_validate(row))
        except ValueError as error:
            message = f"events.jsonl:{index}: {error}"
            schema_errors.append(message)
            errors.append(message)

    sequences: dict[str, list[int]] = defaultdict(list)
    blob_errors: list[str] = []
    for event in events:
        sequences[event.source.collector].append(event.collector_seq)
        if event.content.blob_ref:
            try:
                bundle.read_blob(event.content)
            except (OSError, ValueError) as error:
                blob_errors.append(f"{event.event_id}: {error}")
    errors.extend(blob_errors)

    sequence_gaps: dict[str, list[int]] = {}
    for collector, values in sequences.items():
        unique = sorted(set(values))
        if not unique:
            continue
        missing = sorted(set(range(unique[0], unique[-1] + 1)) - set(unique))
        if missing:
            sequence_gaps[collector] = missing

    edge_rows, edge_errors = _jsonl(bundle.root / "normalized/causal_edges.jsonl")
    errors.extend(edge_errors)
    content_rows, content_errors = _jsonl(bundle.root / "normalized/content_index.jsonl")
    errors.extend(content_errors)
    request_ids: dict[str, set[str]] = defaultdict(set)
    tool_ids: dict[tuple[str, str | None, str], set[str]] = defaultdict(set)
    counts = Counter(event.kind for event in events)
    for event in events:
        if event.correlation.request_id:
            request_ids[event.correlation.request_id].add(event.kind)
        if event.correlation.tool_call_id:
            tool_ids[(event.source.collector, event.correlation.session_id, event.correlation.tool_call_id)].add(event.kind)
    terminal_requests = sum(
        1 for kinds in request_ids.values()
        if "model.request" in kinds
        and ({"model.response.completed", "model.request.failed", "model.request.blocked"} & kinds)
    )
    client_tool_ids = {
        tool_id for tool_id, kinds in tool_ids.items() if "client.tool.started" in kinds
    }
    complete_tools = sum(
        1 for tool_id in client_tool_ids
        if "client.tool.completed" in tool_ids[tool_id]
    )
    marker_flows = [row for row in content_rows if row.get("schema") == "transpect.trace.content_flow/1.0"]
    resolved_marker_flows = [row for row in marker_flows if row.get("status") == "resolved"]
    known_paths = {
        str(row.get("path")) for row in content_rows
        if row.get("schema") == "transpect.trace.content/1.0" and row.get("kind") == "workspace.file"
    }
    file_events = [
        event for event in events
        if event.kind in {"system.file.opened", "system.file.read"}
        and event.operation.target
        and "/workspace/" in str(event.operation.target).replace("\\", "/")
    ]
    known_file_events = [
        event for event in file_events
        if any(str(event.operation.target).replace("\\", "/").endswith("/" + path) or str(event.operation.target) == path for path in known_paths)
    ]
    transported_requests = {
        row.get("to_event_id") for row in edge_rows if row.get("relation") == "transported_request"
    }
    spawned_tools = {
        row.get("from_event_id") for row in edge_rows if row.get("relation") == "spawned_process"
    }
    tool_start_ids = {event.event_id for event in events if event.kind == "client.tool.started"}
    secret_findings = _scan_secrets(bundle.root)
    if secret_findings:
        errors.append("credential-like values found in evidence")
    checksum_errors = _check_checksums(bundle.root) if check_checksums else []
    errors.extend(checksum_errors)

    collector_states = {
        collector.name: collector.model_dump(mode="json") for collector in (manifest.collectors if manifest else [])
    }
    collector_errors = [
        f"{collector.name}: {message}"
        for collector in (manifest.collectors if manifest else [])
        for message in collector.errors
    ]
    errors.extend(collector_errors)
    frida_expected = "system.frida" in collector_states and bool(collector_states["system.frida"].get("started"))
    frida_loaded = counts["system.frida.loaded"]
    frida_hook_errors = counts["system.frida.hook_error"]
    if frida_expected and frida_loaded == 0:
        errors.append("system.frida: no injected-agent lifecycle event was captured")
    if frida_hook_errors:
        errors.append(f"system.frida: {frida_hook_errors} hook or parser errors")

    strace_events = [event for event in events if event.source.collector == "system.strace"]
    frida_events = [event for event in events if event.source.collector == "system.frida"]
    strace_pids = {event.correlation.pid for event in strace_events if event.correlation.pid is not None}
    frida_pids = {
        event.correlation.pid
        for event in frida_events
        if event.kind == "system.frida.loaded" and event.correlation.pid is not None
    }
    dual_pids = strace_pids & frida_pids
    strace_only = sorted(strace_pids - frida_pids)
    frida_only = sorted(frida_pids - strace_pids)

    request_total = counts["model.request"]
    tool_total = len(client_tool_ids)
    report = {
        "schema": "transpect.trace.quality/1.0",
        "run_id": manifest.run_id if manifest else None,
        "status": "complete" if not errors and not sequence_gaps and manifest is not None and manifest.status == "complete" else "incomplete",
        "manifest_status": manifest.status if manifest else "invalid",
        "events": {"total": len(events), "by_kind": dict(sorted(counts.items()))},
        "collectors": collector_states,
        "system_observation": {
            "strace_events": len(strace_events),
            "strace_processes": len(strace_pids),
            "frida_events": len(frida_events),
            "frida_processes_instrumented": len(frida_pids),
            "frida_hook_unavailable": counts["system.frida.hook_unavailable"],
            "frida_hook_errors": frida_hook_errors,
            "processes_seen_by_both": len(dual_pids),
            "dual_observed_pids": sorted(dual_pids),
            "strace_only_pids": strace_only,
            "frida_only_pids": frida_only,
        },
        "integrity": {
            "schema_valid": not json_errors and not schema_errors,
            "schema_errors": schema_errors,
            "blob_errors": blob_errors,
            "checksum_errors": checksum_errors,
            "sequence_gaps": sequence_gaps,
            "secret_findings": secret_findings,
        },
        "correlation": {
            "requests_total": request_total,
            "requests_with_terminal": terminal_requests,
            "request_terminal_rate": terminal_requests / request_total if request_total else 1.0,
            "tools_total": tool_total,
            "tools_complete": complete_tools,
            "tool_completion_rate": complete_tools / tool_total if tool_total else 1.0,
            "causal_edges": len(edge_rows),
            "model_requests_with_network": len(transported_requests),
            "model_request_network_rate": len(transported_requests) / request_total if request_total else 1.0,
            "tools_with_process": len(spawned_tools),
            "tool_process_rate": len(spawned_tools) / len(tool_start_ids) if tool_start_ids else 1.0,
            "known_file_events": len(known_file_events),
            "file_events_total": len(file_events),
            "known_file_rate": len(known_file_events) / len(file_events) if file_events else 1.0,
            "marker_flows": len(marker_flows),
            "resolved_marker_flows": len(resolved_marker_flows),
        },
        "policy": {
            "decisions": counts["policy.decision"],
            "allowed": sum(
                1 for event in events
                if event.kind == "policy.decision" and event.attributes.get("decision") == "allow"
            ),
            "denied": sum(
                1 for event in events
                if event.kind == "policy.decision" and event.attributes.get("decision") == "deny"
            ),
            "blocked_requests": counts["model.request.blocked"],
        },
        "errors": errors,
    }
    if write_report:
        atomic_write(
            bundle.root / "quality/trace-quality.json",
            (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
    return report
