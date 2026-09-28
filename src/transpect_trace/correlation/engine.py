from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from uuid import UUID, uuid5

from transpect_trace.core.models import EventLink, TraceEvent
from transpect_trace.core.storage import TraceBundle


EDGE_NAMESPACE = UUID("f7fd624a-fe1a-419c-b379-5bb21d65264f")
MARKER_RE = re.compile(rb"TRANSPECT_MARKER_[A-Z0-9_]+")


def _edge(source: TraceEvent, target: TraceEvent, relation: str, confidence: float, method: str) -> dict[str, Any]:
    edge_id = str(uuid5(EDGE_NAMESPACE, f"{source.event_id}\0{target.event_id}\0{relation}"))
    return {
        "schema": "transpect.trace.edge/1.0",
        "edge_id": edge_id,
        "run_id": source.run_id,
        "from_event_id": source.event_id,
        "to_event_id": target.event_id,
        "relation": relation,
        "confidence": confidence,
        "method": method,
        "status": "resolved",
    }


def _seconds(event: TraceEvent) -> float:
    from datetime import datetime

    try:
        return datetime.fromisoformat(event.time.wall.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _nearest_before(events: Iterable[TraceEvent], target: TraceEvent, *, window: float = 120.0) -> TraceEvent | None:
    target_time = _seconds(target)
    candidates = [event for event in events if 0 <= target_time - _seconds(event) <= window]
    return max(candidates, key=_seconds) if candidates else None


def _nearest_after(events: Iterable[TraceEvent], source: TraceEvent, *, window: float = 120.0) -> TraceEvent | None:
    source_time = _seconds(source)
    candidates = [event for event in events if 0 <= _seconds(event) - source_time <= window]
    return min(candidates, key=_seconds) if candidates else None


def _chunk_hashes(data: bytes, size: int = 4096) -> list[dict[str, Any]]:
    return [
        {
            "offset": offset,
            "bytes": len(data[offset : offset + size]),
            "sha256": "sha256:" + hashlib.sha256(data[offset : offset + size]).hexdigest(),
        }
        for offset in range(0, len(data), size)
    ]


def _content_index(bundle: TraceBundle, events: list[TraceEvent]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    markers: dict[str, list[str]] = defaultdict(list)
    chunks: list[tuple[str, str, int, bytes, str]] = []
    workspaces = [("before", bundle.root / "input/workspace"), ("after", bundle.root / "workspace")]
    for phase, workspace in workspaces:
        if not workspace.is_dir():
            continue
        for path in sorted(workspace.rglob("*")):
            if not path.is_file():
                continue
            data = path.read_bytes()
            relative = path.relative_to(workspace).as_posix()
            found = sorted({value.decode("ascii") for value in MARKER_RE.findall(data)})
            for marker in found:
                markers[marker].append(f"{phase}:{relative}")
            chunk_rows = _chunk_hashes(data)
            for chunk in chunk_rows:
                offset = int(chunk["offset"])
                value = data[offset : offset + int(chunk["bytes"])]
                if len(value) >= 32:
                    chunks.append((phase, relative, offset, value, str(chunk["sha256"])))
            rows.append(
                {
                    "schema": "transpect.trace.content/1.0",
                    "run_id": events[0].run_id if events else "",
                    "kind": "workspace.file",
                    "phase": phase,
                    "path": relative,
                    "bytes": len(data),
                    "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                    "markers": found,
                    "chunks": chunk_rows,
                }
            )

    model_requests = [event for event in events if event.kind == "model.request" and event.content.blob_ref]
    flows: list[dict[str, Any]] = []
    for request in model_requests:
        try:
            body = bundle.read_blob(request.content)
        except (OSError, ValueError):
            continue
        request_markers = sorted({value.decode("ascii") for value in MARKER_RE.findall(body)})
        rows.append(
            {
                "schema": "transpect.trace.content/1.0",
                "run_id": request.run_id,
                "kind": "model.request",
                "event_id": request.event_id,
                "request_id": request.correlation.request_id,
                "bytes": len(body),
                "sha256": request.content.sha256,
                "markers": request_markers,
            }
        )
        for marker in request_markers:
            sources = markers.get(marker, [])
            flows.append(
                {
                    "schema": "transpect.trace.content_flow/1.0",
                    "run_id": request.run_id,
                    "marker": marker,
                    "source_paths": sources,
                    "request_event_id": request.event_id,
                    "request_id": request.correlation.request_id,
                    "status": "resolved" if sources else "unresolved",
                    "method": "exact_marker",
                    "confidence": 1.0 if sources else 0.0,
                }
            )
        for phase, source_path, offset, value, digest in chunks:
            if value not in body:
                continue
            flows.append(
                {
                    "schema": "transpect.trace.content_flow/1.0",
                    "run_id": request.run_id,
                    "source_phase": phase,
                    "source_paths": [source_path],
                    "source_offset": offset,
                    "source_chunk_sha256": digest,
                    "request_event_id": request.event_id,
                    "request_id": request.correlation.request_id,
                    "status": "resolved",
                    "method": "exact_chunk",
                    "confidence": 1.0,
                }
            )
    return rows, flows


def correlate_run(run_dir: Path | str, events: list[TraceEvent] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bundle = TraceBundle(run_dir)
    if events is None:
        events = [
            TraceEvent.model_validate(json.loads(line))
            for line in (bundle.root / "normalized/events.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    edges: list[dict[str, Any]] = []

    by_request: dict[str, list[TraceEvent]] = defaultdict(list)
    by_tool: dict[str, list[TraceEvent]] = defaultdict(list)
    for event in events:
        if event.correlation.request_id:
            by_request[event.correlation.request_id].append(event)
        if event.correlation.tool_call_id:
            by_tool[event.correlation.tool_call_id].append(event)

    for request_events in by_request.values():
        ordered = sorted(request_events, key=lambda event: event.ingest_seq)
        for source, target in zip(ordered, ordered[1:]):
            edges.append(_edge(source, target, "request_lifecycle", 1.0, "request_id"))

    for tool_events in by_tool.values():
        started = next((event for event in tool_events if event.kind == "client.tool.started"), None)
        completed = next((event for event in tool_events if event.kind == "client.tool.completed"), None)
        if started and completed:
            edges.append(_edge(started, completed, "tool_lifecycle", 1.0, "tool_call_id"))

    prompts = [event for event in events if event.kind == "client.user_message"]
    tool_results = [event for event in events if event.kind == "client.tool.completed"]
    model_requests = [event for event in events if event.kind == "model.request"]
    response_ends = [
        event for event in events
        if event.kind in {"model.response.completed", "model.request.failed", "model.request.blocked"}
    ]
    tool_starts = [event for event in events if event.kind == "client.tool.started"]
    process_starts = [event for event in events if event.kind == "system.process.started"]
    network_events = [event for event in events if event.kind in {"system.network.connect", "system.network.sent"}]

    for request in model_requests:
        source = _nearest_before([*prompts, *tool_results], request)
        if source:
            edges.append(_edge(source, request, "caused_request", 0.8, "nearest_preceding_client_event"))
        network = _nearest_before(network_events, request, window=10.0) or _nearest_after(network_events, request, window=10.0)
        if network:
            edges.append(_edge(network, request, "transported_request", 0.6, "time_window"))

    for response in response_ends:
        tool = _nearest_after(tool_starts, response, window=30.0)
        if tool:
            edges.append(_edge(response, tool, "caused_tool", 0.7, "nearest_following_tool"))

    for tool in tool_starts:
        process = _nearest_after(process_starts, tool, window=10.0)
        if process:
            command = (tool.operation.target or "").lower()
            executable = (process.operation.target or "").lower()
            confidence = 0.85 if executable and executable.split("/")[-1] in command else 0.6
            edges.append(_edge(tool, process, "spawned_process", confidence, "time_and_command"))

    target_by_id = {event.event_id: event for event in events}
    for edge in edges:
        target = target_by_id.get(edge["to_event_id"])
        if target is not None:
            target.links.append(
                EventLink(
                    relation=edge["relation"],
                    event_id=edge["from_event_id"],
                    confidence=edge["confidence"],
                )
            )

    content_rows, flows = _content_index(bundle, events)
    content_rows.extend(flows)
    bundle.replace_jsonl("normalized/causal_edges.jsonl", edges)
    bundle.replace_jsonl("normalized/content_index.jsonl", content_rows)
    bundle.write_events(events)
    return edges, content_rows
