from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from transpect_trace import __version__
from transpect_trace.clients.codex import CodexAdapter
from transpect_trace.clients.claude import ClaudeAdapter
from transpect_trace.core.models import (
    ContentRef,
    Correlation,
    EventSource,
    EventTime,
    Manifest,
    Operation,
    TraceEvent,
    stable_event_id,
)
from transpect_trace.core.storage import TraceBundle

from .frida import iter_frida_rows
from .system import iter_strace_rows


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                if not line.endswith("\n"):
                    continue  # collector may still be appending this record
                yield {"_parse_error": True, "line_number": line_number, "text": line.rstrip("\r\n")}
                continue
            if isinstance(value, dict):
                yield value


def _time_key(wall: str) -> float:
    try:
        return datetime.fromisoformat(wall.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _content(value: Any) -> ContentRef:
    if isinstance(value, dict):
        try:
            return ContentRef.model_validate(value)
        except ValueError:
            pass
    return ContentRef(bytes=0, payload_status="unavailable")


def _candidate(
    *,
    manifest: Manifest,
    collector: str,
    collector_seq: int,
    wall: str,
    monotonic_ns: int,
    plane: str,
    kind: str,
    trust: str,
    operation: str,
    target: str | None = None,
    correlation: Correlation | None = None,
    content: ContentRef | None = None,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "sort": (_time_key(wall), collector, collector_seq),
        "collector": collector,
        "collector_seq": collector_seq,
        "wall": wall,
        "monotonic_ns": max(0, int(monotonic_ns or 0)),
        "plane": plane,
        "kind": kind,
        "trust": trust,
        "operation": operation,
        "target": target,
        "correlation": correlation or Correlation(),
        "content": content or ContentRef(bytes=0),
        "attributes": attributes or {},
        "manifest": manifest,
    }


def _client_candidates(bundle: TraceBundle, manifest: Manifest, *, relative: str = "raw/client/events.jsonl", agent_id: str = "main") -> Iterable[dict[str, Any]]:
    adapter = CodexAdapter()
    current_session: str | None = None
    current_turn: str | None = None
    for raw in _read_jsonl(bundle.root / relative):
        sequence = int(raw.get("collector_seq") or 1)
        wall = str(raw.get("captured_at") or manifest.started_at)
        monotonic = int(raw.get("monotonic_ns") or 0)
        raw_kind = str(raw.get("kind") or "client.unknown")
        if raw.get("_parse_error"):
            yield _candidate(
                manifest=manifest, collector="client.codex", collector_seq=sequence, wall=wall,
                monotonic_ns=monotonic, plane="client", kind="client.unknown", trust="application",
                operation="parse", attributes=raw,
            )
            continue
        if raw_kind == "client.user_message":
            prompt = str(raw.get("prompt") or "")
            content = bundle.put_blob(prompt.encode("utf-8"), media_type="text/plain", encoding="utf-8")
            yield _candidate(
                manifest=manifest, collector="client.codex", collector_seq=sequence, wall=wall,
                monotonic_ns=monotonic, plane="client", kind=raw_kind, trust="application",
                operation="message", target="user", content=content,
            )
            continue
        if raw_kind == "client.process_exited":
            yield _candidate(
                manifest=manifest, collector="client.codex", collector_seq=sequence, wall=wall,
                monotonic_ns=monotonic, plane="client", kind=raw_kind, trust="application",
                operation="exit", attributes={"return_code": raw.get("return_code")},
            )
            continue
        event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
        parsed = next(iter(adapter.parse_event(event)))
        event_type = parsed["event_type"]
        item_type = parsed["item_type"]
        if event_type in {"thread.started", "session.started"}:
            current_session = str(event.get("thread_id") or event.get("session_id") or current_session or "") or None
            kind, operation, target = "client.session.started", "start", "codex"
        elif event_type.startswith("turn."):
            current_turn = str(event.get("turn_id") or current_turn or "") or None
            kind, operation, target = f"client.{event_type}", event_type.rsplit(".", 1)[-1], "turn"
        elif item_type in {"command_execution", "mcp_tool_call", "collab_agent_tool_call"}:
            phase = "started" if event_type.endswith("started") else "completed" if event_type.endswith("completed") else "updated"
            kind, operation = f"client.tool.{phase}", "execute"
            target = str(parsed.get("command") or (event.get("item") or {}).get("tool") or (event.get("item") or {}).get("name") or item_type)
        elif item_type == "agent_message":
            kind, operation, target = "client.assistant_message", "message", "assistant"
        elif item_type == "reasoning":
            kind, operation, target = "client.reasoning", "reason", "assistant"
        elif event_type == "error":
            kind, operation, target = "client.error", "error", None
        else:
            kind, operation, target = "client.unknown", event_type, item_type or None
        text = parsed.get("text")
        content = (
            bundle.put_blob(str(text).encode("utf-8"), media_type="text/plain", encoding="utf-8")
            if text is not None else ContentRef(bytes=0)
        )
        correlation = Correlation(
            session_id=str(parsed.get("session_id") or current_session or "") or None,
            turn_id=str(parsed.get("turn_id") or current_turn or "") or None,
            tool_call_id=str(parsed.get("tool_call_id") or "") or None,
            pid=raw.get("pid"),
        )
        yield _candidate(
            manifest=manifest, collector="client.codex", collector_seq=sequence, wall=wall,
            monotonic_ns=monotonic, plane="client", kind=kind, trust="application",
            operation=operation, target=target, correlation=correlation, content=content,
            attributes={"codex_event_type": event_type, "item_type": item_type, "event": event, "agent_id": agent_id, "raw_file": relative},
        )


def _demo_candidates(bundle: TraceBundle, manifest: Manifest) -> Iterable[dict[str, Any]]:
    for raw in _read_jsonl(bundle.root / "raw/client/demo-events.jsonl"):
        yield _candidate(
            manifest=manifest, collector="adapter.demo", collector_seq=int(raw.get("collector_seq", 1)),
            wall=raw.get("captured_at", manifest.started_at), monotonic_ns=raw.get("monotonic_ns", 0),
            plane="client", kind="demo." + raw.get("kind", "unknown"), trust="application",
            operation=raw.get("kind", "unknown"), target=raw.get("tool_name") or raw.get("agent_id"),
            correlation=Correlation(pid=raw.get("pid"), tool_call_id=raw.get("invocation_id")), attributes=raw,
        )
    for path in sorted((bundle.root / "raw/client").glob("child-*.jsonl")):
        for candidate in _client_candidates(bundle, manifest, relative=path.relative_to(bundle.root).as_posix(), agent_id=path.stem):
            candidate["collector"] = "client.codex." + path.stem
            yield candidate


def _claude_client_candidates(bundle: TraceBundle, manifest: Manifest) -> Iterable[dict[str, Any]]:
    adapter = ClaudeAdapter()
    output_sequence = 0
    for raw in _read_jsonl(bundle.root / "raw/client/events.jsonl"):
        raw_sequence = int(raw.get("collector_seq") or 1)
        wall = str(raw.get("captured_at") or manifest.started_at)
        monotonic = int(raw.get("monotonic_ns") or 0)
        raw_kind = str(raw.get("kind") or "client.unknown")
        if raw_kind == "client.user_message":
            output_sequence += 1
            prompt = str(raw.get("prompt") or "")
            yield _candidate(
                manifest=manifest, collector="client.claude", collector_seq=output_sequence, wall=wall,
                monotonic_ns=monotonic, plane="client", kind=raw_kind, trust="application",
                operation="message", target="user",
                content=bundle.put_blob(prompt.encode(), media_type="text/plain", encoding="utf-8"),
                attributes={"raw_collector_seq": raw_sequence},
            )
            continue
        if raw_kind == "client.process_exited":
            output_sequence += 1
            yield _candidate(
                manifest=manifest, collector="client.claude", collector_seq=output_sequence, wall=wall,
                monotonic_ns=monotonic, plane="client", kind=raw_kind, trust="application",
                operation="exit", attributes={"return_code": raw.get("return_code"), "raw_collector_seq": raw_sequence},
            )
            continue
        event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
        parsed_rows = list(adapter.parse_event(event)) or [{"kind": "unknown", "raw": event}]
        for parsed in parsed_rows:
            output_sequence += 1
            parsed_kind = str(parsed.get("kind") or "unknown")
            if parsed_kind == "session":
                kind, operation, target = "client.session.started", "start", "claude"
                payload = None
            elif parsed_kind == "tool_start":
                kind, operation, target = "client.tool.started", "execute", str(parsed.get("tool_name") or "tool")
                payload = parsed.get("tool_input")
            elif parsed_kind == "tool_result":
                kind, operation, target = "client.tool.completed", "result", "tool"
                payload = parsed.get("tool_result")
            elif parsed_kind in {"message", "result"}:
                kind, operation, target = "client.assistant_message", "message", "assistant"
                payload = parsed.get("text")
            else:
                kind, operation, target = "client.unknown", str(parsed.get("event_type") or "unknown"), None
                payload = None
            if payload is None:
                content = ContentRef(bytes=0)
            elif isinstance(payload, str):
                content = bundle.put_blob(payload.encode(), media_type="text/plain", encoding="utf-8")
            else:
                content = bundle.put_blob(json.dumps(payload, ensure_ascii=False).encode(), media_type="application/json", encoding="utf-8")
            yield _candidate(
                manifest=manifest, collector="client.claude", collector_seq=output_sequence, wall=wall,
                monotonic_ns=monotonic, plane="client", kind=kind, trust="application",
                operation=operation, target=target,
                correlation=Correlation(
                    session_id=str(parsed.get("session_id") or "") or None,
                    tool_call_id=str(parsed.get("tool_call_id") or "") or None,
                    pid=raw.get("pid"),
                ),
                content=content,
                attributes={"claude_event_type": parsed.get("event_type"), "is_error": parsed.get("is_error"), "event": event, "raw_collector_seq": raw_sequence},
            )


def _injecagent_mcp_candidates(bundle: TraceBundle, manifest: Manifest) -> Iterable[dict[str, Any]]:
    for raw in _read_jsonl(bundle.root / "raw/client/mcp-events.jsonl"):
        sequence = int(raw.get("collector_seq") or 1)
        wall = str(raw.get("captured_at") or manifest.started_at)
        monotonic = int(raw.get("monotonic_ns") or 0)
        kind = str(raw.get("kind") or "adapter.mcp.unknown")
        response = raw.get("response")
        content = (
            bundle.put_blob(str(response).encode("utf-8"), media_type="text/plain", encoding="utf-8")
            if response is not None else ContentRef(bytes=0)
        )
        if kind == "adapter.tool.called":
            operation = "call"
        elif kind == "adapter.tool.completed":
            operation = "result"
        elif kind == "adapter.tool.failed":
            operation = "error"
        elif kind == "adapter.mcp.started":
            operation = "start"
        elif kind == "adapter.mcp.stopped":
            operation = "stop"
        else:
            operation = "observe"
        attributes = {
            key: value for key, value in raw.items()
            if key not in {
                "schema", "collector_seq", "captured_at", "monotonic_ns", "kind", "response",
            }
        }
        yield _candidate(
            manifest=manifest,
            collector="adapter.injecagent-mcp",
            collector_seq=sequence,
            wall=wall,
            monotonic_ns=monotonic,
            plane="client",
            kind=kind,
            trust="application",
            operation=operation,
            target=str(raw.get("tool_name") or "injecagent"),
            correlation=Correlation(tool_call_id=str(raw.get("invocation_id") or "") or None),
            content=content,
            attributes=attributes,
        )


def _gateway_candidates(bundle: TraceBundle, manifest: Manifest) -> Iterable[dict[str, Any]]:
    for raw in _read_jsonl(bundle.root / "raw/gateway/events.jsonl"):
        sequence = int(raw.get("collector_seq") or 1)
        wall = str(raw.get("captured_at") or manifest.started_at)
        kind = str(raw.get("kind") or "model.unknown")
        request_id = raw.get("request_id")
        content = _content(raw.get("content"))
        if kind == "model.request":
            operation, target = str(raw.get("method") or "POST"), raw.get("path")
        elif kind == "policy.decision":
            operation, target = "decide", raw.get("policy_id")
        elif kind == "model.request.blocked":
            operation, target = "block", raw.get("rule_id")
        elif kind == "model.response.chunk":
            operation, target = "receive_chunk", raw.get("provider_request_id")
        elif kind.startswith("model.response"):
            operation, target = "receive", raw.get("provider_request_id")
        else:
            operation, target = "request", raw.get("path")
        attributes = {
            key: value for key, value in raw.items()
            if key not in {"schema", "run_id", "collector_seq", "captured_at", "monotonic_ns", "kind", "content", "request_id"}
        }
        yield _candidate(
            manifest=manifest, collector=f"gateway.{manifest.provider}", collector_seq=sequence, wall=wall,
            monotonic_ns=int(raw.get("monotonic_ns") or 0), plane="model", kind=kind, trust="external",
            operation=operation, target=str(target) if target is not None else None,
            correlation=Correlation(request_id=str(request_id) if request_id else None),
            content=content, attributes=attributes,
        )


def _system_candidates(bundle: TraceBundle, manifest: Manifest) -> Iterable[dict[str, Any]]:
    for sequence, raw in enumerate(iter_strace_rows(bundle.root / "raw/system"), start=1):
        result = raw.get("result")
        transferred = result if isinstance(result, int) and result > 0 and raw["kind"] in {
            "system.file.read", "system.file.write", "system.network.sent", "system.network.received"
        } else 0
        attributes = {key: value for key, value in raw.items() if key not in {"wall", "kind", "operation", "target", "pid", "ppid", "fd"}}
        yield _candidate(
            manifest=manifest, collector="system.strace", collector_seq=sequence, wall=raw["wall"],
            monotonic_ns=0, plane="system", kind=raw["kind"], trust="external",
            operation=raw["operation"], target=raw.get("target"),
            correlation=Correlation(pid=raw.get("pid"), ppid=raw.get("ppid"), fd=raw.get("fd")),
            content=ContentRef(bytes=transferred, payload_status="unavailable"), attributes=attributes,
        )


def _frida_candidates(bundle: TraceBundle, manifest: Manifest) -> Iterable[dict[str, Any]]:
    for sequence, raw in enumerate(iter_frida_rows(bundle.root / "raw/frida"), start=1):
        payload = raw.pop("content_bytes", None)
        truncated = bool(raw.pop("content_truncated", False))
        if isinstance(payload, bytes):
            content = bundle.put_blob(payload, media_type="application/octet-stream")
            if truncated:
                content.payload_status = "redacted"
        else:
            content = ContentRef(bytes=0, payload_status="unavailable")
        yield _candidate(
            manifest=manifest,
            collector="system.frida",
            collector_seq=sequence,
            wall=raw["wall"],
            monotonic_ns=0,
            plane="system",
            kind=raw["kind"],
            trust="instrumented",
            operation=raw["operation"],
            target=raw.get("target"),
            correlation=Correlation(pid=raw.get("pid"), tid=raw.get("tid"), fd=raw.get("fd")),
            content=content,
            attributes=raw.get("attributes") or {},
        )


def _otel_candidates(bundle: TraceBundle, manifest: Manifest) -> Iterable[dict[str, Any]]:
    def any_value(value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        for key in ("stringValue", "boolValue", "intValue", "doubleValue", "bytesValue"):
            if key in value:
                return value[key]
        if "arrayValue" in value:
            return [any_value(item) for item in value["arrayValue"].get("values", [])]
        if "kvlistValue" in value:
            return attributes(value["kvlistValue"].get("values", []))
        return value

    def attributes(values: Any) -> dict[str, Any]:
        if not isinstance(values, list):
            return {}
        return {
            str(item.get("key")): any_value(item.get("value"))
            for item in values if isinstance(item, dict) and item.get("key")
        }

    def nano_wall(value: Any) -> str:
        try:
            nanoseconds = int(value)
            return datetime.fromtimestamp(nanoseconds / 1_000_000_000, tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        except (TypeError, ValueError, OSError):
            return manifest.started_at

    def records(document: dict[str, Any]) -> Iterable[dict[str, Any]]:
        for resource_logs in document.get("resourceLogs", []):
            resource = attributes((resource_logs.get("resource") or {}).get("attributes", []))
            for scope_logs in resource_logs.get("scopeLogs", []):
                scope = scope_logs.get("scope") or {}
                for record in scope_logs.get("logRecords", []):
                    attrs = attributes(record.get("attributes", []))
                    body = any_value(record.get("body"))
                    event_name = str(attrs.get("event.name") or attrs.get("name") or body or "log")[:200]
                    yield {
                        "kind": f"client.telemetry.{event_name}",
                        "wall": nano_wall(record.get("timeUnixNano") or record.get("observedTimeUnixNano")),
                        "trace_id": record.get("traceId"),
                        "span_id": record.get("spanId"),
                        "body": body,
                        "attributes": attrs,
                        "resource": resource,
                        "scope": scope,
                    }
        for resource_spans in document.get("resourceSpans", []):
            resource = attributes((resource_spans.get("resource") or {}).get("attributes", []))
            for scope_spans in resource_spans.get("scopeSpans", []):
                scope = scope_spans.get("scope") or {}
                for span in scope_spans.get("spans", []):
                    yield {
                        "kind": "client.telemetry.span",
                        "wall": nano_wall(span.get("startTimeUnixNano")),
                        "trace_id": span.get("traceId"),
                        "span_id": span.get("spanId"),
                        "parent_span_id": span.get("parentSpanId"),
                        "body": span.get("name"),
                        "attributes": attributes(span.get("attributes", [])),
                        "resource": resource,
                        "scope": scope,
                        "end_time_unix_nano": span.get("endTimeUnixNano"),
                    }

    sequence = 0
    for path in sorted((bundle.root / "raw/otel").glob("*.json*")):
        for raw in _read_jsonl(path):
            extracted = list(records(raw))
            if not extracted:
                extracted = [{"kind": "client.telemetry", "wall": str(raw.get("timestamp") or raw.get("time") or manifest.started_at), "body": None, "attributes": {"record": raw}}]
            for record in extracted:
                sequence += 1
                body = record.pop("body", None)
                content = (
                    bundle.put_blob(json.dumps(body, ensure_ascii=False, default=str).encode("utf-8"), media_type="application/json", encoding="utf-8")
                    if body is not None else ContentRef(bytes=0)
                )
                attrs = record.pop("attributes", {})
                correlation = Correlation(
                    session_id=str(attrs.get("conversation.id") or attrs.get("session.id") or "") or None,
                    request_id=str(attrs.get("request.id") or "") or None,
                    tool_call_id=str(attrs.get("tool_use_id") or attrs.get("tool.call.id") or "") or None,
                    trace_id=str(record.pop("trace_id", None) or "") or None,
                    span_id=str(record.pop("span_id", None) or "") or None,
                    parent_span_id=str(record.pop("parent_span_id", None) or "") or None,
                )
                yield _candidate(
                    manifest=manifest, collector="client.otel", collector_seq=sequence,
                    wall=str(record.pop("wall", manifest.started_at)), monotonic_ns=0, plane="client",
                    kind=str(record.pop("kind", "client.telemetry")), trust="application",
                    operation="telemetry", target=path.name, correlation=correlation, content=content,
                    attributes={**attrs, **record},
                )


def _run_candidates(manifest: Manifest) -> Iterable[dict[str, Any]]:
    sequence = 1
    yield _candidate(
        manifest=manifest, collector="run.supervisor", collector_seq=sequence,
        wall=manifest.started_at, monotonic_ns=0, plane="run", kind="run.started", trust="derived",
        operation="start", target=manifest.client,
        attributes={"provider": manifest.provider, "model": manifest.model, "workspace": manifest.workspace},
    )
    for collector in manifest.collectors:
        if collector.started:
            sequence += 1
            yield _candidate(
                manifest=manifest, collector="run.supervisor", collector_seq=sequence,
                wall=manifest.started_at, monotonic_ns=0, plane="run", kind="collector.started", trust="derived",
                operation="start", target=collector.name,
                attributes={"version": collector.version},
            )
        if collector.stopped:
            sequence += 1
            yield _candidate(
                manifest=manifest, collector="run.supervisor", collector_seq=sequence,
                wall=manifest.ended_at or manifest.started_at, monotonic_ns=0, plane="run", kind="collector.stopped", trust="derived",
                operation="stop", target=collector.name,
                attributes={"dropped_events": collector.dropped_events},
            )
        for message in collector.errors:
            sequence += 1
            yield _candidate(
                manifest=manifest, collector="run.supervisor", collector_seq=sequence,
                wall=manifest.ended_at or manifest.started_at, monotonic_ns=0, plane="run", kind="collector.error", trust="derived",
                operation="error", target=collector.name, attributes={"message": message},
            )
        if collector.dropped_events:
            sequence += 1
            yield _candidate(
                manifest=manifest, collector="run.supervisor", collector_seq=sequence,
                wall=manifest.ended_at or manifest.started_at, monotonic_ns=0, plane="run", kind="collector.gap", trust="derived",
                operation="gap", target=collector.name, attributes={"dropped_events": collector.dropped_events},
            )
    if manifest.status == "running":
        return
    sequence += 1
    terminal_kind = "run.completed" if manifest.status == "complete" else "run.failed"
    yield _candidate(
        manifest=manifest, collector="run.supervisor", collector_seq=sequence,
        wall=manifest.ended_at or manifest.started_at, monotonic_ns=0, plane="run", kind=terminal_kind, trust="derived",
        operation="complete" if terminal_kind == "run.completed" else "fail", target=manifest.client,
        attributes={"status": manifest.status, "failure": manifest.failure},
    )


def normalize_run(run_dir: Path | str, *, write: bool = True) -> list[TraceEvent]:
    bundle = TraceBundle(run_dir)
    manifest = Manifest.model_validate_json((bundle.root / "manifest.json").read_text(encoding="utf-8"))
    candidates = [
        *_run_candidates(manifest),
        *(_claude_client_candidates(bundle, manifest) if manifest.client == "claude" else _client_candidates(bundle, manifest)),
        *_injecagent_mcp_candidates(bundle, manifest),
        *_demo_candidates(bundle, manifest),
        *_gateway_candidates(bundle, manifest),
        *_system_candidates(bundle, manifest),
        *_frida_candidates(bundle, manifest),
        *_otel_candidates(bundle, manifest),
    ]
    candidates.sort(key=lambda row: row["sort"])
    events: list[TraceEvent] = []
    for ingest_seq, row in enumerate(candidates, start=1):
        event_id = stable_event_id(manifest.run_id, row["collector"], row["collector_seq"], row["kind"])
        events.append(
            TraceEvent(
                event_id=event_id,
                run_id=manifest.run_id,
                collector_seq=row["collector_seq"],
                ingest_seq=ingest_seq,
                time=EventTime(wall=row["wall"], monotonic_ns=row["monotonic_ns"]),
                plane=row["plane"],
                kind=row["kind"],
                source=EventSource(collector=row["collector"], version=__version__, trust=row["trust"]),
                correlation=row["correlation"],
                operation=Operation(name=row["operation"] or "unknown", target=row["target"]),
                content=row["content"],
                attributes=row["attributes"],
            )
        )
    if write:
        bundle.write_events(events)
    return events
