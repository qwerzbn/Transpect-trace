from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _canonical_json(value: Any) -> str:
    """Encode variable-shaped values without asking Arrow to infer a union type."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _parquet_row(event: dict[str, Any]) -> dict[str, Any]:
    """Create a stable, query-friendly row for TraceEvent v1.

    TraceEvent attributes intentionally allow arbitrary JSON. Different collectors
    can therefore use the same key with different JSON types. Arrow has no general
    JSON union type, so those open-ended structures are retained as canonical JSON
    while the common correlation and content fields are promoted to typed columns.
    """
    event_time = event.get("time") or {}
    source = event.get("source") or {}
    correlation = event.get("correlation") or {}
    operation = event.get("operation") or {}
    content = event.get("content") or {}
    return {
        "schema": event.get("schema"),
        "event_id": event.get("event_id"),
        "run_id": event.get("run_id"),
        "collector_seq": event.get("collector_seq"),
        "ingest_seq": event.get("ingest_seq"),
        "time_wall": event_time.get("wall"),
        "time_monotonic_ns": event_time.get("monotonic_ns"),
        "plane": event.get("plane"),
        "kind": event.get("kind"),
        "source_collector": source.get("collector"),
        "source_version": source.get("version"),
        "source_trust": source.get("trust"),
        "session_id": correlation.get("session_id"),
        "turn_id": correlation.get("turn_id"),
        "request_id": correlation.get("request_id"),
        "tool_call_id": correlation.get("tool_call_id"),
        "trace_id": correlation.get("trace_id"),
        "span_id": correlation.get("span_id"),
        "parent_span_id": correlation.get("parent_span_id"),
        "pid": correlation.get("pid"),
        "ppid": correlation.get("ppid"),
        "tid": correlation.get("tid"),
        "fd": correlation.get("fd"),
        "operation_name": operation.get("name"),
        "operation_target": operation.get("target"),
        "content_bytes": content.get("bytes"),
        "content_sha256": content.get("sha256"),
        "content_blob_ref": content.get("blob_ref"),
        "content_media_type": content.get("media_type"),
        "content_encoding": content.get("encoding"),
        "content_payload_status": content.get("payload_status"),
        "attributes_json": _canonical_json(event.get("attributes") or {}),
        "links_json": _canonical_json(event.get("links") or []),
    }


def export_parquet(run_dir: Path | str) -> Path:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as error:
        raise RuntimeError("Parquet export requires: uv sync --extra export") from error
    root = Path(run_dir).resolve()
    events_path = root / "normalized/events.jsonl"
    if not events_path.is_file():
        raise FileNotFoundError(f"normalized event file does not exist: {events_path}")
    rows = [
        _parquet_row(json.loads(line))
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not rows:
        raise ValueError(f"normalized event file is empty: {events_path}")
    destination = root / "analytics/events.parquet"
    destination.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows)
    pq.write_table(table, destination, compression="zstd")
    return destination
