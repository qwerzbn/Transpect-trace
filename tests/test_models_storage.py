from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from transpect_trace.core.models import (
    EventSource,
    EventTime,
    Manifest,
    Operation,
    TraceEvent,
)
from transpect_trace.core.storage import TraceBundle


def test_trace_event_rejects_unknown_plane() -> None:
    with pytest.raises(ValidationError):
        TraceEvent(
            event_id="event",
            run_id="run",
            collector_seq=1,
            ingest_seq=1,
            time=EventTime(wall="2026-01-01T00:00:00Z", monotonic_ns=1),
            plane="policy",  # type: ignore[arg-type]
            kind="policy.decision",
            source=EventSource(collector="test", version="1", trust="derived"),
            operation=Operation(name="decide"),
        )


def test_blob_is_deduplicated_and_verified(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    first = bundle.put_blob(b"same data", media_type="text/plain")
    second = bundle.put_blob(b"same data", media_type="text/plain")
    assert first.blob_ref == second.blob_ref
    assert bundle.read_blob(first) == b"same data"

    (bundle.root / first.blob_ref).write_bytes(b"corrupt")  # type: ignore[arg-type]
    with pytest.raises(Exception):
        bundle.read_blob(first)


def test_jsonl_append_survives_independent_rows(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    bundle.append_jsonl("raw/client/events.jsonl", {"seq": 1})
    bundle.append_jsonl("raw/client/events.jsonl", {"seq": 2})
    rows = [json.loads(line) for line in (tmp_path / "raw/client/events.jsonl").read_text().splitlines()]
    assert rows == [{"seq": 1}, {"seq": 2}]


def test_manifest_is_atomic_json(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    manifest = Manifest(client="codex", provider="deepseek", model="test", workspace="/workspace")
    bundle.write_manifest(manifest)
    assert json.loads((tmp_path / "manifest.json").read_text())["run_id"] == manifest.run_id

