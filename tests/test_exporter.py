from __future__ import annotations

import json
from pathlib import Path

import pytest

from transpect_trace.exporter import export_parquet


def test_parquet_export_accepts_heterogeneous_attributes(tmp_path: Path) -> None:
    pyarrow = pytest.importorskip("pyarrow")
    events_dir = tmp_path / "normalized"
    events_dir.mkdir(parents=True)
    base = {
        "schema": "transpect.trace.event/1.0",
        "event_id": "event-1",
        "run_id": "run-1",
        "collector_seq": 1,
        "ingest_seq": 1,
        "time": {"wall": "2026-01-01T00:00:00Z", "monotonic_ns": 1},
        "plane": "model",
        "kind": "model.request",
        "source": {"collector": "test", "version": "1", "trust": "derived"},
        "correlation": {"request_id": "request-1"},
        "operation": {"name": "POST", "target": "/v1/responses"},
        "content": {"bytes": 3, "payload_status": "full"},
        "attributes": {"value": 744},
        "links": [],
    }
    second = {**base, "event_id": "event-2", "collector_seq": 2, "ingest_seq": 2}
    second["attributes"] = {"value": "744", "nested": {"ok": True}}
    (events_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(row) for row in (base, second)) + "\n",
        encoding="utf-8",
    )

    destination = export_parquet(tmp_path)

    table = pyarrow.parquet.read_table(destination)
    assert table.num_rows == 2
    assert table.column("request_id").to_pylist() == ["request-1", "request-1"]
    assert json.loads(table.column("attributes_json")[1].as_py())["nested"] == {"ok": True}
