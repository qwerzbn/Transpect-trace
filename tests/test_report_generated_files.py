import json
from pathlib import Path

from transpect_trace.core.models import Manifest
from transpect_trace.core.storage import TraceBundle
from transpect_trace.normalization import normalize_run
from transpect_trace.reporting import project_report


def test_final_snapshot_is_not_attributed_before_observed_write(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    bundle.write_manifest(Manifest(client="codex", provider="deepseek", model="test", workspace="fixture"))
    output = tmp_path / "workspace"
    output.mkdir(exist_ok=True)
    text = "A newly generated report with a unique long sentence."
    (output / "report.txt").write_text(text)
    (tmp_path / "raw/system/strace.123").write_text(
        '1767225600.300 write(3</workspace/report.txt>, "report", 6) = 6\n'
    )
    for seq, time in enumerate(["00:00:00.100000", "00:00:00.400000"], 1):
        content = bundle.put_blob(json.dumps({"input": text}).encode())
        bundle.append_jsonl("raw/gateway/events.jsonl", dict(collector_seq=seq, captured_at=f"2026-01-01T{time}Z",
                               kind="model.request", request_id=str(seq), content=content.model_dump()))
    normalize_run(tmp_path)
    entry = project_report(tmp_path)["files"][0]
    assert len(entry["requests"]) == 1
    assert entry["requests"][0]["target"] == "request:2"
    assert entry["requests"][0]["method"] == "exact_text_final_snapshot"
