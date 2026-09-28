from __future__ import annotations

import json
from pathlib import Path

from transpect_trace.core.models import Manifest
from transpect_trace.core.storage import TraceBundle
from transpect_trace.correlation import correlate_run
from transpect_trace.normalization import normalize_run
from transpect_trace.verification import verify_bundle


def _raw(bundle: TraceBundle, relative: str, row: dict) -> None:
    bundle.append_jsonl(relative, row)


def test_end_to_end_offline_bundle(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    manifest = Manifest(
        run_id="run-test",
        status="complete",
        client="codex",
        provider="deepseek",
        model="test",
        workspace="fixture",
        started_at="2026-01-01T00:00:00.000000Z",
        ended_at="2026-01-01T00:00:03.000000Z",
    )
    bundle.write_manifest(manifest)
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    (workspace / "public.txt").write_text("TRANSPECT_MARKER_PUBLIC_001\npublic", encoding="utf-8")

    _raw(bundle, "raw/client/events.jsonl", {
        "run_id": "run-test", "collector_seq": 1, "captured_at": "2026-01-01T00:00:00.100000Z",
        "monotonic_ns": 1, "kind": "client.user_message", "prompt": "summarize public.txt",
    })
    _raw(bundle, "raw/client/events.jsonl", {
        "run_id": "run-test", "collector_seq": 2, "captured_at": "2026-01-01T00:00:00.200000Z",
        "monotonic_ns": 2, "kind": "client.codex_event",
        "event": {"type": "item.started", "item": {"id": "tool-1", "type": "command_execution", "command": "cat public.txt"}},
    })
    _raw(bundle, "raw/client/events.jsonl", {
        "run_id": "run-test", "collector_seq": 3, "captured_at": "2026-01-01T00:00:00.400000Z",
        "monotonic_ns": 3, "kind": "client.codex_event",
        "event": {"type": "item.completed", "item": {"id": "tool-1", "type": "command_execution", "command": "cat public.txt", "exit_code": 0}},
    })
    request_body = b'{"input":"TRANSPECT_MARKER_PUBLIC_001","stream":true}'
    request_ref = bundle.put_blob(request_body, media_type="application/json")
    response_ref = bundle.put_blob(b"data: [DONE]\n\n", media_type="text/event-stream")
    _raw(bundle, "raw/gateway/events.jsonl", {
        "run_id": "run-test", "collector_seq": 1, "captured_at": "2026-01-01T00:00:00.500000Z",
        "monotonic_ns": 4, "kind": "model.request", "request_id": "req-1", "method": "POST",
        "path": "/v1/responses", "content": request_ref.model_dump(mode="json"),
    })
    _raw(bundle, "raw/gateway/events.jsonl", {
        "run_id": "run-test", "collector_seq": 2, "captured_at": "2026-01-01T00:00:01.000000Z",
        "monotonic_ns": 5, "kind": "model.response.completed", "request_id": "req-1", "status": 200,
        "content": response_ref.model_dump(mode="json"),
    })
    (tmp_path / "raw/system/strace.123").write_text(
        "1767225600.250000 execve(\"/usr/bin/cat\", [\"cat\", \"public.txt\"], 0x0) = 0\n"
        "1767225600.300000 openat(AT_FDCWD, \"public.txt\", O_RDONLY) = 3</workspace/public.txt>\n"
        "1767225600.350000 read(3</workspace/public.txt>, \"public\", 4096) = 6\n"
        "1767225600.450000 connect(4<TCP:[127.0.0.1:40000->172.18.0.2:9000]>, {sa_family=AF_INET, sin_port=htons(9000)}, 16) = 0\n"
        "1767225601.100000 +++ exited with 0 +++\n",
        encoding="utf-8",
    )

    events = normalize_run(tmp_path)
    edges, content = correlate_run(tmp_path, events)
    assert any(event.kind == "system.file.read" for event in events)
    assert any(edge["relation"] == "tool_lifecycle" for edge in edges)
    assert any(row.get("marker") == "TRANSPECT_MARKER_PUBLIC_001" and row["status"] == "resolved" for row in content)

    report = verify_bundle(tmp_path, check_checksums=False)
    assert report["correlation"]["request_terminal_rate"] == 1.0
    assert report["correlation"]["tool_completion_rate"] == 1.0
    assert report["integrity"]["blob_errors"] == []

    bundle.write_checksums()
    final = verify_bundle(tmp_path, check_checksums=True, write_report=False)
    assert final["integrity"]["checksum_errors"] == []


def test_checksum_tamper_is_detected(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    bundle.write_manifest(Manifest(client="codex", provider="deepseek", model="test", workspace="fixture"))
    bundle.replace_jsonl("normalized/events.jsonl", [])
    bundle.replace_jsonl("normalized/causal_edges.jsonl", [])
    bundle.replace_jsonl("normalized/content_index.jsonl", [])
    bundle.write_checksums()
    (tmp_path / "manifest.json").write_text("{}", encoding="utf-8")
    result = verify_bundle(tmp_path, check_checksums=True, write_report=False)
    assert any("checksum mismatch" in error for error in result["integrity"]["checksum_errors"])

