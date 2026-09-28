from __future__ import annotations

import base64
import json
from pathlib import Path

from transpect_trace.core.models import CollectorState, Manifest
from transpect_trace.core.storage import TraceBundle
from transpect_trace.normalization import normalize_run
from transpect_trace.system.frida import gadget_environment
from transpect_trace.verification import verify_bundle


def test_gadget_environment_keeps_strace_ptrace_slot(tmp_path: Path) -> None:
    environment = gadget_environment({"PATH": "/usr/bin"}, log_dir=tmp_path)
    assert environment["LD_PRELOAD"] == "/opt/transpect-frida/libgadget.so"
    assert environment["TTRACE_FRIDA_LOG_DIR"] == str(tmp_path).replace("\\", "/")
    assert environment["PATH"] == "/usr/bin"


def test_frida_evidence_is_normalized_and_reported(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    manifest = Manifest(
        run_id="run-frida",
        status="complete",
        client="codex",
        provider="deepseek",
        model="test",
        workspace="fixture",
        started_at="2026-01-01T00:00:00.000000Z",
        ended_at="2026-01-01T00:00:02.000000Z",
        collectors=[
            CollectorState(name="system.frida", version="17.18.0", started=True, stopped=True),
        ],
    )
    bundle.write_manifest(manifest)
    rows = [
        {
            "schema": "transpect.raw.frida/1.0",
            "run_id": "run-frida",
            "collector_seq": 1,
            "captured_at": "2026-01-01T00:00:00.100000Z",
            "kind": "frida.runtime.loaded",
            "pid": 41,
            "tid": 41,
        },
        {
            "schema": "transpect.raw.frida/1.0",
            "run_id": "run-frida",
            "collector_seq": 2,
            "captured_at": "2026-01-01T00:00:00.200000Z",
            "kind": "frida.io.read",
            "function": "read",
            "pid": 41,
            "tid": 42,
            "fd": 3,
            "path": "/workspace/public.txt",
            "result": 6,
            "captured_bytes": 6,
            "truncated": False,
            "payload_base64": base64.b64encode(b"public").decode(),
        },
    ]
    path = tmp_path / "raw/frida/events.41.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    events = normalize_run(tmp_path)
    read_event = next(event for event in events if event.kind == "system.frida.file.read")
    assert read_event.source.trust == "instrumented"
    assert read_event.correlation.pid == 41
    assert bundle.read_blob(read_event.content) == b"public"

    bundle.replace_jsonl("normalized/causal_edges.jsonl", [])
    bundle.replace_jsonl("normalized/content_index.jsonl", [])
    report = verify_bundle(tmp_path, check_checksums=False)
    assert report["status"] == "complete"
    assert report["system_observation"]["frida_processes_instrumented"] == 1
    assert report["system_observation"]["strace_only_pids"] == []
    assert report["system_observation"]["frida_only_pids"] == [41]


def test_expected_frida_without_lifecycle_is_incomplete(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    bundle.write_manifest(
        Manifest(
            run_id="run-missing-frida",
            status="complete",
            client="codex",
            provider="deepseek",
            model="test",
            workspace="fixture",
            collectors=[CollectorState(name="system.frida", started=True, stopped=True)],
        )
    )
    bundle.replace_jsonl("normalized/events.jsonl", [])
    bundle.replace_jsonl("normalized/causal_edges.jsonl", [])
    bundle.replace_jsonl("normalized/content_index.jsonl", [])

    report = verify_bundle(tmp_path, check_checksums=False)
    assert report["status"] == "incomplete"
    assert any("no injected-agent lifecycle event" in error for error in report["errors"])


def test_strace_without_frida_loaded_is_named_gap(tmp_path: Path) -> None:
    bundle = TraceBundle(tmp_path)
    bundle.write_manifest(
        Manifest(
            run_id="run-strace-only",
            status="complete",
            client="codex",
            provider="deepseek",
            model="test",
            workspace="fixture",
            collectors=[
                CollectorState(name="system.strace", started=True, stopped=True),
                CollectorState(name="system.frida", version="17.18.0", started=True, stopped=True),
            ],
        )
    )
    (tmp_path / "raw/system").mkdir(parents=True, exist_ok=True)
    (tmp_path / "raw/system/strace.7").write_text(
        '1.000000 openat(AT_FDCWD, "/workspace/public.txt", O_RDONLY) = 3\n',
        encoding="utf-8",
    )
    (tmp_path / "raw/system/strace.41").write_text(
        '1.000100 execve("/usr/local/bin/node", ["node"], 0x7ffd) = 0\n',
        encoding="utf-8",
    )
    (tmp_path / "raw/frida").mkdir(parents=True, exist_ok=True)
    (tmp_path / "raw/frida/events.41.jsonl").write_text(
        json.dumps(
            {
                "schema": "transpect.raw.frida/1.0",
                "collector_seq": 1,
                "captured_at": "2026-01-01T00:00:01.000000Z",
                "kind": "frida.runtime.loaded",
                "pid": 41,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    normalize_run(tmp_path)
    bundle.replace_jsonl("normalized/causal_edges.jsonl", [])
    bundle.replace_jsonl("normalized/content_index.jsonl", [])
    report = verify_bundle(tmp_path, check_checksums=False)
    assert report["status"] == "complete"
    assert report["system_observation"]["strace_only_pids"] == [7]
    assert report["system_observation"]["frida_only_pids"] == []
    assert report["system_observation"]["dual_observed_pids"] == [41]
