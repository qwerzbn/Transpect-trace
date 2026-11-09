"""The lab DLL builder must require exact, observation-only collection evidence."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_guard_failstop_current_lab as builder  # noqa: E402

BODY = b"x" * 100
BODY_HASH = hashlib.sha256(BODY).hexdigest()


def _report(transport: str) -> dict:
    body_hash = BODY_HASH
    return {
        "schema": "transpect.desktop-current-capture-lab/1.0",
        "backend_sha256": builder.BACKEND_SHA256,
        "backend_version": builder.BACKEND_VERSION,
        "transport": transport,
        "synthetic_only": True,
        "local_origin_only": True,
        "codex_command_hooks_present": False,
        "frida_enabled": True,
        "trace_origin_exact": True,
        f"synthetic_{transport}_origin_exact": True,
        "full_body_collection_enabled": True,
        "synthetic_collection_validated": True,
        "collection_error": None,
        "native_capture_validated": False,
        "errors": [],
        "origin": {"requests": 1, "marker_in_body": True, "body_bytes": 100,
                   "body_sha256": [body_hash],
                   "paths": ["responses" if transport == "http" else "websocket"]},
        "trace_files": [{"compact_json": {"bytes": 100, "sha256": body_hash}}],
        "native_events": [{"kind": f"synthetic_{transport}_hit", "bytes": 100,
                           "sha256": body_hash, "marker_offset": 50}],
        "collection": {"observation_only": True, "readback_exact": True,
                       "body_bytes": 100, "body_sha256": body_hash,
                       "archive_record_id": "1" * 32,
                       "recorded_decision_point": "none",
                       "recorded_route_decision": "not_enforceable",
                       "recorded_released_by_route": None},
    }


def _write_fixture(tmp_path: Path, report: dict) -> Path:
    path = tmp_path / "report.json"
    evidence_dir = tmp_path / "report-evidence"
    archive_dir = evidence_dir / "archive"
    archive_dir.mkdir(parents=True)
    (archive_dir / "archive-key.dpapi").write_bytes(b"test-key")
    record_id = report["collection"]["archive_record_id"]
    (archive_dir / f"{record_id}.enc").write_bytes(b"test-frame")
    collection_file = evidence_dir / "collection.jsonl"
    collection_file.write_text(json.dumps({
        "schema": "transpect.codex-collection/1.0", "category": "request_envelope",
        "archive_record_id": record_id, "archive_kind": "model_request",
        "protocol": report["transport"], "route": "native", "gate_mode": "observe",
        "content_bytes": len(BODY), "request_sha256": BODY_HASH,
        "decision_point": "none", "route_decision": "not_enforceable",
        "released_by_route": None,
    }) + "\n", encoding="utf-8")
    report["collection"]["archive_directory"] = str(archive_dir)
    report["collection"]["collection_file"] = str(collection_file)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


@pytest.fixture
def fake_archive(monkeypatch):
    class Archive:
        def __init__(self, directory):
            assert directory.name == "archive"

        def read(self, record_id):
            assert record_id == "1" * 32
            receipt = SimpleNamespace(kind="model_request", body_bytes=len(BODY), body_sha256=BODY_HASH)
            return receipt, BODY

    monkeypatch.setattr(builder, "EncryptedRequestArchive", Archive)


@pytest.mark.parametrize("transport", ["http", "wss"])
def test_accepts_exact_observation_only_collection(tmp_path, transport, fake_archive):
    path = _write_fixture(tmp_path, _report(transport))
    evidence = builder._check_capture(path, transport)
    assert evidence["full_body_readback_exact"] is True
    assert evidence["observation_only"] is True
    assert evidence["decrypted_archive_verified"] is True
    assert evidence["collection_envelope_verified"] is True
    assert evidence["target_body_sha256"] == BODY_HASH


@pytest.mark.parametrize("change", [
    lambda report: report["collection"].update(body_sha256="b" * 64),
    lambda report: report.update(synthetic_collection_validated=False),
    lambda report: report.update(codex_command_hooks_present=True),
    lambda report: report["collection"].update(recorded_route_decision="allow"),
])
def test_rejects_missing_or_nonobservation_evidence(tmp_path, change, fake_archive):
    report = deepcopy(_report("http"))
    change(report)
    path = _write_fixture(tmp_path, report)
    with pytest.raises(SystemExit, match="Lab-only fail-stop build refused"):
        builder._check_capture(path, "http")


def test_rejects_collection_envelope_claiming_release(tmp_path, fake_archive):
    path = _write_fixture(tmp_path, _report("http"))
    collection_file = tmp_path / "report-evidence/collection.jsonl"
    row = json.loads(collection_file.read_text(encoding="utf-8"))
    row["released_by_route"] = True
    collection_file.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="collection envelope"):
        builder._check_capture(path, "http")


def test_rejects_unreadable_dpapi_archive(tmp_path, monkeypatch):
    path = _write_fixture(tmp_path, _report("http"))

    class UnreadableArchive:
        def __init__(self, directory):
            pass

        def read(self, record_id):
            raise OSError("DPAPI unavailable")

    monkeypatch.setattr(builder, "EncryptedRequestArchive", UnreadableArchive)
    with pytest.raises(SystemExit, match="DPAPI archive readback failed"):
        builder._check_capture(path, "http")
