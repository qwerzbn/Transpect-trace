"""The deployment gate must require artifacts, not self asserted PASS rows."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import accept_pin  # noqa: E402


def test_acceptance_binds_the_shared_claude_policy():
    from transpect_trace.guard import claude_service
    from transpect_trace.protect.claude_policy import create_claude_engine

    assert claude_service._engine is create_claude_engine
    bindings = claude_service.acceptance_source_hashes(ROOT)
    for name in ("claude_policy.py", "codex_hook_gate.py"):
        path = f"src/transpect_trace/protect/{name}"
        assert bindings[path] == claude_service.common.normalized_sha256(ROOT / path)


def _report(path: Path, digest: str) -> Path:
    row = {"benign": "PASS", "sensitive": "PASS", "marker_at_origin": False,
           "native_audit_file": "audit.jsonl", "native_audit_sha256": digest,
           "origin_receipt_file": "receipt.json", "origin_receipt_sha256": digest}
    tui_row = {"result": "PASS", **row}
    egress_row = {"result": "PASS", **row}
    report = {"schema": "transpect.claude.live-acceptance/1.0",
              "binary_sha256": "a" * 64, "dll_sha256": "b" * 64,
              "providers": {name: row for name in accept_pin.LIVE_PROVIDERS},
              "tui": {name: tui_row for name in accept_pin.TUI_CASES},
              "egress": {name: egress_row for name in accept_pin.EGRESS_CASES}}
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_live_gate_rejects_missing_artifacts(tmp_path: Path):
    report = _report(tmp_path / "live.json", "0" * 64)
    with pytest.raises(FileNotFoundError):
        accept_pin.verify_live_evidence(report, "a" * 64, "b" * 64)


def test_live_gate_rejects_artifact_hash_mismatch(tmp_path: Path):
    raw = b'{"route_event":"model.request","decision":"allow"}\n'
    (tmp_path / "audit.jsonl").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    (tmp_path / "receipt.json").write_bytes(b"{}")
    report = _report(tmp_path / "live.json", digest)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        accept_pin.verify_live_evidence(report, "a" * 64, "b" * 64)
