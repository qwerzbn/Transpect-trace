"""Current-desktop tool receiver requires local addresses and positive controls."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_desktop_tool_egress_current as probe  # noqa: E402


def manifest() -> dict:
    return {
        "schema": probe.mxc.SCHEMA,
        "nonce": "a" * 32,
        "endpoints": {
            "tcp4": {"host": "192.0.2.20", "port": 20000},
            "udp4": {"host": "192.0.2.20", "port": 20001},
        },
    }


def test_client_rejects_unassigned_or_loopback_endpoint(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")
    monkeypatch.setattr(probe.mxc, "_local_candidates",
                        lambda: {4: ["198.51.100.10"], 6: []})
    with pytest.raises(ValueError, match="not assigned"):
        probe.validate_local_manifest(path)
    data = manifest()
    data["endpoints"]["tcp4"]["host"] = "127.0.0.1"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        probe.validate_local_manifest(path)


def test_client_writes_only_synthetic_attempt_metadata_once(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")
    monkeypatch.setattr(probe.mxc, "_local_candidates",
                        lambda: {4: ["192.0.2.20"], 6: []})
    monkeypatch.setattr(probe.mxc, "_attempts",
                        lambda value, phase, routes: {
                            "attempts": {route: {"attempted": True, "sent_bytes": 0,
                                                 "error_type": "PermissionError", "error_code": 13}
                                         for route in routes},
                        })
    result = probe.run_client(path)
    assert result["client_report_written"]
    report_path = tmp_path / "client-report.json"
    report = probe._read_client_report(report_path, manifest())
    assert report and set(report["attempts"]) == {"tcp4", "udp4"}
    assert "FAKE_MXC_EGRESS_" not in report_path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="already used"):
        probe.run_client(path)


def test_receivers_require_positive_control_and_actual_client_attempt():
    value = manifest()
    marker = probe.mxc._marker(value["nonce"], probe.PHASE, "tcp4")
    receipt = {"bytes": len(marker), "sha256": hashlib.sha256(marker).hexdigest()}
    attempted = {"schema": probe.SCHEMA, "phase": probe.PHASE,
                 "attempts": {route: {"attempted": True} for route in value["endpoints"]}}
    absent = probe.classify_routes(value, {"tcp4": True, "udp4": True},
                                   None, {"tcp4": [], "udp4": []})
    assert absent["tcp4"]["status"] == "unvalidated_client"
    no_control = probe.classify_routes(value, {}, attempted,
                                       {"tcp4": [], "udp4": []})
    assert no_control["tcp4"]["status"] == "unvalidated_baseline"
    reached = probe.classify_routes(value, {"tcp4": True, "udp4": True},
                                    attempted, {"tcp4": [receipt], "udp4": []})
    assert reached["tcp4"]["status"] == "egress_reached_receiver"
    assert reached["udp4"]["status"] == "blocked_at_receiver"
    assert reached["tcp6"]["status"] == "unvalidated_baseline"
    unknown = probe.classify_routes(value, {"tcp4": True, "udp4": True},
                                    attempted, {"tcp4": [{"bytes": 0,
                                                           "sha256": hashlib.sha256(b"").hexdigest()}],
                                                "udp4": []})
    assert unknown["tcp4"]["status"] == "unvalidated_other_traffic_or_connection"


def test_client_report_requires_matching_nonce_and_all_routes(tmp_path):
    path = tmp_path / "client-report.json"
    value = manifest()
    bad = {"schema": probe.SCHEMA, "phase": probe.PHASE,
           "nonce_sha256": "0" * 64,
           "attempts": {route: {"attempted": True} for route in value["endpoints"]}}
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert probe._read_client_report(path, value) is None
    bad["nonce_sha256"] = hashlib.sha256(value["nonce"].encode()).hexdigest()
    bad["attempts"].pop("udp4")
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert probe._read_client_report(path, value) is None
