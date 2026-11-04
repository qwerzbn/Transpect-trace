"""MXC receiver verdicts require positive controls and an attempted child send."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_codex_mxc_egress as mxc  # noqa: E402


def test_receiver_addresses_exclude_loopback_and_require_ipv6_scope():
    for address in ("127.0.0.1", "::1", "0.0.0.0", "fe80::1"):
        with pytest.raises(ValueError):
            mxc._address_parts(address)
    assert mxc._address_parts("172.24.240.1") == (socket.AF_INET, "172.24.240.1", 0)
    assert mxc._address_parts("fe80::1%42") == (socket.AF_INET6, "fe80::1", 42)
    assert mxc._socket_address("fe80::1%42", 1234) == ("fe80::1", 1234, 0, 42)


def test_local_inventory_only_returns_assigned_nonloopback_addresses(monkeypatch):
    rows = [
        {"InterfaceAlias": "Loopback Pseudo-Interface 1", "IPAddress": "127.0.0.1"},
        {"InterfaceAlias": "WLAN", "IPAddress": "10.50.30.34"},
        {"InterfaceAlias": "vEthernet (WSL)", "IPAddress": "172.24.240.1"},
        {"InterfaceAlias": "vEthernet (WSL)", "IPAddress": "fe80::1%42"},
        {"InterfaceAlias": "WLAN", "IPAddress": "fe80::2%18"},
    ]
    monkeypatch.setattr(mxc.subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess(a[0], 0, json.dumps(rows)))
    assert mxc._local_candidates() == {
        4: ["172.24.240.1", "10.50.30.34"],
        6: ["fe80::1%42", "fe80::2%18"],
    }


def test_zero_bytes_is_not_a_pass_without_a_live_child_and_positive_control():
    marker = b"FAKE_MXC_EGRESS_test_sandbox_tcp4"
    run = {"exit_code": 0, "result": {"attempts": {"tcp4": {"attempted": True}}}}
    assert mxc.classify_route(False, run, "tcp4", [], marker) == "unvalidated_baseline"
    assert mxc.classify_route(True, {"exit_code": 1, "result": None},
                              "tcp4", [], marker) == "unvalidated_client"
    assert mxc.classify_route(True, run, "tcp4", [], marker) == "blocked_at_receiver"
    assert mxc.classify_route(True, run, "tcp4", [{"bytes": 0,
                                                     "sha256": hashlib.sha256(b"").hexdigest()}],
                              marker) == "unvalidated_other_traffic_or_connection"
    receipt = {"bytes": len(marker), "sha256": hashlib.sha256(marker).hexdigest()}
    assert mxc.classify_route(True, run, "tcp4", [receipt], marker) == "egress_reached_receiver"
    sinks, baseline, failures = mxc._select_family([], 6, "a" * 32)
    assert sinks == {} and baseline["attempts"] == {} and failures == []


def test_manifest_rejects_mismatched_family_and_loopback(tmp_path):
    path = tmp_path / "manifest.json"
    value = {"schema": mxc.SCHEMA, "nonce": "a" * 32,
             "endpoints": {"tcp4": {"host": "::1", "port": 1234}}}
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError):
        mxc._read_manifest(path)
    value["endpoints"]["tcp4"]["host"] = "fe80::1%42"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="family mismatch"):
        mxc._read_manifest(path)
