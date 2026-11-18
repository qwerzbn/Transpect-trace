"""Offline proxy and WFP contract tests; no live filter installation."""
from __future__ import annotations

import json
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import sys
import time
from threading import Thread
from types import SimpleNamespace
import subprocess

import pytest

from transpect_trace.guard.claude_egress import (
    CONFIG_SCHEMA, EgressBoundaryError, EgressConfig, check_egress_health,
    start_proxy_permit, stop_egress,
)
from transpect_trace.guard.claude_proxy import ClaudeProxyPolicy, ClaudeToolProxyAddon, MAX_BODY


SID = "S-1-5-21-101-202-303-1001"
TOKEN = b"ghp_" + b"aB3d4E" * 6


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "egress.json"
    path.write_text(json.dumps({
        "schema": CONFIG_SCHEMA, "isolated_vm": True,
        "wfp_executable": str(Path(__file__).resolve()), "dedicated_sid": SID,
        "proxy_host": "127.0.0.1", "proxy_port": 8765,
        "v4_filter_id": 101, "v6_filter_id": 102,
    }), encoding="utf-8")
    return path


def test_proxy_policy_allows_plain_text_and_blocks_secret(tmp_path):
    policy = ClaudeProxyPolicy(tmp_path)
    common = {"url": "https://example.org/upload",
              "headers": [("Content-Type", "text/plain")],
              "content_type": "text/plain"}
    assert policy.decide(**common, body=b"ordinary data").allow is True
    denied = policy.decide(**common, body=TOKEN)
    assert denied.allow is False and denied.reason == "SENSITIVE_OR_UNINSPECTABLE_CONTENT"
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [row["decision"] for row in rows] == ["allow", "deny"]
    assert not any("ghp_" in json.dumps(row) for row in rows)


def test_proxy_policy_blocks_oversize_opaque_and_auth_header(tmp_path):
    policy = ClaudeProxyPolicy(tmp_path)
    base = {"url": "https://example.org/upload", "headers": [],
            "content_type": "application/octet-stream"}
    assert not policy.decide(**base, body=b"opaque").allow
    assert not policy.decide(**base, body=b"x" * (MAX_BODY + 1)).allow
    assert not policy.decide(url=base["url"], headers=[("Authorization", "Bearer example")],
                             content_type="text/plain", body=b"normal").allow
    encoded_key = b'{"value":"' + b'\\u0067' + TOKEN[1:] + b'"}'
    assert not policy.decide(url=base["url"], headers=[],
                             content_type="application/json", body=encoded_key).allow
    assert not policy.decide(url=base["url"], headers=[],
                             content_type="application/json",
                             body=b'{"attachment":"data:application/octet-stream;base64,QQ=="}').allow


def test_proxy_policy_fails_closed_on_archive_error(tmp_path, monkeypatch):
    policy = ClaudeProxyPolicy(tmp_path)
    archive, _ = policy.gate._prepare()
    monkeypatch.setattr(archive, "save", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk")))
    decision = policy.decide(url="https://example.org/", headers=[],
                             content_type="text/plain", body=b"normal")
    assert decision.allow is False and decision.reason == "INSPECTION_FAILED"


def test_addon_exception_keeps_local_503(tmp_path):
    pytest.importorskip("mitmproxy")
    addon = ClaudeToolProxyAddon(tmp_path)

    class BrokenRequest:
        pretty_host = "example.org"
        path = "/upload"
        pretty_url = "https://example.org/upload"
        headers = {"Content-Type": "text/plain"}

        def get_content(self, strict=True):
            raise RuntimeError("decompression failed")

    flow = SimpleNamespace(request=BrokenRequest(), response=None)
    addon.request(flow)
    assert flow.response.status_code == 503


def test_config_requires_vm_loopback_and_dedicated_sid(tmp_path):
    path = _config(tmp_path)
    assert EgressConfig.load(path).proxy_host == "127.0.0.1"
    value = json.loads(path.read_text())
    value["proxy_host"] = "0.0.0.0"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid Claude VM"):
        EgressConfig.load(path)
    value["proxy_host"] = "127.0.0.1"
    value["isolated_vm"] = False
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="isolated VM"):
        EgressConfig.load(path)


def test_health_never_infers_vm_acceptance_from_live_components(tmp_path, monkeypatch):
    from transpect_trace.guard import claude_egress as module
    path = _config(tmp_path)
    monkeypatch.setattr(module.WfpBoundary, "assert_default_deny", lambda self: {"installed": True})
    monkeypatch.setattr(module, "_native_status", lambda config: True)
    monkeypatch.setattr(module, "_proxy_health", lambda config: True)
    monkeypatch.setattr(module, "_health_cache", None)
    health = check_egress_health(path)
    assert not health.ready and health.reason == "VM_ACCEPTANCE_PENDING"
    assert health.wfp_verified and health.permit_verified and health.proxy_verified
    assert health.vm_accepted is False


def test_stop_without_vm_config_is_noop(tmp_path):
    stop_egress(tmp_path / "absent.json")


def test_stop_detects_setup_before_proxy_config(tmp_path, monkeypatch):
    from transpect_trace.guard import claude_egress as module
    marker = tmp_path / "marker.json"
    marker.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(module, "DEFAULT_MARKER", marker)
    with pytest.raises(EgressBoundaryError, match="NETWORK_RULES_UNKNOWN"):
        stop_egress(tmp_path / "absent.json")


def test_stop_reports_rules_remaining_when_remove_fails(tmp_path, monkeypatch):
    from transpect_trace.guard import claude_egress as module
    path = _config(tmp_path)
    monkeypatch.setattr(module.WfpBoundary, "_command",
                        lambda self, command: (_ for _ in ()).throw(OSError("access denied")))
    with pytest.raises(EgressBoundaryError, match="NETWORK_RULES_REMAIN"):
        stop_egress(path)


def test_proxy_permit_requires_controller_and_proxy_identities(tmp_path, monkeypatch):
    from transpect_trace.guard import claude_egress as module
    class Output:
        def readline(self):
            return ('{"state":"proxy_permit_active","v4_filter_id":11,'
                    '"v6_filter_id":12,"sid_wide":true,"loopback_only":true,'
                    '"pid_exact_filter":false}\n')
        def close(self):
            pass
    class Process:
        stdout = Output()
        stderr = Output()
        def __init__(self, args, **kwargs):
            self.args = args
        def poll(self):
            return None
        def terminate(self):
            pass
        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(subprocess, "Popen", Process)
    lease = start_proxy_permit(executable=Path(__file__), sid=SID, port=8765,
                               controller_pid=21, controller_birth=22,
                               proxy_pid=31, proxy_birth=32)
    assert lease.process.args[1:] == ["proxy-lease", SID, "8765", "21", "22", "31", "32", "--isolated-vm"]
    assert lease.v4_filter_id == 11 and lease.v6_filter_id == 12
    lease.close()
    with pytest.raises(ValueError, match="invalid isolated VM"):
        start_proxy_permit(executable=Path(__file__), sid=SID, port=8765,
                           controller_pid=21, controller_birth=22,
                           proxy_pid=21, proxy_birth=32)


def test_local_proxy_keeps_denied_and_oversize_bodies_off_origin(tmp_path):
    """Local synthetic origin only; no WFP setup or external network."""
    executable = Path(sys.executable).with_name("mitmdump.exe")
    if not executable.is_file():
        pytest.skip("locked mitmproxy extra is unavailable")
    received: list[bytes] = []

    class Origin(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *_):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    server_thread = Thread(target=origin.serve_forever, daemon=True)
    server_thread.start()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ, TTRACE_CLAUDE_PROXY_STATE=str(tmp_path / "proxy"))
    process = subprocess.Popen([
        str(executable), "--mode", f"regular@127.0.0.1:{port}",
        "--mode", f"regular@[::1]:{port}", "--set", "flow_detail=0",
        "--set", "body_size_limit=1m", "-s",
        str(root / "scripts/claude_tool_proxy_addon.py")],
        cwd=root, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("local proxy did not start")
        def send(body: bytes) -> int | None:
            client = HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                client.request("POST", f"http://127.0.0.1:{origin.server_port}/upload",
                               body=body, headers={"Content-Type": "text/plain"})
                response = client.getresponse()
                response.read()
                return response.status
            except OSError:
                return None
            finally:
                client.close()
        assert send(b"ordinary demo data") == 200
        assert send(TOKEN) == 400
        send(b"x" * (1024 * 1024 + 1))
        time.sleep(0.2)
        assert received == [b"ordinary demo data"]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        origin.shutdown()
        origin.server_close()
        server_thread.join(timeout=5)
