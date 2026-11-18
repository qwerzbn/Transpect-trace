"""Model proxy policy and mitmproxy adapter, with no external destination."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from mitmproxy import http

from transpect_trace.guard.claude_model_proxy import (
    CONFIG_SCHEMA, ClaudeModelProxyAddon, ClaudeModelProxyPolicy,
    ModelProxyConfig,
)
from transpect_trace.protect.archive import EncryptedRequestArchive


TOKEN = "ghp_" + "aB3d4E" * 6
ORIGIN = "https://example.test:8443"


def _config(tmp_path: Path) -> ModelProxyConfig:
    path = tmp_path / "model-proxy.json"
    path.write_text(json.dumps({"schema": CONFIG_SCHEMA,
                                "state_dir": str(tmp_path / "state"),
                                "session_id": "isolated-claude-1",
                                "allowed_origins": [ORIGIN]}), encoding="utf-8")
    return ModelProxyConfig.load(path)


def _body(messages) -> bytes:
    return json.dumps({"model": "claude-sonnet-4-5", "max_tokens": 128,
                       "stream": True, "messages": messages},
                      ensure_ascii=False).encode()


def _decide(policy, body: bytes):
    return policy.decide(client_connection_id="client-a", method="POST",
                         url=ORIGIN + "/v1/messages?beta=true",
                         headers=[("Content-Type", "application/json"),
                                  ("Authorization", "Bearer synthetic-lab-token")],
                         body=body, content_type="application/json",
                         content_encoding="")


def test_model_proxy_denies_current_block_and_scrubs_only_later_history(tmp_path):
    policy = ClaudeModelProxyPolicy(_config(tmp_path))
    first = _body([{"role": "user", "content": "现在只回答 OK"}])
    allowed = _decide(policy, first)
    assert allowed.allow and allowed.forward_body == first

    messages = [{"role": "user", "content": "现在只回答 OK"},
                {"role": "assistant", "content": "OK"},
                {"role": "user", "content": "内部令牌：" + TOKEN}]
    denied = _decide(policy, _body(messages))
    assert not denied.allow and denied.forward_body is None
    messages.append({"role": "user", "content": "再回答 OK"})
    continued = _decide(policy, _body(messages))
    assert continued.allow and continued.forward_body is not None
    assert TOKEN.encode() not in continued.forward_body
    assert b"OK" in continued.forward_body
    assert continued.forward_sha256 != continued.original_sha256
    rows = [json.loads(line) for line in policy.audit_file.read_text().splitlines()]
    assert [row["decision"] for row in rows] == ["allow", "deny", "allow"]
    assert all(TOKEN not in json.dumps(row) for row in rows)


def test_model_proxy_fail_closed_on_destination_format_and_audit_error(tmp_path):
    policy = ClaudeModelProxyPolicy(_config(tmp_path))
    body = _body([{"role": "user", "content": "hello"}])
    assert not policy.decide(client_connection_id="client-a", method="POST",
                             url="https://other.test:8443/v1/messages",
                             headers=[], body=body, content_type="application/json",
                             content_encoding="").allow
    assert policy.decide(client_connection_id="client-a", method="POST",
                         url=ORIGIN + "/other",
                         headers=[], body=body, content_type="application/json",
                         content_encoding="").allow
    assert not policy.decide(client_connection_id="client-a", method="POST",
                             url=ORIGIN + "/v1/messages",
                             headers=[], body=body, content_type="application/json",
                             content_encoding="zstd").allow
    assert not policy.decide(client_connection_id="client-a", method="POST",
                             url=ORIGIN + "/v1/messages",
                             headers=[], body=b'{"messages":[],"messages":[]}',
                             content_type="application/json",
                             content_encoding="").allow
    policy.audit_file = tmp_path
    assert not _decide(policy, body).allow


def test_model_proxy_accepts_explicit_https_default_port(tmp_path):
    config = ModelProxyConfig(tmp_path / "state", "one-session",
                              frozenset({"https://api.anthropic.com:443"}))
    policy = ClaudeModelProxyPolicy(config)
    decision = policy.decide(client_connection_id="client-a", method="POST",
                             url="https://api.anthropic.com/v1/messages",
                             headers=[("Content-Type", "application/json")],
                             body=_body([{"role": "user", "content": "hello"}]),
                             content_type="application/json", content_encoding="")
    assert decision.allow


def test_model_proxy_does_not_share_denied_history_across_clients(tmp_path):
    policy = ClaudeModelProxyPolicy(_config(tmp_path))
    secret = _body([{"role": "user", "content": "内部令牌：" + TOKEN}])
    first = _decide(policy, secret)
    assert not first.allow
    later = _body([{"role": "user", "content": "内部令牌：" + TOKEN},
                   {"role": "user", "content": "现在回答 OK"}])
    other_client = policy.decide(
        client_connection_id="client-b", method="POST",
        url=ORIGIN + "/v1/messages", headers=[("Content-Type", "application/json")],
        body=later, content_type="application/json", content_encoding="")
    assert not other_client.allow


def test_model_proxy_addon_recompresses_scrubbed_gzip(tmp_path):
    addon = ClaudeModelProxyAddon(_config(tmp_path))
    first = _body([{"role": "user", "content": "内部令牌：" + TOKEN}])
    denied_request = http.Request.make("POST", ORIGIN + "/v1/messages", first,
                                       {"Content-Type": "application/json",
                                        "Content-Encoding": "gzip"})
    denied_flow = SimpleNamespace(request=denied_request, response=None, metadata={},
                                  client_conn=SimpleNamespace(id="client-a"))
    addon.request(denied_flow)
    assert denied_flow.response.status_code == 403

    later = _body([{"role": "user", "content": "内部令牌：" + TOKEN},
                   {"role": "user", "content": "现在回答 OK"}])
    allowed_request = http.Request.make("POST", ORIGIN + "/v1/messages", later,
                                        {"Content-Type": "application/json",
                                         "Content-Encoding": "gzip"})
    allowed_flow = SimpleNamespace(request=allowed_request, response=None, metadata={},
                                   client_conn=SimpleNamespace(id="client-a"))
    addon.request(allowed_flow)
    assert allowed_flow.response is None
    allowed_flow.response = http.Response.make(200, b"data: hello\n\n",
                                                {"Content-Type": "text/event-stream"})
    addon.responseheaders(allowed_flow)
    assert allowed_flow.response.stream is True
    assert TOKEN.encode() not in allowed_request.get_content(strict=True)
    assert allowed_request.raw_content.startswith(b"\x1f\x8b")
    assert int(allowed_request.headers["Content-Length"]) == len(allowed_request.raw_content)


def test_model_proxy_addon_keeps_503_on_decode_error(tmp_path):
    addon = ClaudeModelProxyAddon(_config(tmp_path))
    request = http.Request.make("POST", ORIGIN + "/v1/messages", b"bad gzip",
                                {"Content-Type": "application/json",
                                 "Content-Encoding": "gzip"})
    request.raw_content = b"bad gzip"
    flow = SimpleNamespace(request=request, response=None, metadata={},
                           client_conn=SimpleNamespace(id="client-a"))
    addon.request(flow)
    assert flow.response.status_code == 503


def test_generic_json_scans_provider_shapes_and_archives_before_allow(tmp_path):
    policy = ClaudeModelProxyPolicy(_config(tmp_path))
    cases = [
        ("/model/anthropic.claude/invoke", {"anthropic_version": "bedrock-2023-05-31",
                                                "messages": [{"role": "user", "content": "OK"}]}),
        ("/v1/projects/test/locations/us/publishers/anthropic/models/claude:rawPredict",
         {"contents": [{"role": "user", "parts": [{"text": "OK"}]}]}),
        ("/openai/responses", {"input": [{"role": "user", "content": "OK"}]}),
    ]
    archive = EncryptedRequestArchive(tmp_path / "state" / "archive")
    for path, value in cases:
        body = json.dumps(value).encode()
        decision = policy.decide(client_connection_id="client-a", method="POST",
                                 url=ORIGIN + path, headers=[], body=body,
                                 content_type="application/json", content_encoding="")
        assert decision.allow and decision.forward_body == body
    rows = [json.loads(line) for line in policy.audit_file.read_text().splitlines()]
    assert [row["dialect"] for row in rows] == ["generic_model_json"] * 3
    for row, (_, value) in zip(rows, cases):
        receipt, recovered = archive.read(row["archive_record_id"])
        assert receipt.kind == "model_request"
        assert recovered == json.dumps(value).encode()


def test_generic_json_rejects_sensitive_split_and_opaque_content(tmp_path):
    policy = ClaudeModelProxyPolicy(_config(tmp_path))
    cases = [
        {"messages": [{"content": "内部令牌：" + TOKEN}]},
        {"input": ["内部令牌：", TOKEN[:22], TOKEN[22:]]},
        {"input": {"银行卡": 4111111111111111}},
        {"contents": [{"parts": [{"type": "image", "source": {"data": "AA=="}}]}]},
        {"messages": [{"content": [{"image": {"source": {"bytes": "AA=="}}}]}]},
        {"prompt": "data:image/png;base64,AA=="},
    ]
    for index, value in enumerate(cases):
        body = json.dumps(value, ensure_ascii=False).encode()
        decision = policy.decide(client_connection_id="client-a", method="POST",
                                 url=ORIGIN + f"/provider/{index}", headers=[], body=body,
                                 content_type="application/json", content_encoding="")
        assert not decision.allow and decision.forward_body is None
    duplicate = b'{"input":"safe","input":"hidden"}'
    assert not policy.decide(client_connection_id="client-a", method="POST",
                             url=ORIGIN + "/provider", headers=[], body=duplicate,
                             content_type="application/json", content_encoding="").allow


def test_signed_generic_request_preserves_bytes_and_custom_403(tmp_path):
    config = replace(_config(tmp_path), deny_message="本地策略已阻止本次请求")
    addon = ClaudeModelProxyAddon(config)
    headers = {"Content-Type": "application/json",
               "Authorization": "AWS4-HMAC-SHA256 Credential=synthetic"}
    safe = b'{ "messages" : [ { "content" : "OK" } ], "model": "claude" }'
    request = http.Request.make("POST", ORIGIN + "/model/claude/invoke", safe, headers)
    flow = SimpleNamespace(request=request, response=None, metadata={},
                           client_conn=SimpleNamespace(id="client-a"))
    addon.request(flow)
    assert flow.response is None and request.content == safe
    assert request.raw_content == safe
    unsafe = json.dumps({"input": "内部令牌：" + TOKEN}).encode()
    request = http.Request.make("POST", ORIGIN + "/model/claude/invoke", unsafe, headers)
    flow = SimpleNamespace(request=request, response=None, metadata={},
                           client_conn=SimpleNamespace(id="client-a"))
    addon.request(flow)
    assert flow.response.status_code == 403
    assert json.loads(flow.response.content)["error"]["message"] == config.deny_message


def test_generic_gzip_is_scanned_without_changing_allowed_wire_body(tmp_path):
    addon = ClaudeModelProxyAddon(_config(tmp_path))
    safe = json.dumps({"contents": [{"parts": [{"text": "OK"}]}]}).encode()
    request = http.Request.make("POST", ORIGIN + "/provider:rawPredict", safe,
                                {"Content-Type": "application/json",
                                 "Content-Encoding": "gzip"})
    before = request.raw_content
    flow = SimpleNamespace(request=request, response=None, metadata={},
                           client_conn=SimpleNamespace(id="client-a"))
    addon.request(flow)
    assert flow.response is None
    assert request.raw_content == before
    assert request.get_content(strict=True) == safe
    unsafe = json.dumps({"contents": [{"text": "内部令牌：" + TOKEN}]},
                        ensure_ascii=False).encode()
    request = http.Request.make("POST", ORIGIN + "/provider:rawPredict", unsafe,
                                {"Content-Type": "application/json",
                                 "Content-Encoding": "gzip"})
    flow = SimpleNamespace(request=request, response=None, metadata={},
                           client_conn=SimpleNamespace(id="client-a"))
    addon.request(flow)
    assert flow.response.status_code == 403


def test_custom_403_reason_template_only_exposes_safe_categories(tmp_path):
    config = replace(_config(tmp_path), deny_message="本地 DLP 已拒绝请求：{reason}。")
    addon = ClaudeModelProxyAddon(config)
    cases = [
        (ORIGIN + "/provider", {"input": "内部令牌：" + TOKEN},
         "application/json", "检测到凭据或密钥"),
        (ORIGIN + "/provider", {"input": {"银行卡": 4111111111111111}},
         "application/json", "检测到个人信息"),
        (ORIGIN + "/provider", {"input": "OK"},
         "text/plain", "请求内容无法完整检查"),
        ("https://other.test:8443/provider", {"input": "OK"},
         "application/json", "目标地址未获准"),
        (ORIGIN + "/v1/messages", {"model": "claude", "messages": [
            {"role": "user", "content": "内部令牌：" + TOKEN}]},
         "application/json", "检测到敏感内容"),
    ]
    for url, value, media_type, expected in cases:
        request = http.Request.make("POST", url,
                                    json.dumps(value, ensure_ascii=False).encode(),
                                    {"Content-Type": media_type})
        flow = SimpleNamespace(request=request, response=None, metadata={},
                               client_conn=SimpleNamespace(id="client-a"))
        addon.request(flow)
        assert flow.response.status_code == 403
        message = json.loads(flow.response.content)["error"]["message"]
        assert expected in message
        assert TOKEN not in message and "GITHUB_TOKEN" not in message
        assert "{reason}" not in message
