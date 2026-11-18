"""Fail-closed mitmproxy addon for the isolated Claude tool account.

Only HTTP request bodies and WebSocket client messages can be released. An
unparseable payload, audit failure, unsupported generic TCP/UDP flow, or policy
exception is denied before application bytes are forwarded upstream. Run the
addon in regular proxy mode with request streaming disabled.
"""
from __future__ import annotations

from dataclasses import dataclass
from email import policy as email_policy
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import threading
from urllib.parse import urlsplit

from transpect_trace.protect.codex_hook_gate import CodexHookGate, GateConfig


MAX_BODY = 16 * 1024 * 1024
MAX_HEADERS = 64 * 1024
MAX_PARTS = 32
_AUTH_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key"}
_TEXT_MIME = {"application/json", "application/xml", "application/x-www-form-urlencoded",
              "application/javascript", "application/graphql", "application/yaml"}


@dataclass(frozen=True)
class ProxyDecision:
    allow: bool
    reason: str
    body_sha256: str


class ClaudeProxyPolicy:
    def __init__(self, state_dir: Path):
        directory = Path(state_dir)
        config = GateConfig(mode="enforce", archive_directory=directory / "archive",
                            audit_file=directory / "audit.jsonl", registration_directory=None,
                            review_override_ttl_seconds=0)
        self.gate = CodexHookGate(config)
        self.audit_file = config.audit_file
        self._lock = threading.RLock()

    def _inspect_body(self, engine, content_type: str, body: bytes, url: str) -> list:
        if not body:
            return []
        mime = content_type.split(";", 1)[0].strip().lower()
        if mime == "multipart/form-data":
            message = BytesParser(policy=email_policy.default).parsebytes(
                ("MIME-Version: 1.0\r\nContent-Type: " + content_type + "\r\n\r\n").encode("ascii")
                + body)
            if not message.is_multipart():
                raise ValueError("malformed multipart body")
            parts = list(message.iter_parts())
            if not 1 <= len(parts) <= MAX_PARTS:
                raise ValueError("multipart part count outside limit")
            verdicts = []
            for part in parts:
                if part.is_multipart():
                    raise ValueError("nested multipart unsupported")
                data = part.get_payload(decode=True)
                if not isinstance(data, bytes) or len(data) > MAX_BODY:
                    raise ValueError("multipart part unavailable")
                filename = part.get_filename()
                if filename:
                    verdicts.append(engine.inspect_file_bytes(Path(filename).name, data))
                else:
                    verdicts.append(engine.inspect_text(data.decode("utf-8", "strict")))
            return verdicts
        if mime == "application/json":
            value = json.loads(body.decode("utf-8", "strict"))
            leaves: list[str] = []
            nodes = 0
            def visit(item, depth: int) -> None:
                nonlocal nodes
                nodes += 1
                if depth > 64 or nodes > 100_000:
                    raise ValueError("JSON inspection limit exceeded")
                if isinstance(item, dict):
                    for key, child in item.items():
                        if not isinstance(key, str) or "base64" in key.lower():
                            raise ValueError("uninspectable JSON object")
                        leaves.append(key)
                        visit(child, depth + 1)
                elif isinstance(item, list):
                    for child in item:
                        visit(child, depth + 1)
                elif isinstance(item, str):
                    if item.startswith("data:"):
                        raise ValueError("uninspectable inline data")
                    leaves.append(item)
                elif item is not None:
                    leaves.append(str(item))
            visit(value, 0)
            return [engine.inspect_text("\n".join(leaves))]
        if mime.startswith("text/") or mime in _TEXT_MIME:
            return [engine.inspect_text(body.decode("utf-8", "strict"))]
        # A known filename lets the existing document parser inspect PDF and
        # office formats. A generic octet stream has no safe interpretation.
        name = Path(urlsplit(url).path).name
        if name and Path(name).suffix.lower() in {".txt", ".md", ".csv", ".json",
                                                   ".pdf", ".docx", ".xlsx", ".pptx"}:
            return [engine.inspect_file_bytes(name, body)]
        raise ValueError("unsupported body media type")

    def decide(self, *, url: str, headers: list[tuple[str, str]],
               content_type: str, body: bytes) -> ProxyDecision:
        sha = hashlib.sha256(body).hexdigest() if isinstance(body, bytes) else ""
        reason = "INSPECTION_FAILED"
        allow = False
        try:
            if (not isinstance(body, bytes) or len(body) > MAX_BODY or not isinstance(url, str)
                    or len(url.encode("utf-8")) > 8192):
                raise ValueError("request too large")
            if sum(len(k) + len(v) for k, v in headers) > MAX_HEADERS:
                raise ValueError("headers too large")
            # Tool credentials require a separate allowlist/credential policy;
            # forwarding an opaque bearer value would violate full inspection.
            if any(k.lower() in _AUTH_HEADERS for k, _ in headers):
                raise ValueError("tool authentication header not approved")
            with self._lock:
                archive, engine = self.gate._prepare()
                visible = [url, *(f"{key}: {value}" for key, value in headers)]
                verdicts = [engine.inspect_text("\n".join(visible))]
                verdicts.extend(self._inspect_body(engine, content_type, body, url))
                if all(self.gate.actionable(item) == "ALLOW" for item in verdicts):
                    reason, allow = "REQUIRED_CHECKS_COMPLETE", True
                else:
                    reason = "SENSITIVE_OR_UNINSPECTABLE_CONTENT"
                # Durable encrypted snapshot and metadata audit precede allow.
                archive.save("tool_command", "\n".join(visible).encode("utf-8"))
                if body:
                    archive.save("attachment", body)
                row = {"schema": "transpect.claude-tool-egress/1.0",
                       "decision": "allow" if allow else "deny", "reason": reason,
                       "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                       "body_sha256": sha, "body_bytes": len(body)}
                self.audit_file.parent.mkdir(parents=True, exist_ok=True)
                with self.audit_file.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
        except Exception:
            allow = False
            reason = "INSPECTION_FAILED"
        return ProxyDecision(allow, reason, sha)


class ClaudeToolProxyAddon:
    """mitmproxy event adapter; an explicit local response is the default."""

    def __init__(self, state_dir: Path):
        self.policy = ClaudeProxyPolicy(state_dir)

    def configure(self, updated) -> None:
        from mitmproxy import ctx, exceptions
        options = ctx.options
        if (getattr(options, "stream_large_bodies", None)
                or getattr(options, "stream_websockets", False)
                or getattr(options, "ignore_hosts", ())
                or getattr(options, "ssl_insecure", False)):
            raise exceptions.OptionsError("Claude tool proxy requires full buffering and TLS verification")

    def requestheaders(self, flow) -> None:
        # The request hook must run before the first upstream body byte.
        flow.request.stream = False

    def request(self, flow) -> None:
        from mitmproxy import http
        request = flow.request
        if request.pretty_host == "transpect.invalid" and request.path == "/__ttrace_health":
            nonce = request.headers.get("X-TTrace-Nonce", "")
            if len(nonce) == 24 and all(c in "0123456789abcdef" for c in nonce):
                flow.response = http.Response.make(204, b"", {
                    "X-TTrace-Nonce": nonce, "X-TTrace-Proxy": "claude-egress/1"})
            else:
                flow.response = http.Response.make(400, b"invalid health challenge")
            return
        flow.response = http.Response.make(503, b"local DLP unavailable")
        try:
            body = request.get_content(strict=True)
            if body is None:
                return
            decision = self.policy.decide(
                url=request.pretty_url, headers=list(request.headers.items(multi=True)),
                content_type=request.headers.get("Content-Type", ""), body=body)
            if decision.allow:
                flow.response = None
            else:
                flow.response = http.Response.make(400, b"local DLP denied request")
        except Exception:
            # Keep the preinstalled 503. mitmproxy must never continue after an
            # addon exception or missing/decompressed body.
            return

    def websocket_message(self, flow) -> None:
        message = flow.websocket.messages[-1]
        if not message.from_client:
            return
        try:
            body = bytes(message.content)
            if not message.is_text:
                self._drop_or_kill(message, flow)
                return
            decision = self.policy.decide(url=flow.request.pretty_url, headers=[],
                                          content_type="text/plain", body=body)
            if not decision.allow:
                self._drop_or_kill(message, flow)
        except Exception:
            self._drop_or_kill(message, flow)

    @staticmethod
    def _drop_or_kill(message, flow) -> None:
        try:
            message.drop()
        except Exception:
            flow.kill()

    def tcp_message(self, flow) -> None:
        if flow.messages[-1].from_client:
            self._drop_or_kill(flow.messages[-1], flow)

    def udp_message(self, flow) -> None:
        if flow.messages[-1].from_client:
            self._drop_or_kill(flow.messages[-1], flow)
