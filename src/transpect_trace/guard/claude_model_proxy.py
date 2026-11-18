"""Explicit, fail-closed Claude model proxy for one isolated CLI session.

The addon is intentionally separate from the tool-egress proxy. It has a
permitted destination list and keeps model authorization headers opaque while
the complete JSON body is archived and inspected before it may go upstream.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit
import uuid

from ..protect.claude_policy import create_claude_engine
from .policy import GuardRequest


CONFIG_SCHEMA = "transpect.claude-model-proxy/1.0"
MAX_BODY = 16 * 1024 * 1024
MAX_HEADERS = 64 * 1024
_AUTH_HEADERS = frozenset(("authorization", "proxy-authorization", "x-api-key",
                           "x-goog-api-key", "x-amz-security-token", "cookie"))
_ENCODINGS = frozenset(("", "identity", "gzip"))
_MODEL_FIELDS = frozenset(("messages", "input", "contents", "instances", "prompt"))
_OPAQUE_PARTS = frozenset(("image", "document", "file", "input_image", "input_file"))
_OPAQUE_KEYS = frozenset(("file_id", "attachment_id", "image_url", "inline_data",
                          "inlinedata", "blob", "image", "document", "file_data",
                          "bytes", "binary", "media_type", "mime_type"))
_DEFAULT_DENY_MESSAGE = "Request blocked by Transpect local policy."
_LOG = logging.getLogger(__name__)


def _public_denial_reason(reason: str) -> str:
    """Describe a denial without returning request bytes or internal rule IDs."""
    if reason.startswith("SENSITIVE_OR_AMBIGUOUS_CONTENT:"):
        rule_ids = reason.partition(":")[2].split(",")
        if any(rule.startswith(("PAYMENT_CARD", "CN_ID", "PHONE", "EDM_"))
               for rule in rule_ids):
            return "检测到个人信息"
        if any(rule.startswith(("GITHUB_TOKEN", "PRIVATE_KEY", "AWS_", "ENTROPY_TOKEN"))
               for rule in rule_ids):
            return "检测到凭据或密钥"
        if any(rule.startswith(("FINGERPRINT:", "CODE_STRUCTURE"))
               for rule in rule_ids):
            return "检测到内部资料或源码"
    if (reason.startswith("SENSITIVE_OR_AMBIGUOUS_CONTENT")
            or reason == "DUPLICATE_INVOCATION"):
        return "检测到敏感内容"
    if reason.startswith("sensitive URL or header"):
        return "请求地址或请求头包含敏感内容"
    if reason == "destination is not an allowed origin":
        return "目标地址未获准"
    if "deadline exceeded" in reason:
        return "本地检查超时"
    if reason in ("MODEL_PROXY_CHECK_FAILED", "MODEL_PROXY_AUDIT_FAILED"):
        return "本地检查暂不可用"
    return "请求内容无法完整检查"


def _render_deny_message(template: str, reason: str) -> str:
    return template.replace("{reason}", _public_denial_reason(reason))


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.scheme not in ("https", "http"):
        raise ValueError("invalid proxy origin")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}:{port}"


def _generic_json_views(raw: bytes) -> tuple[str, str]:
    """Conservative fallback for model JSON outside the Messages dialect.

    Every key, string and numeric value is inspected. Opaque or referenced attachments
    cannot be proved safe by a text scanner, so they fail closed. No rewritten
    bytes are returned: signed provider requests remain byte-identical.
    """
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    def invalid_constant(value):
        raise ValueError("nonfinite JSON number")

    parsed = json.loads(raw.decode("utf-8", "strict"),
                        object_pairs_hook=unique_pairs,
                        parse_constant=invalid_constant)
    if (not isinstance(parsed, dict)
            or not any(key in parsed and parsed[key] for key in _MODEL_FIELDS)):
        raise ValueError("unrecognized model JSON")
    leaves: list[str] = []
    values: list[str] = []
    count = 0

    def walk(node, depth=0):
        nonlocal count
        count += 1
        if count > 100_000 or depth > 64:
            raise ValueError("model JSON traversal limit")
        if isinstance(node, dict):
            kind = node.get("type")
            if isinstance(kind, str) and kind in _OPAQUE_PARTS:
                raise ValueError("attachment format requires a parser")
            for key, item in node.items():
                leaves.append(key)
                if key.lower() in _OPAQUE_KEYS:
                    raise ValueError("referenced attachment requires a parser")
                walk(item, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)
        elif isinstance(node, str):
            if node.startswith("data:") or "\x00" in node:
                raise ValueError("opaque or invalid model string")
            # A long base64 value that decodes to binary is not inspectable
            # text. Text encodings are independently scanned by the DLP engine.
            if len(node) >= 64 and len(node) % 4 == 0 and re.fullmatch(
                    r"[A-Za-z0-9+/]+={0,2}", node):
                try:
                    base64.b64decode(node, validate=True).decode("utf-8", "strict")
                except (ValueError, UnicodeError, binascii.Error):
                    raise ValueError("opaque encoded model content") from None
            leaves.append(node)
            values.append(node)
        elif isinstance(node, (int, float)) and not isinstance(node, bool):
            if isinstance(node, float) and not math.isfinite(node):
                raise ValueError("nonfinite JSON number")
            number = str(node)
            leaves.append(number)
            values.append(number)

    walk(parsed)
    return "\n".join(leaves), "".join(values)


@dataclass(frozen=True)
class ModelProxyConfig:
    state_dir: Path
    session_id: str
    allowed_origins: frozenset[str]
    allow_http_loopback: bool = False
    deny_message: str = _DEFAULT_DENY_MESSAGE

    @classmethod
    def load(cls, path: Path) -> "ModelProxyConfig":
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if (not isinstance(value, dict) or value.get("schema") != CONFIG_SCHEMA
                or not isinstance(value.get("session_id"), str)
                or not 1 <= len(value["session_id"]) <= 64
                or not isinstance(value.get("allowed_origins"), list)
                or not value["allowed_origins"]):
            raise ValueError("invalid model proxy configuration")
        origins = set()
        allow_loopback = value.get("allow_http_loopback", False)
        if not isinstance(allow_loopback, bool):
            raise ValueError("invalid loopback setting")
        for origin in value["allowed_origins"]:
            if not isinstance(origin, str):
                raise ValueError("invalid proxy origin")
            parsed = urlsplit(origin)
            if (parsed.username or parsed.password or parsed.path or parsed.query
                    or parsed.fragment or not parsed.hostname
                    or f"{parsed.scheme}://{parsed.netloc}" != origin
                    or (parsed.scheme != "https" and not (
                        allow_loopback and parsed.scheme == "http"
                        and parsed.hostname in ("127.0.0.1", "localhost", "::1")))):
                raise ValueError("invalid proxy origin")
            origins.add(_canonical_origin(origin))
        state = Path(value.get("state_dir", ""))
        if not state.is_absolute():
            raise ValueError("model proxy state_dir must be absolute")
        deny_message = value.get("deny_message", _DEFAULT_DENY_MESSAGE)
        if (not isinstance(deny_message, str) or not 1 <= len(deny_message) <= 200
                or any(ord(char) < 32 for char in deny_message)):
            raise ValueError("invalid denial message")
        return cls(state, value["session_id"], frozenset(origins),
                   allow_loopback, deny_message)


@dataclass(frozen=True)
class ModelProxyDecision:
    allow: bool
    reason: str
    request_id: str
    original_sha256: str
    forward_sha256: str | None = None
    forward_body: bytes | None = None


class ClaudeModelProxyPolicy:
    def __init__(self, config: ModelProxyConfig):
        self.config = config
        self.engine = create_claude_engine(config.state_dir)
        self.audit_file = config.state_dir / "model-proxy-audit.jsonl"
        self._lock = threading.RLock()

    def _write_audit(self, row: dict) -> None:
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_file.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def decide(self, *, client_connection_id: str, method: str, url: str,
               headers: list[tuple[str, str]],
               body: bytes, content_type: str, content_encoding: str) -> ModelProxyDecision:
        began = time.monotonic()
        request_id = uuid.uuid4().hex
        original_sha = hashlib.sha256(body).hexdigest() if isinstance(body, bytes) else ""
        archive_record_id = None
        dialect = "unrecognized"
        guard_session_id = hashlib.sha256(
            (self.config.session_id + ":" + str(client_connection_id)).encode()).hexdigest()
        try:
            if (not isinstance(client_connection_id, str)
                    or not 1 <= len(client_connection_id) <= 128):
                raise ValueError("missing client connection identity")
            if not isinstance(body, bytes) or len(body) > MAX_BODY:
                raise ValueError("body unavailable or oversized")
            if (not isinstance(url, str) or len(url.encode("utf-8")) > 8192
                    or method != "POST" or not isinstance(headers, list)
                    or sum(len(k) + len(v) for k, v in headers) > MAX_HEADERS):
                raise ValueError("unsupported request metadata")
            parsed = urlsplit(url)
            origin = _canonical_origin(url)
            if (origin not in self.config.allowed_origins
                    or parsed.username or parsed.password or parsed.fragment):
                raise ValueError("destination is not an allowed origin")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError("unsupported body media type")
            if content_encoding.strip().lower() not in _ENCODINGS:
                raise ValueError("unsupported content encoding")
            if any(key.lower() == "transfer-encoding" for key, _ in headers):
                raise ValueError("transfer encoding requires separate validation")
            # Authorization values are forwarded as supplied by Claude, but
            # never written to the proxy audit or to the request archive.
            with self._lock:
                archive, detector = self.engine.gate._prepare()
                archive_record_id = archive.save("model_request", body).record_id
                for key, value in [("url", url), *[(key, value) for key, value in headers
                                                  if key.lower() not in _AUTH_HEADERS]]:
                    if key.lower() == "anthropic-beta":
                        # Claude's long comma-separated feature identifiers
                        # trigger the generic entropy heuristic. Only the
                        # expected protocol-token grammar may bypass it.
                        flags = [part.strip() for part in value.split(",")]
                        if (not 1 <= len(flags) <= 32
                                or any(not re.fullmatch(r"[a-z][a-z0-9-]{0,100}", part)
                                       for part in flags)):
                            raise ValueError("invalid anthropic-beta metadata")
                        continue
                    header_verdict = detector.inspect_text(value)
                    if self.engine.gate.actionable(header_verdict) != "ALLOW":
                        raise ValueError("sensitive URL or header "
                                         + ",".join(header_verdict.rule_ids))
                signed = any(
                    k.lower() in ("x-amz-content-sha256", "x-amz-date") or
                    (k.lower() == "authorization" and
                     v.lstrip().upper().startswith(("AWS4-HMAC-SHA256",
                                                   "AWS4-ECDSA-P256-SHA256")))
                    for k, v in headers)
                messages_path = parsed.path.endswith("/v1/messages")
                if messages_path and not signed:
                    dialect = "anthropic_messages"
                    request = GuardRequest.model_validate({
                        "schema": "transpect.guard.request/1.0",
                        "request_id": request_id,
                        "guard_session_id": guard_session_id,
                        "pid": os.getpid(), "tid": threading.get_native_id(),
                        "kind": "model.request", "protocol": "http",
                        "destination": origin, "completeness": "complete",
                        "payload_utf8": body.decode("utf-8", "strict"),
                    })
                    verdict, _ = self.engine.evaluate(request)
                    allowed = verdict.decision == "allow"
                    reason = verdict.reason
                    forwarded = (verdict.redacted_payload.encode("utf-8")
                                 if verdict.redacted_payload is not None else body)
                else:
                    dialect = "generic_model_json"
                    views = _generic_json_views(body)
                    reasons = []
                    for view in views:
                        checked = detector.inspect_text(view)
                        if self.engine.gate.actionable(checked) != "ALLOW":
                            reasons.extend(checked.rule_ids)
                    allowed = not reasons
                    reason = ("REQUIRED_CHECKS_COMPLETE" if allowed else
                              "SENSITIVE_OR_AMBIGUOUS_CONTENT:" + ",".join(sorted(set(reasons))))
                    forwarded = body
                if time.monotonic() - began > 2.0:
                    raise ValueError("model proxy decision deadline exceeded")
                forward_sha = hashlib.sha256(forwarded).hexdigest() if allowed else None
                row = {"schema": "transpect.claude-model-proxy-audit/1.0",
                       "request_id": request_id, "guard_session_id": guard_session_id,
                       "decision": "allow" if allowed else "deny", "reason": reason,
                       "dialect": dialect, "archive_record_id": archive_record_id,
                       "origin_sha256": hashlib.sha256(origin.encode()).hexdigest(),
                       "original_sha256": original_sha, "forward_sha256": forward_sha,
                       "original_bytes": len(body),
                       "forward_bytes": len(forwarded) if allowed else 0}
                self._write_audit(row)
                return ModelProxyDecision(allowed, reason, request_id,
                                          original_sha, forward_sha,
                                          forwarded if allowed else None)
        except ValueError as error:
            reason = str(error)
            try:
                with self._lock:
                    self._write_audit({
                        "schema": "transpect.claude-model-proxy-audit/1.0",
                        "request_id": request_id, "guard_session_id": guard_session_id,
                        "decision": "deny", "reason": reason,
                        "dialect": dialect, "archive_record_id": archive_record_id,
                        "origin_sha256": hashlib.sha256(str(url).encode()).hexdigest(),
                        "original_sha256": original_sha, "forward_sha256": None,
                        "original_bytes": len(body) if isinstance(body, bytes) else 0,
                        "forward_bytes": 0,
                    })
            except Exception:
                reason = "MODEL_PROXY_AUDIT_FAILED"
            return ModelProxyDecision(False, reason, request_id, original_sha)
        except Exception:
            # A failed check or failed audit cannot release application bytes.
            try:
                with self._lock:
                    self._write_audit({
                        "schema": "transpect.claude-model-proxy-audit/1.0",
                        "request_id": request_id, "guard_session_id": guard_session_id,
                        "decision": "deny", "reason": "MODEL_PROXY_CHECK_FAILED",
                        "dialect": dialect, "archive_record_id": archive_record_id,
                        "origin_sha256": hashlib.sha256(str(url).encode()).hexdigest(),
                        "original_sha256": original_sha, "forward_sha256": None,
                        "original_bytes": len(body) if isinstance(body, bytes) else 0,
                        "forward_bytes": 0,
                    })
            except Exception:
                pass
            return ModelProxyDecision(False, "MODEL_PROXY_CHECK_FAILED", request_id,
                                      original_sha)


class ClaudeModelProxyAddon:
    """mitmproxy adapter: only inspected model JSON POSTs can leave the proxy."""

    def __init__(self, config: ModelProxyConfig):
        self.policy = ClaudeModelProxyPolicy(config)

    def configure(self, updated) -> None:
        from mitmproxy import ctx, exceptions
        options = ctx.options
        if (getattr(options, "stream_large_bodies", None)
                or getattr(options, "stream_websockets", False)
                or getattr(options, "ignore_hosts", ())
                or getattr(options, "ssl_insecure", False)
                or getattr(options, "connection_strategy", None) != "lazy"
                or getattr(options, "upstream_cert", True)
                or getattr(options, "http3", True)
                or getattr(options, "keep_alt_svc_header", False)
                or not getattr(options, "validate_inbound_headers", True)
                or any(not mode.startswith("regular")
                       for mode in getattr(options, "mode", ()))):
            raise exceptions.OptionsError("model proxy requires full buffering and lazy verified TLS")

    def requestheaders(self, flow) -> None:
        flow.request.stream = False

    def request(self, flow) -> None:
        from mitmproxy import http
        flow.response = http.Response.make(503, b"Local model DLP unavailable")
        try:
            request = flow.request
            body = request.get_content(strict=True)
            if body is None:
                return
            verdict = self.policy.decide(
                client_connection_id=str(flow.client_conn.id),
                method=request.method, url=request.pretty_url,
                headers=list(request.headers.items(multi=True)), body=body,
                content_type=request.headers.get("Content-Type", ""),
                content_encoding=request.headers.get("Content-Encoding", ""))
            _LOG.info("model proxy %s %s", request.method, verdict.reason)
            if not verdict.allow:
                flow.response = http.Response.make(
                    403, json.dumps({"type": "error", "error": {
                        "type": "permission_error",
                        "message": _render_deny_message(
                            self.policy.config.deny_message, verdict.reason)}},
                        ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                    {"Content-Type": "application/json"})
                return
            if verdict.forward_body != body:
                request.content = verdict.forward_body
            flow.metadata["ttrace_model_proxy_approved"] = True
            flow.metadata["ttrace_model_proxy_request_id"] = verdict.request_id
            flow.response = None
        except Exception as error:
            _LOG.warning("model proxy adapter failed: %s", type(error).__name__)
            return

    def responseheaders(self, flow) -> None:
        if flow.metadata.get("ttrace_model_proxy_approved"):
            try:
                with self.policy._lock:
                    self.policy._write_audit({
                        "schema": "transpect.claude-model-proxy-upstream/1.0",
                        "request_id": flow.metadata["ttrace_model_proxy_request_id"],
                        "status_code": flow.response.status_code,
                        "content_type": flow.response.headers.get("Content-Type", "")[:120],
                    })
            except Exception:
                _LOG.warning("model proxy upstream response audit failed")
            flow.response.stream = True

    def websocket_message(self, flow) -> None:
        if flow.websocket.messages[-1].from_client:
            flow.kill()

    def websocket_start(self, flow) -> None:
        flow.kill()

    def tcp_start(self, flow) -> None:
        flow.kill()

    def udp_start(self, flow) -> None:
        flow.kill()

    def tcp_message(self, flow) -> None:
        if flow.messages[-1].from_client:
            flow.kill()

    def udp_message(self, flow) -> None:
        if flow.messages[-1].from_client:
            flow.kill()
