from __future__ import annotations

import argparse
import asyncio
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from aiohttp import ClientConnectorError, ClientSession, ClientTimeout, web

from transpect_trace import __version__
from transpect_trace.core.models import utc_now
from transpect_trace.core.storage import TraceBundle

from .policy import GatewayPolicy, evaluate_policy, load_policy
from .sse import SSEDecoder


DEEPSEEK_ROUTES = {
    ("GET", "/models"),
    ("POST", "/responses"),
    ("POST", "/v1/responses"),
    ("POST", "/chat/completions"),
    ("POST", "/v1/chat/completions"),
}
ANTHROPIC_ROUTES = {("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens")}
FORWARDED_RESPONSE_HEADERS = {"content-type", "x-request-id", "request-id", "openai-request-id"}


@dataclass(frozen=True)
class GatewayConfig:
    run_id: str
    run_dir: Path
    upstream: str = "https://api.deepseek.com"
    api_key: str = ""
    provider: str = "deepseek"
    max_request_bytes: int = 32 * 1024 * 1024
    max_response_bytes: int = 64 * 1024 * 1024
    timeout_seconds: float = 600.0
    policy: GatewayPolicy | None = None


class GatewayRecorder:
    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.bundle = TraceBundle(config.run_dir)
        self._sequence = 0
        self._lock = asyncio.Lock()

    async def record(self, kind: str, **fields: Any) -> dict[str, Any]:
        async with self._lock:
            self._sequence += 1
            row = {
                "schema": "transpect.raw.gateway/1.0",
                "run_id": self.config.run_id,
                "collector_seq": self._sequence,
                "captured_at": utc_now(),
                "monotonic_ns": time.monotonic_ns(),
                "kind": kind,
                **fields,
            }
            self.bundle.append_jsonl("raw/gateway/events.jsonl", row)
            return row


CONFIG_KEY = web.AppKey("config", GatewayConfig)
RECORDER_KEY = web.AppKey("recorder", GatewayRecorder)
SESSION_KEY = web.AppKey("session", ClientSession)


async def _session_context(app: web.Application):
    config = app[CONFIG_KEY]
    timeout = ClientTimeout(total=config.timeout_seconds, connect=min(config.timeout_seconds, 30))
    app[SESSION_KEY] = ClientSession(timeout=timeout, auto_decompress=False)
    yield
    await app[SESSION_KEY].close()


def create_app(config: GatewayConfig) -> web.Application:
    if not config.api_key:
        raise ValueError(f"{config.provider} API key is required")
    app = web.Application(client_max_size=config.max_request_bytes)
    app[CONFIG_KEY] = config
    app[RECORDER_KEY] = GatewayRecorder(config)
    app.cleanup_ctx.append(_session_context)
    app.router.add_get("/health", _health)
    app.router.add_route("*", "/{tail:.*}", _forward)
    return app


async def _health(_: web.Request) -> web.Response:
    return web.json_response({"ok": True, "version": __version__})


async def _forward(request: web.Request) -> web.StreamResponse:
    config = request.app[CONFIG_KEY]
    recorder = request.app[RECORDER_KEY]
    path = request.path
    # A per-agent route prefix gives concurrent child clients an explicit
    # identity without forwarding that prefix or any tracing header upstream.
    agent_id = None
    parts = path.split("/", 3)
    if len(parts) == 4 and parts[1] == "agents":
        agent_id = parts[2]
        path = "/" + parts[3]
    request_id = str(uuid4())
    allowed_routes = ANTHROPIC_ROUTES if config.provider == "anthropic" else DEEPSEEK_ROUTES
    if (request.method, path) not in allowed_routes:
        await recorder.record(
            "model.request.failed",
            request_id=request_id,
            method=request.method,
            path=path,
            reason="route_not_allowed",
        )
        return web.json_response({"error": "route_not_allowed"}, status=403)

    try:
        body = await request.read()
    except web.HTTPRequestEntityTooLarge:
        await recorder.record("model.request.failed", request_id=request_id, reason="request_too_large")
        return web.json_response({"error": "request_too_large"}, status=413)

    if len(body) > config.max_request_bytes:
        await recorder.record("model.request.failed", request_id=request_id, reason="request_too_large")
        return web.json_response({"error": "request_too_large"}, status=413)

    request_content = recorder.bundle.put_blob(
        body,
        media_type=request.content_type or "application/json",
        encoding=request.charset,
    )
    await recorder.record(
        "model.request",
        request_id=request_id,
        method=request.method,
        path=path,
        headers={
            key.lower(): value
            for key, value in request.headers.items()
            if key.lower() in {"accept", "content-type", "user-agent"}
        },
        provider=config.provider,
        agent_id=agent_id,
        upstream=config.upstream,
        content=request_content.model_dump(mode="json"),
    )

    upstream_url = config.upstream.rstrip("/") + path
    if config.policy is not None:
        decision = evaluate_policy(config.policy, body, config.upstream)
        decision_id = str(uuid4())
        await recorder.record(
            "policy.decision",
            request_id=request_id,
            decision_id=decision_id,
            policy_id=config.policy.policy_id,
            policy_version=config.policy.version,
            decision=decision.decision,
            rule_id=decision.rule_id,
            reason=decision.reason,
            requested_upstream=decision.requested_upstream,
            matched_marker_ids=list(decision.matched_marker_ids),
            matched_source_paths=list(decision.matched_source_paths),
            matched_marker_sha256=list(decision.matched_marker_sha256),
            forwarded=False if decision.decision == "deny" else None,
        )
        if decision.decision == "deny":
            await recorder.record(
                "model.request.blocked",
                request_id=request_id,
                decision_id=decision_id,
                policy_id=config.policy.policy_id,
                rule_id=decision.rule_id,
                forwarded=False,
            )
            return web.json_response(
                {
                    "error": "policy_denied",
                    "request_id": request_id,
                    "decision_id": decision_id,
                    "rule_id": decision.rule_id,
                },
                status=403,
                headers={"X-Transpect-Request-ID": request_id},
            )

    upstream_headers = {
        "Accept": request.headers.get("Accept", "application/json"),
        "Content-Type": request.headers.get("Content-Type", "application/json"),
        "User-Agent": f"Transpect-Trace-Gateway/{__version__}",
    }
    if config.provider == "anthropic":
        upstream_headers["x-api-key"] = config.api_key
        upstream_headers["anthropic-version"] = request.headers.get("anthropic-version", "2023-06-01")
        if request.headers.get("anthropic-beta"):
            upstream_headers["anthropic-beta"] = request.headers["anthropic-beta"]
    else:
        upstream_headers["Authorization"] = f"Bearer {config.api_key}"
    session = request.app[SESSION_KEY]
    started_ns = time.monotonic_ns()
    downstream: web.StreamResponse | None = None
    response_bytes = bytearray()
    decoder = SSEDecoder()
    stream_sequence = 0
    first_byte_ns: int | None = None
    provider_request_id: str | None = None
    try:
        async with session.request(request.method, upstream_url, data=body or None, headers=upstream_headers) as upstream:
            provider_request_id = next(
                (upstream.headers.get(name) for name in ("x-request-id", "request-id", "openai-request-id") if upstream.headers.get(name)),
                None,
            )
            response_headers = {
                key: value for key, value in upstream.headers.items() if key.lower() in FORWARDED_RESPONSE_HEADERS
            }
            response_headers["X-Transpect-Request-ID"] = request_id
            downstream = web.StreamResponse(status=upstream.status, headers=response_headers)
            await downstream.prepare(request)
            await recorder.record(
                "model.response.started",
                request_id=request_id,
                provider_request_id=provider_request_id,
                status=upstream.status,
                headers={key.lower(): value for key, value in response_headers.items()},
            )
            is_sse = "text/event-stream" in upstream.headers.get("Content-Type", "").lower()
            async for chunk in upstream.content.iter_any():
                if not chunk:
                    continue
                if first_byte_ns is None:
                    first_byte_ns = time.monotonic_ns()
                if len(response_bytes) + len(chunk) > config.max_response_bytes:
                    raise RuntimeError("response_too_large")
                response_bytes.extend(chunk)
                stream_sequence += 1
                chunk_ref = recorder.bundle.put_blob(chunk, media_type="application/octet-stream")
                parsed = decoder.feed(chunk) if is_sse else []
                await recorder.record(
                    "model.response.chunk",
                    request_id=request_id,
                    provider_request_id=provider_request_id,
                    stream_seq=stream_sequence,
                    content=chunk_ref.model_dump(mode="json"),
                    sse_events=parsed,
                )
                await downstream.write(chunk)
            trailing = decoder.finish() if is_sse else []
            if trailing:
                await recorder.record(
                    "model.response.sse_incomplete",
                    request_id=request_id,
                    provider_request_id=provider_request_id,
                    sse_events=trailing,
                )
            await downstream.write_eof()
            response_ref = recorder.bundle.put_blob(
                bytes(response_bytes),
                media_type=upstream.headers.get("Content-Type", "application/octet-stream").split(";", 1)[0],
            )
            completed_ns = time.monotonic_ns()
            await recorder.record(
                "model.response.completed",
                request_id=request_id,
                provider_request_id=provider_request_id,
                status=upstream.status,
                chunks=stream_sequence,
                content=response_ref.model_dump(mode="json"),
                first_byte_ms=((first_byte_ns - started_ns) / 1_000_000) if first_byte_ns else None,
                duration_ms=(completed_ns - started_ns) / 1_000_000,
            )
            return downstream
    except ConnectionResetError as error:
        await recorder.record(
            "model.request.failed",
            request_id=request_id,
            provider_request_id=provider_request_id,
            reason="client_disconnected",
            detail=str(error)[:1000],
            response_started=downstream is not None,
        )
        if downstream is not None:
            downstream.force_close()
            return downstream
        raise
    except (asyncio.TimeoutError, ClientConnectorError, OSError, RuntimeError) as error:
        await recorder.record(
            "model.request.failed",
            request_id=request_id,
            provider_request_id=provider_request_id,
            reason=type(error).__name__,
            detail=str(error)[:1000],
            response_started=downstream is not None,
        )
        if downstream is not None:
            downstream.force_close()
            return downstream
        return web.json_response({"error": "upstream_failure", "request_id": request_id}, status=502)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Transpect model trace gateway")
    parser.add_argument("--run-dir", default=os.environ.get("TTRACE_RUN_DIR"))
    parser.add_argument("--run-id", default=os.environ.get("TTRACE_RUN_ID"))
    parser.add_argument("--upstream", default=os.environ.get("TTRACE_UPSTREAM", "https://api.deepseek.com"))
    parser.add_argument("--provider", default=os.environ.get("TTRACE_PROVIDER", "deepseek"), choices=["deepseek", "anthropic"])
    parser.add_argument("--policy-file", default=os.environ.get("TTRACE_POLICY_FILE"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    if not args.run_dir or not args.run_id:
        raise SystemExit("--run-dir and --run-id are required")
    api_key = (
        os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("API_KEY", "")
        if args.provider == "anthropic"
        else os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("TRANSPECT_MODEL_API_KEY") or os.environ.get("API_KEY", "")
    )
    app = create_app(
        GatewayConfig(
            run_id=args.run_id,
            run_dir=Path(args.run_dir),
            upstream=args.upstream,
            api_key=api_key,
            provider=args.provider,
            policy=load_policy(args.policy_file) if args.policy_file else None,
        )
    )
    web.run_app(app, host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
