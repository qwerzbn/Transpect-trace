from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aiohttp import ClientSession, web

from transpect_trace.gateway.server import GatewayConfig, create_app
from transpect_trace.gateway.sse import SSEDecoder


def test_sse_decoder_handles_arbitrary_boundaries() -> None:
    decoder = SSEDecoder()
    assert decoder.feed(b"event: response.ou") == []
    assert decoder.feed(b"tput\r\ndata: {\"x\":") == []
    events = decoder.feed(b"1}\r\n\r\ndata: [DONE]\n\n")
    assert events == [
        {"event": "response.output", "data": '{"x":1}', "incomplete": False},
        {"event": "message", "data": "[DONE]", "incomplete": False},
    ]
    assert decoder.finish() == []


async def _start(app: web.Application) -> tuple[web.AppRunner, str]:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    sockets = site._server.sockets  # type: ignore[union-attr]
    port = sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


def test_gateway_preserves_stream_and_records_evidence(tmp_path: Path) -> None:
    async def scenario() -> None:
        observed: dict[str, str] = {}

        async def upstream_handler(request: web.Request) -> web.StreamResponse:
            observed["authorization"] = request.headers.get("Authorization", "")
            observed["body"] = (await request.read()).decode()
            response = web.StreamResponse(status=200, headers={"Content-Type": "text/event-stream", "X-Request-ID": "provider-1"})
            await response.prepare(request)
            await response.write(b"event: response.created\ndata: {\"id\":")
            await response.write(b"\"r1\"}\n\n")
            await response.write_eof()
            return response

        upstream = web.Application()
        upstream.router.add_post("/v1/responses", upstream_handler)
        upstream_runner, upstream_url = await _start(upstream)
        gateway = create_app(GatewayConfig(run_id="run-1", run_dir=tmp_path, upstream=upstream_url, api_key="fake-key"))
        gateway_runner, gateway_url = await _start(gateway)
        try:
            async with ClientSession() as session:
                async with session.post(
                    gateway_url + "/v1/responses",
                    json={"model": "test", "input": "TRANSPECT_MARKER_PUBLIC_001", "stream": True},
                ) as response:
                    payload = await response.read()
                    assert response.status == 200
                    assert b"response.created" in payload
                    assert response.headers["X-Transpect-Request-ID"]
        finally:
            await gateway_runner.cleanup()
            await upstream_runner.cleanup()

        assert observed["authorization"] == "Bearer fake-key"
        assert "TRANSPECT_MARKER_PUBLIC_001" in observed["body"]
        rows = [json.loads(line) for line in (tmp_path / "raw/gateway/events.jsonl").read_text().splitlines()]
        kinds = [row["kind"] for row in rows]
        assert kinds[:2] == ["model.request", "model.response.started"]
        assert kinds[-1] == "model.response.completed"
        assert kinds.count("model.response.chunk") >= 1
        assert sum(row.get("chunks", 0) for row in rows if row["kind"] == "model.response.completed") >= 1
        assert "fake-key" not in (tmp_path / "raw/gateway/events.jsonl").read_text()

    asyncio.run(scenario())


def test_anthropic_gateway_uses_x_api_key(tmp_path: Path) -> None:
    async def scenario() -> None:
        observed: dict[str, str] = {}

        async def handler(request: web.Request) -> web.Response:
            observed["key"] = request.headers.get("x-api-key", "")
            observed["version"] = request.headers.get("anthropic-version", "")
            return web.json_response({"id": "msg-1", "content": []})

        upstream = web.Application()
        upstream.router.add_post("/v1/messages", handler)
        upstream_runner, upstream_url = await _start(upstream)
        gateway = create_app(GatewayConfig(
            run_id="run-a", run_dir=tmp_path, upstream=upstream_url,
            api_key="anthropic-fake", provider="anthropic",
        ))
        gateway_runner, gateway_url = await _start(gateway)
        try:
            async with ClientSession() as session:
                async with session.post(
                    gateway_url + "/v1/messages",
                    headers={"anthropic-version": "2023-06-01"},
                    json={"model": "test", "messages": []},
                ) as response:
                    assert response.status == 200
                    await response.read()
        finally:
            await gateway_runner.cleanup()
            await upstream_runner.cleanup()
        assert observed == {"key": "anthropic-fake", "version": "2023-06-01"}
        assert "anthropic-fake" not in (tmp_path / "raw/gateway/events.jsonl").read_text()

    asyncio.run(scenario())
