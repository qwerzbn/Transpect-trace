from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aiohttp import ClientSession, web
from jsonschema import Draft202012Validator

from transpect_trace.core.models import Manifest
from transpect_trace.core.storage import TraceBundle
from transpect_trace.correlation import correlate_run
from transpect_trace.gateway.policy import load_policy
from transpect_trace.gateway.server import GatewayConfig, create_app
from transpect_trace.normalization import normalize_run
from transpect_trace.verification import verify_bundle


FIXTURE = Path(__file__).parent / "fixtures" / "exfiltration"
EXPECTED = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))


async def _start(app: web.Application) -> tuple[web.AppRunner, str]:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    sockets = site._server.sockets  # type: ignore[union-attr]
    port = sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


def _rows(run_dir: Path) -> list[dict]:
    path = run_dir / "raw" / "gateway" / "events.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_out_of_scope_marker_is_blocked_before_upstream(tmp_path: Path) -> None:
    async def scenario() -> None:
        upstream_requests = 0

        async def upstream_handler(_: web.Request) -> web.Response:
            nonlocal upstream_requests
            upstream_requests += 1
            return web.json_response({"unexpected": True})

        upstream = web.Application()
        upstream.router.add_post("/v1/responses", upstream_handler)
        upstream_runner, upstream_url = await _start(upstream)
        gateway = create_app(
            GatewayConfig(
                run_id="policy-block-run",
                run_dir=tmp_path,
                upstream=upstream_url,
                api_key="fake-key",
                policy=load_policy(FIXTURE / "policy.json"),
            )
        )
        gateway_runner, gateway_url = await _start(gateway)
        try:
            async with ClientSession() as session:
                async with session.post(
                    gateway_url + "/v1/responses",
                    json={
                        "model": "test",
                        "input": "TRANSPECT_MARKER_FAKE_SECRET_EXFIL_001",
                    },
                ) as response:
                    result = await response.json()
                    assert response.status == EXPECTED["expected_status"]
                    assert response.headers["X-Transpect-Request-ID"] == result["request_id"]
                    assert result["error"] == "policy_denied"
                    assert result["rule_id"] == EXPECTED["expected_rule_id"]
        finally:
            await gateway_runner.cleanup()
            await upstream_runner.cleanup()

        assert upstream_requests == EXPECTED["expected_upstream_requests"]

    asyncio.run(scenario())

    rows = _rows(tmp_path)
    assert [row["kind"] for row in rows] == [
        "model.request",
        "policy.decision",
        "model.request.blocked",
    ]
    request_ids = {row["request_id"] for row in rows}
    assert len(request_ids) == 1
    decision = rows[1]
    assert decision["decision"] == EXPECTED["expected_decision"]
    assert decision["rule_id"] == EXPECTED["expected_rule_id"]
    assert decision["matched_marker_ids"] == [EXPECTED["protected_marker_id"]]
    assert decision["matched_source_paths"] == ["/workspace/fake_credentials.txt"]
    assert decision["forwarded"] is EXPECTED["expected_forwarded"]
    assert "not-a-real-password" not in json.dumps(decision)

    bundle = TraceBundle(tmp_path)
    bundle.write_manifest(
        Manifest(
            run_id="policy-block-run",
            status="complete",
            client="codex",
            provider="deepseek",
            model="test",
            workspace="fixture",
        )
    )
    events = normalize_run(tmp_path)
    correlate_run(tmp_path, events)
    report = verify_bundle(tmp_path, check_checksums=False)
    assert report["correlation"]["request_terminal_rate"] == 1.0
    assert report["policy"] == {
        "decisions": 1,
        "allowed": 0,
        "denied": 1,
        "blocked_requests": 1,
    }


def test_allowed_request_is_forwarded_and_audited(tmp_path: Path) -> None:
    async def scenario() -> None:
        upstream_requests = 0

        async def upstream_handler(_: web.Request) -> web.Response:
            nonlocal upstream_requests
            upstream_requests += 1
            return web.json_response({"ok": True})

        upstream = web.Application()
        upstream.router.add_post("/v1/responses", upstream_handler)
        upstream_runner, upstream_url = await _start(upstream)
        gateway = create_app(
            GatewayConfig(
                run_id="policy-allow-run",
                run_dir=tmp_path,
                upstream=upstream_url,
                api_key="fake-key",
                policy=load_policy(FIXTURE / "policy.json"),
            )
        )
        gateway_runner, gateway_url = await _start(gateway)
        try:
            async with ClientSession() as session:
                async with session.post(
                    gateway_url + "/v1/responses",
                    json={"model": "test", "input": "TRANSPECT_MARKER_PUBLIC_EXFIL_TEST_001"},
                ) as response:
                    assert response.status == 200
                    assert await response.json() == {"ok": True}
        finally:
            await gateway_runner.cleanup()
            await upstream_runner.cleanup()

        assert upstream_requests == 1

    asyncio.run(scenario())
    rows = _rows(tmp_path)
    decision = next(row for row in rows if row["kind"] == "policy.decision")
    assert decision["decision"] == "allow"
    assert decision["rule_id"] == "POLICY_ALLOW"
    assert not any(row["kind"] == "model.request.blocked" for row in rows)


def test_unapproved_upstream_is_blocked_before_connection(tmp_path: Path) -> None:
    async def scenario() -> None:
        policy = load_policy(FIXTURE / "policy.json").model_copy(
            update={"allowed_upstreams": ["api.deepseek.com"]}
        )
        gateway = create_app(
            GatewayConfig(
                run_id="upstream-block-run",
                run_dir=tmp_path,
                upstream="http://127.0.0.1:1",
                api_key="fake-key",
                policy=policy,
            )
        )
        gateway_runner, gateway_url = await _start(gateway)
        try:
            async with ClientSession() as session:
                async with session.post(
                    gateway_url + "/v1/responses",
                    json={"model": "test", "input": "public"},
                ) as response:
                    result = await response.json()
                    assert response.status == 403
                    assert result["rule_id"] == "UPSTREAM_NOT_ALLOWED"
        finally:
            await gateway_runner.cleanup()

    asyncio.run(scenario())
    rows = _rows(tmp_path)
    decision = next(row for row in rows if row["kind"] == "policy.decision")
    assert decision["requested_upstream"] == "127.0.0.1"
    assert decision["forwarded"] is False


def test_exfiltration_policy_fixture_matches_schema() -> None:
    schema_path = Path(__file__).parents[1] / "schemas" / "gateway-policy-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    policy = json.loads((FIXTURE / "policy.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(policy)
