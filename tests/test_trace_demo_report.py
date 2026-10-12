from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aiohttp import ClientSession, web
from typer.testing import CliRunner

from transpect_trace.cli import app
from transpect_trace.core.models import Manifest
from transpect_trace.core.storage import TraceBundle
from transpect_trace.gateway.server import GatewayConfig, create_app
from transpect_trace.normalization import normalize_run
from transpect_trace.normalization.system import iter_strace_rows
from transpect_trace.reporting import build_report, project_report
from transpect_trace.supervisor import _snapshot_workspace


def test_parent_resolution_resumed_fork_and_pid_namespaces(tmp_path: Path) -> None:
    (tmp_path / "strace.100").write_text('1.100 execve("/usr/bin/cat", ["cat"], 0x0) = 0\n')
    (tmp_path / "strace.90").write_text('1.000 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n1.050 <... clone resumed>) = 100\n')
    (tmp_path / "gateway-strace.2").write_text('1.000 fork() = 100\n')
    (tmp_path / "gateway-strace.100").write_text('1.100 execve("/gateway", ["gateway"], 0x0) = 0\n')
    rows = list(iter_strace_rows(tmp_path))
    child = next(r for r in rows if r["source_file"] == "strace.100")
    gateway = next(r for r in rows if r["source_file"] == "gateway-strace.100")
    assert child["ppid"] == 90
    assert gateway["ppid"] == 2


def test_report_distinguishes_reads_references_blocked_and_received(tmp_path: Path) -> None:
    root = tmp_path / "run"
    bundle = TraceBundle(root)
    bundle.write_manifest(Manifest(client="codex", provider="deepseek", model="fake", workspace="fixture"))
    source = root / "input/workspace"
    source.mkdir(parents=True)
    (source / "read.txt").write_text("TRANSPECT_MARKER_READ\n", encoding="utf-8")
    (source / "unread.txt").write_text("TRANSPECT_MARKER_UNREAD\n", encoding="utf-8")
    (root / "input/prompt.txt").write_text('</script><script>alert("x")</script>', encoding="utf-8")
    (root / "raw/system/strace.22").write_text(
        '1767225600.100 openat(AT_FDCWD, "unread.txt", O_RDONLY) = 3</workspace/unread.txt>\n'
        '1767225600.200 read(3</workspace/unread.txt>, "", 64) = 0\n'
        '1767225600.300 read(4</workspace/read.txt>, "TRANSPECT_MARKER_READ", 64) = 21\n'
    )
    for seq, (rid, text, blocked) in enumerate([("blocked", "TRANSPECT_MARKER_READ", True), ("received", "TRANSPECT_MARKER_READ", False)]):
        ref = bundle.put_blob(json.dumps({"input": [{"content": text}]}).encode())
        bundle.append_jsonl("raw/gateway/events.jsonl", dict(collector_seq=2*seq+1, kind="model.request", request_id=rid, agent_id="main", content=ref.model_dump()))
        bundle.append_jsonl("raw/gateway/events.jsonl", dict(collector_seq=2*seq+2, kind="model.request.blocked" if blocked else "model.response.started", request_id=rid, status=403 if blocked else 200))
    bundle.append_jsonl("raw/client/demo-events.jsonl", dict(collector_seq=1, kind="tool.received", invocation_id="path-only", tool_name="submit_report", arguments={"path": "read.txt"}))
    normalize_run(root)
    before = (root / "normalized/events.jsonl").read_bytes()
    data = project_report(root)
    files = {f["path"]: f for f in data["files"]}
    assert files["read.txt"]["reads"]
    assert not files["unread.txt"]["reads"]
    assert not files["read.txt"]["tools"]
    assert files["read.txt"]["references"]
    assert not any(e["source"] == "request:blocked" and e["target"] == "upstream" for e in data["edges"])
    assert any(e["source"] == "request:received" and e["target"] == "upstream" for e in data["edges"])
    output = build_report(root)
    assert '<script>alert("x")</script>' not in output.read_text(encoding="utf-8")
    assert (root / "normalized/events.jsonl").read_bytes() == before


def test_snapshot_does_not_recurse_into_runs_or_follow_links(tmp_path: Path) -> None:
    workspace = tmp_path / "work"
    workspace.mkdir()
    (workspace / "task.txt").write_text("real task without synthetic marker")
    (workspace / ".env").write_text("secret configuration")
    destination = workspace / "runs/new/input/workspace"
    destination.parent.mkdir(parents=True)
    _snapshot_workspace(workspace, destination, require_markers=False)
    assert (destination / "task.txt").exists()
    assert not (destination / "runs").exists()
    assert not (destination / ".env").exists()


def test_trace_requires_one_prompt(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["trace", "--workspace", str(tmp_path)])
    assert result.exit_code != 0
    assert "exactly one" in result.output


def test_agent_gateway_route_preserves_payload_and_strips_prefix(tmp_path: Path) -> None:
    async def start(app: web.Application):
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"

    async def scenario():
        seen = []
        async def receive(request):
            seen.append((request.path, await request.json()))
            return web.json_response({"ok": True})
        upstream = web.Application()
        upstream.router.add_post("/responses", receive)
        up_runner, url = await start(upstream)
        gw_runner, gw_url = await start(create_app(GatewayConfig(run_id="route-test", run_dir=tmp_path, upstream=url, api_key="fake")))
        try:
            async with ClientSession() as session:
                async with session.post(gw_url + "/agents/child-123/responses", json={"input": "hello"}) as response:
                    assert response.status == 200
                    await response.read()
            assert seen == [("/responses", {"input": "hello"})]
            rows = [json.loads(line) for line in (tmp_path / "raw/gateway/events.jsonl").read_text().splitlines()]
            assert rows[0]["agent_id"] == "child-123"
        finally:
            await gw_runner.cleanup()
            await up_runner.cleanup()
    asyncio.run(scenario())
