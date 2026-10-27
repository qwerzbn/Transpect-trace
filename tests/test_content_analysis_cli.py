from typer.testing import CliRunner

from transpect_trace.cli import app


def test_content_agent_commands_are_registered():
    result = CliRunner().invoke(app, ["protect", "content-agent", "--help"])
    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "status" in result.stdout


def test_content_agent_status_never_claims_live_normal_chrome(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "status.json").write_text(
        '{"state":"sdk_protocol_ready","normal_chrome_can_enforce":true}',
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app, ["protect", "content-agent", "status", str(run)]
    )
    assert result.exit_code == 0
    assert '"normal_chrome_can_enforce": false' in result.stdout
    assert '"snapshot_only": true' in result.stdout
