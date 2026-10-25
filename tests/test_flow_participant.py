"""Controlled Windows fixture checks; these are not ETW/eCapture certification."""
import json
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Win32 participant")


def test_file_participant_waits_before_source_access_and_preserves_utf8(tmp_path):
    source, handoff = tmp_path / "not-created-yet.txt", tmp_path / "handoff.txt"
    process = subprocess.Popen([sys.executable, "-m", "transpect_trace.flow.participant",
                                "--scenario", "file", "--source", str(source), "--handoff", str(handoff)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        ready = json.loads(process.stdout.readline())
        assert ready["kind"] == "ready"
        assert ready["source_access_started"] is False
        assert not handoff.exists()
        content = ("中文假数据\r\n" * 10000).encode("utf-8")
        source.write_bytes(content)
        stdout, stderr = process.communicate(b"release\nfinish\n", timeout=15)
        assert process.returncode == 0, stderr.decode(errors="replace")
        rows = [json.loads(line) for line in stdout.splitlines()]
        assert [row["kind"] for row in rows] == ["transfer_complete", "finished"]
        assert rows[0]["bytes"] == len(content)
        assert handoff.read_bytes() == content
        assert content not in stdout + stderr
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def test_oversized_source_never_creates_handoff_and_errors_are_redacted(tmp_path):
    source, handoff = tmp_path / "fake-private-source.txt", tmp_path / "handoff.txt"
    source.write_bytes(b"x" * (1024 * 1024 + 1))
    result = subprocess.run([sys.executable, "-m", "transpect_trace.flow.participant",
                             "--scenario", "file", "--source", str(source), "--handoff", str(handoff)],
                            input=b"release\nfinish\n", capture_output=True, timeout=15)
    assert result.returncode == 2
    assert not handoff.exists()
    assert b"fake-private-source" not in result.stdout + result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert rows[-1]["kind"] == "error"
