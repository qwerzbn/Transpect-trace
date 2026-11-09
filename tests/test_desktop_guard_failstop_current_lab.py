"""The integrated lab accepts only its own pinned app-server child."""
from __future__ import annotations

from pathlib import Path
import socket
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import probe_desktop_guard_failstop_current_lab as lab  # noqa: E402


def _rows(monkeypatch, **changes):
    backend = Path(r"C:\lab\codex.exe")
    process = {"ParentProcessId": lab.os.getpid(), "CommandLine": "app-server",
               "UserSid": "S-1-5-21-1"}
    image = {"pid": 1234, "creation_filetime": 42,
             "image_path": str(backend), "image_sha256": lab.BACKEND_SHA256}
    for key, value in changes.items():
        (process if key in process else image)[key] = value
    monkeypatch.setattr(lab, "_cim_process", lambda _pid: process)
    monkeypatch.setattr(lab, "image_identity", lambda _pid: image)
    monkeypatch.setattr(lab, "command_arguments", lambda line: ["codex.exe", line])
    return backend


def test_lab_child_identity_accepts_exact_instance(monkeypatch):
    backend = _rows(monkeypatch)
    result = lab.child_identity(1234, backend, "S-1-5-21-1", creation_filetime=42)
    assert result["guard_session_id"] == "1234-42"
    assert result["baseline"]["sha256"] == lab.BACKEND_SHA256


@pytest.mark.parametrize("changed", [
    {"ParentProcessId": 9999}, {"CommandLine": "exec-server"},
    {"UserSid": "S-1-5-21-2"}, {"pid": 5678},
    {"creation_filetime": 43}, {"creation_filetime": 0},
    {"image_path": r"C:\lab\other.exe"}, {"image_sha256": "0" * 64},
])
def test_lab_child_identity_fails_closed(monkeypatch, changed):
    backend = _rows(monkeypatch, **changed)
    with pytest.raises(ValueError, match="identity changed"):
        lab.child_identity(1234, backend, "S-1-5-21-1", creation_filetime=42)


def test_http_origin_counts_partial_body_after_handlers_quiesce(tmp_path):
    request = (b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               b"Content-Length: 10\r\n\r\nabc")
    with lab.counted_local_origin("http", tmp_path, b"TTRACE_NATIVE_LAB_TEST") as sink:
        with socket.create_connection(("127.0.0.1", sink.server_port), timeout=3) as client:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
    rows = lab.origin_rows(sink, "http")
    assert len(rows) == 1
    assert rows[0]["wire_bytes"] == len(request)
    assert rows[0]["http_body_bytes_received"] == 3
    assert rows[0]["complete"] is False
    assert rows[0]["error"] == "EOFError"
