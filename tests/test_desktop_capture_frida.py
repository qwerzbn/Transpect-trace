"""The synthetic Frida probe emits bounded metadata and survives worker exit."""
from __future__ import annotations

import multiprocessing
from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from _desktop_capture_frida import CaptureSession, _safe_event  # noqa: E402
from _desktop_failstop_frida import FailStopSession  # noqa: E402


def test_hit_event_never_copies_a_request_body():
    result = _safe_event({"kind": "synthetic_http_hit", "bytes": 123,
                          "sha256": "a" * 64, "marker_offset": 8,
                          "payload_utf8": "SYNTHETIC_SECRET", "unexpected": [1, 2]})
    assert result == {"kind": "synthetic_http_hit", "bytes": 123,
                      "sha256": "a" * 64, "marker_offset": 8}
    assert _safe_event({"kind": "synthetic_http_hit", "bytes": 0,
                        "sha256": "a" * 64, "marker_offset": 0}) is None
    wss = _safe_event({"kind": "synthetic_wss_hit", "bytes": 123,
                       "sha256": "b" * 64, "marker_offset": 8,
                       "request_shape": "response.create-input",
                       "payload_utf8": "SYNTHETIC_SECRET"})
    assert wss == {"kind": "synthetic_wss_hit", "bytes": 123,
                   "sha256": "b" * 64, "marker_offset": 8,
                   "request_shape": "response.create-input"}
    stopped = _safe_event({"kind": "synthetic_failstop_triggered", "hook": "wss",
                           "bytes": 123, "sha256": "c" * 64,
                           "payload_utf8": "SYNTHETIC_SECRET"})
    assert stopped == {"kind": "synthetic_failstop_triggered", "hook": "wss",
                       "bytes": 123, "sha256": "c" * 64}


def test_worker_pipe_exit_is_treated_as_eof():
    parent, child = multiprocessing.Pipe()
    child.close()
    session = CaptureSession.__new__(CaptureSession)
    session.channel = parent
    session.events = []
    try:
        assert session._collect(0) is False
        assert session.events == []
    finally:
        parent.close()


def test_failstop_refuses_nonlab_process(monkeypatch, tmp_path):
    import _desktop_failstop_frida as module

    monkeypatch.setattr(module, "_cim_process", lambda _pid: {
        "ParentProcessId": module.os.getpid() + 1,
        "CommandLine": "codex.exe app-server",
    })
    with pytest.raises(ValueError, match="direct synthetic"):
        FailStopSession(100, tmp_path / "unused.exe", "a" * 64, 1,
                        b"TTRACE_NATIVE_LAB_12345678901234567890123456789012")
