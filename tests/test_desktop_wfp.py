"""Wrapper and build checks. Live WFP policy is exercised only in an isolated VM."""
from __future__ import annotations

import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest

from transpect_trace.behavior.desktop_wfp import WfpBoundary, WfpBoundaryError
import transpect_trace.behavior.desktop_wfp as desktop_wfp


SID = "S-1-5-21-101-202-303-1001"
TOOL_SID = "S-1-5-21-101-202-303-1002"


def boundary() -> WfpBoundary:
    return WfpBoundary(Path(sys.executable), SID, isolated_vm=True)


def test_vm_and_dedicated_sid_required():
    with pytest.raises(WfpBoundaryError, match="isolated VM"):
        WfpBoundary(Path(sys.executable), SID)
    with pytest.raises(ValueError, match="dedicated"):
        WfpBoundary(Path(sys.executable), "S-1-5-18", isolated_vm=True)
    with pytest.raises(ValueError, match="distinct"):
        WfpBoundary(Path(sys.executable), SID, isolated_vm=True, tool_sids=[SID])


def test_default_deny_must_have_both_ipv4_and_ipv6(monkeypatch):
    def run(args, **kwargs):
        assert args[1:] == ["status", SID, "--isolated-vm"]
        return subprocess.CompletedProcess(args, 0, json.dumps({
            "installed": True, "v4_filter_id": 31, "v6_filter_id": 32,
            "in_v4_filter_id": 33, "in_v6_filter_id": 34, "error": 0,
        }))
    monkeypatch.setattr(subprocess, "run", run)
    assert boundary().assert_default_deny()["v6_filter_id"] == 32

    def partial(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, json.dumps({
            "installed": True, "v4_filter_id": 31, "v6_filter_id": 32,
            "in_v4_filter_id": 33, "in_v6_filter_id": 0, "error": 0,
        }))
    monkeypatch.setattr(subprocess, "run", partial)
    with pytest.raises(WfpBoundaryError, match="not attested"):
        boundary().assert_default_deny()


def test_distinct_tool_sid_is_attested_before_desktop_permit(monkeypatch):
    seen = []
    def run(args, **kwargs):
        seen.append(args[2])
        installed = args[2] == SID
        return subprocess.CompletedProcess(args, 0, json.dumps({
            "installed": installed, "v4_filter_id": 31, "v6_filter_id": 32,
            "in_v4_filter_id": 33, "in_v6_filter_id": 34, "error": 0,
        }))
    monkeypatch.setattr(subprocess, "run", run)
    b = WfpBoundary(Path(sys.executable), SID, isolated_vm=True, tool_sids=[TOOL_SID])
    with pytest.raises(WfpBoundaryError, match=TOOL_SID):
        b.assert_default_deny()
    assert seen == [SID, TOOL_SID]
    with pytest.raises(WfpBoundaryError, match=TOOL_SID):
        b.start_guarded_lease(pid=10, creation_filetime=100, image_sha256="a" * 64,
                              ip="127.0.0.1", port=443)


def test_lease_is_tcp_only_and_requires_attestation(monkeypatch):
    b = boundary()
    monkeypatch.setattr(b, "assert_default_deny", lambda: {"installed": True})
    monkeypatch.setattr(desktop_wfp, "_own_creation_filetime", lambda: 56789)
    calls = []

    class Output:
        def readline(self):
            return '{"state":"permit_active","filter_id":44,"pid_exact_filter":false}\n'
        def close(self):
            pass

    class Process:
        stdout = Output()
        stderr = Output()
        def __init__(self, args, **kwargs):
            calls.append(args)
        def poll(self):
            return None
        def terminate(self):
            pass
        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(subprocess, "Popen", Process)
    lease = b.start_guarded_lease(pid=100, creation_filetime=12345,
                                   image_sha256="a" * 64, ip="::1", port=443, seconds=30)
    assert lease.filter_id == 44 and lease.alive and lease.pid_exact_filter is False
    assert calls == [[str(b.executable), "lease", SID, "100", "12345", "a" * 64,
                      "::1", "443", "tcp", "30", str(os.getpid()), "56789", "--isolated-vm"]]
    lease.close()


def test_lease_rejects_unattested_policy_and_bad_bounds(monkeypatch):
    b = boundary()
    monkeypatch.setattr(b, "assert_default_deny", lambda: (_ for _ in ()).throw(WfpBoundaryError("missing")))
    with pytest.raises(WfpBoundaryError, match="missing"):
        b.start_guarded_lease(pid=1, creation_filetime=1, image_sha256="a" * 64,
                              ip="127.0.0.1", port=443)
    monkeypatch.setattr(b, "assert_default_deny", lambda: {"installed": True})
    with pytest.raises(ValueError, match="bounds"):
        b.start_guarded_lease(pid=1, creation_filetime=1, image_sha256="a" * 64,
                              ip="127.0.0.1", port=0)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows executable smoke check")
def test_native_utility_requires_explicit_vm_marker(tmp_path):
    if importlib.util.find_spec("ziglang.__main__") is None:
        pytest.skip("ziglang unavailable")
    root = Path(__file__).resolve().parents[1]
    exe = tmp_path / "wfp_desktop.exe"
    subprocess.run([sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu", "-O2",
                    str(root / "native/behavior/wfp_desktop.c"), "-lfwpuclnt", "-ladvapi32",
                    "-lbcrypt", "-lrpcrt4", "-lws2_32", "-municode", "-o", str(exe)], check=True)
    result = subprocess.run([str(exe), "install", SID], capture_output=True, text=True, check=False)
    assert result.returncode == 2
    # This rejects a broad built-in account before opening BFE or changing rules.
    result = subprocess.run([str(exe), "status", "S-1-5-18", "--isolated-vm"],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 4
