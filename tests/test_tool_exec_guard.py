"""The split-out tool execution gate must stay version-independent and survivable.

The probe in `scripts/tool_exec_probe.py` measures the live behaviour against a
real host. These checks hold the properties that make that measurement mean
something on the next client release: no pin, no host termination, no denial of
what merely could not be classified, and coverage of every documented entry of
the CreateProcess family rather than the wide one alone.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from transpect_trace.guard import tool_exec_guard as gate
from transpect_trace.guard.policy import GuardRequest

SOURCE = (Path(__file__).resolve().parents[1] /
          "native" / "guard" / "tool_exec_guard.c").read_text(encoding="utf-8")

DOCUMENTED_ENTRIES = [(module, symbol)
                      for module in ("kernel32", "kernelbase")
                      for symbol in ("CreateProcessW", "CreateProcessA",
                                     "CreateProcessAsUserW", "CreateProcessAsUserA")]


def test_no_version_pin_takes_part_in_the_build():
    for pinned in ("REQUEST_RVA", "PREFIX_BYTES", "EXPECTED_HASH",
                   "GetModuleHandleW(NULL)"):
        assert pinned not in SOURCE
    digests = gate.source_digests()
    assert "native/guard/tool_exec_guard.c" in digests
    assert all(len(value) == 64 for value in digests.values())


def test_build_key_follows_the_source_bytes(tmp_path):
    digests = gate.source_digests()
    changed = {**digests, "native/guard/tool_exec_guard.c": "0" * 64}
    assert gate.build_key(digests) != gate.build_key(changed)
    assert gate.build_key(digests) == gate.build_key(dict(reversed(digests.items())))


def test_a_denial_never_terminates_the_host():
    assert "TerminateProcess" not in SOURCE
    assert "ExitProcess" not in SOURCE
    assert SOURCE.count("ERROR_ACCESS_DENIED") >= 1


@pytest.mark.parametrize("module,symbol", DOCUMENTED_ENTRIES)
def test_every_documented_entry_point_is_hooked(module, symbol):
    """The ANSI and AsUser exports do not pass through CreateProcessW."""
    assert f'{{L"{module}", "{symbol}"' in SOURCE


def test_hooks_are_installed_only_behind_a_live_lease():
    index = SOURCE.index("OpenMutexW")
    assert "MH_Initialize" in SOURCE[index:]
    assert "MH_Initialize" not in SOURCE[:index]
    assert "lease_state() != LEASE_ACTIVE) return 2" in SOURCE


def test_ready_frame_reports_installed_hooks_and_nothing_else_may():
    ready = GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": "1-1",
        "guard_session_id": "1-2", "pid": 1, "tid": 2, "kind": "native.ready",
        "protocol": "control", "completeness": "complete", "payload_utf8": "",
        "installed": "k32.W=0/1 kb.W=0/1"})
    assert ready.installed.startswith("k32.W=0/1")
    with pytest.raises(ValueError, match="only reported on the ready frame"):
        GuardRequest.model_validate({**ready.model_dump(by_alias=True),
                                     "kind": "native.initialize"})


def test_controller_records_each_decision_and_both_stop_meanings(tmp_path):
    guard = gate.ToolExecGuard(4242, run_dir=tmp_path)
    guard._on_frame(GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": "1-1",
        "guard_session_id": "1-2", "pid": 4242, "tid": 2, "kind": "native.ready",
        "protocol": "control", "completeness": "complete", "payload_utf8": "",
        "installed": "k32.W=0/1 kb.userA=0/0"}))
    assert guard.status.hooks == {"k32.W": "0/1", "kb.userA": "0/0"}
    guard._on_tool({"decision": "allow", "application": "cmd.exe",
                    "reason": "TOOL_EXEC_ALLOWED"})
    guard._on_tool({"decision": "deny", "application": "curl.exe",
                    "reason": "SENSITIVE_DATA_EGRESS"})
    assert (guard.status.allowed, guard.status.denied) == (1, 1)
    guard.status.state = "GATED"
    guard.stop(controlled=False)
    assert guard.status.state == "FAILED_CLOSED"
    guard.status.state = "GATED"
    guard.stop(controlled=True)
    assert guard.status.state == "STOPPED"


@pytest.mark.skipif(not gate.SOURCE.is_file(), reason="source tree unavailable")
def test_manifest_states_that_the_build_carries_no_pin(tmp_path):
    pytest.importorskip("ziglang")
    dll = gate.ensure_dll()
    manifest = json.loads(dll.with_suffix(".json").read_text(encoding="utf-8"))
    assert manifest["version_pinned"] is False
    assert manifest["sources"] == gate.source_digests()
    assert gate.ensure_dll() == dll  # an unchanged source is not rebuilt
