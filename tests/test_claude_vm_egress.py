"""VM command validation without installing or removing system WFP filters."""
from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = spec_from_file_location("claude_vm_egress", ROOT / "scripts/claude_vm_egress.py")
vm = module_from_spec(SPEC)
SPEC.loader.exec_module(vm)


def test_model_lease_binds_exact_ready_pid_and_destination(tmp_path, monkeypatch, capsys):
    binary = (tmp_path / "AppData/Roaming/npm/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
    binary.parent.mkdir(parents=True)
    binary.touch()
    pin = {"binary": {"sha256": "a" * 64}}
    args = SimpleNamespace(pid=123, sid="S-1-5-21-101-202-303-1001",
                           wfp_exe=binary, model_ip="127.0.0.1",
                           model_port=443, seconds=30)
    monkeypatch.setattr(vm, "process_details", lambda pid: {
        "user_sid": args.sid, "image_path": str(binary),
        "creation_filetime": 456,
    })
    monkeypatch.setattr(vm.claude_lab, "load_pin", lambda: pin)
    monkeypatch.setattr(vm.claude_lab, "check_binary", lambda p, b: None)
    recorded = {}

    class Lease:
        filter_id = 789
        pid_exact_filter = False
        alive = False
        def close(self):
            recorded["closed"] = True

    def start(self, **kwargs):
        recorded.update(kwargs)
        return Lease()

    monkeypatch.setattr(vm.WfpBoundary, "start_guarded_lease", start)
    assert vm.model_lease(args) == 0
    assert recorded["pid"] == 123 and recorded["creation_filetime"] == 456
    assert recorded["image_sha256"] == "a" * 64
    assert recorded["ip"] == "127.0.0.1" and recorded["port"] == 443
    assert recorded["closed"] is True
    assert '"pid_exact_filter": false' in capsys.readouterr().out


def test_model_lease_rejects_different_claude_image(monkeypatch):
    args = SimpleNamespace(pid=123, sid="S-1-5-21-101-202-303-1001",
                           wfp_exe=Path(__file__), model_ip="127.0.0.1",
                           model_port=443, seconds=30)
    monkeypatch.setattr(vm, "process_details", lambda pid: {
        "user_sid": args.sid, "image_path": str(Path(__file__).resolve()),
        "creation_filetime": 456,
    })
    with pytest.raises(RuntimeError, match="not the pinned npm"):
        vm.model_lease(args)
