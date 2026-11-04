"""Host research can attach only to the separate, exact pinned Appx instance."""
from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import probe_desktop_paths_host as host  # noqa: E402


PINNED = "OpenAI.Codex_26.1029.7803.0_x64__2p2nqsd0c76g0"
DEDICATED = "S-1-5-21-111-222-333-1002"
PROTECTED = "S-1-5-21-111-222-333-1001"


def adapter() -> dict:
    return {"status": "candidate_unvalidated", "production_ready": False,
            "coverage": {name: {"validated": False} for name in
                         ("model.http", "model.wss", "attachment.upload")},
            "package_full_name": PINNED,
            "package_version": "26.1029.7803.0",
            "package_publisher": "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B",
            "desktop_image_sha256": "c" * 64, "binary_sha256": "a" * 64}


@pytest.mark.skipif(os.name != "nt", reason="Windows Appx host probe")
def test_host_observer_requires_separate_dedicated_windows_user(monkeypatch):
    monkeypatch.setattr(host, "current_user_sid", lambda: DEDICATED)
    host.require_dedicated_user(DEDICATED, PROTECTED)
    with pytest.raises(ValueError, match="distinct"):
        host.require_dedicated_user(PROTECTED, PROTECTED)
    monkeypatch.setattr(host, "current_user_sid", lambda: PROTECTED)
    with pytest.raises(ValueError, match="dedicated desktop user"):
        host.require_dedicated_user(DEDICATED, PROTECTED)


@pytest.mark.skipif(os.name != "nt", reason="Windows Appx host probe")
def test_registered_appx_version_must_match_archived_fixed_package(monkeypatch):
    row = {"FullName": PINNED, "Version": "26.1029.7803.0",
           "Publisher": adapter()["package_publisher"],
           "Location": rf"C:\Program Files\WindowsApps\{PINNED}"}
    monkeypatch.setattr(host.subprocess, "run", lambda *a, **kw:
                        SimpleNamespace(returncode=0, stdout=json.dumps(row)))
    assert host.registered_package(adapter()) == row
    row["Version"] = "26.1027.6604.0"
    with pytest.raises(ValueError, match="fixed package"):
        host.registered_package(adapter())


def test_host_targets_pin_owner_parent_role_hash_and_installed_path(monkeypatch):
    monkeypatch.setattr(host, "require_dedicated_user", lambda *_: None)
    root = rf"C:\Program Files\WindowsApps\{PINNED}"
    package = {"Location": root}
    images = {
        100: {"creation_filetime": 10, "image_sha256": "c" * 64,
              "image_path": root + r"\app\ChatGPT.exe"},
        200: {"creation_filetime": 20, "image_sha256": "a" * 64,
              "image_path": root + r"\app\resources\codex.exe"},
        300: {"creation_filetime": 30, "image_sha256": "c" * 64,
              "image_path": root + r"\app\ChatGPT.exe"},
    }
    rows = {100: {"UserSid": DEDICATED},
            200: {"UserSid": DEDICATED, "ParentProcessId": 100,
                  "CommandLine": '"' + root + r"\app\resources\codex.exe" + '" app-server'},
            300: {"UserSid": DEDICATED, "ParentProcessId": 100,
                  "CommandLine": "--type=utility --utility-sub-type=network.mojom.NetworkService"}}
    monkeypatch.setattr(host, "process_identity", lambda pid: images[pid])
    monkeypatch.setattr(host, "_cim_process", lambda pid: rows[pid])
    result = host.verify_host_targets(adapter(), package, 100, 200, 300, DEDICATED, PROTECTED)
    assert set(result) == {"desktop", "backend", "network"}
    promoted = adapter()
    promoted["status"] = "validated"
    with pytest.raises(ValueError, match="unvalidated"):
        host.verify_host_targets(promoted, package, 100, 200, 300, DEDICATED, PROTECTED)
    rows[200]["UserSid"] = PROTECTED
    with pytest.raises(ValueError, match="app-server"):
        host.verify_host_targets(adapter(), package, 100, 200, 300, DEDICATED, PROTECTED)
    rows[200]["UserSid"] = DEDICATED
    images[100]["image_path"] = rf"C:\other\{PINNED}\app\ChatGPT.exe"
    with pytest.raises(ValueError, match="pinned desktop"):
        host.verify_host_targets(adapter(), package, 100, 200, 300, DEDICATED, PROTECTED)


def test_host_trace_refuses_enforcement_mode_before_any_attach():
    with pytest.raises(ValueError, match="observation-only"):
        host.run_trace(SimpleNamespace(observation_only=False))


@pytest.mark.skipif(os.name != "nt", reason="Windows process handle pinning")
def test_host_probe_holds_process_identity_during_attach():
    birth = host.process_identity(os.getpid())["creation_filetime"]
    with host.hold_processes({"self": {"pid": os.getpid(), "birth": birth}}):
        pass
    with pytest.raises(ValueError, match="changed before attach"):
        with host.hold_processes({"self": {"pid": os.getpid(), "birth": birth + 1}}):
            pass


def test_frida_child_refuses_wrong_user_before_native_attach(monkeypatch):
    class Sender:
        def __init__(self):
            self.rows = []

        def send(self, row):
            self.rows.append(row)

        def close(self):
            pass

    monkeypatch.setattr(host, "require_dedicated_user", lambda *_:
                        (_ for _ in ()).throw(ValueError("wrong account")))
    sender = Sender()
    host._frida_worker(adapter(), {"Location": "irrelevant"}, {}, 100, 200, None,
                       DEDICATED, PROTECTED, "", Path("synthetic.txt"), sender)
    assert sender.rows == [{"error": "frida_worker_ValueError"}]


def test_frida_pipe_requires_all_expected_roles_and_rejects_foreign_role():
    receiver, sender = multiprocessing.Pipe(duplex=False)
    rows, errors, version = [], [], {}
    ready = threading.Event()
    collector = threading.Thread(target=host._read_frida_events,
                                 args=(receiver, rows, errors, {"desktop", "backend"},
                                       ready, version))
    collector.start()
    sender.send({"event": {"role": "foreign", "kind": "probe_ready"}})
    sender.send({"event": {"role": "desktop", "kind": "probe_ready"}})
    assert not ready.wait(0.05)
    sender.send({"event": {"role": "backend", "kind": "probe_ready"}})
    assert ready.wait(1)
    sender.close()
    collector.join(timeout=1)
    receiver.close()
    assert not collector.is_alive()
    assert "unexpected_frida_role" in errors
    assert {row["role"] for row in rows} == {"desktop", "backend"}
