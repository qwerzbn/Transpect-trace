"""A desktop static candidate must never become an enabled guard by accident."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

import pytest

from transpect_trace.guard.desktop import (
    OFFICIAL_MSIX_PUBLISHER, OFFICIAL_MSIX_SIGNER_SHA1,
    PINNED_MSIX_VERSION, PINNED_MSIX_SHA256, PINNED_DESKTOP_IMAGE_SHA256,
    PINNED_BACKEND_VERSION, PINNED_BACKEND_SHA256,
    SCHEMA, DesktopGuardSession, desktop_mode, require_desktop_ready,
    require_desktop_dlp_engine, validate_desktop_adapter, validate_desktop_identity,
    verify_guard_build, verify_hook_entries, verify_live_model_module,
    _attachment_ready, _validate_image_sid_peers,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_guard_native import pin_defines  # noqa: E402
from discover_desktop_guard import candidate_adapter, inspect_msix, verify_msix_signature  # noqa: E402


def adapter(validated=True):
    result = {
        "schema": SCHEMA, "architecture": "windows-x64", "package_name": "OpenAI.Codex",
        "package_publisher": OFFICIAL_MSIX_PUBLISHER,
        "package_signer_thumbprint": OFFICIAL_MSIX_SIGNER_SHA1,
        "package_version": PINNED_MSIX_VERSION,
        "package_full_name": f"OpenAI.Codex_{PINNED_MSIX_VERSION}_x64__2p2nqsd0c76g0",
        "package_sha256": PINNED_MSIX_SHA256,
        "desktop_image_sha256": PINNED_DESKTOP_IMAGE_SHA256,
        "backend_version": PINNED_BACKEND_VERSION,
        "binary_sha256": PINNED_BACKEND_SHA256,
        "modes": ["app-server"], "status": "validated" if validated else "candidate_unvalidated",
        "production_ready": False,
        "hooks": [
            {"layer": "http_encoded_body_preparation", "rva": "0x1000",
             "entry_prefix_hex": "90" * 16, "owned_headers_drop_rva": "0x3000",
             "abi_compatible": validated},
            {"layer": "wss_request_serialization", "rva": "0x2000",
             "entry_prefix_hex": "91" * 16, "abi_compatible": validated},
        ],
        "coverage": {name: {"validated": validated, "evidence_sha256": "d" * 64 if validated else None}
                     for name in ("model.http", "model.wss", "attachment.upload")},
    }
    result["coverage"]["attachment.upload"].update(
        process_role="desktop-network-service", process_image_sha256=result["desktop_image_sha256"],
        upload_dll_sha256="e" * 64)
    return result


def identities(config):
    sid = "S-1-5-21-111-222-333-1001"
    backend = {"pid": 200, "parent_pid": 100, "user_sid": sid,
               "image_path": r"C:\Users\demo\AppData\Local\OpenAI\Codex\bin\fixed\codex.exe",
               "image_sha256": config["binary_sha256"], "mode": "app-server",
               "creation_filetime": 1000000}
    desktop = {"pid": 100, "user_sid": sid, "image_path":
               rf"C:\Program Files\WindowsApps\{config['package_full_name']}\app\ChatGPT.exe",
               "image_sha256": config["desktop_image_sha256"],
               "package_full_name": config["package_full_name"], "creation_filetime": 900000}
    return backend, desktop, sid


def registered_bridge(identity):
    from transpect_trace.protect.content_dlp import ContentDLPEngine, EDMIndex, FingerprintIndex
    from transpect_trace.protect.desktop_bridge import DesktopDLPBridge
    class Archive:
        def prune(self, *, now): pass
    dlp = ContentDLPEngine(
        index=FingerprintIndex.from_documents({"doc": ("INTERNAL_DOC", "one two three four five six")}),
        edm_index=EDMIndex.from_records({"record": {"name": "Alice Smith", "id": "ABC12345"}}, b"k" * 32))
    return DesktopDLPBridge(identity, Archive(), dlp)


def test_real_desktop_mode_only():
    assert desktop_mode(["codex.exe", "-c", "x=1", "app-server", "--analytics-default-enabled"]) == "app-server"
    assert desktop_mode(["codex.exe", "-c", "app-server", "exec-server"]) == "unsupported"
    assert desktop_mode(["codex.exe", "exec", "app-server"]) == "unsupported"
    assert desktop_mode(["ChatGPT.exe", "app-server"]) == "unsupported"


def test_static_candidate_cannot_build_or_activate(tmp_path):
    value = adapter(validated=False)
    value["hooks"][0]["owned_headers_drop_rva"] = "needs_dynamic_validation"
    validate_desktop_adapter(value, require_validated=False)
    with pytest.raises(ValueError, match="not validated"):
        validate_desktop_adapter(value)
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(value))
    with pytest.raises(SystemExit, match="not dynamically validated"):
        pin_defines(path)


def test_attachment_proof_and_hook_abi_are_both_required():
    value = adapter()
    value["coverage"]["attachment.upload"]["validated"] = False
    with pytest.raises(ValueError, match="attachment.upload"):
        validate_desktop_adapter(value)
    value = adapter()
    value["hooks"][1]["abi_compatible"] = False
    with pytest.raises(ValueError, match="ABI"):
        validate_desktop_adapter(value)


def test_process_ancestry_pins_and_network_default_deny():
    value = adapter()
    backend, desktop, sid = identities(value)
    identity = validate_desktop_identity(value, backend, desktop, expected_sid=sid)
    with pytest.raises(ValueError, match="default deny"):
        require_desktop_ready(value, identity, wfp_default_deny=False,
                              model_guard_ready=True, attachment_guard_ready=True)
    with pytest.raises(ValueError, match="all desktop content gates"):
        require_desktop_ready(value, identity, wfp_default_deny=True,
                              model_guard_ready=True, attachment_guard_ready=False)
    require_desktop_ready(value, identity, wfp_default_deny=True,
                          model_guard_ready=True, attachment_guard_ready=True)
    desktop["pid"] = 101
    with pytest.raises(ValueError, match="child"):
        validate_desktop_identity(value, backend, desktop, expected_sid=sid)


def test_backend_or_desktop_hash_change_rejected():
    value = adapter()
    backend, desktop, sid = identities(value)
    backend["image_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="backend hash"):
        validate_desktop_identity(value, backend, desktop, expected_sid=sid)
    backend["image_sha256"] = value["binary_sha256"]
    desktop["image_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="desktop image hash"):
        validate_desktop_identity(value, backend, desktop, expected_sid=sid)


def test_offline_msix_discovery_emits_candidate_only(tmp_path):
    msix = tmp_path / "Codex.msix"
    with zipfile.ZipFile(msix, "w") as archive:
        archive.writestr("AppxManifest.xml", f'<Package><Identity Name="OpenAI.Codex" '
                         f'Publisher="{OFFICIAL_MSIX_PUBLISHER}" '
                         f'Version="{PINNED_MSIX_VERSION}" ProcessorArchitecture="x64"/></Package>')
        archive.writestr("app/ChatGPT.exe", b"fake signed desktop fixture")
    package = inspect_msix(msix, adapter()["package_full_name"])
    assert package["desktop_image_sha256"] == hashlib.sha256(b"fake signed desktop fixture").hexdigest()
    discovery = {"binary_sha256": PINNED_BACKEND_SHA256, "candidates": [
        {"layer": "http_body_preparation", "function_rva": "0x1000", "entry_prefix_hex": "90" * 16},
        {"layer": "serialization", "function_rva": "0x2000", "entry_prefix_hex": "91" * 16}]}
    fixture_pins = {"package_signer_thumbprint": OFFICIAL_MSIX_SIGNER_SHA1,
                    "package_sha256": PINNED_MSIX_SHA256,
                    "desktop_image_sha256": PINNED_DESKTOP_IMAGE_SHA256}
    candidate = candidate_adapter(package | fixture_pins, discovery, PINNED_BACKEND_VERSION)
    assert candidate["status"] == "candidate_unvalidated"
    assert not candidate["coverage"]["attachment.upload"]["validated"]
    with pytest.raises(ValueError):
        validate_desktop_adapter(candidate)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Authenticode fixture")
def test_msix_signer_is_pinned_beyond_valid_status(tmp_path, monkeypatch):
    from types import SimpleNamespace
    package = tmp_path / "fixed.msix"
    package.write_bytes(b"fixture")
    def run_for(subject, thumbprint):
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "Status": "Valid", "Subject": subject, "Thumbprint": thumbprint}))
    monkeypatch.setattr("discover_desktop_guard.subprocess.run", lambda *a, **kw:
                        run_for("CN=Another Trusted Publisher", OFFICIAL_MSIX_SIGNER_SHA1))
    with pytest.raises(ValueError, match="signer"):
        verify_msix_signature(package)
    monkeypatch.setattr("discover_desktop_guard.subprocess.run", lambda *a, **kw:
                        run_for(OFFICIAL_MSIX_PUBLISHER, "0" * 40))
    with pytest.raises(ValueError, match="signer"):
        verify_msix_signature(package)
    monkeypatch.setattr("discover_desktop_guard.subprocess.run", lambda *a, **kw:
                        run_for(OFFICIAL_MSIX_PUBLISHER, OFFICIAL_MSIX_SIGNER_SHA1.upper()))
    assert verify_msix_signature(package)["package_signer_thumbprint"] == OFFICIAL_MSIX_SIGNER_SHA1


def test_dll_must_be_built_from_exact_desktop_manifest(tmp_path):
    value = adapter()
    adapter_path = tmp_path / "adapter.json"
    adapter_path.write_text(json.dumps(value))
    dll = tmp_path / "ttrace-guard.dll"
    dll.write_bytes(b"fixture DLL")
    build = {"adapter_sha256": hashlib.sha256(adapter_path.read_bytes()).hexdigest(),
             "target_binary_sha256": value["binary_sha256"],
             "artifacts_sha256": {dll.name: hashlib.sha256(dll.read_bytes()).hexdigest()}}
    (tmp_path / "build-manifest.json").write_text(json.dumps(build))
    assert verify_guard_build(dll, adapter_path, value) == hashlib.sha256(dll.read_bytes()).hexdigest()
    dll.write_bytes(b"stale CLI DLL")
    with pytest.raises(ValueError, match="not pinned"):
        verify_guard_build(dll, adapter_path, value)


def test_hook_entries_must_match_exact_pe_text(tmp_path):
    value = adapter()
    value["hooks"][1]["rva"] = "0x1010"
    value["hooks"][0]["owned_headers_drop_rva"] = "0x1020"
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    data[0x188:0x18d] = b".text"
    struct.pack_into("<IIII", data, 0x190, 0x100, 0x1000, 0x100, 0x200)
    data[0x200:0x210] = b"\x90" * 16
    data[0x210:0x220] = b"\x91" * 16
    binary = tmp_path / "codex.exe"
    binary.write_bytes(data)
    verify_hook_entries(binary, value)
    data[0x210] = 0x92
    binary.write_bytes(data)
    with pytest.raises(ValueError, match="entry bytes changed"):
        verify_hook_entries(binary, value)


def test_no_model_permit_without_live_attachment_attestation(monkeypatch):
    value = adapter()
    backend, desktop, sid = identities(value)
    identity = validate_desktop_identity(value, backend, desktop, expected_sid=sid)
    import threading
    class Server:
        errors = []
        ready = threading.Event()
        def close(self): pass
    class Boundary:
        def __init__(self): self.calls = self.closed = 0
        def assert_default_deny(self): return True
        def start_guarded_lease(self, *args, **kwargs):
            self.calls += 1
            return self
        def close(self): self.closed += 1
    class Attachment:
        ready = False
        def attest(self, adapter, identity):
            return {"ready": self.ready, "process_role": "desktop-network-service",
                    "image_sha256": adapter["desktop_image_sha256"],
                    "desktop_creation_filetime": identity["desktop_creation_filetime"], "pid": 300}
    monkeypatch.setattr("transpect_trace.guard.desktop.collect_desktop_identity", lambda *a, **kw: identity)
    server, boundary, attachment = Server(), Boundary(), Attachment()
    server.ready.set()
    engine = registered_bridge(identity)
    attachment.bridge = engine
    monkeypatch.setattr("transpect_trace.guard.desktop.assert_no_duplicate_image_sid", lambda _: None)
    monkeypatch.setattr("transpect_trace.guard.desktop.verify_live_model_module", lambda *a: None)
    monkeypatch.setattr("transpect_trace.guard.desktop._attachment_ready",
                        lambda adapter, current, gate, bridge: gate.ready and gate.bridge is bridge)
    session = DesktopGuardSession(value, identity, server, boundary, attachment,
                                  engine, model_dll=Path("fixture.dll"), model_dll_sha256="a" * 64)
    with pytest.raises(ValueError, match="all desktop content gates"):
        session.permit_model_destination("203.0.113.10", 443)
    assert boundary.calls == 0
    attachment.ready = True
    attachment.bridge = registered_bridge(identity)
    with pytest.raises(ValueError, match="all desktop content gates"):
        session.permit_model_destination("203.0.113.10", 443)
    attachment.bridge = engine
    session.permit_model_destination("203.0.113.10", 443)
    assert boundary.calls == 1
    session.close()


@pytest.mark.parametrize("failure", ("model", "upload", "birth", "hash"))
def test_watchdog_revokes_existing_lease_on_gate_or_process_change(monkeypatch, failure):
    import threading
    value = adapter()
    backend, desktop, sid = identities(value)
    identity = validate_desktop_identity(value, backend, desktop, expected_sid=sid)
    current = [identity]
    monkeypatch.setattr("transpect_trace.guard.desktop.collect_desktop_identity",
                        lambda *a, **kw: current[0])
    monkeypatch.setattr("transpect_trace.guard.desktop.assert_no_duplicate_image_sid", lambda _: None)
    monkeypatch.setattr("transpect_trace.guard.desktop.verify_live_model_module", lambda *a: None)
    monkeypatch.setattr("transpect_trace.guard.desktop._attachment_ready",
                        lambda adapter, now, gate, bridge: gate.ready and gate.bridge is bridge)
    class Server:
        errors = []
        ready = threading.Event()
        def close(self): pass
    class Lease:
        closed = False
        def close(self): self.closed = True
    class Boundary:
        lease = Lease()
        def assert_default_deny(self): pass
        def start_guarded_lease(self, **kwargs): return self.lease
    class Gate:
        ready = True
    server, boundary, gate = Server(), Boundary(), Gate()
    server.ready.set()
    engine = registered_bridge(identity)
    gate.bridge = engine
    session = DesktopGuardSession(value, identity, server, boundary, gate, engine,
                                  model_dll=Path("fixture.dll"), model_dll_sha256="a" * 64)
    try:
        session.permit_model_destination("203.0.113.10", 443)
        if failure == "model":
            server.ready.clear()
        elif failure == "upload":
            gate.ready = False
        elif failure == "birth":
            current[0] = identity | {"creation_filetime": identity["creation_filetime"] + 1}
        else:
            current[0] = identity | {"baseline": identity["baseline"] | {"sha256": "0" * 64}}
        assert session.gate_failed.wait(3), "watchdog did not notice the failure"
        assert boundary.lease.closed
        with pytest.raises(ValueError, match="no longer healthy"):
            session.permit_model_destination("203.0.113.10", 443)
    finally:
        session.close()


def test_model_ready_event_requires_loaded_exact_dll(tmp_path, monkeypatch):
    dll = tmp_path / "ttrace-guard.dll"
    dll.write_bytes(b"native model gate fixture")
    checksum = hashlib.sha256(dll.read_bytes()).hexdigest()
    monkeypatch.setattr("transpect_trace.observe.windows.modules",
                        lambda pid: [{"path": str(dll)}])
    monkeypatch.setattr("transpect_trace.observe.windows.digest",
                        lambda path: checksum)
    verify_live_model_module(200, dll, checksum)
    with pytest.raises(ValueError, match="hash changed"):
        verify_live_model_module(200, dll, "0" * 64)
    monkeypatch.setattr("transpect_trace.observe.windows.modules", lambda pid: [])
    with pytest.raises(ValueError, match="no longer loaded"):
        verify_live_model_module(200, dll, checksum)


def test_arbitrary_ready_claim_cannot_replace_native_upload_pipe():
    value = adapter()
    backend, desktop, sid = identities(value)
    identity = validate_desktop_identity(value, backend, desktop, expected_sid=sid)
    engine = registered_bridge(identity)
    class FakeGate:
        bridge = engine
        def attest(self, adapter, identity):
            return {"ready": True, "process_role": "desktop-network-service",
                    "image_sha256": adapter["desktop_image_sha256"],
                    "desktop_creation_filetime": identity["desktop_creation_filetime"], "pid": 300}
    assert not _attachment_ready(value, identity, FakeGate(), engine)


def test_desktop_engine_requires_pinned_subject_and_all_registered_layers():
    value = adapter()
    backend, desktop, sid = identities(value)
    identity = validate_desktop_identity(value, backend, desktop, expected_sid=sid)
    require_desktop_dlp_engine(registered_bridge(identity), identity)
    with pytest.raises(ValueError, match="DesktopDLPBridge"):
        require_desktop_dlp_engine(object(), identity)
    wrong = dict(identity, guard_session_id="other")
    with pytest.raises(ValueError, match="subject"):
        require_desktop_dlp_engine(registered_bridge(wrong), identity)
    from transpect_trace.protect.desktop_bridge import DesktopDLPBridge
    class Archive:
        def prune(self, *, now): pass
    with pytest.raises(ValueError, match="registrations"):
        require_desktop_dlp_engine(DesktopDLPBridge(identity, Archive()), identity)


def test_wfp_same_image_sid_peer_is_refused():
    value = adapter()
    backend, desktop, sid = identities(value)
    identity = validate_desktop_identity(value, backend, desktop, expected_sid=sid)
    path = identity["baseline"]["path"]
    own = {"Pid": identity["pid"], "Image": path, "Sid": sid}
    _validate_image_sid_peers([own], identity)
    with pytest.raises(ValueError, match="another same-image"):
        _validate_image_sid_peers([own, {"Pid": 300, "Image": path.upper(), "Sid": sid}], identity)
    with pytest.raises(ValueError, match="unknown WFP peer"):
        _validate_image_sid_peers([own, {"Pid": 300, "Image": None, "Sid": sid}], identity)
