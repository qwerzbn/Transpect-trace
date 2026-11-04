"""Pinned Codex desktop identity and activation preflight.

This module does not certify a desktop request path.  A static RVA candidate is
never sufficient to admit network traffic; the isolated VM must first produce
separate model and attachment gate evidence for its exact package and backend.
"""
from __future__ import annotations

import csv
import json
import ntpath
import os
from pathlib import Path
import re
import struct
import subprocess
import threading
from typing import Protocol


SCHEMA = "transpect.guard.desktop-adapter/1.0"
# Pinned from the archived official 26.1029.7803.0 x64 MSIX, not inferred from
# a live user's installed desktop client. A certificate rotation requires a
# new reviewed fixed-build adapter.
OFFICIAL_MSIX_PUBLISHER = "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B"
OFFICIAL_MSIX_SIGNER_SHA1 = "b0429f3569607833179400e29d6d641b363ca6a4"
PINNED_MSIX_VERSION = "26.1029.7803.0"
PINNED_MSIX_SHA256 = "19487892b7e27c74e75c6422088e91b35b4291ed485045f82a1984a13b22d128"
PINNED_DESKTOP_IMAGE_SHA256 = "74dcbc67421c5d5406ea5e4cc80d9c8d8a05d0df62f1d7be5690f090f182e71f"
PINNED_BACKEND_VERSION = "codex-cli 0.166.0-alpha.6"
PINNED_BACKEND_SHA256 = "925c7d0665ffa49b0dcf748e034a805a04da984164ac92301432073b47789b99"
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_RVA = re.compile(r"0x[0-9a-fA-F]+\Z")
_REQUIRED_PATHS = frozenset(("model.http", "model.wss", "attachment.upload"))


def windows_powershell_env() -> dict[str, str]:
    """Use only OS PowerShell modules for local identity and signature probes."""
    result = dict(os.environ)
    program_files = result.get("ProgramFiles", r"C:\Program Files")
    system_root = result.get("SystemRoot", r"C:\Windows")
    result["PSModulePath"] = ";".join((
        str(Path(program_files) / "WindowsPowerShell" / "Modules"),
        str(Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"),
    ))
    return result


def desktop_mode(arguments: list[str]) -> str:
    """Recognize only a local app-server, never exec-server or prompt text."""
    if not arguments or Path(arguments[0]).name.lower() != "codex.exe":
        return "unsupported"
    takes_value = {"-c", "--config", "-p", "--profile", "-C", "--cd", "-m", "--model"}
    skip = False
    for item in arguments[1:]:
        if skip:
            skip = False
            continue
        if item in takes_value:
            skip = True
            continue
        if item == "--":
            return "unsupported"
        if item.startswith("-"):
            continue
        return "app-server" if item == "app-server" else "unsupported"
    return "unsupported"


def validate_desktop_adapter(adapter: dict, *, require_validated: bool = True) -> dict:
    """Validate a VM pin and reject any unproved send or attachment path."""
    if not isinstance(adapter, dict) or adapter.get("schema") != SCHEMA:
        raise ValueError("invalid desktop adapter schema")
    if adapter.get("architecture") != "windows-x64" or adapter.get("package_name") != "OpenAI.Codex":
        raise ValueError("unsupported desktop package or architecture")
    if (adapter.get("package_publisher") != OFFICIAL_MSIX_PUBLISHER
            or adapter.get("package_signer_thumbprint") != OFFICIAL_MSIX_SIGNER_SHA1):
        raise ValueError("desktop MSIX signer is not pinned to the official archived build")
    if not isinstance(adapter.get("package_full_name"), str) or not re.fullmatch(
            r"OpenAI\.Codex_\d+\.\d+\.\d+\.\d+_x64__[a-z0-9]+", adapter["package_full_name"]):
        raise ValueError("missing fixed desktop package identity")
    if adapter.get("package_version") != adapter["package_full_name"].split("_")[1]:
        raise ValueError("desktop package version mismatch")
    pins = {"package_version": PINNED_MSIX_VERSION,
            "package_sha256": PINNED_MSIX_SHA256,
            "desktop_image_sha256": PINNED_DESKTOP_IMAGE_SHA256,
            "backend_version": PINNED_BACKEND_VERSION,
            "binary_sha256": PINNED_BACKEND_SHA256}
    if any(adapter.get(name) != value for name, value in pins.items()):
        raise ValueError("desktop package or backend differs from the fixed archived build")
    if adapter.get("modes") != ["app-server"]:
        raise ValueError("desktop adapter must be app-server only")
    coverage = adapter.get("coverage")
    if not isinstance(coverage, dict) or set(coverage) != _REQUIRED_PATHS:
        raise ValueError("desktop adapter must enumerate model HTTP/WSS and attachment upload")
    hooks = adapter.get("hooks")
    if not isinstance(hooks, list) or len(hooks) < 2:
        raise ValueError("missing model hook candidates")
    names = {item.get("layer") for item in hooks if isinstance(item, dict)}
    if names != {"http_encoded_body_preparation", "wss_request_serialization"}:
        raise ValueError("model hook layers are incomplete or unknown")
    for item in hooks:
        if not _RVA.fullmatch(str(item.get("rva", ""))):
            raise ValueError("invalid hook RVA")
        if not re.fullmatch(r"(?:[a-fA-F0-9]{2}){8,32}", str(item.get("entry_prefix_hex", ""))):
            raise ValueError("invalid hook entry bytes")
    if require_validated:
        if adapter.get("status") != "validated" or adapter.get("production_ready") is not False:
            # This is explicitly a bounded demo, not a general production adapter.
            raise ValueError("desktop adapter is not validated for this demo")
        http = next(item for item in hooks if item["layer"] == "http_encoded_body_preparation")
        if not _RVA.fullmatch(str(http.get("owned_headers_drop_rva", ""))):
            raise ValueError("HTTP owned headers cleanup is unvalidated")
        for name in _REQUIRED_PATHS:
            proof = coverage[name]
            if not isinstance(proof, dict) or proof.get("validated") is not True or not _SHA256.fullmatch(str(proof.get("evidence_sha256", ""))):
                raise ValueError(f"desktop path {name} has no dynamic validation evidence")
        attachment = coverage["attachment.upload"]
        if (attachment.get("process_role") not in {"app-server", "desktop-network-service"}
                or not _SHA256.fullmatch(str(attachment.get("process_image_sha256", "")))
                or not _SHA256.fullmatch(str(attachment.get("upload_dll_sha256", "")))):
            raise ValueError("desktop attachment upload process identity is unvalidated")
        if any(item.get("abi_compatible") is not True for item in hooks):
            raise ValueError("desktop model hook ABI is unvalidated")
    return adapter


def load_desktop_adapter(path: Path, *, require_validated: bool = True) -> dict:
    return validate_desktop_adapter(json.loads(Path(path).read_text(encoding="utf-8")),
                                    require_validated=require_validated)


def verify_hook_entries(binary: Path, adapter: dict) -> None:
    """Check exact bytes within executable .text before a DLL can dereference RVAs."""
    with Path(binary).open("rb") as stream:
        header = stream.read(65536)
        if len(header) < 64 or header[:2] != b"MZ":
            raise ValueError("desktop backend is not a PE image")
        pe = struct.unpack_from("<I", header, 60)[0]
        if pe + 24 > len(header) or header[pe:pe + 4] != b"PE\0\0":
            raise ValueError("desktop backend PE header is invalid")
        count = struct.unpack_from("<H", header, pe + 6)[0]
        opt_size = struct.unpack_from("<H", header, pe + 20)[0]
        table = pe + 24 + opt_size
        if count > 96 or table + count * 40 > len(header):
            raise ValueError("desktop backend PE sections are invalid")
        sections = []
        for i in range(count):
            offset = table + i * 40
            name = header[offset:offset + 8].rstrip(b"\0")
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", header, offset + 8)
            sections.append((name, rva, min(virtual_size, raw_size), raw_offset))
        code = next((section for section in sections if section[0] == b".text"), None)
        if code is None:
            raise ValueError("desktop backend has no .text section")
        _, base, size, raw = code
        for hook in adapter["hooks"]:
            address = int(hook["rva"], 16)
            prefix = bytes.fromhex(hook["entry_prefix_hex"])
            if not base <= address <= base + size - len(prefix):
                raise ValueError("desktop hook RVA is outside .text")
            stream.seek(raw + address - base)
            if stream.read(len(prefix)) != prefix:
                raise ValueError("desktop hook entry bytes changed")
        drop = int(next(item for item in adapter["hooks"] if item["layer"] == "http_encoded_body_preparation")
                   ["owned_headers_drop_rva"], 16)
        if not base <= drop < base + size:
            raise ValueError("desktop HTTP cleanup RVA is outside .text")


def validate_desktop_identity(adapter: dict, backend: dict, desktop: dict, *, expected_sid: str) -> dict:
    """Bind the backend to its desktop parent, pinned files, and demo account."""
    validate_desktop_adapter(adapter)
    if not re.fullmatch(r"S-1-(?:\d+-)+\d+", expected_sid):
        raise ValueError("invalid dedicated desktop user SID")
    if backend.get("pid") == desktop.get("pid") or backend.get("parent_pid") != desktop.get("pid"):
        raise ValueError("backend is not a child of the pinned desktop")
    if backend.get("user_sid") != expected_sid or desktop.get("user_sid") != expected_sid:
        raise ValueError("desktop process user identity mismatch")
    if backend.get("image_sha256") != adapter["binary_sha256"]:
        raise ValueError("desktop backend hash mismatch")
    if desktop.get("image_sha256") != adapter["desktop_image_sha256"]:
        raise ValueError("desktop image hash mismatch")
    if desktop.get("package_full_name") != adapter["package_full_name"]:
        raise ValueError("desktop MSIX identity mismatch")
    if backend.get("mode") != "app-server":
        raise ValueError("backend is not a local app-server")
    if not all(isinstance(item.get("creation_filetime"), int) and item["creation_filetime"] > 0
               for item in (backend, desktop)):
        raise ValueError("missing process creation identity")
    if not Path(str(backend.get("image_path", ""))).name.lower() == "codex.exe":
        raise ValueError("unexpected backend executable")
    if not Path(str(desktop.get("image_path", ""))).name.lower() == "chatgpt.exe":
        raise ValueError("unexpected desktop executable")
    if adapter["package_full_name"].lower() not in str(desktop["image_path"]).lower():
        raise ValueError("desktop binary is outside pinned package")
    return {
        "pid": backend["pid"], "creation_filetime": backend["creation_filetime"],
        "guard_session_id": f'{backend["pid"]}-{backend["creation_filetime"]}',
        "baseline": {"path": backend["image_path"], "sha256": backend["image_sha256"],
                     "supported": True, "version": adapter["backend_version"]},
        "mode": "app-server", "channel": "desktop", "user_sid": expected_sid,
        "desktop_pid": desktop["pid"], "desktop_creation_filetime": desktop["creation_filetime"],
        "package_full_name": adapter["package_full_name"],
    }


def require_desktop_ready(adapter: dict, identity: dict, *, wfp_default_deny: bool,
                          model_guard_ready: bool, attachment_guard_ready: bool) -> None:
    """Single point at which a controller may consider opening VM egress."""
    validate_desktop_adapter(adapter)
    if identity.get("channel") != "desktop" or identity.get("baseline", {}).get("sha256") != adapter["binary_sha256"]:
        raise ValueError("desktop gate identity mismatch")
    if not wfp_default_deny:
        raise ValueError("persistent default deny must precede desktop network permits")
    if not model_guard_ready or not attachment_guard_ready:
        raise ValueError("all desktop content gates must attest readiness before egress")


def require_desktop_dlp_engine(engine, identity: dict) -> None:
    """Never route a desktop model Hook to the legacy or unregistered policy."""
    from transpect_trace.protect.content_dlp import ContentDLPEngine, EDMIndex, FingerprintIndex
    from transpect_trace.protect.desktop_bridge import DesktopDLPBridge
    if not isinstance(engine, DesktopDLPBridge):
        raise ValueError("desktop model gate requires DesktopDLPBridge")
    subject = engine.subject
    if not isinstance(subject, dict) or any(subject.get(key) != identity.get(key)
                                            for key in ("pid", "creation_filetime", "guard_session_id",
                                                        "channel", "user_sid")):
        raise ValueError("desktop DLP subject is not the pinned process")
    dlp = engine.dlp
    if (not isinstance(dlp, ContentDLPEngine)
            or not isinstance(dlp.edm_index, EDMIndex) or not dlp.edm_index._digests
            or not isinstance(dlp.index, FingerprintIndex) or not dlp.index._records):
        raise ValueError("desktop four-layer registrations are missing")


def _cim_process(pid: int) -> dict:
    if os.name != "nt":
        raise RuntimeError("desktop process discovery requires Windows")
    if pid < 1:
        raise ValueError("invalid process id")
    command = (f'$p=Get-CimInstance Win32_Process -Filter "ProcessId={pid}"; '
               'if ($null -eq $p) { exit 2 }; '
               '$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid; '
               '[pscustomobject]@{ParentProcessId=$p.ParentProcessId;CommandLine=$p.CommandLine;'
               'UserSid=$o.Sid}|ConvertTo-Json -Compress')
    result = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=15, check=False,
                            env=windows_powershell_env())
    if result.returncode or not result.stdout.strip():
        raise ValueError("cannot establish desktop process ancestry")
    return json.loads(result.stdout)


def collect_desktop_identity(backend_pid: int, adapter: dict, *, expected_sid: str) -> dict:
    """Inspect an explicit VM PID; do not print or retain its command line."""
    from transpect_trace.observe.windows import identity as image_identity
    validate_desktop_adapter(adapter)
    backend_row = _cim_process(backend_pid)
    parent_pid = int(backend_row["ParentProcessId"])
    desktop_row = _cim_process(parent_pid)
    from .native import command_arguments
    backend = {**image_identity(backend_pid), "parent_pid": parent_pid,
               "user_sid": backend_row.get("UserSid"),
               "mode": desktop_mode(command_arguments(backend_row.get("CommandLine") or ""))}
    parent_image = image_identity(parent_pid)
    desktop = {**parent_image, "user_sid": desktop_row.get("UserSid"),
               "package_full_name": adapter["package_full_name"] if adapter["package_full_name"].lower()
               in parent_image["image_path"].lower() else None}
    result = validate_desktop_identity(adapter, backend, desktop, expected_sid=expected_sid)
    verify_hook_entries(Path(backend["image_path"]), adapter)
    return result


def assert_no_duplicate_image_sid(identity: dict) -> None:
    """Reject a concurrent process that could share WFP's APP_ID + SID permit.

    This is a point-in-time preflight, not a PID-bound WFP filter or a proof
    that a matching process cannot start after this check.
    """
    if os.name != "nt":
        raise RuntimeError("desktop process enumeration requires Windows")
    command = (
        '$rows=@(Get-CimInstance Win32_Process -Filter "Name=\'codex.exe\'" | '
        'ForEach-Object { $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid; '
        '[pscustomobject]@{Pid=$_.ProcessId;Image=$_.ExecutablePath;Sid=$owner.Sid} }); '
        'ConvertTo-Json -InputObject $rows -Compress'
    )
    result = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=15, check=False,
                            env=windows_powershell_env())
    if result.returncode or not result.stdout.strip():
        raise ValueError("cannot enumerate potential WFP permit peers")
    rows = json.loads(result.stdout)
    _validate_image_sid_peers(rows, identity)


def _validate_image_sid_peers(rows: object, identity: dict) -> None:
    """Pure validator for Windows WFP APP_ID and user-SID permit peers."""
    if not isinstance(rows, list):
        raise ValueError("invalid process enumeration for WFP preflight")
    image = ntpath.normcase(ntpath.normpath(identity["baseline"]["path"]))
    own_pid = identity["pid"]
    seen_self = False
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("Pid"), int):
            raise ValueError("invalid WFP peer process record")
        path = row.get("Image")
        if not isinstance(path, str) or not path:
            # Unknown executable paths may include this APP_ID; fail closed.
            raise ValueError("unknown WFP peer executable path")
        if ntpath.normcase(ntpath.normpath(path)) != image:
            continue
        if not isinstance(row.get("Sid"), str):
            raise ValueError("unknown WFP peer user SID")
        if row["Pid"] == own_pid and row["Sid"] == identity["user_sid"]:
            seen_self = True
        elif row["Sid"] == identity["user_sid"]:
            raise ValueError("another same-image, same-SID process can share WFP permit")
    if not seen_self:
        raise ValueError("pinned desktop backend disappeared during WFP preflight")


def current_user_sid() -> str:
    """The gate controller must be a different account from Codex."""
    if os.name != "nt":
        raise RuntimeError("desktop gate requires Windows")
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=10, check=False)
    rows = list(csv.reader(result.stdout.splitlines()))
    if result.returncode or len(rows) != 1 or len(rows[0]) < 2:
        raise ValueError("cannot establish gate controller SID")
    sid = rows[0][-1].strip()
    if not re.fullmatch(r"S-1-(?:\d+-)+\d+", sid):
        raise ValueError("invalid gate controller SID")
    return sid


class AttachmentGate(Protocol):
    """A separately implemented, pinned plaintext upload gate for the VM."""
    def attest(self, adapter: dict, desktop_identity: dict) -> dict: ...


def _attachment_ready(adapter: dict, identity: dict, gate: AttachmentGate, engine=None) -> bool:
    from .desktop_upload import DesktopUploadPipe
    if type(gate) is not DesktopUploadPipe:
        return False
    if engine is not None and getattr(gate, "bridge", None) is not engine:
        return False
    proof = gate.attest(adapter, identity)
    expected = adapter["coverage"]["attachment.upload"]
    return (isinstance(proof, dict) and proof.get("ready") is True
            and proof.get("process_role") == expected["process_role"]
            and proof.get("image_sha256") == expected["process_image_sha256"]
            and proof.get("desktop_creation_filetime") == identity["desktop_creation_filetime"]
            and isinstance(proof.get("pid"), int) and proof["pid"] > 0)


def verify_guard_build(dll: Path, adapter_path: Path, adapter: dict) -> str:
    """Reject a stale CLI DLL even when the target backend hash happens to match."""
    import hashlib
    manifest = json.loads((dll.parent / "build-manifest.json").read_text(encoding="utf-8"))
    with dll.open("rb") as stream:
        dll_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    with adapter_path.open("rb") as stream:
        adapter_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    if (manifest.get("adapter_sha256") != adapter_hash
            or manifest.get("target_binary_sha256") != adapter["binary_sha256"]
            or manifest.get("artifacts_sha256", {}).get(dll.name) != dll_hash):
        raise ValueError("desktop DLL build is not pinned to this validated adapter")
    return dll_hash


def verify_live_model_module(pid: int, dll: Path, expected_sha256: str) -> None:
    """A stale ready event does not prove the resident model Hook is loaded."""
    from transpect_trace.observe.windows import digest, modules
    if not _SHA256.fullmatch(expected_sha256):
        raise ValueError("missing pinned model DLL hash")
    expected_path = Path(dll).resolve()
    for row in modules(pid):
        path = Path(row["path"]).resolve()
        if path == expected_path:
            if digest(path) != expected_sha256:
                raise ValueError("loaded model DLL hash changed")
            return
    raise ValueError("pinned model DLL is no longer loaded")


class DesktopGuardSession:
    """Retain the model gate; opening egress still requires live attachment proof."""
    def __init__(self, adapter, identity, server, boundary, attachment_gate, engine,
                 *, model_dll: Path, model_dll_sha256: str):
        self.adapter, self.identity = adapter, identity
        self.server, self.boundary, self.attachment_gate, self.engine = server, boundary, attachment_gate, engine
        self.model_dll = Path(model_dll).resolve()
        self.model_dll_sha256 = model_dll_sha256
        self.leases = []
        self._lease_lock = threading.Lock()
        self._stop = threading.Event()
        self.gate_failed = threading.Event()
        self._watcher: threading.Thread | None = None
        from .desktop_upload import DesktopUploadPipe
        if type(attachment_gate) is DesktopUploadPipe:
            attachment_gate.on_failure = self._revoke_leases

    def _revoke_leases(self) -> None:
        self.gate_failed.set()
        self._close_leases()

    def _close_leases(self) -> None:
        with self._lease_lock:
            leases, self.leases = self.leases, []
        for lease in reversed(leases):
            try:
                lease.close()
            except Exception:
                # Continue closing the other permits even if one helper failed.
                pass

    def _watchdog(self) -> None:
        """Short leases are revoked if any live precondition stops holding."""
        while not self._stop.wait(0.2):
            try:
                if self.server.errors or not self.server.ready.is_set():
                    raise ValueError("model gate lost readiness")
                verify_live_model_module(self.identity["pid"], self.model_dll, self.model_dll_sha256)
                now = collect_desktop_identity(self.identity["pid"], self.adapter,
                                               expected_sid=self.identity["user_sid"])
                if (now["creation_filetime"] != self.identity["creation_filetime"]
                        or now["baseline"]["sha256"] != self.identity["baseline"]["sha256"]
                        or now["desktop_creation_filetime"] != self.identity["desktop_creation_filetime"]):
                    raise ValueError("pinned desktop process changed")
                require_desktop_dlp_engine(self.engine, now)
                assert_no_duplicate_image_sid(now)
                self.boundary.assert_default_deny()
                if not _attachment_ready(self.adapter, now, self.attachment_gate, self.engine):
                    raise ValueError("attachment gate lost readiness")
            except Exception:
                self._revoke_leases()
                return

    def permit_model_destination(self, ip: str, port: int, *, seconds: int = 300):
        # Recheck both process identity and all gates before each short lease.
        if self._stop.is_set() or self.gate_failed.is_set():
            raise ValueError("desktop gate session is no longer healthy")
        now = collect_desktop_identity(self.identity["pid"], self.adapter,
                                       expected_sid=self.identity["user_sid"])
        if (now["creation_filetime"] != self.identity["creation_filetime"]
                or now["desktop_creation_filetime"] != self.identity["desktop_creation_filetime"]):
            raise ValueError("desktop process PID was reused")
        require_desktop_dlp_engine(self.engine, now)
        assert_no_duplicate_image_sid(now)
        verify_live_model_module(now["pid"], self.model_dll, self.model_dll_sha256)
        self.boundary.assert_default_deny()
        require_desktop_ready(self.adapter, now, wfp_default_deny=True,
                              model_guard_ready=not self.server.errors and self.server.ready.is_set(),
                              attachment_guard_ready=_attachment_ready(self.adapter, now, self.attachment_gate,
                                                                       self.engine))
        lease = self.boundary.start_guarded_lease(
            pid=now["pid"], creation_filetime=now["creation_filetime"],
            image_sha256=now["baseline"]["sha256"], ip=ip, port=port, seconds=seconds)
        with self._lease_lock:
            if self._stop.is_set() or self.gate_failed.is_set():
                lease.close()
                raise ValueError("desktop gate failed during network permit")
            self.leases.append(lease)
            if self._watcher is None:
                self._watcher = threading.Thread(target=self._watchdog, name="desktop-gate-watchdog",
                                                 daemon=True)
                try:
                    self._watcher.start()
                except Exception:
                    self.leases.remove(lease)
                    lease.close()
                    raise
        return lease

    def close(self) -> None:
        self._stop.set()
        self._close_leases()
        if self._watcher is not None and self._watcher is not threading.current_thread():
            self._watcher.join(timeout=1)
        try:
            self.server.close()
        finally:
            from .desktop_upload import DesktopUploadPipe
            if type(self.attachment_gate) is DesktopUploadPipe:
                self.attachment_gate.on_failure = None
                self.attachment_gate.close()


def attach_desktop_model(adapter_path: Path, backend_pid: int, expected_sid: str,
                         dll: Path, engine, audit: Path, *, boundary, attachment_gate: AttachmentGate):
    """Attach only with a VM's persistent deny already installed.

    The current repository has no verified desktop attachment gate; callers
    cannot obtain an egress lease merely by installing a model hook.
    """
    from .native import inject, wait_ready
    from .pipe import PipeServer
    adapter_path, dll = Path(adapter_path), Path(dll)
    if current_user_sid() == expected_sid:
        raise ValueError("desktop and gate controller must use separate Windows accounts")
    adapter = load_desktop_adapter(adapter_path)
    boundary.assert_default_deny()
    identity = collect_desktop_identity(backend_pid, adapter, expected_sid=expected_sid)
    model_dll_sha256 = verify_guard_build(dll, adapter_path, adapter)
    require_desktop_dlp_engine(engine, identity)
    server = PipeServer(backend_pid, engine, Path(audit), client_sid=expected_sid)
    try:
        server.start()
        inject(backend_pid, dll, identity,
               identity_resolver=lambda pid: collect_desktop_identity(pid, adapter, expected_sid=expected_sid))
        if not wait_ready(identity):
            raise RuntimeError("desktop model hook did not attest readiness")
        require_desktop_ready(adapter, identity, wfp_default_deny=True,
                              model_guard_ready=not server.errors and server.ready.is_set(),
                              attachment_guard_ready=_attachment_ready(adapter, identity, attachment_gate, engine))
        return DesktopGuardSession(adapter, identity, server, boundary, attachment_gate, engine,
                                   model_dll=dll, model_dll_sha256=model_dll_sha256)
    except Exception:
        try:
            server.close()
        finally:
            from .desktop_upload import DesktopUploadPipe
            if type(attachment_gate) is DesktopUploadPipe:
                attachment_gate.close()
        raise
