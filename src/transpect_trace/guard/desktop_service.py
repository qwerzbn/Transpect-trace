"""Production desktop guard: pinned-version build, discovery, attach and reconnect.

One supervisor per Windows logon session watches for the local Codex desktop
backend (``codex.exe app-server``). A backend whose image hash matches a pin in
``deploy/desktop-guard/`` is attached as soon as it is seen: the Native DLL,
built on this machine from ``native/guard/desktop_guard.c``, is injected and a
controller thread answers its model requests through the local content policy.

Lease semantics (see desktop_guard.c): a controlled stop lets requests pass;
a lost controller makes the DLL deny. A new supervisor takes the lease of an
already-guarded backend and resumes inspection without restarting Codex.
"""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Callable

ROOT = Path(__file__).resolve().parents[3]
PIN_DIR = ROOT / "deploy" / "desktop-guard"
BUILD_DIR = ROOT / "build" / "desktop-guard"
STATE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TranspectTrace" / "desktop-guard"
PIN_SCHEMA = "transpect.desktop-guard.pin/1.0"
MANIFEST_SCHEMA = "transpect.desktop-guard.build/1.0"
STATE_SCHEMA = "transpect.desktop-guard.state/1.0"
DLL_PREFIX = "ttrace-guard-desktop-"
GUARD_SOURCE = "native/guard/desktop_guard.c"
THIRD_PARTY = "native/guard/third_party"
COMPILED = (GUARD_SOURCE,
            f"{THIRD_PARTY}/minhook/src/buffer.c",
            f"{THIRD_PARTY}/minhook/src/hook.c",
            f"{THIRD_PARTY}/minhook/src/trampoline.c",
            f"{THIRD_PARTY}/minhook/src/hde/hde64.c")
HOOK_NAMES = ("http", "wss", "drop_headers", "api_error_map")
SUPERVISOR_MUTEX = "Local\\ttrace-desktop-guard-supervisor"
SUPERVISOR_STOP = "Local\\ttrace-desktop-guard-stop"


# --------------------------------------------------------------------------
# Version pins and local build
# --------------------------------------------------------------------------

def normalized_sha256(path: Path) -> str:
    """Line-ending independent digest, so any checkout yields the same value."""
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def file_sha256(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _validate_pin(pin: dict, origin: Path) -> dict:
    try:
        code = pin["backend"].get("code_sha256")
        ok = (pin["schema"] == PIN_SCHEMA
              and isinstance(pin["codex_desktop_version"], str)
              and len(pin["backend"]["sha256"]) == 64
              and (code is None or (isinstance(code, str) and len(code) == 64))
              and isinstance(pin["backend"]["version"], str)
              and set(pin["hooks"]) == set(HOOK_NAMES)
              and all(int(pin["hooks"][name]["rva"], 16) > 0
                      and len(bytes.fromhex(pin["hooks"][name]["prefix_hex"])) >= 8
                      for name in HOOK_NAMES)
              and all(isinstance(pin["abi"][key], int)
                      for key in ("http_denied_tag", "wss_success_tag", "wss_denied_tag"))
              and ("api_error_denied_tag" not in pin["abi"]
                   or (type(pin["abi"]["api_error_denied_tag"]) is int
                       and 0 < pin["abi"]["api_error_denied_tag"] <= 255)))
    except (KeyError, TypeError, ValueError, AttributeError):
        ok = False
    if not ok:
        raise ValueError(f"invalid desktop guard pin: {origin.name}")
    return pin


def load_pins(directory: Path = PIN_DIR, local_directory: Path | None = None) -> dict[str, dict]:
    """Supported backends keyed by image SHA-256.

    `directory` holds the validated pins shipped with the repository;
    `local_directory` holds pins this machine derived automatically.
    """
    pins = {}
    for folder in (directory, local_directory):
        if folder is None or not Path(folder).is_dir():
            continue
        for path in sorted(Path(folder).glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if (isinstance(value, dict)
                    and (value.get("production_ready") is False
                         or value.get("status") == "candidate_lab_only")):
                raise ValueError(f"candidate pin cannot be loaded by the desktop guard: {path.name}")
            pin = _validate_pin(value, path)
            pin = {**pin, "_path": path, "_sha256": normalized_sha256(path)}
            pins.setdefault(pin["backend"]["sha256"], pin)
    if not pins:
        raise ValueError(f"no desktop guard pins in {directory}")
    return pins


def code_sha256(path: Path) -> str:
    """Digest of a PE32+ image without its signature and checksum.

    Excludes the optional-header CheckSum, the certificate-table directory
    entry and the certificate table itself, as the Authenticode image hash
    does. Two files with the same value contain the same code and data; they
    differ only in how they were signed.
    """
    with Path(path).open("rb") as stream:
        header = stream.read(4096)
        pe = int.from_bytes(header[0x3C:0x40], "little")
        if header[pe:pe + 4] != b"PE\0\0" or int.from_bytes(header[pe + 24:pe + 26], "little") != 0x20B:
            raise ValueError("not a PE32+ image")
        optional = pe + 24
        checksum, certificates = optional + 64, optional + 112 + 4 * 8
        cert_offset = int.from_bytes(header[certificates:certificates + 4], "little")
        cert_size = int.from_bytes(header[certificates + 4:certificates + 8], "little")
        size = os.fstat(stream.fileno()).st_size
        skipped = sorted([(checksum, 4), (certificates, 8)]
                         + ([(cert_offset, cert_size)] if cert_offset else []))
        digest, position = hashlib.sha256(), 0
        for start, length in [*skipped, (size, 0)]:
            stream.seek(position)
            remaining = start - position
            while remaining > 0:
                chunk = stream.read(min(remaining, 1 << 20))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            position = max(position, start + length)
        return digest.hexdigest()


def derive_pin(base: dict, backend_sha256: str, backend_code_sha256: str, version: str,
               directory: Path, package_full_name: str | None = None) -> dict:
    """Write the pin of a re-signed build whose code equals a validated one."""
    if base["backend"].get("code_sha256") != backend_code_sha256:
        raise ValueError("code digest differs from the validated build")
    value = {"schema": PIN_SCHEMA, "codex_desktop_version": version,
             "package_full_name": package_full_name,
             "backend": {"version": base["backend"]["version"], "sha256": backend_sha256,
                         "code_sha256": backend_code_sha256},
             "hooks": base["hooks"], "abi": base["abi"],
             "derived_from": {"codex_desktop_version": base["codex_desktop_version"],
                              "backend_sha256": base["backend"]["sha256"],
                              "method": "identical_code_resigned",
                              "derived_at": datetime.now().isoformat(timespec="seconds")}}
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{version}-{backend_sha256[:12]}.json"
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {**_validate_pin(value, path), "_path": path, "_sha256": normalized_sha256(path)}


_PACKAGES_KEY = (r"Software\Classes\Local Settings\Software\Microsoft\Windows"
                 r"\CurrentVersion\AppModel\Repository\Packages")


def installed_packages() -> dict[str, Path]:
    """Installed Codex desktop packages: full name -> package root (registry, ~10 ms)."""
    import winreg
    found = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PACKAGES_KEY) as key:
            for index in range(winreg.QueryInfoKey(key)[0]):
                name = winreg.EnumKey(key, index)
                if not name.startswith("OpenAI.Codex_"):
                    continue
                with winreg.OpenKey(key, name) as package:
                    try:
                        found[name] = Path(winreg.QueryValueEx(package, "PackageRootFolder")[0])
                    except OSError:
                        pass
    except OSError:
        pass
    return found


def package_version(full_name: str) -> str:
    """'OpenAI.Codex_26.1103.4239.0_x64__…' -> '26.1103.4239.0'."""
    parts = full_name.split("_")
    return parts[1] if len(parts) > 1 else full_name


def pe_read(path: Path, rva: int, size: int) -> bytes:
    """Read bytes at an RVA of a PE32+ file without loading it."""
    with Path(path).open("rb") as stream:
        header = stream.read(4096)
        pe = int.from_bytes(header[0x3C:0x40], "little")
        if header[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE image")
        sections = int.from_bytes(header[pe + 6:pe + 8], "little")
        optional = int.from_bytes(header[pe + 20:pe + 22], "little")
        for index in range(sections):
            entry = pe + 24 + optional + index * 40
            vsize, base, raw_size, raw = (int.from_bytes(header[entry + 8 + 4 * i:entry + 12 + 4 * i],
                                                         "little") for i in range(4))
            if base <= rva and rva + size <= base + min(vsize, raw_size):
                stream.seek(raw + rva - base)
                return stream.read(size)
    raise ValueError(f"RVA 0x{rva:x} is outside the image sections")


def check_backend(pin: dict, backend: Path, image_sha256: str | None = None) -> None:
    """Exact backend hash plus every hook entry prefix."""
    if (image_sha256 or file_sha256(backend)) != pin["backend"]["sha256"]:
        raise ValueError("backend image does not match the pinned Codex version")
    for name in HOOK_NAMES:
        hook = pin["hooks"][name]
        prefix = bytes.fromhex(hook["prefix_hex"])
        if pe_read(backend, int(hook["rva"], 16), len(prefix)) != prefix:
            raise ValueError(f"{name} hook entry bytes differ from the pin")


def compile_defines(pin: dict) -> list[str]:
    def prefix(name: str, hook: str) -> str:
        data = bytes.fromhex(pin["hooks"][hook]["prefix_hex"])
        return f"-D{name}={{" + ",".join(f"0x{byte:02x}" for byte in data) + "}"

    hooks, abi = pin["hooks"], pin["abi"]
    return ["-DJSMN_PARENT_LINKS", "-DTTRACE_FAIL_STOP_DENY=0",
            "-DTTRACE_GRACEFUL_LEASE=1", "-DTTRACE_NONRETRY_DENY_LAB=1",
            "-DHTTP_EMPTY_ERROR_STRING=0",
            f"-DHTTP_DENIED_TAG={abi['http_denied_tag']}",
            f"-DWSS_SUCCESS_TAG=0x{abi['wss_success_tag']:x}",
            f"-DWSS_DENIED_TAG={abi['wss_denied_tag']}",
            f"-DAPI_ERROR_DENIED_TAG={abi.get('api_error_denied_tag', 25)}",
            f"-DHTTP_RVA={hooks['http']['rva']}", f"-DWSS_RVA={hooks['wss']['rva']}",
            f"-DDROP_HEADERS_RVA={hooks['drop_headers']['rva']}",
            f"-DAPI_ERROR_MAP_RVA={hooks['api_error_map']['rva']}",
            prefix("HTTP_ENTRY_PREFIX_BYTES", "http"),
            prefix("WSS_ENTRY_PREFIX_BYTES", "wss"),
            prefix("DROP_HEADERS_PREFIX_BYTES", "drop_headers"),
            prefix("API_ERROR_MAP_PREFIX_BYTES", "api_error_map"),
            f'-DTTRACE_EXPECTED_HASH="{pin["backend"]["sha256"]}"']


def native_digest(root: Path = ROOT) -> dict[str, str]:
    """Every file the DLL is compiled from, including headers."""
    files = [root / GUARD_SOURCE, *sorted(
        path for path in (root / THIRD_PARTY).rglob("*")
        if path.is_file() and path.suffix in (".c", ".h"))]
    return {path.relative_to(root).as_posix(): normalized_sha256(path) for path in files}


def build_key(pin: dict, digest: dict[str, str]) -> str:
    material = json.dumps({"pin": pin["_sha256"], "sources": digest,
                           "defines": compile_defines(pin)}, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()[:12]


def _zig(arguments: list[str], cwd: Path) -> None:
    subprocess.run([sys.executable, "-m", "ziglang", "cc", *arguments], check=True, cwd=cwd)


def ensure_dll(pin: dict, backend: Path | None = None, *, root: Path = ROOT,
               compiler: Callable[[list[str], Path], None] = _zig) -> Path:
    """Build the DLL for this pin and source tree once; reuse it afterwards.

    The file name carries a digest of the pin, sources and defines, so a
    rebuild never overwrites a DLL that a running Codex still has mapped.
    """
    digest = native_digest(root)
    key = build_key(pin, digest)
    out = root / "build" / "desktop-guard" / pin["codex_desktop_version"]
    dll = out / f"{DLL_PREFIX}{key}.dll"
    manifest_path = dll.with_suffix(".json")
    if dll.is_file() and manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("dll_sha256") == file_sha256(dll) and manifest.get("sources") == digest:
            return dll
    if backend is not None:
        check_backend(pin, backend)
    out.mkdir(parents=True, exist_ok=True)
    temporary = out / f"build-{os.getpid()}-{key}.dll"
    try:
        compiler(["-target", "x86_64-windows-gnu", "-O2", "-shared",
                  *compile_defines(pin), *COMPILED, "-lbcrypt", "-o", str(temporary)], root)
        os.replace(temporary, dll)
    finally:
        for leftover in (*out.glob(f"build-{os.getpid()}-{key}.*"), *out.glob("*.lib")):
            leftover.unlink(missing_ok=True)
    manifest = {"schema": MANIFEST_SCHEMA, "codex_desktop_version": pin["codex_desktop_version"],
                "pin": pin["_path"].relative_to(root).as_posix() if pin["_path"].is_relative_to(root)
                else pin["_path"].name,
                "pin_sha256": pin["_sha256"], "backend_sha256": pin["backend"]["sha256"],
                "sources": digest, "dll": dll.name, "dll_sha256": file_sha256(dll)}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dll


def installed_backends() -> list[Path]:
    """Codex desktop backends present on disk, for building before Codex starts."""
    base = Path(os.environ.get("LOCALAPPDATA", "")) / "OpenAI" / "Codex" / "bin"
    return sorted(base.glob("*/codex.exe")) if base.is_dir() else []


# --------------------------------------------------------------------------
# Fast process discovery (no PowerShell, no child processes)
# --------------------------------------------------------------------------

class _ProcessEntry(c.Structure):
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("pid", w.DWORD),
                ("heap", c.c_size_t), ("module", w.DWORD), ("threads", w.DWORD),
                ("parent", w.DWORD), ("priority", c.c_long), ("flags", w.DWORD),
                ("exe", w.WCHAR * 260)]


class _UnicodeString(c.Structure):
    _fields_ = [("length", w.USHORT), ("maximum", w.USHORT), ("buffer", c.c_void_p)]


def _kernel():
    k = c.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    k.CreateToolhelp32Snapshot.restype = w.HANDLE
    k.Process32FirstW.argtypes = k.Process32NextW.argtypes = [w.HANDLE, c.POINTER(_ProcessEntry)]
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k.OpenProcess.restype = w.HANDLE
    k.CloseHandle.argtypes = [w.HANDLE]
    k.GetProcessTimes.argtypes = [w.HANDLE, *(c.POINTER(w.FILETIME),) * 4]
    k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
    k.GetCurrentProcess.restype = w.HANDLE
    k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    k.WaitForSingleObject.restype = w.DWORD
    k.CreateMutexW.argtypes = [c.c_void_p, w.BOOL, w.LPCWSTR]
    k.CreateMutexW.restype = w.HANDLE
    k.ReleaseMutex.argtypes = [w.HANDLE]
    k.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
    k.CreateEventW.restype = w.HANDLE
    k.OpenEventW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
    k.OpenEventW.restype = w.HANDLE
    k.SetEvent.argtypes = k.ResetEvent.argtypes = [w.HANDLE]
    k.LocalFree.argtypes = [c.c_void_p]
    return k


def list_processes() -> list[tuple[int, int, str]]:
    """(pid, parent pid, executable name) for every process."""
    k = _kernel()
    snapshot = k.CreateToolhelp32Snapshot(0x2, 0)
    if snapshot in (None, w.HANDLE(-1).value):
        raise c.WinError(c.get_last_error())
    rows = []
    try:
        entry = _ProcessEntry()
        entry.size = c.sizeof(entry)
        ok = k.Process32FirstW(snapshot, c.byref(entry))
        while ok:
            rows.append((entry.pid, entry.parent, entry.exe))
            ok = k.Process32NextW(snapshot, c.byref(entry))
    finally:
        k.CloseHandle(snapshot)
    return rows


def _token_sid(k, process) -> str | None:
    advapi = c.WinDLL("advapi32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    advapi.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD,
                                           c.POINTER(w.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(c.c_void_p)]
    token = w.HANDLE()
    if not advapi.OpenProcessToken(process, 0x8, c.byref(token)):
        return None
    try:
        needed = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, c.byref(needed))
        buffer = c.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, c.byref(needed)):
            return None
        sid = c.c_void_p.from_buffer(buffer).value
        text = c.c_void_p()
        if not advapi.ConvertSidToStringSidW(sid, c.byref(text)):
            return None
        try:
            return c.wstring_at(text.value)
        finally:
            k.LocalFree(text)
    finally:
        k.CloseHandle(token)


def current_user_sid() -> str:
    k = _kernel()
    sid = _token_sid(k, k.GetCurrentProcess())
    if not sid:
        raise OSError("cannot read the current user SID")
    return sid


def process_details(pid: int) -> dict | None:
    """Creation time, image, command line and user of a process, or None."""
    k = _kernel()
    handle = k.OpenProcess(0x1000 | 0x100000, False, pid)  # QUERY_LIMITED | SYNCHRONIZE
    if not handle:
        return None
    try:
        times = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle, *(c.byref(item) for item in times)):
            return None
        image = c.create_unicode_buffer(32768)
        size = w.DWORD(len(image))
        if not k.QueryFullProcessImageNameW(handle, 0, image, c.byref(size)):
            return None
        ntdll = c.WinDLL("ntdll")
        ntdll.NtQueryInformationProcess.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.ULONG,
                                                    c.POINTER(w.ULONG)]
        ntdll.NtQueryInformationProcess.restype = c.c_long
        needed = w.ULONG()
        ntdll.NtQueryInformationProcess(handle, 60, None, 0, c.byref(needed))
        command = ""
        if needed.value:
            buffer = c.create_string_buffer(needed.value)
            if ntdll.NtQueryInformationProcess(handle, 60, buffer, needed, c.byref(needed)) == 0:
                text = _UnicodeString.from_buffer(buffer)
                command = c.wstring_at(text.buffer, text.length // 2) if text.buffer else ""
        return {"pid": pid,
                "creation_filetime": times[0].dwLowDateTime | (times[0].dwHighDateTime << 32),
                "image_path": image.value, "command_line": command,
                "user_sid": _token_sid(k, handle)}
    finally:
        k.CloseHandle(handle)


def is_local_app_server(command_line: str) -> bool:
    from .desktop import desktop_mode
    from .native import command_arguments
    try:
        return desktop_mode(command_arguments(command_line)) == "app-server"
    except ValueError:
        return False


class ImageHashCache:
    """Hash each backend image once per (path, size, mtime)."""

    def __init__(self):
        self._known: dict[tuple, str] = {}

    def _cached(self, kind: str, path: str, compute) -> str:
        stat = os.stat(path)
        key = (kind, ntpath.normcase(str(path)), stat.st_size, stat.st_mtime_ns)
        if key not in self._known:
            self._known[key] = compute(Path(path))
        return self._known[key]

    def sha256(self, path: str) -> str:
        return self._cached("file", path, file_sha256)

    def code_sha256(self, path: str) -> str:
        return self._cached("code", path, code_sha256)


def resident_guard_dlls(pid: int) -> list[str]:
    from ..observe.windows import modules
    return [ntpath.basename(row["path"]) for row in modules(pid)
            if ntpath.basename(row["path"]).lower().startswith("ttrace-guard")
            and row["path"].lower().endswith(".dll")]


# --------------------------------------------------------------------------
# Controller: one thread per backend generation
# --------------------------------------------------------------------------

class Lease:
    """The Native lease of one backend generation, owned by one thread."""

    def __init__(self, pid: int, creation_filetime: int):
        self.k = _kernel()
        session = f"{pid}-{creation_filetime}"
        self.name = f"Local\\ttrace-guard-lease-{session}"
        self.stop_name = f"Local\\ttrace-guard-stop-{session}"
        self.handle = None
        self.owner = None

    def acquire(self, timeout_ms: int = 3000) -> None:
        handle = self.k.CreateMutexW(None, False, self.name)
        if not handle:
            raise c.WinError(c.get_last_error())
        outcome = self.k.WaitForSingleObject(handle, timeout_ms)
        if outcome not in (0, 0x80):  # WAIT_OBJECT_0, WAIT_ABANDONED
            self.k.CloseHandle(handle)
            raise RuntimeError("another controller holds this backend's lease")
        self.handle, self.owner = handle, threading.get_ident()

    def _stop_event(self, set_it: bool) -> bool:
        event = self.k.OpenEventW(0x0002 | 0x100000, False, self.stop_name)
        if not event:
            return False
        try:
            return bool((self.k.SetEvent if set_it else self.k.ResetEvent)(event))
        finally:
            self.k.CloseHandle(event)

    def resume(self) -> bool:
        """Reconnect: clear a previous controlled stop."""
        return self._stop_event(False)

    def release(self, *, controlled: bool) -> None:
        """Controlled: requests pass afterwards. Otherwise the DLL denies."""
        if self.handle is None:
            return
        if threading.get_ident() != self.owner:
            raise RuntimeError("the lease must be released by its owner thread")
        if controlled:
            self._stop_event(True)
        self.k.ReleaseMutex(self.handle)
        self.k.CloseHandle(self.handle)
        self.handle = None


@dataclass
class BackendStatus:
    pid: int
    creation_filetime: int
    state: str = "STARTING"
    detail: str = ""
    mode: str = ""
    attach_ms: float | None = None
    requests: int = 0
    allowed: int = 0
    denied: int = 0
    tools_allowed: int = 0
    tools_denied: int = 0
    last_decision: str = ""
    seen_at: float = field(default_factory=time.time)


class _DecisionLog:
    """Wraps the shared engine for one backend and reports each decision."""

    def __init__(self, engine, results: dict, on_decision, on_tool=None):
        self._engine = engine
        self._results = results
        self._on_decision = on_decision
        self._on_tool = on_tool
        self.policy = engine.policy
        self.concurrent_safe = getattr(engine, "concurrent_safe", False)

    def _tool_exec(self, request):
        """Decide a process creation; any failure denies it."""
        from ..protect import tool_exec
        from .policy import GuardDecision
        try:
            row = tool_exec.decide(self._engine.gate, request.payload_utf8)
        except Exception as error:
            row = {"schema": tool_exec.SCHEMA, "decision": "deny",
                   "reason": f"TOOL_EXEC_CHECK_FAILED_{type(error).__name__}", "rules": [],
                   "application": "", "sensitive_files": []}
        allowed = row["decision"] == "allow"
        row = {**row, "kind": request.kind, "request_id": request.request_id,
               "guard_session_id": request.guard_session_id}
        if self._on_tool:
            self._on_tool(row)
        decision = GuardDecision(request_id=request.request_id,
                                 decision="allow" if allowed else "deny",
                                 action="none" if allowed else "block_request",
                                 reason=row["reason"][:1023], policy_version=self.policy.version)
        return decision, row

    def evaluate(self, request):
        if request.kind == "tool.exec":
            return self._tool_exec(request)
        began = time.perf_counter()
        decision, row = self._engine.evaluate(request)
        if request.kind == "model.request":
            result = self._results.pop(request.request_id, None)
            rules = sorted({rule for record in (result.records if result else ())
                            if record.get("actionable_decision") not in (None, "ALLOW")
                            for rule in record.get("matched_rule_ids") or ()})
            self._on_decision(request, decision, rules,
                              (time.perf_counter() - began) * 1000)
        return decision, row


class _Exited(Exception):
    """The backend exited before or while it was being attached."""


class _Incompatible(Exception):
    """Another guard DLL build is already resident in the backend."""


class BackendController(threading.Thread):
    def __init__(self, details: dict, dll: Path, engine, results: dict, run_dir: Path,
                 status: BackendStatus, log: Callable[[str], None]):
        super().__init__(name=f"guard-{details['pid']}", daemon=True)
        self.details, self.dll, self.engine, self.results = details, dll, engine, results
        self.run_dir, self.status, self.log = run_dir, status, log
        self.stop_requested = threading.Event()
        self.finished = threading.Event()

    def _decision(self, request, decision, rules, elapsed_ms):
        status = self.status
        status.requests += 1
        allowed = decision.decision == "allow"
        status.allowed += allowed
        status.denied += not allowed
        status.last_decision = datetime.now().strftime("%H:%M:%S")
        kb = len(request.payload_utf8.encode("utf-8", "surrogatepass")) / 1024
        what = "放行" if allowed else "拒绝"
        reason = "" if allowed else "  " + (", ".join(rules) or decision.reason)
        self.log(f"[Codex {status.pid}] {what}  {request.protocol} {kb:.0f} KB  "
                 f"{elapsed_ms:.0f} ms{reason}")

    def _tool(self, row: dict) -> None:
        status = self.status
        allowed = row["decision"] == "allow"
        status.tools_allowed += allowed
        status.tools_denied += not allowed
        status.last_decision = datetime.now().strftime("%H:%M:%S")
        if allowed:
            return  # process launches are frequent; only denials are printed
        files = f"  文件：{', '.join(row['sensitive_files'])}" if row.get("sensitive_files") else ""
        rules = ", ".join(row.get("rules") or ()) or row["reason"]
        self.log(f"[Codex {status.pid}] 拒绝执行  {row.get('application') or '?'}  "
                 f"{row['reason']}  {rules}{files}")

    def run(self) -> None:
        from .native import inject, wait_ready
        from .pipe import PipeServer
        pid, birth = self.details["pid"], self.details["creation_filetime"]
        status, began = self.status, time.monotonic()
        identity = {"pid": pid, "creation_filetime": birth,
                    "guard_session_id": f"{pid}-{birth}",
                    "baseline": {"path": self.details["image_path"]}}
        lease = Lease(pid, birth)
        pipe = None
        controlled = True
        k = _kernel()
        process = k.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE

        def alive() -> bool:
            return bool(process) and k.WaitForSingleObject(process, 0) == 258  # WAIT_TIMEOUT

        try:
            if not alive():
                raise _Exited()
            engine = _DecisionLog(self.engine, self.results, self._decision, self._tool)
            pipe = PipeServer(pid, engine, self.run_dir / f"native-audit-{pid}.jsonl",
                              client_sid=self.details["user_sid"])
            pipe.desktop_history_wire = True
            pipe.start()
            lease.acquire()
            # A backend that is still starting or already exiting can refuse
            # access for a moment; retry while it lives. A DLL that loaded but
            # was not ready yet is then taken over instead of injected twice.
            for attempt in range(3):
                try:
                    resident = resident_guard_dlls(pid)
                    if not resident:
                        inject(pid, self.dll, identity,
                               identity_resolver=lambda _pid: dict(identity))
                        if not wait_ready(identity, 15):
                            raise RuntimeError("Native DLL did not become ready")
                        status.mode = "已注入"
                    elif resident == [self.dll.name]:
                        lease.resume()
                        if not wait_ready(identity, 2):
                            raise RuntimeError("resident Native DLL is not ready")
                        status.mode = "已重连"
                    else:
                        raise _Incompatible()
                    break
                except _Incompatible:
                    raise
                except Exception:
                    if not alive():
                        raise _Exited()
                    if attempt == 2:
                        raise
                    time.sleep(0.5)
            status.attach_ms = (time.monotonic() - began) * 1000
            status.state = "PROTECTED"
            self.log(f"[Codex {pid}] 已接入防护（{status.mode}，{status.attach_ms:.0f} ms）")
            while not self.stop_requested.is_set():
                if k.WaitForSingleObject(process, 250) == 0:
                    status.state, status.detail = "EXITED", "Codex 后端已退出"
                    self.log(f"[Codex {pid}] 后端已退出")
                    break
        except _Exited:
            status.state, status.detail = "EXITED", "后端在接入完成前已退出"
            self.log(f"[Codex {pid}] 后端在接入完成前已退出，无需防护")
        except _Incompatible:
            controlled = False
            status.state = "FAILED"
            status.detail = "进程内已有其他版本的 DLL，请重启 Codex"
            self.log(f"[Codex {pid}] 接入失败：{status.detail}")
        except Exception as error:  # report and leave the DLL fail-closed
            status.state, status.detail = "FAILED", f"{type(error).__name__}: {error}"
            self.log(f"[Codex {pid}] 接入失败：{status.detail}")
            controlled = False
        finally:
            if status.state == "PROTECTED":
                status.state, status.detail = "STOPPED", "防护已停止，请求直接放行"
            try:
                lease.release(controlled=controlled and status.state != "FAILED")
            finally:
                if process:
                    k.CloseHandle(process)
                if pipe is not None:
                    pipe.close()
                self.finished.set()


# --------------------------------------------------------------------------
# Supervisor
# --------------------------------------------------------------------------

def _write_state(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for attempt in range(40):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 39:
                raise
            time.sleep(0.05)


def create_desktop_engine(config):
    from ..protect.native_collection import NativeCollectionEngine
    engine = NativeCollectionEngine(config, archive_full_body=True, shared_request_archive=True,
                                    scrub_codex_denied_history=True)
    engine.concurrent_safe = True
    return engine


class Supervisor:
    def __init__(self, *, state_dir: Path = STATE_DIR, pins_dir: Path = PIN_DIR,
                 poll_seconds: float = 0.25, log: Callable[[str], None] = print):
        self.state_dir, self.poll, self.log = Path(state_dir), poll_seconds, log
        self.local_pins_dir = self.state_dir / "pins"
        self.pins = load_pins(pins_dir, self.local_pins_dir)
        self.hashes = ImageHashCache()
        self.adapt_lock = threading.RLock()
        self.seen_packages: set[str] = set()
        self.backends: dict[tuple[int, int], BackendStatus] = {}
        self.controllers: dict[tuple[int, int], BackendController] = {}
        self.dlls: dict[str, Path] = {}
        self.stop = threading.Event()
        self.k = _kernel()
        self.started = datetime.now()
        self.run_dir = self.state_dir / "runs" / self.started.strftime("%Y%m%d-%H%M%S")

    def _prepare(self) -> None:
        from ..protect.codex_hook_gate import GateConfig
        self.user_sid = current_user_sid()
        for backend in installed_backends():
            try:
                self.adapt(backend)
            except Exception as error:  # a broken leftover must not stop the guard
                self.log(f"后端 {backend} 适配失败：{type(error).__name__}: {error}")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        config = GateConfig(mode="enforce", archive_directory=self.run_dir / "archive",
                            audit_file=self.run_dir / "audit.jsonl", registration_directory=None,
                            review_override_ttl_seconds=0,
                            collection_file=self.run_dir / "collection.jsonl")
        self.engine = create_desktop_engine(config)
        self.results: dict = {}
        collect = self.engine.collector.collect

        def remember(request):
            result = collect(request)
            self.results[request.request_id] = result
            return result

        self.engine.collector.collect = remember

    def _package_of(self, sha: str) -> str | None:
        """Full name of the installed package whose backend has this hash."""
        for name, root in installed_packages().items():
            image = root / "app" / "resources" / "codex.exe"
            try:
                if image.is_file() and self.hashes.sha256(str(image)) == sha:
                    return name
            except OSError:
                continue
        return None

    def adapt(self, image: Path, package_full_name: str | None = None) -> dict | None:
        """Return the pin for this backend and make sure its DLL is built.

        Tier 1 of automatic adaptation: a backend whose code digest equals a
        validated build is a re-signed copy of it, so that build's hooks and
        ABI apply unchanged and a local pin is derived for its file hash.
        Returns None when the code differs from every validated build.
        """
        with self.adapt_lock:
            sha = self.hashes.sha256(str(image))
            pin = self.pins.get(sha)
            if pin is None:
                code = self.hashes.code_sha256(str(image))
                base = next((p for p in self.pins.values()
                             if p["backend"].get("code_sha256") == code), None)
                if base is None:
                    return None
                package_full_name = package_full_name or self._package_of(sha)
                version = (package_version(package_full_name) if package_full_name
                           else f"{base['codex_desktop_version']}+{sha[:8]}")
                pin = derive_pin(base, sha, code, version, self.local_pins_dir,
                                 package_full_name)
                self.pins[sha] = pin
                self.log(f"检测到 Codex {version}：代码与已验证的 "
                         f"{base['codex_desktop_version']} 完全相同（仅签名不同），已自动适配")
            if sha not in self.dlls:
                self.dlls[sha] = ensure_dll(pin, Path(image))
                self._backup(pin, Path(image))
            return pin

    def _backup(self, pin: dict, image: Path, keep: int = 3) -> None:
        """Keep a copy of each supported backend for later adaptation work.

        Codex deletes the previous backend the moment it starts an update, so
        the last few validated builds are kept here (newest `keep` versions).
        """
        import shutil
        root = self.state_dir / "backends"
        target = root / f"{pin['codex_desktop_version']}-{pin['backend']['sha256'][:12]}"
        try:
            if not (target / "codex.exe").is_file():
                target.mkdir(parents=True, exist_ok=True)
                shutil.copy2(image, target / "codex.exe")
                (target / "pin.json").write_text(json.dumps(
                    {k: v for k, v in pin.items() if not k.startswith("_")},
                    ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            kept = sorted((path for path in root.iterdir() if path.is_dir()),
                          key=lambda path: path.stat().st_mtime, reverse=True)
            for old in kept[keep:]:
                shutil.rmtree(old, ignore_errors=True)
        except OSError as error:
            self.log(f"后端备份失败（不影响防护）：{error}")

    def _preadapt(self, name: str, root: Path) -> None:
        """Adapt a newly installed package before Codex starts its backend."""
        image = root / "app" / "resources" / "codex.exe"
        try:
            if not image.is_file():
                return
            known = self.hashes.sha256(str(image)) in self.pins
            pin = self.adapt(image, name)
        except Exception as error:
            self.log(f"安装包 {package_version(name)} 适配失败：{type(error).__name__}: {error}")
            return
        if pin is None:
            self.log(f"安装包 {package_version(name)} 的代码与已验证版本不同，无法自动适配；"
                     f"该版本启动后不会接入防护")
        elif not known:
            self.log(f"安装包 {package_version(name)} 已预先完成适配，Codex 启动后即可接入")

    def _watch_packages(self) -> None:
        for name, root in installed_packages().items():
            if name not in self.seen_packages:
                self.seen_packages.add(name)
                threading.Thread(target=self._preadapt, args=(name, root), daemon=True,
                                 name=f"preadapt-{name}").start()

    def _consider(self, pid: int) -> None:
        details = process_details(pid)
        if (not details or details["user_sid"] != self.user_sid
                or not is_local_app_server(details["command_line"])):
            return
        key = (pid, details["creation_filetime"])
        if key in self.backends:
            return
        status = BackendStatus(pid, details["creation_filetime"])
        self.backends[key] = status
        try:
            sha = self.hashes.sha256(details["image_path"])
        except OSError as error:
            status.state, status.detail = "FAILED", f"cannot hash backend: {error}"
            return
        try:
            pin = self.adapt(Path(details["image_path"]))
        except Exception as error:
            status.state, status.detail = "FAILED", f"适配失败：{type(error).__name__}: {error}"
            self.log(f"[Codex {pid}] {status.detail}")
            return
        if pin is None:
            status.state = "UNSUPPORTED_VERSION"
            status.detail = f"后端 SHA-256 {sha[:12]}… 的代码与已验证版本不同"
            supported = ", ".join(sorted({p["codex_desktop_version"] for p in self.pins.values()}))
            self.log(f"[Codex {pid}] 告警：版本不受支持，未接入，该 Codex 的请求目前不受保护。"
                     f"代码与已验证版本不同，需要人工适配；请暂缓在其他电脑上推送此版本。"
                     f"已支持：{supported}")
            return
        controller = BackendController(details, self.dlls[sha], self.engine, self.results,
                                       self.run_dir, status, self.log)
        self.controllers[key] = controller
        self.log(f"[Codex {pid}] 发现 Codex {pin['codex_desktop_version']}，正在接入…")
        controller.start()

    def state(self) -> dict:
        return {"schema": STATE_SCHEMA, "supervisor_pid": os.getpid(),
                "started_at": self.started.isoformat(timespec="seconds"),
                "updated_at": datetime.now().isoformat(timespec="seconds"),
                "run_dir": str(self.run_dir),
                "supported_versions": sorted({p["codex_desktop_version"]
                                              for p in self.pins.values()}),
                "adapted_versions": sorted({p["codex_desktop_version"] for p in self.pins.values()
                                            if "derived_from" in p}),
                "backends": [vars(status) for status in self.backends.values()]}

    def run(self) -> None:
        guard = self.k.CreateMutexW(None, True, SUPERVISOR_MUTEX)
        if not guard:
            raise c.WinError(c.get_last_error())
        if c.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            self.k.CloseHandle(guard)
            raise RuntimeError("防护已在运行（./start.sh status 查看）")
        stop_event = self.k.CreateEventW(None, True, False, SUPERVISOR_STOP)
        self.k.ResetEvent(stop_event)
        state_file = self.state_dir / "state.json"
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            self._prepare()
            self.log(f"防护已启动，正在监视 Codex。记录目录：{self.run_dir}")
            last_write = last_packages = 0.0
            known: set[int] = set()
            while not self.stop.is_set() and self.k.WaitForSingleObject(stop_event, 0) != 0:
                current = {pid for pid, _parent, exe in list_processes()
                           if exe.lower() == "codex.exe"}
                # A PID is examined once while it lives; a reused PID reappears
                # only after it left the list, and is then examined again.
                for pid in sorted(current - known):
                    self._consider(pid)
                for (pid, _birth), status in self.backends.items():
                    # Controllers report their own exit; a backend that was
                    # never attached is marked here once its process is gone.
                    if pid not in current and status.state in (
                            "FAILED", "UNSUPPORTED_VERSION", "STARTING"):
                        status.detail = f"进程已退出（{status.detail or status.state}）"
                        status.state = "EXITED"
                known = current
                if time.monotonic() - last_packages >= 2:
                    self._watch_packages()
                    last_packages = time.monotonic()
                if time.monotonic() - last_write >= 1:
                    _write_state(state_file, self.state())
                    last_write = time.monotonic()
                time.sleep(self.poll)
        finally:
            for controller in self.controllers.values():
                controller.stop_requested.set()
            for controller in self.controllers.values():
                controller.finished.wait(5)
            if self.state_dir.is_dir():
                final = self.state()
                final["stopped_at"] = datetime.now().isoformat(timespec="seconds")
                _write_state(state_file, final)
            self.log("防护已停止，已接入的 Codex 请求恢复直接发送")
            self.k.CloseHandle(stop_event)
            self.k.ReleaseMutex(guard)
            self.k.CloseHandle(guard)


def request_stop() -> bool:
    """Ask a running supervisor of this logon session to stop."""
    k = _kernel()
    event = k.OpenEventW(0x0002, False, SUPERVISOR_STOP)
    if not event:
        return False
    try:
        return bool(k.SetEvent(event))
    finally:
        k.CloseHandle(event)


def read_state(state_dir: Path = STATE_DIR) -> dict | None:
    path = Path(state_dir) / "state.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
