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
        ok = (pin["schema"] == PIN_SCHEMA
              and isinstance(pin["codex_desktop_version"], str)
              and len(pin["backend"]["sha256"]) == 64
              and isinstance(pin["backend"]["version"], str)
              and set(pin["hooks"]) == set(HOOK_NAMES)
              and all(int(pin["hooks"][name]["rva"], 16) > 0
                      and len(bytes.fromhex(pin["hooks"][name]["prefix_hex"])) >= 8
                      for name in HOOK_NAMES)
              and all(isinstance(pin["abi"][key], int)
                      for key in ("http_denied_tag", "wss_success_tag", "wss_denied_tag")))
    except (KeyError, TypeError, ValueError):
        ok = False
    if not ok:
        raise ValueError(f"invalid desktop guard pin: {origin.name}")
    return pin


def load_pins(directory: Path = PIN_DIR) -> dict[str, dict]:
    """Supported backends keyed by image SHA-256."""
    pins = {}
    for path in sorted(Path(directory).glob("*.json")):
        pin = _validate_pin(json.loads(path.read_text(encoding="utf-8")), path)
        pin = {**pin, "_path": path, "_sha256": normalized_sha256(path)}
        pins[pin["backend"]["sha256"]] = pin
    if not pins:
        raise ValueError(f"no desktop guard pins in {directory}")
    return pins


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

    def sha256(self, path: str) -> str:
        stat = os.stat(path)
        key = (ntpath.normcase(path), stat.st_size, stat.st_mtime_ns)
        if key not in self._known:
            self._known[key] = file_sha256(Path(path))
        return self._known[key]


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
    last_decision: str = ""
    seen_at: float = field(default_factory=time.time)


class _DecisionLog:
    """Wraps the shared engine for one backend and reports each decision."""

    def __init__(self, engine, results: dict, on_decision):
        self._engine = engine
        self._results = results
        self._on_decision = on_decision
        self.policy = engine.policy
        self.concurrent_safe = getattr(engine, "concurrent_safe", False)

    def evaluate(self, request):
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
        try:
            engine = _DecisionLog(self.engine, self.results, self._decision)
            pipe = PipeServer(pid, engine, self.run_dir / f"native-audit-{pid}.jsonl",
                              client_sid=self.details["user_sid"])
            pipe.start()
            lease.acquire()
            resident = resident_guard_dlls(pid)
            if not resident:
                inject(pid, self.dll, identity, identity_resolver=lambda _pid: dict(identity))
                if not wait_ready(identity, 15):
                    raise RuntimeError("Native DLL did not become ready")
                status.mode = "已注入"
            elif resident == [self.dll.name]:
                lease.resume()
                if not wait_ready(identity, 2):
                    raise RuntimeError("resident Native DLL is not ready")
                status.mode = "已重连"
            else:
                controlled = False
                raise RuntimeError("进程内已有其他版本的 DLL，请重启 Codex")
            status.attach_ms = (time.monotonic() - began) * 1000
            status.state = "PROTECTED"
            self.log(f"[Codex {pid}] 已接入防护（{status.mode}，{status.attach_ms:.0f} ms）")
            k = _kernel()
            process = k.OpenProcess(0x100000, False, pid)
            try:
                while not self.stop_requested.is_set():
                    if process and k.WaitForSingleObject(process, 250) == 0:
                        status.state, status.detail = "EXITED", "Codex 后端已退出"
                        self.log(f"[Codex {pid}] 后端已退出")
                        break
                    if not process:
                        time.sleep(0.25)
            finally:
                if process:
                    k.CloseHandle(process)
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


class Supervisor:
    def __init__(self, *, state_dir: Path = STATE_DIR, pins_dir: Path = PIN_DIR,
                 poll_seconds: float = 0.25, log: Callable[[str], None] = print):
        self.state_dir, self.poll, self.log = Path(state_dir), poll_seconds, log
        self.pins = load_pins(pins_dir)
        self.hashes = ImageHashCache()
        self.backends: dict[tuple[int, int], BackendStatus] = {}
        self.controllers: dict[tuple[int, int], BackendController] = {}
        self.dlls: dict[str, Path] = {}
        self.stop = threading.Event()
        self.k = _kernel()
        self.started = datetime.now()
        self.run_dir = self.state_dir / "runs" / self.started.strftime("%Y%m%d-%H%M%S")

    def _prepare(self) -> None:
        from ..protect.codex_hook_gate import GateConfig
        from ..protect.native_collection import NativeCollectionEngine
        self.user_sid = current_user_sid()
        for backend in installed_backends():
            pin = self.pins.get(self.hashes.sha256(str(backend)))
            if pin and pin["backend"]["sha256"] not in self.dlls:
                self.dlls[pin["backend"]["sha256"]] = ensure_dll(pin, backend)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        config = GateConfig(mode="enforce", archive_directory=self.run_dir / "archive",
                            audit_file=self.run_dir / "audit.jsonl", registration_directory=None,
                            review_override_ttl_seconds=0,
                            collection_file=self.run_dir / "collection.jsonl")
        self.engine = NativeCollectionEngine(config, archive_full_body=True,
                                             shared_request_archive=True)
        self.engine.concurrent_safe = True
        self.results: dict = {}
        collect = self.engine.collector.collect

        def remember(request):
            result = collect(request)
            self.results[request.request_id] = result
            return result

        self.engine.collector.collect = remember

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
        pin = self.pins.get(sha)
        if pin is None:
            status.state = "UNSUPPORTED_VERSION"
            status.detail = f"后端 SHA-256 {sha[:12]}… 不在支持列表"
            supported = ", ".join(sorted(p["codex_desktop_version"] for p in self.pins.values()))
            self.log(f"[Codex {pid}] 版本不受支持，未接入。支持的版本：{supported}")
            return
        if sha not in self.dlls:
            self.dlls[sha] = ensure_dll(pin, Path(details["image_path"]))
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
                "supported_versions": sorted(p["codex_desktop_version"] for p in self.pins.values()),
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
            last_write = 0.0
            known: set[int] = set()
            while not self.stop.is_set() and self.k.WaitForSingleObject(stop_event, 0) != 0:
                current = {pid for pid, _parent, exe in list_processes()
                           if exe.lower() == "codex.exe"}
                # A PID is examined once while it lives; a reused PID reappears
                # only after it left the list, and is then examined again.
                for pid in sorted(current - known):
                    self._consider(pid)
                known = current
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
