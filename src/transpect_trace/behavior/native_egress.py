"""Opt-in, identity-bound Native connection gate for an explicit process tree.

The root only propagates enrollment; its model connections remain Guard's concern.
This is a user-mode fixed-Windows experiment, not a kernel isolation boundary.
"""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import struct
import sys
import threading
import time
import uuid

from transpect_trace.guard.native import ModuleEntry, api
from transpect_trace.guard.pipe import pipe_security, windows_api

MAGIC = 0x31474554
REQUEST = struct.Struct("<IIIIQ32sIIQII16siIQ")
RESPONSE = struct.Struct("<IIIIQ")
REGISTER, READY, CHILD, CONNECT, RESULT, HELD, HEARTBEAT = range(1, 8)


def descendant_pipe_security(k, restricted_sids=()):
    """Current-user/SYSTEM plus restricted-token check; peer enrollment remains mandatory.

    Codex sandbox children can carry a restricted token and low integrity. The
    explicit local pipe allows that token to authenticate; no target sandbox or
    system security setting is changed.
    """
    security = pipe_security(k)
    adv = c.WinDLL("advapi32", use_last_error=True)
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = w.BOOL
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    text = c.c_void_p()
    replacement = c.c_void_p()
    try:
        if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(security.descriptor, 1, 4, c.byref(text), None):
            raise c.WinError(c.get_last_error())
        sddl = c.wstring_at(text) + "".join(f"(A;;GRGW;;;{sid})" for sid in sorted(set(restricted_sids))) + "S:(ML;;NW;;;LW)"
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(replacement), None):
            raise c.WinError(c.get_last_error())
        k.LocalFree(security.descriptor)
        security.descriptor = replacement
        return security
    finally:
        if text.value:
            k.LocalFree(text)


def restricted_process_sids(pid):
    k = api()
    adv = c.WinDLL("advapi32", use_last_error=True)
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(c.c_void_p)]
    process = k.OpenProcess(0x1000, False, pid)
    if not process:
        raise c.WinError(c.get_last_error())
    token = w.HANDLE()
    try:
        if not adv.OpenProcessToken(process, 8, c.byref(token)):
            raise c.WinError(c.get_last_error())
        count = w.DWORD()
        adv.GetTokenInformation(token, 11, None, 0, c.byref(count))
        if count.value > 1024 * 1024:
            raise ValueError("restricted SID list exceeds bound")
        data = c.create_string_buffer(count.value)
        if not adv.GetTokenInformation(token, 11, data, len(data), c.byref(count)):
            raise c.WinError(c.get_last_error())
        class Sid(c.Structure):
            _fields_ = [("sid", c.c_void_p), ("attributes", w.DWORD)]
        total = c.cast(data, c.POINTER(w.DWORD))[0]
        if total > 256 or 8 + total * c.sizeof(Sid) > len(data):
            raise ValueError("invalid restricted SID list")
        rows = c.cast(c.addressof(data) + 8, c.POINTER(Sid))
        result = []
        for index in range(total):
            text = c.c_void_p()
            if not adv.ConvertSidToStringSidW(rows[index].sid, c.byref(text)):
                raise c.WinError(c.get_last_error())
            try:
                result.append(c.wstring_at(text))
            finally:
                k.LocalFree(text)
        return result
    finally:
        if token:
            k.CloseHandle(token)
        k.CloseHandle(process)


class NativeConfig(c.Structure):
    _pack_ = 1
    _fields_ = [("magic", w.DWORD), ("version", w.DWORD), ("root", w.DWORD),
                ("controller_pid", w.DWORD), ("creation", c.c_uint64),
                ("token", c.c_ubyte * 32), ("pipe_name", w.WCHAR * 128), ("dll_path", w.WCHAR * 1024)]
    _fields_ += [("create_rva", c.c_uint64), ("create_prologue", c.c_ubyte * 16)]


def host_fingerprint():
    k = api()
    module = k.GetModuleHandleW("kernelbase.dll")
    entry = k.GetProcAddress(module, b"CreateProcessInternalW")
    if not entry:
        raise RuntimeError("Private creation entry absent on this Windows build")
    path = c.create_unicode_buffer(32768)
    if not k.GetModuleFileNameW(module, path, len(path)):
        raise c.WinError(c.get_last_error())
    version = sys.getwindowsversion()
    return {"windows_version": [version.major, version.minor, version.build], "kernelbase_sha256": hashlib.sha256(Path(path.value).read_bytes()).hexdigest(), "createprocessinternalw_rva": entry - module, "createprocessinternalw_prologue": c.string_at(entry, 16).hex()}


def normalize_policy(policy: dict) -> dict:
    if not isinstance(policy, dict) or set(policy) - {"default_action", "targets", "allowed_image_hashes"}:
        raise ValueError("unexpected egress policy field")
    if not isinstance(policy.get("targets", []), list):
        raise ValueError("targets must be an array")
    if policy.get("default_action", "allow") not in {"allow", "block"}:
        raise ValueError("default_action must be allow or block")
    targets = []
    for row in policy.get("targets", []):
        if not isinstance(row, dict) or not {"address", "port"} <= set(row):
            raise ValueError("target requires address and port")
        if set(row) - {"address", "port", "action", "protocol"}:
            raise ValueError("unexpected target policy field")
        address = normalized_address(row["address"])
        port = row["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port <= 65535:
            raise ValueError("target port must be 1..65535")
        if row.get("protocol", "tcp") != "tcp" or row.get("action", "block") not in {"allow", "block"}:
            raise ValueError("only explicit TCP allow/block targets are supported")
        target = {"address": str(address), "port": port, "action": row.get("action", "block"), "protocol": "tcp"}
        if any(x["address"] == target["address"] and x["port"] == port for x in targets):
            raise ValueError("duplicate target")
        targets.append(target)
    hashes = policy.get("allowed_image_hashes", [])
    if not isinstance(hashes, list) or any(not isinstance(x, str) or len(x) != 64 or any(c not in "0123456789abcdef" for c in x) for x in hashes):
        raise ValueError("allowed_image_hashes must contain lowercase SHA-256 values")
    return {"default_action": policy.get("default_action", "allow"), "targets": targets, "allowed_image_hashes": hashes}


def destination_decision(policy: dict, address: str, port: int) -> str:
    normalized = str(normalized_address(address))
    return next((row["action"] for row in policy["targets"] if row["address"] == normalized and row["port"] == port), policy["default_action"])


def normalized_address(address):
    value = ipaddress.ip_address(address)
    if isinstance(value, ipaddress.IPv6Address) and value.scope_id is not None:
        raise ValueError("scoped IPv6 policy addresses require an unsupported scope interface")
    return value.ipv4_mapped or value if isinstance(value, ipaddress.IPv6Address) else value


def inspect_process(pid: int, *, hash_image: bool = True) -> dict:
    """Read process identity directly; no command line or environment is persisted."""
    k = api()
    process = k.OpenProcess(0x1000, False, pid)
    if not process:
        raise c.WinError(c.get_last_error())
    try:
        times = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(process, *(c.byref(t) for t in times)):
            raise c.WinError(c.get_last_error())
        path = c.create_unicode_buffer(32768)
        size = w.DWORD(len(path))
        if not k.QueryFullProcessImageNameW(process, 0, path, c.byref(size)):
            raise c.WinError(c.get_last_error())
        class Basic(c.Structure):
            _fields_ = [("reserved1", c.c_void_p), ("peb", c.c_void_p), ("reserved2", c.c_void_p * 2), ("pid", c.c_size_t), ("parent", c.c_size_t)]
        basic = Basic()
        nt = c.WinDLL("ntdll")
        nt.NtQueryInformationProcess.argtypes = [w.HANDLE, w.ULONG, c.c_void_p, w.ULONG, c.c_void_p]
        nt.NtQueryInformationProcess.restype = c.c_long
        if nt.NtQueryInformationProcess(process, 0, c.byref(basic), c.sizeof(basic), None):
            raise RuntimeError("parent identity unavailable")
        created = times[0].dwLowDateTime | (times[0].dwHighDateTime << 32)
        digest = hashlib.sha256(Path(path.value).read_bytes()).hexdigest() if hash_image else None
        return {"pid": pid, "creation_filetime": created, "parent_pid": basic.parent, "image_sha256": digest, "image_name": Path(path.value).name}
    finally:
        k.CloseHandle(process)


def process_lifetime_ended(pid: int, created: int) -> bool:
    """Prove exit/reuse; access-denied or unknown errors never imply exit."""
    k = api()
    handle = k.OpenProcess(0x100000 | 0x1000, False, pid)
    if not handle:
        return c.get_last_error() in {87, 1168}
    try:
        times = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle, *(c.byref(t) for t in times)):
            return False
        current = times[0].dwLowDateTime | (times[0].dwHighDateTime << 32)
        return current != created or k.WaitForSingleObject(handle, 0) == 0
    finally:
        k.CloseHandle(handle)


def _module_base(pid: int, path: Path) -> int:
    k = api()
    for attempt in range(8):
        snapshot = k.CreateToolhelp32Snapshot(0x18, pid)
        if snapshot != w.HANDLE(-1).value:
            break
        error=c.get_last_error()
        if error!=24 or attempt==7:
            raise c.WinError(error)
        time.sleep(.005)  # ERROR_BAD_LENGTH: module list changed during snapshot.
    try:
        entry = ModuleEntry()
        entry.size = c.sizeof(entry)
        ok = k.Module32FirstW(snapshot, c.byref(entry))
        while ok:
            if Path(entry.path).resolve() == path.resolve():
                return entry.base
            ok = k.Module32NextW(snapshot, c.byref(entry))
        raise RuntimeError(f"Native module not present: {path.name}")
    finally:
        k.CloseHandle(snapshot)


def _verify_process_lifetime(k,process,created):
    times=[w.FILETIME() for _ in range(4)]
    if not k.GetProcessTimes(process,*(c.byref(t) for t in times)):
        raise c.WinError(c.get_last_error())
    actual=times[0].dwLowDateTime|(times[0].dwHighDateTime<<32)
    if actual!=created:
        raise ValueError('Native target process lifetime changed')
    wait=k.WaitForSingleObject(process,0)
    if wait==0:
        raise RuntimeError('Native target process exited before initialization')
    if wait!=258:
        raise c.WinError(c.get_last_error())


def _wait_startup_module(pid,path,k,process,created,*,timeout=2):
    """Wait only for a startup system module, never assume an injected DLL loaded."""
    deadline=time.monotonic()+timeout
    while True:
        _verify_process_lifetime(k,process,created)
        try:
            base=_module_base(pid,path)
        except OSError as error:
            if getattr(error,'winerror',None) not in {24,299}:
                raise
        except RuntimeError:
            pass  # A new process can have an empty/ntdll-only module list.
        else:
            _verify_process_lifetime(k,process,created)
            return base
        if time.monotonic()>=deadline:
            raise TimeoutError(f'Native startup module unavailable: {path.name}')
        time.sleep(.01)


def _inject(pid: int, dll: Path, config: NativeConfig):
    k = api()
    k.GetExitCodeThread.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    k.GetExitCodeThread.restype = w.BOOL
    process = k.OpenProcess(0x2 | 0x8 | 0x10 | 0x20 | 0x400 | 0x100000, False, pid)
    if not process:
        raise c.WinError(c.get_last_error())
    allocation = None
    safe_to_free = True
    def remote(function, argument):
        nonlocal safe_to_free
        thread = k.CreateRemoteThread(process, None, 0, function, argument, 0, None)
        if not thread:
            raise c.WinError(c.get_last_error())
        try:
            if k.WaitForSingleObject(thread, 15000):
                safe_to_free = False
                raise TimeoutError("Native initialization did not complete")
            result = w.DWORD()
            if not k.GetExitCodeThread(thread, c.byref(result)):
                raise c.WinError(c.get_last_error())
            return result.value
        finally:
            k.CloseHandle(thread)
    try:
        _verify_process_lifetime(k,process,config.creation)
        allocation = k.VirtualAllocEx(process, None, c.sizeof(config), 0x3000, 4)
        if not allocation:
            raise c.WinError(c.get_last_error())
        written = c.c_size_t()
        data = (str(dll) + "\0").encode("utf-16-le")
        if not k.WriteProcessMemory(process, allocation, data, len(data), c.byref(written)) or written.value != len(data):
            raise c.WinError(c.get_last_error())
        loader = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        owner = w.HMODULE()
        if not k.GetModuleHandleExW(6, c.cast(loader, w.LPCWSTR), c.byref(owner)):
            raise c.WinError(c.get_last_error())
        path = c.create_unicode_buffer(32768)
        k.GetModuleFileNameW(owner, path, len(path))
        loader_base=_wait_startup_module(pid,Path(path.value),k,process,config.creation)
        remote(loader_base + loader - owner.value, allocation)
        _verify_process_lifetime(k,process,config.creation)
        remote_base = _module_base(pid, dll)
        k.LoadLibraryExW.argtypes = [w.LPCWSTR, w.HANDLE, w.DWORD]
        k.LoadLibraryExW.restype = w.HMODULE
        k.FreeLibrary.argtypes = [w.HMODULE]
        local = k.LoadLibraryExW(str(dll), None, 1)  # map exports; do not execute DllMain locally
        if not local:
            raise c.WinError(c.get_last_error())
        try:
            entry = k.GetProcAddress(local, b"EgressInitialize")
            if not entry:
                raise RuntimeError("Native initializer missing")
            data = bytes(config)
            if not k.WriteProcessMemory(process, allocation, data, len(data), c.byref(written)) or written.value != len(data):
                raise c.WinError(c.get_last_error())
            if remote(remote_base + entry - local, allocation) != MAGIC:
                raise RuntimeError("Native egress initialization rejected; do not release the tool boundary")
        finally:
            k.FreeLibrary(local)
    finally:
        if allocation and safe_to_free:
            k.VirtualFreeEx(process, allocation, 0, 0x8000)
        k.CloseHandle(process)


class EgressController:
    def __init__(self, subject, dll: Path, policy: dict, run_dir: Path):
        self.subject = subject.model_dump() if hasattr(subject, "model_dump") else dict(subject)
        self.dll = Path(dll).resolve()
        self.policy = normalize_policy(policy)
        self.run_dir = Path(run_dir)
        self.run_id = str(uuid.uuid4())
        self.pipe_name = rf"\\.\pipe\ttrace-egress-{secrets.token_hex(24)}"
        self.token = secrets.token_bytes(32)
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.listening = threading.Event()
        self.ready = threading.Event()
        self.threads = []
        self.members: dict[int, dict] = {}
        # A rejected enrollment can still leave a real child held before main.
        # Keep these cleanup candidates separate from authorized pipe peers.
        self.held_candidates: dict[tuple[int, int], dict] = {}
        self.records = []
        self.errors = []
        self.state = {"schema": "transpect.native.egress.status/1.0", "run_id": self.run_id, "state": "not_started", "can_enforce": False, "scope": "explicitly_enrolled_descendants_tcp", "root_network_filtered": False, "uncovered": ["UDP", "QUIC", "existing connections", "custom network stacks", "unverified process creation paths", "administrator bypass"]}
        self.k = None
        self.security = None
        self.child_security = []

    def _persist(self):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.state["members"] = [dict(row) for row in self.members.values()]
        self.state["errors"] = list(self.errors)
        (self.run_dir / "egress-status.json").write_text(json.dumps(self.state, indent=2) + "\n", encoding="utf-8")

    def _record(self, row):
        row.update(run_id=self.run_id, timestamp_unix_ns=time.time_ns())
        self.records.append(row)
        with (self.run_dir / "egress-audit.jsonl").open("a", encoding="utf-8") as file:
            file.write(json.dumps(row) + "\n")

    def start(self):
        if self.k is not None:
            raise RuntimeError("controller already started")
        if not self.dll.is_file():
            raise FileNotFoundError(self.dll)
        manifest = json.loads((self.dll.parent / "build-manifest.json").read_text())
        digest = hashlib.sha256(self.dll.read_bytes()).hexdigest()
        if manifest.get("schema") != "transpect.native.egress.build/1.0" or manifest.get("artifacts_sha256", {}).get(self.dll.name) != digest:
            raise ValueError("Native build identity mismatch")
        fingerprint = host_fingerprint()
        if manifest.get("host_fingerprint") != fingerprint:
            raise ValueError("Windows private creation entry baseline mismatch; rebuild and revalidate explicitly")
        identity = inspect_process(int(self.subject["pid"]))
        expected_hash = self.subject.get("image_sha256") or self.subject.get("baseline", {}).get("sha256")
        if identity["creation_filetime"] != int(self.subject["creation_filetime"]) or (expected_hash and identity["image_sha256"] != expected_hash):
            raise ValueError("root process identity mismatch")
        self.k = windows_api()
        self.security = descendant_pipe_security(self.k)
        self.members[identity["pid"]] = dict(identity, root=True, ready=False, registered=False)
        self.state.update(state="initializing", dll_sha256=digest, host_fingerprint=fingerprint)
        self.state["controller_identity"] = inspect_process(os.getpid(), hash_image=False)
        self._persist()
        for _ in range(4):
            thread = threading.Thread(target=self._serve, daemon=True)
            self.threads.append(thread)
            thread.start()
        if not self.listening.wait(5):
            self.close()
            raise RuntimeError("egress listener unavailable")
        config = NativeConfig(magic=MAGIC, version=1, root=1, controller_pid=os.getpid(), creation=identity["creation_filetime"], pipe_name=self.pipe_name, dll_path=str(self.dll))
        config.token[:] = self.token
        config.create_rva = fingerprint["createprocessinternalw_rva"]
        config.create_prologue[:] = bytes.fromhex(fingerprint["createprocessinternalw_prologue"])
        try:
            _inject(identity["pid"], self.dll, config)
            if not self.ready.wait(5):
                raise RuntimeError("Native readiness not attested")
        except BaseException:
            self.state.update(state="initialization_failed", can_enforce=False)
            self._persist()
            self.close()
            raise
        self.state.update(state="active_limited", can_enforce=True, protected_since_unix_ns=time.time_ns())
        self._persist()
        return self

    def _read(self, handle, size):
        data = bytearray()
        deadline = time.monotonic() + 2
        self.k.PeekNamedPipe.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.c_void_p, c.POINTER(w.DWORD), c.c_void_p]
        self.k.PeekNamedPipe.restype = w.BOOL
        while len(data) < size:
            available = w.DWORD()
            if not self.k.PeekNamedPipe(handle, None, 0, None, c.byref(available), None):
                raise OSError("pipe disconnected")
            if not available.value:
                if time.monotonic() >= deadline or self.stop.wait(0.005):
                    raise TimeoutError("pipe deadline")
                continue
            buffer = c.create_string_buffer(min(available.value, size - len(data)))
            count = w.DWORD()
            if not self.k.ReadFile(handle, buffer, len(buffer), c.byref(count), None) or not count.value:
                raise OSError("pipe read failed")
            data.extend(buffer.raw[:count.value])
        return bytes(data)

    def _handle(self, peer: int, values: tuple) -> tuple[bool, int]:
        if self.stop.is_set():
            return False, 14
        magic, version, kind, pid, created, token, child_pid, flags, child_created, family, port, packed_address, result, error, sequence = values
        if magic != MAGIC or version != 1 or peer != pid or not hmac.compare_digest(token, self.token):
            return False, 1
        member = self.members.get(pid)
        if not member or member["creation_filetime"] != created:
            return False, 2
        identity = inspect_process(pid, hash_image=False)
        if identity["creation_filetime"] != created or identity["image_name"] != member["image_name"]:
            return False, 2
        member["last_seen_unix_ns"] = time.time_ns()
        if kind == REGISTER:
            member["registered"] = True
            self._record({"kind": "process.register", "subject": dict(member)})
            return True, 0
        if not member["registered"]:
            return False, 3
        if kind == READY:
            if flags != 0x0f:
                return False, 4
            member["ready"] = True
            self._record({"kind": "process.ready", "subject": dict(member), "hook_mask": flags})
            if member["root"]:
                self.ready.set()
            return True, 0
        if kind == HEARTBEAT:
            if flags != 1:
                member["native_health"] = "fail_closed"
                self.state.update(state="degraded_native_fail_closed", can_enforce=False)
                self._persist()
            return True, 0
        if not member["ready"]:
            return False, 5
        if kind == CHILD:
            if len(self.members) >= 256:
                return False, 13
            child = inspect_process(child_pid)
            if child["creation_filetime"] != child_created or child["parent_pid"] != pid:
                return False, 6
            if self.policy["allowed_image_hashes"] and child["image_sha256"] not in self.policy["allowed_image_hashes"]:
                return False, 7
            if child_pid in self.members and self.members[child_pid]["creation_filetime"] == child_created:
                return False, 8
            sids = set(restricted_process_sids(child_pid))
            self.members[child_pid] = dict(child, root=False, ready=False, registered=False, parent_identity=f"{pid}-{created}")
            security = descendant_pipe_security(self.k, sids)
            self.child_security.append(security)
            listening = threading.Event()
            thread = threading.Thread(target=self._serve, args=(self.pipe_name + f"-{child_pid}", security, listening), daemon=True)
            self.threads.append(thread)
            thread.start()
            # The parent remains paused at the creation boundary while this
            # dedicated child pipe is prepared; no existing pipe ACL changes.
            if not listening.wait(1):
                return False, 12
            self._record({"kind": "process.enroll", "subject": dict(self.members[child_pid]), "readiness": "suspended_pending_native"})
            self._persist()
            return True, 0
        if kind == HELD:
            key = (child_pid, child_created)
            try:
                candidate = inspect_process(child_pid)
            except (OSError, RuntimeError):
                candidate = None
            if (not candidate or child_pid == pid or child_created <= 0 or
                    candidate['creation_filetime'] != child_created or candidate['parent_pid'] != pid):
                self.state.update(state='degraded_held_identity_unknown', can_enforce=False,
                    last_unverified_held_claim={'pid':child_pid,'creation_filetime':child_created,
                        'identity_verified':False,'cleanup':'verify_identity_before_any_operator_action'})
                self._record({'kind':'process.held_unverified','child_pid':child_pid,
                    'creation_filetime':child_created,'reason':'child_identity_or_parent_not_verified'})
                self._persist()
                return False, 6
            if key not in self.held_candidates and len(self.held_candidates) >= 256:
                self.state.update(state='degraded_held_capacity', can_enforce=False)
                self._record({'kind':'process.held_unverified','child_pid':child_pid,
                    'creation_filetime':child_created,'reason':'held_candidate_capacity_exceeded'})
                self._persist()
                return False, 13
            child = self.members.get(child_pid)
            enrolled = bool(child and child['creation_filetime'] == child_created)
            candidate.update(parent_identity=f'{pid}-{created}', held=True,
                held_reason='native_initialization_or_resume_failed',
                enrollment='registered' if enrolled else 'not_registered')
            self.held_candidates[key] = candidate
            if enrolled:
                child['held'] = True
                child['held_reason'] = candidate['held_reason']
            self.state.update(state="degraded_child_held", can_enforce=False)
            self._record({"kind": "process.held", "child_pid": child_pid, "creation_filetime": child_created, "reason": "native_initialization_or_resume_failed", "injection_stage": result, "winerror": error})
            self.state['held_processes'] = self._held_processes()
            self._persist()
            return True, 0
        if kind == CONNECT:
            if member["root"] or family not in (4, 6) or not 0 < port <= 65535:
                return False, 9
            address = str(ipaddress.ip_address(packed_address[:4] if family == 4 else packed_address))
            action = destination_decision(self.policy, address, port)
            self._record({"kind": "connection.decision", "pid": pid, "creation_filetime": created, "attempt_id": sequence, "destination_address": address, "destination_port": port, "protocol": "tcp", "decision": action, "execution": "pending"})
            return action == "allow", 0 if action == "allow" else 10
        if kind == RESULT:
            self._record({"kind": "connection.rejected", "pid": pid, "creation_filetime": created, "attempt_id": child_created, "native_result": result, "winsock_error": error, "evidence": "native_failure_return_before_original_connect"})
            return True, 0
        return False, 11

    def response_frame(self, values, allowed, reason):
        return RESPONSE.pack(MAGIC, 1, int(allowed), reason, values[-1])

    def receipt_confirmation(self, values):
        return b"\x5a"

    def _held_processes(self):
        """Recheck exact lifetimes; cleanup metadata never authorizes enrollment."""
        candidates = dict(self.held_candidates)
        for member in self.members.values():
            if not member.get('ready') or member.get('held'):
                candidates.setdefault((member['pid'],member['creation_filetime']), member)
        held = []
        for (pid, created), member in candidates.items():
            try:
                identity = inspect_process(pid, hash_image=False)
            except (OSError,RuntimeError) as error:
                if getattr(error,'winerror',None) in {87,1168}:
                    continue
                lifetime = 'unknown'
            else:
                if identity['creation_filetime'] != created:
                    continue
                lifetime = 'matching_process_observed'
            held.append({'pid':pid,'creation_filetime':created,
                'image_sha256':member.get('image_sha256'),'parent_identity':member.get('parent_identity'),
                'enrollment':member.get('enrollment','registered' if member.get('registered') else 'pending'),
                'liveness':lifetime,'cleanup':'explicit_operator_action_required_no_automatic_resume'})
        return held

    def _serve(self, name=None, security=None, listening=None):
        name = name or self.pipe_name
        security = security or self.security
        while not self.stop.is_set():
            handle = self.k.CreateNamedPipeW(name, 3, 0x8, 4, 4096, 4096, 2000, c.byref(security))
            if handle == w.HANDLE(-1).value:
                self.errors.append("pipe_create_failed")
                return
            self.listening.set()
            if listening:
                listening.set()
            try:
                if not self.k.ConnectNamedPipe(handle, None) and c.get_last_error() != 535:
                    continue
                if self.stop.is_set():
                    continue
                peer = w.ULONG()
                if not self.k.GetNamedPipeClientProcessId(handle, c.byref(peer)):
                    raise OSError("peer identity unavailable")
                with self.lock:
                    enrolled = self.members.get(peer.value)
                    if not enrolled:
                        continue
                    peer_identity = inspect_process(peer.value, hash_image=False)
                    if peer_identity["creation_filetime"] != enrolled["creation_filetime"]:
                        continue
                values = REQUEST.unpack(self._read(handle, REQUEST.size))
                with self.lock:
                    allowed, reason = self._handle(peer.value, values)
                response = self.response_frame(values, allowed, reason)
                count = w.DWORD()
                if not self.k.WriteFile(handle, response, len(response), c.byref(count), None) or count.value != len(response):
                    raise OSError("reply failed")
                if self._read(handle, 1) != b"\xa5":
                    raise ValueError("invalid Native reply acknowledgment")
                confirmation = self.receipt_confirmation(values)
                if not self.k.WriteFile(handle, confirmation, len(confirmation), c.byref(count), None) or count.value != len(confirmation):
                    raise OSError("confirmation failed")
                if self._read(handle, 1) != b"\xa6":
                    raise ValueError("invalid Native receipt completion")
            except (OSError, ValueError, TimeoutError, RuntimeError) as exc:
                with self.lock:
                    # A short-lived tool may exit during its background
                    # heartbeat. Retire only a directly verified ended lifetime;
                    # a live/unknown failure still degrades the controller.
                    member = self.members.get(peer.value) if 'peer' in locals() else None
                    if member and process_lifetime_ended(member['pid'], member['creation_filetime']):
                        member['lifecycle'] = 'ended'
                        self._record({'kind':'process.communication_ended','pid':member['pid'],
                            'creation_filetime':member['creation_filetime'], 'error_type':type(exc).__name__})
                    else:
                        self.errors.append(f"{type(exc).__name__}:{getattr(exc, 'winerror', None)}:{str(exc)[:120]}")
                        self.state.update(state="degraded", can_enforce=False)
                    self._persist()
            finally:
                self.k.DisconnectNamedPipe(handle)
                with self.lock:
                    self.k.CloseHandle(handle)

    def close(self):
        # _handle runs under this same lock. Once stopped, no accepted CHILD
        # request may grow the members, pipe names or worker collection.
        with self.lock:
            if self.stop.is_set():
                return
            self.stop.set()
            names = [self.pipe_name] * 4 + [self.pipe_name + f"-{pid}" for pid, row in self.members.items() if not row["root"]]
            threads = list(self.threads)
        if self.k:
            for name in names:
                handle = self.k.CreateFileW(name, 0xc0000000, 0, None, 3, 0, None)
                if handle != w.HANDLE(-1).value:
                    self.k.CloseHandle(handle)
            for thread in threads:
                thread.join(timeout=2.5)
            if self.security and not any(t.is_alive() for t in threads):
                self.k.LocalFree(self.security.descriptor)
                for security in self.child_security:
                    self.k.LocalFree(security.descriptor)
        with self.lock:
            if self.state["state"] != "initialization_failed":
                self.state.update(state="controller_stopped_fail_closed", can_enforce=False)
            self.state["held_processes"] = self._held_processes()
            self._persist()
