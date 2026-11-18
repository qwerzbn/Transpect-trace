"""Version-independent tool execution gate: local build and attach.

The DLL built here hooks only ``kernelbase!CreateProcessW``. No image hash, RVA
or entry-byte pin takes part, so a client update cannot invalidate the build and
there is no ``UNSUPPORTED_VERSION`` state on this path. A denial returns
``ERROR_ACCESS_DENIED`` to the caller; nothing terminates the host, so the agent
receives an ordinary tool error and its session continues.

This gate is an execution-intent check. It cannot see the payload a launched
program sends later, so it does not by itself cover tool network egress.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Callable

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "native" / "guard" / "tool_exec_guard.c"
THIRD_PARTY = "native/guard/third_party"
COMPILED = ("native/guard/tool_exec_guard.c",
            f"{THIRD_PARTY}/minhook/src/buffer.c",
            f"{THIRD_PARTY}/minhook/src/hook.c",
            f"{THIRD_PARTY}/minhook/src/trampoline.c",
            f"{THIRD_PARTY}/minhook/src/hde/hde64.c")
BUILD_SCHEMA = "transpect.tool-exec-guard.build/1.0"


def source_digests(root: Path = ROOT) -> dict[str, str]:
    """Line-ending independent digests of every compiled source and header."""
    from .desktop_service import normalized_sha256

    native = Path(root) / "native" / "guard"
    third = native / "third_party"
    paths = [native / "tool_exec_guard.c",
             *sorted(path for path in third.rglob("*")
                     if path.is_file() and path.suffix in (".c", ".h"))]
    if not paths[0].is_file():
        raise FileNotFoundError(f"gate implementation is absent: {paths[0]}")
    return {path.relative_to(root).as_posix(): normalized_sha256(path)
            for path in paths}


def build_key(digests: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(digests, sort_keys=True).encode()).hexdigest()[:12]


def ensure_dll(*, root: Path = ROOT) -> Path:
    """Build a new immutable DLL name whenever the source bytes change."""
    from .desktop_service import file_sha256

    root = Path(root)
    digests = source_digests(root)
    key = build_key(digests)
    directory = root / "build" / "tool-exec-guard"
    # The resident-DLL check matches this prefix, so a second controller on the
    # same process is refused instead of installing a duplicate hook.
    dll = directory / f"ttrace-guard-toolexec-{key}.dll"
    manifest_path = dll.with_suffix(".json")
    if dll.is_file() and manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (manifest.get("dll_sha256") == file_sha256(dll)
                and manifest.get("sources") == digests):
            return dll
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / f"build-{os.getpid()}-{key}.dll"
    try:
        subprocess.run([sys.executable, "-m", "ziglang", "cc", "-target",
                        "x86_64-windows-gnu", "-O2", "-shared",
                        "-DJSMN_PARENT_LINKS", *COMPILED, "-o", str(temporary)],
                       cwd=root, check=True)
        os.replace(temporary, dll)
    finally:
        temporary.unlink(missing_ok=True)
    manifest_path.write_text(json.dumps(
        {"schema": BUILD_SCHEMA, "version_pinned": False,
         "hooks": ["kernelbase!CreateProcessW"], "sources": digests,
         "dll": dll.name, "dll_sha256": file_sha256(dll)},
        indent=2) + "\n", encoding="utf-8")
    return dll


def _engine(run_dir: Path):
    from ..protect.codex_hook_gate import GateConfig
    from ..protect.native_collection import NativeCollectionEngine

    config = GateConfig(mode="enforce", archive_directory=run_dir / "archive",
                        audit_file=run_dir / "audit.jsonl",
                        registration_directory=None,
                        review_override_ttl_seconds=0,
                        collection_file=run_dir / "collection.jsonl")
    engine = NativeCollectionEngine(config, archive_full_body=True)
    engine.concurrent_safe = True
    return engine


@dataclass
class ToolExecStatus:
    pid: int
    creation_filetime: int = 0
    image_path: str = ""
    state: str = "STARTING"
    detail: str = ""
    attach_ms: float | None = None
    hooks: dict = field(default_factory=dict)
    allowed: int = 0
    denied: int = 0
    last_decision: str = ""
    rows: list = field(default_factory=list)


class ToolExecGuard:
    """One attached process generation: pipe server, lease and injected DLL.

    ``start`` and ``stop`` must run on the same thread: the lease refuses to be
    released by any other owner.
    """

    def __init__(self, pid: int, *, run_dir: Path, dll: Path | None = None,
                 details: dict | None = None,
                 log: Callable[[str], None] = lambda _message: None):
        self.pid = pid
        self.run_dir = Path(run_dir)
        self.dll = dll
        self.log = log
        self.status = ToolExecStatus(pid)
        self._details = details
        self._lock = threading.Lock()
        self._pipe = None
        self._lease = None
        self._engine = None

    def _on_frame(self, request) -> None:
        """The ready frame reports which exports the gate patched."""
        if request.kind == "native.ready" and request.installed:
            self.status.hooks = dict(
                item.split("=", 1) for item in request.installed.split(" ")
                if "=" in item)

    def _on_tool(self, row: dict) -> None:
        with self._lock:
            allowed = row.get("decision") == "allow"
            self.status.allowed += allowed
            self.status.denied += not allowed
            self.status.last_decision = (
                f"{row.get('decision')} {row.get('application') or ''} "
                f"{row.get('reason') or ''}".strip())
            self.status.rows.append(row)
        self.log(f"[tool.exec {self.pid}] {self.status.last_decision}")

    def start(self, *, timeout: float = 15) -> ToolExecStatus:
        import time

        from .desktop_service import (Lease, current_user_sid, process_details,
                                      resident_guard_dlls)
        from .native import inject, wait_ready
        from .pipe import PipeServer

        began = time.monotonic()
        details = self._details or process_details(self.pid)
        if details is None:
            raise RuntimeError(f"process {self.pid} is unavailable")
        if details["user_sid"] != current_user_sid():
            raise RuntimeError("the target runs under a different user")
        if resident_guard_dlls(self.pid):
            raise RuntimeError("a guard DLL is already resident in the target")
        birth = details["creation_filetime"]
        identity = {"pid": self.pid, "creation_filetime": birth,
                    "guard_session_id": f"{self.pid}-{birth}",
                    "baseline": {"path": details["image_path"]}}
        self.status.creation_filetime = birth
        self.status.image_path = details["image_path"]
        self.run_dir.mkdir(parents=True, exist_ok=True)
        dll = self.dll or ensure_dll()
        self.dll = dll
        self._engine = _engine(self.run_dir)
        from .desktop_service import _DecisionLog

        policy_engine = _DecisionLog(self._engine, {}, lambda *_args: None,
                                     self._on_tool)
        self._pipe = PipeServer(self.pid, policy_engine,
                                self.run_dir / "tool-exec-audit.jsonl",
                                request_tap=self._on_frame,
                                client_sid=details["user_sid"])
        self._pipe.start()
        # The lease must exist before the DLL initializes: without it the DLL
        # installs no hook at all and leaves the host untouched.
        self._lease = Lease(self.pid, birth)
        self._lease.acquire()
        inject(self.pid, dll, identity,
               identity_resolver=lambda _pid: dict(identity))
        if not wait_ready(identity, timeout):
            raise RuntimeError("the tool execution gate did not become ready")
        self.status.attach_ms = (time.monotonic() - began) * 1000
        self.status.state = "GATED"
        self.status.detail = ("CreateProcessW is gated for processes created "
                              "after this time; earlier ones are not covered")
        self.log(f"[tool.exec {self.pid}] 已接入工具执行门控"
                 f"（{self.status.attach_ms:.0f} ms）")
        return self.status

    def stop(self, *, controlled: bool = True) -> None:
        """Controlled: creations pass afterwards. Otherwise the DLL denies."""
        if self._lease is not None:
            self._lease.release(controlled=controlled)
            self._lease = None
        if self._pipe is not None:
            self._pipe.close()
            self._pipe = None
        if self.status.state == "GATED":
            self.status.state = "STOPPED" if controlled else "FAILED_CLOSED"
            self.status.detail = ("门控已停止，进程创建直接放行" if controlled else
                                  "控制器未受控退出，进程创建一律被拒")

    def __enter__(self) -> "ToolExecGuard":
        self.start()
        return self

    def __exit__(self, *_exception) -> None:
        self.stop()
