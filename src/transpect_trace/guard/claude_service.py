"""Fixed-binary Claude Code guard and resident process discovery.

The print-mode lab still holds stdin until its own child is attached. The
resident supervisor instead discovers arbitrary same-user npm CLI processes;
its readiness applies only from the reported attach time, never retroactively.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Mapping, Sequence

from ..protect.claude_policy import create_claude_engine as _engine
from . import desktop_service as common


ROOT = Path(__file__).resolve().parents[3]
PIN_FILE = ROOT / "deploy" / "claude-guard-lab" / "2.1.317.json"
SOURCE = ROOT / "native" / "guard" / "claude_guard.c"
STATE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TranspectTrace" / "claude-guard-lab"
RESIDENT_STATE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TranspectTrace" / "claude-guard"
SUPERVISOR_MUTEX = "Local\\ttrace-claude-guard-supervisor"
SUPERVISOR_STOP = "Local\\ttrace-claude-guard-supervisor-stop"
RESIDENT_STATE_SCHEMA = "transpect.claude-guard.state/1.0"
PIN_SCHEMA = "transpect.claude-guard-lab.pin/1.0"
BUILD_SCHEMA = "transpect.claude-guard-lab.build/1.0"
ACCEPTANCE_SUITE_VERSION = "claude-2.1.317-full/4"
ACCEPTANCE_FULL_CASES = 17
MAX_PROMPT_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
HOOK_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")


VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.+][0-9A-Za-z]+)?\Z")


def pin_directory() -> Path:
    """All pinned versions live here; a supervisor scans it per binary SHA-256."""
    return ROOT / "deploy" / "claude-guard-lab"


def installed_claude() -> Path:
    """The npm native executable studied for this lab, never a shim or app copy."""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is unavailable")
    return (Path(appdata) / "npm" / "node_modules" / "@anthropic-ai" /
            "claude-code" / "bin" / "claude.exe")


def load_pin(path: Path | None = None) -> dict:
    if path is None:
        path = Path(os.environ.get("TTRACE_PIN", PIN_FILE))
    path = Path(path)
    pin = json.loads(path.read_text(encoding="utf-8"))
    try:
        binary = pin["binary"]
        hooks = pin["hooks"]
        valid = (pin["schema"] == PIN_SCHEMA
                 and bool(VERSION.fullmatch(pin.get("claude_code_version", "")))
                 and binary["name"] == "claude.exe"
                 and bool(SHA256.fullmatch(binary["sha256"]))
                 and isinstance(hooks, dict) and bool(hooks))
        for name, hook in hooks.items():
            prefix = bytes.fromhex(hook["prefix_hex"])
            valid = (valid and bool(HOOK_NAME.fullmatch(name))
                     and int(hook["rva"], 16) > 0 and len(prefix) >= 8)
    except (KeyError, TypeError, ValueError, AttributeError):
        valid = False
    if not valid:
        raise ValueError(f"invalid Claude lab pin: {path}")
    core = {key: value for key, value in pin.items() if key != "accepted"}
    core_bytes = json.dumps(core, sort_keys=True, ensure_ascii=False,
                            separators=(",", ":")).encode("utf-8")
    core_sha256 = hashlib.sha256(core_bytes).hexdigest()
    return {**pin, "_path": path, "_sha256": core_sha256}


def accepted_pin_valid(pin: dict, *, root: Path = ROOT) -> bool:
    """An acceptance stamp applies only to its exact pin, sources and DLL."""
    accepted = pin.get("accepted")
    if not isinstance(accepted, dict):
        return False
    if (accepted.get("schema") != "transpect.claude-guard-lab.accepted/2.0"
            or accepted.get("suite") != "full"
            or accepted.get("suite_version") != ACCEPTANCE_SUITE_VERSION
            or accepted.get("failed") != 0
            or accepted.get("passed") != ACCEPTANCE_FULL_CASES
            or accepted.get("binary_sha256") != pin["binary"]["sha256"]
            or accepted.get("pin_core_sha256") != pin["_sha256"]):
        return False
    sources = acceptance_source_hashes(root)
    if accepted.get("sources") != sources:
        return False
    evidence_name = accepted.get("evidence")
    evidence_hash = accepted.get("evidence_sha256")
    if (not isinstance(evidence_name, str)
            or Path(evidence_name).name != evidence_name
            or not isinstance(evidence_hash, str)
            or not SHA256.fullmatch(evidence_hash)):
        return False
    evidence_path = root / "runs" / "accept" / evidence_name
    if not evidence_path.is_file() or common.file_sha256(evidence_path) != evidence_hash:
        return False
    try:
        results = [json.loads(line) for line in evidence_path.read_text(encoding="utf-8").splitlines()]
    except (OSError, ValueError):
        return False
    if len(results) != ACCEPTANCE_FULL_CASES or any(row.get("result") != "PASS" for row in results):
        return False
    live_name = accepted.get("live_evidence")
    live_hash = accepted.get("live_evidence_sha256")
    if (not isinstance(live_name, str) or Path(live_name).name != live_name
            or not isinstance(live_hash, str) or not SHA256.fullmatch(live_hash)):
        return False
    live_path = root / "runs" / "accept" / live_name
    if not live_path.is_file() or common.file_sha256(live_path) != live_hash:
        return False
    artifacts = accepted.get("live_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        return False
    for name, digest in artifacts.items():
        if (not isinstance(name, str) or Path(name).name != name
                or not isinstance(digest, str) or not SHA256.fullmatch(digest)):
            return False
        artifact_path = root / "runs" / "accept" / name
        if not artifact_path.is_file() or common.file_sha256(artifact_path) != digest:
            return False
    dll = root / "build" / "claude-guard-lab" / pin["claude_code_version"] / accepted.get("dll", "")
    return dll.is_file() and common.file_sha256(dll) == accepted.get("dll_sha256")


def pin_for_binary(sha256: str, directory: Path | None = None) -> dict | None:
    """First ACCEPTED pin whose binary SHA-256 matches, or None (fail-closed).

    A pin only becomes adoptable after the deterministic acceptance gate
    (scripts/accept_pin.py) has stamped it with an "accepted" record."""
    directory = directory or pin_directory()
    if not directory.is_dir():
        return None
    for path in sorted(directory.glob("*.json")):
        try:
            pin = load_pin(path)
        except ValueError:
            continue
        if (pin["claude_code_version"] == "2.1.317"
                and pin["binary"]["sha256"] == sha256
                and accepted_pin_valid(pin)):
            return pin
    return None


def check_binary(pin: dict, binary: Path) -> None:
    binary = Path(binary)
    if binary.name.lower() != pin["binary"]["name"]:
        raise ValueError("target is not claude.exe")
    if common.file_sha256(binary) != pin["binary"]["sha256"]:
        raise ValueError("Claude binary SHA-256 differs from the fixed 2.1.317 pin")
    for name, hook in pin["hooks"].items():
        prefix = bytes.fromhex(hook["prefix_hex"])
        if common.pe_read(binary, int(hook["rva"], 16), len(prefix)) != prefix:
            raise ValueError(f"Claude {name} hook bytes differ from the pin")


def _defines(pin: dict) -> list[str]:
    defines = [f'-DTTRACE_EXPECTED_HASH="{pin["binary"]["sha256"]}"']
    for name, hook in sorted(pin["hooks"].items()):
        key = name.upper()
        prefix = bytes.fromhex(hook["prefix_hex"])
        defines.extend((f"-D{key}_RVA={hook['rva']}",
                        f"-D{key}_PREFIX_BYTES={{" +
                        ",".join(f"0x{byte:02x}" for byte in prefix) + "}"))
    return defines


def _sources(root: Path) -> list[Path]:
    native = root / "native" / "guard"
    third = native / "third_party"
    return [native / "claude_guard.c", *sorted(path for path in third.rglob("*")
            if path.is_file() and path.suffix in (".c", ".h"))]


def acceptance_source_hashes(root: Path = ROOT) -> dict[str, str]:
    """Bind an approval to both the injected DLL and the local policy runtime."""
    paths = [*_sources(root),
             *(root / "src" / "transpect_trace" / folder / name
               for folder, names in {
                   "guard": ("claude_service.py", "pipe.py", "policy.py", "wire.py"),
                   "protect": ("claude_policy.py", "codex_hook_gate.py",
                               "native_collection.py", "redact.py", "claude_wire.py",
                               "wire_items.py", "content_dlp.py", "archive.py"),
               }.items() for name in names),
             root / "scripts" / "accept_pin.py",
             root / "scripts" / "claude_guard.py",
             root / "scripts" / "probe_claude_multiturn.py",
             root / "scripts" / "probe_claude_gzip_exact.py",
             root / "scripts" / "probe_claude_tui_origin.py",
             root / "scripts" / "run_claude_tui_local.py",
             root / "scripts" / "verify_claude_tui_local.py",
             root / "tests" / "test_claude_redact.py",
             root / "tests" / "test_claude_accept_pin.py",
             root / "tests" / "test_content_dlp_core.py",
             root / "scripts" / "prep_dlp_workspace.py",
             root / "pyproject.toml", root / "uv.lock"]
    return {path.relative_to(root).as_posix(): common.normalized_sha256(path)
            for path in paths}


def ensure_dll(pin: dict, binary: Path, *, root: Path = ROOT) -> Path:
    """Build a new immutable DLL name when the pin or source bytes change."""
    check_binary(pin, binary)
    sources = _sources(root)
    if not sources[0].is_file():
        raise FileNotFoundError(f"native hook implementation is absent: {sources[0]}")
    digests = {path.relative_to(root).as_posix(): common.normalized_sha256(path)
               for path in sources}
    key_material = json.dumps({"pin": pin["_sha256"], "sources": digests,
                               "defines": _defines(pin)}, sort_keys=True)
    key = hashlib.sha256(key_material.encode()).hexdigest()[:12]
    directory = root / "build" / "claude-guard-lab" / pin["claude_code_version"]
    dll = directory / f"ttrace-guard-claude-{key}.dll"
    manifest_path = dll.with_suffix(".json")
    if dll.is_file() and manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (manifest.get("dll_sha256") == common.file_sha256(dll)
                and manifest.get("sources") == digests
                and manifest.get("pin_sha256") == pin["_sha256"]):
            return dll
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / f"build-{os.getpid()}-{key}.dll"
    compiled = ["native/guard/claude_guard.c",
                "native/guard/third_party/minhook/src/buffer.c",
                "native/guard/third_party/minhook/src/hook.c",
                "native/guard/third_party/minhook/src/trampoline.c",
                "native/guard/third_party/minhook/src/hde/hde64.c",
                "native/guard/third_party/miniz/miniz.c",
                "native/guard/third_party/miniz/miniz_tdef.c",
                "native/guard/third_party/miniz/miniz_tinfl.c",
                "native/guard/third_party/miniz/miniz_zip.c"]
    try:
        subprocess.run([sys.executable, "-m", "ziglang", "cc", "-target",
                        "x86_64-windows-gnu", "-O2", "-shared", "-DJSMN_PARENT_LINKS",
                        "-DMINIZ_NO_STDIO", "-DMINIZ_NO_TIME",
                        "-DMINIZ_NO_ARCHIVE_APIS", "-DMINIZ_NO_ARCHIVE_WRITING_APIS",
                        *_defines(pin), *compiled, "-lbcrypt", "-o", str(temporary)],
                       cwd=root, check=True)
        os.replace(temporary, dll)
    finally:
        temporary.unlink(missing_ok=True)
    manifest = {"schema": BUILD_SCHEMA, "pin_sha256": pin["_sha256"],
                "binary_sha256": pin["binary"]["sha256"], "sources": digests,
                "dll": dll.name, "dll_sha256": common.file_sha256(dll)}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dll


def run_print(prompt: bytes, *, binary: Path | None = None, pin_path: Path = PIN_FILE,
              state_dir: Path = STATE_DIR,
              child_env: Mapping[str, str] | None = None,
              child_cwd: Path | None = None,
              child_args: Sequence[str] = (), child_stdout=None,
              child_stderr=None) -> int:
    """Launch one pinned print-mode child and release stdin only after ready."""
    from .desktop_service import Lease, current_user_sid, process_details, resident_guard_dlls
    from .native import inject, wait_ready
    from .pipe import PipeServer

    if not prompt or len(prompt) > MAX_PROMPT_BYTES:
        raise ValueError("prompt must contain 1 to 1048576 bytes")
    pin = load_pin(pin_path)
    binary = Path(binary or installed_claude()).resolve(strict=True)
    dll = ensure_dll(pin, binary)
    run_dir = Path(state_dir) / "runs" / f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{time.time_ns()}"
    run_dir.mkdir(parents=True, exist_ok=False)
    engine = _engine(run_dir)
    environment = dict(os.environ if child_env is None else child_env)
    # The pinned writer experiment covers identity-encoded JSON and model
    # traffic only. Keep that shape stable for both isolated and manual runs.
    environment["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    environment["CLAUDE_CODE_GZIP_REQUEST_BODIES"] = "0"
    child = subprocess.Popen([str(binary), "-p", "--max-turns", "1",
                              "--no-session-persistence", *child_args],
                             stdin=subprocess.PIPE, stdout=child_stdout,
                             stderr=child_stderr,
                             env=environment, cwd=child_cwd)
    pipe = lease = None
    released = False
    try:
        details = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and child.poll() is None:
            details = process_details(child.pid)
            if details is not None:
                break
            time.sleep(0.05)
        if details is None or child.poll() is not None:
            raise RuntimeError("Claude exited before its identity was established")
        if Path(details["image_path"]).resolve() != binary:
            raise RuntimeError("launched Claude image changed")
        if details["user_sid"] != current_user_sid():
            raise RuntimeError("Claude is running under a different user")
        check_binary(pin, Path(details["image_path"]))
        if resident_guard_dlls(child.pid):
            raise RuntimeError("Claude process already has a guard DLL")
        birth = details["creation_filetime"]
        identity = {"pid": child.pid, "creation_filetime": birth,
                    "guard_session_id": f"{child.pid}-{birth}",
                    "baseline": {"path": details["image_path"]}}
        policy_engine = common._DecisionLog(engine, {}, lambda *_args: None)
        pipe = PipeServer(child.pid, policy_engine, run_dir / "native-audit.jsonl",
                          client_sid=details["user_sid"])
        pipe.start()
        lease = Lease(child.pid, birth)
        lease.acquire()
        inject(child.pid, dll, identity,
               identity_resolver=lambda _pid: dict(identity))
        if not wait_ready(identity, 15):
            raise RuntimeError("Claude native hook did not become ready")
        if child.poll() is not None:
            raise RuntimeError("Claude exited before its prompt was released")
        assert child.stdin is not None
        child.stdin.write(prompt)
        child.stdin.close()
        released = True
        exit_code = child.wait()
        decisions = [row for row in pipe.records
                     if row.get("route_event") == "model.request"]
        allowed = sum(row.get("decision") == "allow" for row in decisions)
        denied = len(decisions) - allowed
        print(f"[Claude DLP lab] requests={len(decisions)} allow={allowed} "
              f"deny={denied} audit={run_dir}", file=sys.stderr, flush=True)
        # A successful CLI without any pipe decision is not evidence that the
        # child's model traffic passed the guard.
        return 2 if exit_code == 0 and not decisions else exit_code
    except BaseException:
        # An interrupted controller must not leave its owned child sending
        # additional requests after the local lease and pipe are gone.
        if child.poll() is None:
            child.kill()
        raise
    finally:
        if not released and child.poll() is None:
            child.kill()  # no prompt is released when attach fails
        child.wait(timeout=5)
        if lease is not None:
            lease.release(controlled=False)
        if pipe is not None:
            pipe.close()


# --------------------------------------------------------------------------
# Resident guard. A ready native hook is deliberately not full-coverage proof.
# --------------------------------------------------------------------------


def _not_accepted() -> tuple[bool, str]:
    return False, ("2.1.317 currently has one accepted HTTPS Messages path; "
                   "all model routes and session-preserving denial are unverified")


def _model_path_accepted() -> tuple[bool, str]:
    """Operator-enabled coverage gate for resident auto-attach.

    Only used when TTRACE_CLAUDE_ALLOW_ATTACH=1. The 2026-11-13 isolated
    acceptance covers the pinned Anthropic Messages HTTP/1.1 path with the
    session-preserving denial ABI (soft deny, zero retry budget), multi-turn
    denial, tool-result and base64-decoded tool-result scenarios. Provider
    shapes beyond ``anthropic_messages`` remain unverified and keep failing
    closed in the parser; the VM/WFP tool egress boundary is reported
    separately in status and does not block model-path attach under this
    operator switch.
    """
    try:
        if not accepted_pin_valid(load_pin()):
            if os.environ.get("TTRACE_CLAUDE_LIVE_TEST") == "1":
                return True, "实机证据采集模式（TTRACE_CLAUDE_LIVE_TEST=1，未正式验收）"
            return False, "当前 pin、源码或 DLL 未通过新版完整验收"
    except (OSError, ValueError):
        return False, "无法核对当前 pin 的验收印章"
    return True, ("固定版 Messages 路径已验收；其他提供商尚未验收")


def _egress_health() -> tuple[bool, str]:
    try:
        from .claude_egress import check_egress_health
        health = check_egress_health()
        return bool(health.ready), str(health.reason)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        return False, f"tool egress boundary unavailable: {type(error).__name__}: {error}"


def _same_path(left: str | Path, right: str | Path) -> bool:
    return ntpath.normcase(ntpath.normpath(str(left))) == ntpath.normcase(ntpath.normpath(str(right)))


@dataclass
class ClaudeProcessStatus:
    pid: int
    creation_filetime: int
    image_path: str
    state: str = "DISCOVERED"
    detail: str = ""
    mode: str = ""
    attach_ms: float | None = None
    attached_at: str = ""
    requests: int = 0
    allowed: int = 0
    denied: int = 0
    tools_allowed: int = 0
    tools_denied: int = 0
    last_decision: str = ""
    seen_at: float = field(default_factory=time.time)


class _Exited(Exception):
    pass


class _Incompatible(Exception):
    pass


class ClaudeController(threading.Thread):
    """One controller/lease for one process generation."""

    def __init__(self, details: dict, dll: Path, engine, run_dir: Path,
                 status: ClaudeProcessStatus, log: Callable[[str], None]):
        super().__init__(name=f"claude-guard-{details['pid']}", daemon=True)
        self.details, self.dll, self.engine = details, Path(dll), engine
        self.run_dir, self.status, self.log = Path(run_dir), status, log
        self.stop_requested = threading.Event()
        self.finished = threading.Event()
        self.controlled_stop = True

    def _decision(self, request, decision, rules, elapsed_ms):
        status = self.status
        status.requests += 1
        allowed = decision.decision == "allow"
        status.allowed += allowed
        status.denied += not allowed
        status.last_decision = datetime.now().strftime("%H:%M:%S")
        what = "放行" if allowed else "拒绝"
        reason = "" if allowed else f"  {', '.join(rules) or decision.reason}"
        size = len(request.payload_utf8.encode("utf-8", "surrogatepass")) / 1024
        self.log(f"[Claude {status.pid}] {what} {request.protocol} {size:.0f} KB "
                 f"{elapsed_ms:.0f} ms{reason}")

    def _tool(self, row: dict):
        status = self.status
        allowed = row["decision"] == "allow"
        status.tools_allowed += allowed
        status.tools_denied += not allowed
        if not allowed:
            self.log(f"[Claude {status.pid}] 拒绝工具进程：{row['reason']}")

    def run(self) -> None:
        from .desktop_service import Lease, _DecisionLog, _kernel, resident_guard_dlls
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
        kernel = _kernel()
        process = kernel.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE

        def alive() -> bool:
            return bool(process) and kernel.WaitForSingleObject(process, 0) == 258

        try:
            if not alive():
                raise _Exited()
            status.state = "ATTACHING"
            engine = _DecisionLog(self.engine, {}, self._decision, self._tool)
            pipe = PipeServer(pid, engine, self.run_dir / f"native-audit-{pid}-{birth}.jsonl",
                              client_sid=self.details["user_sid"])
            pipe.start()
            lease.acquire()
            for attempt in range(3):
                try:
                    resident = resident_guard_dlls(pid)
                    if not resident:
                        inject(pid, self.dll, identity,
                               identity_resolver=lambda _pid: dict(identity))
                        if not wait_ready(identity, 15):
                            raise RuntimeError("Claude native hook did not become ready")
                        status.mode = "injected"
                    elif resident == [self.dll.name]:
                        lease.resume()
                        if not wait_ready(identity, 2):
                            raise RuntimeError("resident Claude hook is not ready")
                        status.mode = "reconnected"
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
            status.attached_at = datetime.now().isoformat(timespec="seconds")
            status.state = "HOOK_READY_LIMITED"
            status.detail = "仅已验证的 Messages HTTPS 路径；完整模型与工具出口尚未验收"
            self.log(f"[Claude {pid}] Hook 已接入（{status.mode}, {status.attach_ms:.0f} ms）；"
                     "等待完整覆盖验收")
            while not self.stop_requested.wait(0.25):
                if kernel.WaitForSingleObject(process, 0) == 0:
                    status.state, status.detail = "EXITED", "Claude 进程已退出"
                    break
                if not any(worker.is_alive() for worker in pipe.threads):
                    raise RuntimeError("all local policy pipe workers stopped")
        except _Exited:
            status.state, status.detail = "EXITED", "进程在接入完成前已退出"
        except _Incompatible:
            controlled = False
            status.state, status.detail = "FAILED", "进程内已有另一版本 Guard DLL"
        except Exception as error:
            controlled = False
            status.state = "FAILED"
            status.detail = f"{type(error).__name__}: {error}"
            self.log(f"[Claude {pid}] 接入失败：{status.detail}")
        finally:
            was_ready = status.state in ("HOOK_READY_LIMITED", "PROTECTED")
            allow_direct = controlled and self.controlled_stop and status.state != "FAILED"
            if was_ready and allow_direct and alive() and not lease._stop_event(True):
                allow_direct = False
                status.state, status.detail = "FAILED_CLOSED", "Native stop event 不可用，保持拒绝"
            try:
                lease.release(controlled=allow_direct)
                if was_ready and status.state != "FAILED_CLOSED":
                    if allow_direct:
                        status.state, status.detail = "STOPPED", "防护已主动停止，Native Hook 直连放行"
                    else:
                        status.state, status.detail = "FAILED_CLOSED", "控制器异常退出，Native Hook 拒绝请求"
            except Exception as error:
                lease._stop_event(False)
                status.state, status.detail = "FAILED_CLOSED", f"租约释放失败：{type(error).__name__}"
            finally:
                if process:
                    kernel.CloseHandle(process)
                try:
                    if pipe is not None:
                        pipe.close()
                finally:
                    self.finished.set()


class ClaudeSupervisor:
    """Watch the exact npm CLI build; never attest unverified model routes."""

    def __init__(self, *, state_dir: Path = RESIDENT_STATE_DIR,
                 pin_path: Path = PIN_FILE, poll_seconds: float = 0.25,
                 log: Callable[[str], None] = print,
                 coverage_check: Callable[[], tuple[bool, str]] | None = None,
                 boundary_check: Callable[[], tuple[bool, str]] | None = None):
        self.state_dir, self.pin_path = Path(state_dir), Path(pin_path)
        self.poll, self.log = poll_seconds, log
        # 默认保持原有准入门闩（模型路径 + 工具出口都就绪才接入）。
        # 设置 TTRACE_CLAUDE_ALLOW_ATTACH=1 后，模型 Hook 验收通过即可
        # 自动接入；工具出口边界就绪与否只影响状态标注（PROTECTED /
        # HOOK_READY_LIMITED），不阻断模型路径接入。
        allow_attach = os.environ.get("TTRACE_CLAUDE_ALLOW_ATTACH") == "1"
        self.coverage_check = coverage_check or (
            _model_path_accepted if allow_attach else _not_accepted)
        self.boundary_check = boundary_check or _egress_health
        self.pin: dict | None = None
        self.target_path: Path | None = None
        self.dll: Path | None = None
        self.stop = threading.Event()
        self.started = datetime.now()
        self.run_dir = self.state_dir / "runs" / self.started.strftime("%Y%m%d-%H%M%S")
        self.processes: dict[tuple[int, int], ClaudeProcessStatus] = {}
        self.controllers: dict[tuple[int, int], ClaudeController] = {}
        self.hashes = common.ImageHashCache()
        self.kernel = common._kernel()
        self.coverage_ready = self.boundary_ready = False
        self.coverage_reason = self.boundary_reason = "not checked"
        self._had_full_readiness = False

    def _prepare(self):
        self.pin = load_pin(self.pin_path)
        self.user_sid = common.current_user_sid()
        self.target_path = installed_claude()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.engine = _engine(self.run_dir)
        self.dll = None

    def _consider(self, pid: int, details: dict | None = None):
        details = details if details is not None else common.process_details(pid)
        if not details or details["user_sid"] != self.user_sid:
            return
        key = (pid, details["creation_filetime"])
        previous = self.processes.get(key)
        if previous and previous.state != "ATTACH_DISABLED":
            return
        if previous and not self.coverage_ready:
            previous.detail = (f"等待模型路径完整验收："
                               f"模型={self.coverage_reason}")
            return
        status = previous or ClaudeProcessStatus(pid, key[1], details["image_path"])
        self.processes[key] = status
        if not _same_path(details["image_path"], self.target_path):
            status.state = "OUT_OF_SCOPE"
            status.detail = "非固定 npm CLI 路径（可能是 VS Code 扩展或 Claude Desktop）"
            return
        try:
            sha = self.hashes.sha256(details["image_path"])
            pin = self.pin
            if sha != pin["binary"]["sha256"]:
                # 多版本自动适配：找到"已验收"的新版本 pin 即热切换；
                # 没有则保持 fail-closed（拒绝注入）。
                alternate = pin_for_binary(sha)
                if alternate is None:
                    status.state, status.detail = "UNSUPPORTED_VERSION", \
                        f"SHA-256 {sha[:12]}… 无已验收 pin（fail-closed）"
                    return
                pin = alternate
                self.pin = pin
                self.dll = None  # 新 pin 编译入不同版本常量，需要新 DLL
            if not self.coverage_ready:
                # Fail-stop DLL injection is held until the model-path
                # acceptance covers this fixed version. The tool egress
                # boundary is reported in status but does not block attach
                # under the operator switch.
                status.state = "ATTACH_DISABLED"
                status.detail = (f"等待模型路径完整验收：模型={self.coverage_reason}")
                return
            check_binary(pin, Path(details["image_path"]))
            dll = self.dll or ensure_dll(pin, Path(details["image_path"]))
            self.dll = dll
        except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
            status.state, status.detail = "FAILED", f"固定版核验或构建失败：{error}"
            return
        controller = ClaudeController(details, dll, self.engine, self.run_dir, status, self.log)
        self.controllers[key] = controller
        self.log(f"[Claude {pid}] 发现已验收 npm 版 {pin['claude_code_version']}，正在接入")
        controller.start()

    @staticmethod
    def _checked(checker: Callable[[], tuple[bool, str]], name: str) -> tuple[bool, str]:
        try:
            ready, reason = checker()
            return bool(ready), str(reason)
        except Exception as error:
            return False, f"{name} check failed: {type(error).__name__}: {error}"

    def _refresh_readiness(self):
        self.coverage_ready, self.coverage_reason = self._checked(self.coverage_check, "coverage")
        self.boundary_ready, self.boundary_reason = self._checked(self.boundary_check, "egress")
        full = self.coverage_ready and self.boundary_ready
        if self._had_full_readiness and not full:
            # A status downgrade alone would leave the Native lease active.
            # Release it as a lost controller so further model writes fail
            # closed. The VM network boundary must independently remain in
            # force; a missing/tampered WFP rule cannot be repaired by a UI
            # state transition.
            for controller in self.controllers.values():
                if not controller.finished.is_set():
                    controller.controlled_stop = False
                    controller.stop_requested.set()
            self.log("Claude 准入条件失效；已接入 Native 租约转为失联拒绝，"
                     "虚拟机网络规则需管理员核验")
        self._had_full_readiness = full
        for status in self.processes.values():
            if status.state not in ("HOOK_READY_LIMITED", "PROTECTED"):
                continue
            target = "PROTECTED" if full else "HOOK_READY_LIMITED"
            if status.state != target:
                status.state = target
                self.log(f"[Claude {status.pid}] 状态变为 {target}")
            status.detail = ("模型 Hook 与工具出口均通过验收；只覆盖接入后的请求" if full else
                             f"完整验收未通过：模型={self.coverage_reason}; 出口={self.boundary_reason}")

    def state(self) -> dict:
        live = [row for row in self.processes.values() if row.state != "EXITED"]
        scoped = [row for row in live if row.state != "OUT_OF_SCOPE"]
        overall = ("READY" if (self.coverage_ready and self.boundary_ready and scoped
                               and all(row.state == "PROTECTED" for row in scoped))
                   else "WATCHING" if not scoped else "NOT_READY")
        return {"schema": RESIDENT_STATE_SCHEMA, "supervisor_pid": os.getpid(),
                "started_at": self.started.isoformat(timespec="seconds"),
                "updated_at": datetime.now().isoformat(timespec="seconds"),
                "run_dir": str(self.run_dir), "target_path": str(self.target_path or ""),
                "target_version": self.pin["claude_code_version"] if self.pin else "unknown",
                "overall": overall,
                "coverage": {"ready": self.coverage_ready, "reason": self.coverage_reason},
                "egress": {"ready": self.boundary_ready, "reason": self.boundary_reason},
                "processes": [vars(row).copy() for row in self.processes.values()]}

    def _mark_exits(self, current: set[int], current_births: dict[int, int]):
        for (pid, birth), status in self.processes.items():
            generation_gone = (pid not in current or
                               (pid in current_births and current_births[pid] != birth))
            if generation_gone and status.state != "EXITED":
                status.state = "EXITED"
                status.detail = "进程已退出"

    def run(self):
        kernel = self.kernel
        guard = kernel.CreateMutexW(None, True, SUPERVISOR_MUTEX)
        if not guard:
            raise RuntimeError("cannot create Claude supervisor mutex")
        if common.c.get_last_error() == 183:
            kernel.CloseHandle(guard)
            raise RuntimeError("Claude 防护已在运行（./start.sh claude status 查看）")
        stop_event = kernel.CreateEventW(None, True, False, SUPERVISOR_STOP)
        if not stop_event:
            kernel.ReleaseMutex(guard)
            kernel.CloseHandle(guard)
            raise RuntimeError("cannot create Claude supervisor stop event")
        kernel.ResetEvent(stop_event)
        state_file = self.state_dir / "state.json"
        orderly = False
        try:
            self._prepare()
            self.log(f"Claude 防护正在监视固定 npm 版；记录目录：{self.run_dir}")
            last_write = last_health = 0.0
            while not self.stop.is_set() and kernel.WaitForSingleObject(stop_event, 0) != 0:
                if time.monotonic() - last_health >= 1:
                    self._refresh_readiness()
                    last_health = time.monotonic()
                current = {pid for pid, _parent, exe in common.list_processes()
                           if exe.lower() == "claude.exe"}
                current_births = {}
                # Recheck creation time on every scan so rapid PID reuse is visible.
                for pid in sorted(current):
                    details = common.process_details(pid)
                    if details is not None:
                        current_births[pid] = details["creation_filetime"]
                        self._consider(pid, details)
                self._mark_exits(current, current_births)
                if time.monotonic() - last_write >= 1:
                    common._write_state(state_file, self.state())
                    last_write = time.monotonic()
                time.sleep(self.poll)
            orderly = True
        except KeyboardInterrupt:
            self.stop.set()
            orderly = True
        finally:
            for controller in self.controllers.values():
                controller.controlled_stop = orderly
                controller.stop_requested.set()
            for controller in self.controllers.values():
                if not controller.finished.wait(5):
                    controller.controlled_stop = False
                    orderly = False
            if any(status.state == "FAILED_CLOSED" for status in self.processes.values()):
                orderly = False
            try:
                if self.state_dir.is_dir():
                    final = self.state()
                    final["overall"] = "STOPPED" if orderly else "FAILED_CLOSED"
                    final["stopped_at"] = datetime.now().isoformat(timespec="seconds")
                    common._write_state(state_file, final)
                self.log("Claude Native 防护已主动停止" if orderly else
                         "Claude 驻守服务异常退出；已注入进程保持拒绝")
            finally:
                kernel.CloseHandle(stop_event)
                kernel.ReleaseMutex(guard)
                kernel.CloseHandle(guard)


def request_claude_stop() -> bool:
    kernel = common._kernel()
    event = kernel.OpenEventW(0x0002, False, SUPERVISOR_STOP)
    if not event:
        return False
    try:
        return bool(kernel.SetEvent(event))
    finally:
        kernel.CloseHandle(event)


def read_claude_state(state_dir: Path = RESIDENT_STATE_DIR) -> dict | None:
    try:
        return json.loads((Path(state_dir) / "state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
