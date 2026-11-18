"""Isolated-VM Claude tool egress boundary and conservative readiness probe.

The WFP helper's persistent SID blocks are installed only by an operator in an
isolated VM. A dynamic SID-wide exception permits TCP to one local inspection
proxy port; it never grants external network access to a tool process. This
module deliberately does not treat a healthy proxy and filter readback as a
completed VM acceptance test. Until that test has durable, admin-owned evidence,
``ready`` remains false and the resident Claude service must not claim full
protection.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from queue import Empty, Queue
import re
import socket
import subprocess
import threading
import time

from transpect_trace.behavior.desktop_wfp import WfpBoundary, WfpBoundaryError


CONFIG_ENV = "TTRACE_CLAUDE_EGRESS_CONFIG"
CONFIG_SCHEMA = "transpect.claude-egress-vm/1.0"
DEFAULT_CONFIG = (Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) /
                  "TranspectTrace" / "claude-egress-control" / "egress.json")
DEFAULT_MARKER = (Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) /
                  "TranspectTrace" / "claude-egress-setup" / "marker.json")
_SID = re.compile(r"S-1-5-21-(?:\d+-){2}\d+-\d+\Z")


class EgressBoundaryError(RuntimeError):
    pass


@dataclass(frozen=True)
class EgressHealth:
    ready: bool
    reason: str
    wfp_verified: bool = False
    permit_verified: bool = False
    proxy_verified: bool = False
    vm_accepted: bool = False


@dataclass(frozen=True)
class EgressConfig:
    wfp_executable: Path
    dedicated_sid: str
    proxy_host: str
    proxy_port: int
    v4_filter_id: int
    v6_filter_id: int

    @classmethod
    def load(cls, path: Path) -> "EgressConfig":
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if (not isinstance(value, dict) or value.get("schema") != CONFIG_SCHEMA
                or value.get("isolated_vm") is not True):
            raise ValueError("Claude egress configuration requires an isolated VM")
        allowed = {"schema", "isolated_vm", "wfp_executable", "dedicated_sid",
                   "proxy_host", "proxy_port", "v4_filter_id", "v6_filter_id"}
        if set(value) != allowed:
            raise ValueError("Claude egress configuration fields differ from schema")
        exe = Path(value["wfp_executable"])
        sid, host, port = value["dedicated_sid"], value["proxy_host"], value["proxy_port"]
        ids = value["v4_filter_id"], value["v6_filter_id"]
        if (not exe.is_absolute() or not exe.is_file() or not isinstance(sid, str)
                or not _SID.fullmatch(sid) or host != "127.0.0.1"
                or type(port) is not int or not 1 <= port <= 65535
                or any(type(item) is not int or item <= 0 for item in ids)
                or ids[0] == ids[1]):
            raise ValueError("invalid Claude VM egress identity or proxy endpoint")
        return cls(exe.resolve(strict=True), sid, host, port, *ids)


def _config_path(path: Path | None) -> Path:
    return Path(path or os.environ.get(CONFIG_ENV, DEFAULT_CONFIG))


def _native_status(config: EgressConfig) -> bool:
    args = [str(config.wfp_executable), "proxy-status", config.dedicated_sid,
            str(config.v4_filter_id), str(config.v6_filter_id), str(config.proxy_port),
            "--isolated-vm"]
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=3, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        row = json.loads(result.stdout.splitlines()[-1])
    except (IndexError, ValueError) as error:
        raise EgressBoundaryError("proxy WFP permit returned no valid status") from error
    return bool(result.returncode == 0 and row.get("error") == 0
                and row.get("proxy_permit_verified") is True
                and row.get("v4_filter_id") == config.v4_filter_id
                and row.get("v6_filter_id") == config.v6_filter_id
                and row.get("port") == config.proxy_port)


def _proxy_health(config: EgressConfig) -> bool:
    nonce = os.urandom(12).hex()
    request = ("GET http://transpect.invalid/__ttrace_health HTTP/1.1\r\n"
               "Host: transpect.invalid\r\n"
               f"X-TTrace-Nonce: {nonce}\r\nConnection: close\r\n\r\n").encode("ascii")
    for host in (config.proxy_host, "::1"):
        with socket.create_connection((host, config.proxy_port), timeout=0.5) as conn:
            conn.settimeout(0.5)
            conn.sendall(request)
            response = conn.recv(2048)
        if not (response.startswith(b"HTTP/1.1 204 ") and
                f"X-TTrace-Nonce: {nonce}".encode("ascii") in response and
                b"X-TTrace-Proxy: claude-egress/1" in response):
            return False
    return True


_health_cache: tuple[float, str, EgressHealth] | None = None
_health_lock = threading.Lock()


def check_egress_health(config_path: Path | None = None) -> EgressHealth:
    """Read-only probe; always conservative until live VM acceptance exists."""
    global _health_cache
    path = _config_path(config_path)
    key = str(path.resolve())
    with _health_lock:
        if _health_cache and _health_cache[1] == key and time.monotonic() - _health_cache[0] < 1:
            return _health_cache[2]
    if not path.is_file():
        result = EgressHealth(False, "VM_CONFIG_MISSING")
    else:
        try:
            config = EgressConfig.load(path)
            boundary = WfpBoundary(config.wfp_executable, config.dedicated_sid,
                                   isolated_vm=True)
            boundary.assert_default_deny()
        except (OSError, ValueError, WfpBoundaryError, subprocess.TimeoutExpired) as error:
            result = EgressHealth(False, f"WFP_NOT_ATTESTED:{type(error).__name__}")
        else:
            try:
                permit = _native_status(config)
            except (OSError, ValueError, EgressBoundaryError, subprocess.TimeoutExpired):
                permit = False
            if not permit:
                result = EgressHealth(False, "PROXY_PERMIT_NOT_ATTESTED", wfp_verified=True)
            else:
                try:
                    proxy = _proxy_health(config)
                except OSError:
                    proxy = False
                if not proxy:
                    result = EgressHealth(False, "PROXY_UNAVAILABLE", True, True)
                else:
                    # Filter shape and liveness do not establish an observed
                    # zero-byte deny at the origin. Never infer VM acceptance.
                    result = EgressHealth(False, "VM_ACCEPTANCE_PENDING", True, True, True)
    with _health_lock:
        _health_cache = (time.monotonic(), key, result)
    return result


def stop_egress(config_path: Path | None = None) -> None:
    """Explicit elevated VM teardown. Failure leaves default-deny in place."""
    path = _config_path(config_path)
    if not path.is_file():
        if DEFAULT_MARKER.is_file():
            raise EgressBoundaryError("NETWORK_RULES_UNKNOWN: VM setup marker exists without runtime config")
        return  # No VM setup marker or config exists for this account.
    try:
        config = EgressConfig.load(path)
        boundary = WfpBoundary(config.wfp_executable, config.dedicated_sid,
                               isolated_vm=True)
        boundary._command("remove-if-present")
    except (OSError, ValueError, WfpBoundaryError, subprocess.TimeoutExpired) as error:
        raise EgressBoundaryError("NETWORK_RULES_REMAIN: administrator VM teardown failed") from error
    global _health_cache
    with _health_lock:
        _health_cache = None


@dataclass
class ProxyPermitLease:
    process: subprocess.Popen
    v4_filter_id: int
    v6_filter_id: int

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()


def start_proxy_permit(*, executable: Path, sid: str, port: int,
                       controller_pid: int, controller_birth: int,
                       proxy_pid: int, proxy_birth: int) -> ProxyPermitLease:
    """Start a dynamic loopback-only WFP permit from an elevated VM controller."""
    if (not _SID.fullmatch(sid) or not 1 <= port <= 65535
            or controller_pid <= 0 or controller_birth <= 0
            or proxy_pid <= 0 or proxy_birth <= 0 or proxy_pid == controller_pid):
        raise ValueError("invalid isolated VM proxy permit identity")
    args = [str(Path(executable).resolve(strict=True)), "proxy-lease", sid, str(port),
            str(controller_pid), str(controller_birth), str(proxy_pid), str(proxy_birth),
            "--isolated-vm"]
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace",
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    lines: Queue[str] = Queue(maxsize=1)
    threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
    try:
        row = json.loads(lines.get(timeout=10))
        if (process.poll() is not None or row.get("state") != "proxy_permit_active"
                or row.get("sid_wide") is not True or row.get("loopback_only") is not True
                or row.get("pid_exact_filter") is not False
                or type(row.get("v4_filter_id")) is not int
                or type(row.get("v6_filter_id")) is not int
                or row["v4_filter_id"] <= 0 or row["v6_filter_id"] <= 0):
            raise ValueError("proxy WFP permit did not become active")
        return ProxyPermitLease(process, row["v4_filter_id"], row["v6_filter_id"])
    except (Empty, ValueError, TypeError) as error:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()
        raise EgressBoundaryError("proxy WFP permit startup failed") from error
