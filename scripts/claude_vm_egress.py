"""Explicit isolated-VM setup and foreground tool proxy for Claude demo.

Run from an elevated administrator shell in an isolated VM. The Claude CLI and
its tools must run under a *different*, dedicated local user SID. This script
never installs policy unless `setup` is explicitly requested. It does not
create enterprise acceptance evidence, so the resident guard remains in
ATTACH_DISABLED rather than PROTECTED after only this setup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.behavior.desktop_wfp import WfpBoundary, _own_creation_filetime  # noqa: E402
from transpect_trace.guard import claude_egress as egress  # noqa: E402
from transpect_trace.guard.desktop_service import process_details  # noqa: E402
from transpect_trace.guard import claude_service as claude_lab  # noqa: E402


def _proxy_birth(pid: int) -> int:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        row = process_details(pid)
        if row and row.get("creation_filetime"):
            return row["creation_filetime"]
        time.sleep(0.05)
    raise RuntimeError("proxy process identity unavailable")


def _wait_proxy(config: egress.EgressConfig, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and process.poll() is None:
        try:
            if egress._proxy_health(config):
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("inspection proxy did not report its addon challenge")


def _write_config(path: Path, config: egress.EgressConfig) -> None:
    value = {"schema": egress.CONFIG_SCHEMA, "isolated_vm": True,
             "wfp_executable": str(config.wfp_executable),
             "dedicated_sid": config.dedicated_sid,
             "proxy_host": config.proxy_host, "proxy_port": config.proxy_port,
             "v4_filter_id": config.v4_filter_id, "v6_filter_id": config.v6_filter_id}
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _publish_public_ca(state_dir: Path, config_path: Path) -> Path:
    source = state_dir / "mitmproxy" / "mitmproxy-ca-cert.pem"
    if not source.is_file():
        raise RuntimeError("proxy CA public certificate was not generated")
    target = config_path.with_suffix(".ca.pem")
    target.write_bytes(source.read_bytes())  # certificate only; private key stays admin-only
    return target


def _create_acl_directory(path: Path, *, user_read: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(exist_ok=False)
    grants = ["*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"]
    if user_read:
        grants.append("*S-1-5-32-545:(OI)(CI)RX")
    for operation in (("/inheritance:r",), ("/grant:r", *grants)):
        subprocess.run(["icacls", str(path), *operation], check=True,
                       capture_output=True, text=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _write_setup_marker(*, sid: str, wfp_exe: Path, config: Path) -> None:
    marker = egress.DEFAULT_MARKER
    if marker.exists():
        value = json.loads(marker.read_text(encoding="utf-8"))
        if (value.get("dedicated_sid") != sid or
                Path(value.get("wfp_executable", "")).resolve() != wfp_exe or
                Path(value.get("config", "")).resolve() != config.resolve()):
            raise RuntimeError("another VM egress setup marker already exists")
        return
    _create_acl_directory(marker.parent, user_read=True)
    marker.write_text(json.dumps({
        "schema": "transpect.claude-egress-setup/1.0",
        "dedicated_sid": sid, "wfp_executable": str(wfp_exe),
        "config": str(config.resolve()),
    }, indent=2) + "\n", encoding="utf-8")


def _mitmdump() -> Path:
    name = "mitmdump.exe" if os.name == "nt" else "mitmdump"
    executable = Path(sys.executable).with_name(name)
    if not executable.is_file():
        raise RuntimeError("install the locked claude-proxy extra first")
    return executable


def run(args) -> int:
    marker = egress.DEFAULT_MARKER
    if not marker.is_file():
        raise RuntimeError("run requires an explicit VM setup marker")
    setup = json.loads(marker.read_text(encoding="utf-8"))
    if (setup.get("dedicated_sid") != args.sid or
            Path(setup.get("wfp_executable", "")).resolve() != args.wfp_exe or
            Path(setup.get("config", "")).resolve() != args.config.resolve()):
        raise RuntimeError("VM setup marker does not match proxy run")
    boundary = WfpBoundary(args.wfp_exe, args.sid, isolated_vm=True)
    boundary.assert_default_deny()
    # The proxy's mitmproxy CA private key is generated under this directory.
    # Require a fresh directory, then remove inherited Users access before any
    # key material is written. A repeat run must name a new state directory.
    _create_acl_directory(args.state_dir, user_read=False)
    _create_acl_directory(args.config.parent, user_read=True)
    source_addon = ROOT / "scripts" / "claude_tool_proxy_addon.py"
    frozen_addon = args.state_dir / "claude_tool_proxy_addon.py"
    frozen_addon.write_bytes(source_addon.read_bytes())
    addon_sha256 = hashlib.sha256(frozen_addon.read_bytes()).hexdigest()
    mitmdump = _mitmdump()
    environment = dict(os.environ)
    environment["TTRACE_CLAUDE_PROXY_STATE"] = str(args.state_dir)
    environment["TTRACE_ROOT"] = str(ROOT)
    command = [str(mitmdump), "--mode", f"regular@127.0.0.1:{args.port}",
               "--mode", f"regular@[::1]:{args.port}",
               "--set", "flow_detail=0", "--set", "body_size_limit=16m",
               "--set", f"confdir={args.state_dir / 'mitmproxy'}",
               "-s", str(frozen_addon)]
    proxy = subprocess.Popen(command, env=environment,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    lease = None
    try:
        initial = egress.EgressConfig(args.wfp_exe, args.sid, "127.0.0.1", args.port, 1, 2)
        _wait_proxy(initial, proxy)
        lease = egress.start_proxy_permit(
            executable=args.wfp_exe, sid=args.sid, port=args.port,
            controller_pid=os.getpid(), controller_birth=_own_creation_filetime(),
            proxy_pid=proxy.pid, proxy_birth=_proxy_birth(proxy.pid))
        config = egress.EgressConfig(args.wfp_exe, args.sid, "127.0.0.1", args.port,
                                     lease.v4_filter_id, lease.v6_filter_id)
        if not egress._native_status(config):
            raise RuntimeError("proxy WFP permit failed readback")
        _write_config(args.config, config)
        ca = _publish_public_ca(args.state_dir, args.config)
        print(json.dumps({"state": "TOOL_PROXY_RUNNING", "proxy_port": args.port,
                          "v4_filter_id": lease.v4_filter_id,
                          "v6_filter_id": lease.v6_filter_id,
                          "public_ca": str(ca),
                          "addon_sha256": addon_sha256,
                          "full_dlp_acceptance": False}), flush=True)
        while proxy.poll() is None and lease.process.poll() is None:
            if hashlib.sha256(frozen_addon.read_bytes()).hexdigest() != addon_sha256:
                raise RuntimeError("proxy addon changed during the protected session")
            time.sleep(0.2)
        raise RuntimeError("proxy or WFP permit stopped unexpectedly")
    except KeyboardInterrupt:
        return 0
    finally:
        if lease:
            lease.close()
        if proxy.poll() is None:
            proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.wait(timeout=5)


def model_lease(args) -> int:
    """Permit one ready, pinned Claude image to one literal model destination."""
    if not args.pid or not args.model_ip or not args.model_port:
        raise ValueError("model-lease needs --pid, --model-ip and --model-port")
    details = process_details(args.pid)
    if not details or details["user_sid"] != args.sid:
        raise RuntimeError("target Claude PID/SID is not live and verified")
    binary = Path(details["image_path"]).resolve(strict=True)
    expected_tail = ("appdata", "roaming", "npm", "node_modules", "@anthropic-ai",
                     "claude-code", "bin", "claude.exe")
    if tuple(part.lower() for part in binary.parts[-len(expected_tail):]) != expected_tail:
        raise RuntimeError("target is not the pinned npm Claude CLI")
    pin = claude_lab.load_pin()
    claude_lab.check_binary(pin, binary)
    boundary = WfpBoundary(args.wfp_exe, args.sid, isolated_vm=True)
    lease = boundary.start_guarded_lease(
        pid=args.pid, creation_filetime=details["creation_filetime"],
        image_sha256=pin["binary"]["sha256"], ip=args.model_ip,
        port=args.model_port, seconds=args.seconds)
    try:
        print(json.dumps({"state": "MODEL_DESTINATION_PERMIT_ACTIVE",
                          "pid": args.pid, "filter_id": lease.filter_id,
                          "pid_exact_filter": lease.pid_exact_filter,
                          "destination": f"{args.model_ip}:{args.model_port}",
                          "full_dlp_acceptance": False}), flush=True)
        while lease.alive:
            time.sleep(0.2)
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        lease.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true", required=True)
    parser.add_argument("--sid", required=True)
    parser.add_argument("--wfp-exe", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18765)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--model-ip")
    parser.add_argument("--model-port", type=int)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--config", type=Path, default=egress.DEFAULT_CONFIG)
    parser.add_argument("--state-dir", type=Path,
                        default=Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) /
                        "TranspectTrace" / "claude-tool-proxy")
    parser.add_argument("command", choices=("setup", "run", "status", "teardown", "model-lease"))
    args = parser.parse_args()
    args.wfp_exe = args.wfp_exe.resolve(strict=True)
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    boundary = WfpBoundary(args.wfp_exe, args.sid, isolated_vm=True)
    if args.command == "setup":
        _write_setup_marker(sid=args.sid, wfp_exe=args.wfp_exe, config=args.config)
        try:
            boundary.assert_default_deny()
        except Exception:
            boundary.install_default_deny()
        print(json.dumps({"default_deny_installed": True, "sid": args.sid}))
        return 0
    if args.command == "run":
        return run(args)
    if args.command == "model-lease":
        return model_lease(args)
    if args.command == "status":
        health = egress.check_egress_health(args.config)
        print(json.dumps(health.__dict__))
        return 0 if health.wfp_verified and health.permit_verified and health.proxy_verified else 1
    marker = egress.DEFAULT_MARKER
    value = None
    if marker.is_file():
        value = json.loads(marker.read_text(encoding="utf-8"))
        if value.get("dedicated_sid") != args.sid:
            raise RuntimeError("VM setup marker belongs to a different SID")
    boundary._command("remove-if-present")
    if value is not None:
        config_path = Path(value.get("config", ""))
        if config_path.is_file():
            config_path.unlink()
        public_ca = config_path.with_suffix(".ca.pem")
        if public_ca.is_file():
            public_ca.unlink()
        marker.unlink()
        marker.parent.rmdir()
    print(json.dumps({"default_deny_removed": True, "sid": args.sid}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
