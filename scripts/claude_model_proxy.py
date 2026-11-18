"""Start the limited Claude model proxy with an explicit upstream allowlist.

By default this starts a proxy only. --claude launches one pinned CLI process
through it. Neither route setting is an enforced egress boundary.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard.claude_model_proxy import (  # noqa: E402
    CONFIG_SCHEMA, ModelProxyConfig,
)
from transpect_trace.guard import claude_service as svc  # noqa: E402


def _trusted_in_windows(cert: Path) -> bool:
    if not hasattr(ssl, "enum_certificates"):
        return False
    expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        cert.read_text(encoding="ascii"))).digest()
    return any(encoding == "x509_asn" and hashlib.sha256(raw).digest() == expected
               for raw, encoding, _trust in ssl.enum_certificates("ROOT"))


def _supervise_child(child: subprocess.Popen, proxy: subprocess.Popen) -> int:
    while child.poll() is None:
        if proxy.poll() is not None:
            print("模型代理已退出，正在结束此 Claude 会话。", file=sys.stderr,
                  flush=True)
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            return 1
        time.sleep(0.2)
    return child.returncode


def serve(args) -> int:
    mitmdump = Path(sys.executable).with_name("mitmdump.exe")
    if not mitmdump.is_file():
        raise RuntimeError("mitmdump is unavailable; install the locked claude-proxy extra")
    state = args.state_dir.resolve() if args.state_dir else (
        Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TranspectTrace" /
        "claude-model-proxy" / "runs" / datetime.now().strftime("%Y%m%d-%H%M%S"))
    state.mkdir(parents=True, exist_ok=False)
    confdir = Path.home() / ".mitmproxy" if args.ca == "windows-store" else state / "mitmproxy"
    if args.ca == "ephemeral":
        confdir.mkdir()
    else:
        cert = confdir / "mitmproxy-ca-cert.pem"
        if not cert.is_file() or not _trusted_in_windows(cert):
            raise RuntimeError("mitmproxy CA is not trusted in the Windows user root store")
    config_path = state / "model-proxy.json"
    config_path.write_text(json.dumps({
        "schema": CONFIG_SCHEMA, "state_dir": str(state),
        "session_id": uuid.uuid4().hex,
        "allowed_origins": args.origin,
        "allow_http_loopback": args.allow_http_loopback,
        "deny_message": args.deny_message,
    }, indent=2), encoding="utf-8")
    ModelProxyConfig.load(config_path)
    environment = dict(os.environ, TTRACE_CLAUDE_MODEL_PROXY_CONFIG=str(config_path))
    command = [str(mitmdump), "--mode", f"regular@127.0.0.1:{args.port}",
               "--set", f"confdir={confdir}",
               "--set", "connection_strategy=lazy", "--set", "upstream_cert=false",
               "--set", "ssl_insecure=false", "--set", "http3=false",
               "--set", "body_size_limit=16m", "--set", "flow_detail=0",
               "-s", str(ROOT / "scripts" / "claude_model_proxy_addon.py")]
    # Claude owns this interactive console. Keep mitmdump's live flow logs in
    # its run directory so they cannot overwrite the TUI's input and status.
    proxy_log = (state / "proxy-process.log").open("ab", buffering=0)
    try:
        process = subprocess.Popen(
            command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=proxy_log, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        proxy_log.close()
        raise
    child = None
    try:
        deadline = time.monotonic() + 20
        while process.poll() is None and time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", args.port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("model proxy did not become ready")
        print("PROXY_READY_LIMITED：代理仅在请求实际经过此端口时生效。", flush=True)
        print(f"代理地址：http://127.0.0.1:{args.port}", flush=True)
        print(f"允许上游：{', '.join(args.origin)}", flush=True)
        print(f"审计目录：{state}", flush=True)
        print(f"代理日志：{state / 'proxy-process.log'}", flush=True)
        if args.ca == "ephemeral":
            print(f"客户端需信任本次生成的 CA：{confdir / 'mitmproxy-ca-cert.pem'}",
                  flush=True)
        print("关闭此窗口会停止代理；尚无防直连网络门闩。", flush=True)
        if not args.claude:
            return process.wait()
        binary = svc.installed_claude()
        svc.check_binary(svc.load_pin(), binary)
        # The Hook supervisor only attaches to the installed CLI path. An
        # isolated, revalidated image keeps the two routes separate.
        isolated_binary = state / "claude.exe"
        try:
            os.link(binary, isolated_binary)
        except OSError:
            shutil.copy2(binary, isolated_binary)
        svc.check_binary(svc.load_pin(), isolated_binary)
        child_env = dict(os.environ)
        child_env.update(HTTPS_PROXY=f"http://127.0.0.1:{args.port}",
                         HTTP_PROXY=f"http://127.0.0.1:{args.port}", NO_PROXY="")
        print("已启动固定版 Claude；该进程使用本地代理。", flush=True)
        workspace = args.workspace.resolve(strict=True)
        if not workspace.is_dir():
            raise ValueError("workspace must be a directory")
        child = subprocess.Popen([str(isolated_binary)], cwd=workspace, env=child_env)
        return _supervise_child(child, process)
    except KeyboardInterrupt:
        return 130
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        proxy_log.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", action="append", required=True,
                        help="permitted upstream origin, e.g. https://api.anthropic.com")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--ca", choices=("windows-store", "ephemeral"),
                        default="windows-store")
    parser.add_argument("--allow-http-loopback", action="store_true",
                        help="isolated local-origin tests only")
    parser.add_argument("--deny-message", default="本地 DLP 已拒绝请求：{reason}。",
                        help="local 403 message; {reason} inserts a safe reason category")
    parser.add_argument("--claude", action="store_true",
                        help="launch isolated pinned Claude TUI and stop proxy when it exits")
    parser.add_argument("--workspace", type=Path, default=ROOT,
                        help="working directory for --claude (default: repository root)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        return serve(args)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"模型代理启动失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
