"""Start both client supervisors and a separate persistent read-only monitor."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import hub

TASK_NAME = "TranspectTrace Unified Guard"


def start(live_test=False, *, recover_pid: int | None = None) -> int:
    stop_file = hub.STATE_DIR / hub.STOP_INTENT_FILE
    state = hub.read_json(hub.STATE_DIR / "state.json")
    if recover_pid is not None:
        if not hub.recovery_allowed(state, stop_requested=stop_file.exists(), expected_pid=recover_pid):
            print("未执行自动恢复：已有停止意图或观察到的 hub 代次已改变。")
            return 0
        # Recovery inherits persisted mode; it cannot invent a weaker gate.
        live_test = bool(state.get("claude_live_test"))
    if hub.mutex_running(hub.MUTEX):
        print("统一守护已在运行；保留现有会话与启动配置。")
        if live_test and not state.get("claude_live_test"):
            print("当前不是 Claude 实机采证模式；本次命令不会热改现有守护配置。")
        return status()
    if recover_pid is None:
        stop_file.unlink(missing_ok=True)
    elif stop_file.exists():
        return 0
    args = [sys.executable, str(Path(__file__).resolve()), "run"]
    if live_test:
        args.append("--claude-live-test")
    child = hub.hidden_process(args, log_name="hub.log")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if hub.mutex_running(hub.MUTEX):
            print("统一守护已启动：同时监视 Codex 桌面端与固定版 Claude CLI。")
            print("独立监视窗会自动打开；关闭按钮只最小化，关闭当前终端不会停止守护。")
            print(r"可以用 .\guard-service.bat status 查看各进程的防护状态，用 .\guard-service.bat stop 停止。")
            return 0
        if child.poll() is not None:
            break
        time.sleep(0.1)
    print(f"启动失败，请查看 {hub.STATE_DIR / 'hub.log'}", file=sys.stderr)
    return 1


def status(as_json=False) -> int:
    state = hub.read_json(hub.STATE_DIR / "state.json")
    running = hub.mutex_running(hub.MUTEX)
    state["hub_running"] = running
    # Refresh liveness now; an old file must never look like active protection.
    state["services"] = {name: hub.service_snapshot(name,
        hub.read_json(hub.STATE_DIR.parent / directory / "state.json"),
        running=hub.mutex_running(hub.SERVICE_MUTEXES[name]),
        experimental=name == "claude" and bool(state.get("claude_live_test")))
        for name, directory in hub.SERVICE_DIRS.items()}
    if as_json:
        print(json.dumps(state, ensure_ascii=False, indent=2))
    else:
        print(f"统一守护：{'运行中' if running else '未运行'}")
        for name, service in state["services"].items():
            print(f"{name}: {service['status']}；守护 PID {service.get('supervisor_pid') or '-'}")
            for row in service["processes"]:
                print(f"  PID {row['pid']}: {row['state']}；请求 {row['requests'] or 0}，"
                      f"放行 {row['allowed'] or 0}，拒绝 {row['denied'] or 0}")
        print(f"状态与诊断日志：{hub.STATE_DIR}")
    return 0 if running else 1


def stop() -> int:
    state = hub.read_json(hub.STATE_DIR / "state.json")
    hub.atomic_json(hub.STATE_DIR / hub.STOP_INTENT_FILE,
                    {"schema": "transpect.guard-hub.stop-request/1.0", "hub_pid": state.get("pid")})
    if not hub.signal_stop():
        print("统一守护未运行；自动恢复已停用，未停止独立启动的客户端守护。")
        return 1
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and hub.mutex_running(hub.MUTEX):
        time.sleep(0.25)
    state = hub.read_json(hub.STATE_DIR / "state.json")
    if hub.mutex_running(hub.MUTEX) or state.get("status") != "STOPPED":
        print("停止尚未完整确认，请检查状态；未强制终止客户端。", file=sys.stderr)
        return 2
    print("统一守护已停止；客户端会话保留。停止后不再提供该门控防护。")
    return 0


def install() -> int:
    # An explicit experimental startup is allowed, but never persisted as daily protection.
    from transpect_trace.guard import claude_service as claude
    try:
        ready = claude.accepted_pin_valid(claude.load_pin())
        boundary, reason = claude._egress_health()
    except Exception as error:
        print(f"无法确认安装验收：{error}", file=sys.stderr)
        return 2
    if not ready or not boundary:
        print(f"拒绝日常自启安装：Claude 完整验收未通过（模型={ready}；出口={reason}）。"
              "可先用 start --claude-live-test 明示有限采证模式。", file=sys.stderr)
        return 2
    codex = hub.service_snapshot("codex",
        hub.read_json(hub.STATE_DIR.parent / "desktop-guard" / "state.json"),
        running=hub.mutex_running(hub.SERVICE_MUTEXES["codex"]))
    if codex["status"] != "PROTECTED":
        print("拒绝日常自启安装：Codex 尚无新鲜的模型与工具出口完整验收状态。", file=sys.stderr)
        return 2
    # PowerShell registers an interactive per-user task with failure recovery.
    script = ROOT / "scripts" / "install_guard_hub.ps1"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-File", str(script),
                             "-PythonPath", sys.executable, "-ScriptPath", str(Path(__file__).resolve())])
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command")
    for name in ("start", "run"):
        sub = subs.add_parser(name)
        sub.add_argument("--claude-live-test", action="store_true",
                         help="固定版实验接入；仍显示未完整验收，不自动接受新版本")
        sub.add_argument("--background", action="store_true", help=argparse.SUPPRESS)
        if name == "start":
            sub.add_argument("--recover-hub-pid", type=int, help=argparse.SUPPRESS)
        else:
            sub.add_argument("--new-session", action="store_true", help=argparse.SUPPRESS)
    sub = subs.add_parser("status")
    sub.add_argument("--json", action="store_true")
    for name in ("stop", "watch", "build", "install", "uninstall"):
        subs.add_parser(name)
    args = parser.parse_args()
    choice = args.command or "start"
    if choice == "run":
        return hub.Hub(live_test=args.claude_live_test, new_session=args.new_session).run()
    if choice == "start":
        return start(getattr(args, "claude_live_test", False), recover_pid=getattr(args, "recover_hub_pid", None))
    if choice == "status":
        return status(args.json)
    if choice == "stop":
        return stop()
    if choice == "watch":
        if not hub.mutex_running(hub.MONITOR_MUTEX):
            hub.Hub().launch("monitor")
        return 0
    if choice == "build":
        codes = [subprocess.run([sys.executable, str(ROOT / "scripts" / script), "build"]).returncode
                 for script in hub.SERVICE_SCRIPTS.values()]
        return max(codes)
    if choice == "install":
        return install()
    if choice == "uninstall":
        result = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME], capture_output=True)
        print("已取消统一守护登录自启" if result.returncode == 0 else "未找到统一守护登录自启任务")
        return stop() if hub.mutex_running(hub.MUTEX) else 0
    return 1


if __name__ == "__main__":
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr is not None and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
