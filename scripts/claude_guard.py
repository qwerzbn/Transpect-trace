"""Resident guard for the exact npm Claude Code 2.1.317 CLI build."""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
from datetime import datetime
from pathlib import Path
import subprocess
import sys
import threading
import time

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import claude_service as svc  # noqa: E402


TASK_NAME = "TranspectTrace Claude Guard"
LOG_FILE = svc.RESIDENT_STATE_DIR / "guard.log"


def _log(message: str, *, background: bool) -> None:
    stamp = datetime.now()
    if not background:
        print(f"{stamp:%H:%M:%S} {message}", flush=True)
        return
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as stream:
        stream.write(f"{stamp:%Y-%m-%d %H:%M:%S} {message}\n")


def _running() -> bool:
    kernel = svc.common._kernel()
    kernel.OpenMutexW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
    kernel.OpenMutexW.restype = w.HANDLE
    handle = kernel.OpenMutexW(0x100000, False, svc.SUPERVISOR_MUTEX)
    if handle:
        kernel.CloseHandle(handle)
    return bool(handle)


def _stop_egress() -> bool:
    """Controlled stop removes VM network rules; never claim success if it fails."""
    try:
        from transpect_trace.guard.claude_egress import stop_egress
        stop_egress()
        return True
    except ImportError:
        print("NETWORK_RULES_UNKNOWN: Claude VM 出口组件尚未安装，无法核对网络规则", file=sys.stderr)
    except Exception as error:
        print(f"NETWORK_RULES_REMAIN: {type(error).__name__}: {error}", file=sys.stderr)
    return False


def start(background: bool) -> int:
    supervisor = svc.ClaudeSupervisor(log=lambda message: _log(message, background=background))
    done = threading.Event()

    @c.WINFUNCTYPE(w.BOOL, w.DWORD)
    def on_console_event(_event):
        supervisor.stop.set()
        done.wait(4.5)
        return True

    if not background:
        c.windll.kernel32.SetConsoleCtrlHandler(on_console_event, True)
        print("正在监视 Claude 2.1.317；按 Ctrl+C 主动停止。"
              " 完整验收前只报告状态，不注入日常会话。", flush=True)
    try:
        supervisor.run()
    except KeyboardInterrupt:
        supervisor.stop.set()
    except Exception as error:
        _log(f"Claude 驻守服务失败：{type(error).__name__}: {error}", background=background)
        return 1
    finally:
        done.set()
    final = svc.read_claude_state()
    if not final or final.get("overall") != "STOPPED":
        print("Claude 主动停止未完成；网络规则保持生效", file=sys.stderr)
        return 2
    return 0 if _stop_egress() else 2


def stop() -> int:
    notified = svc.request_claude_stop()
    if not notified:
        print("Claude 驻守服务未在运行；网络规则保持原状")
        return 1
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline and _running():
        time.sleep(0.1)
    final = svc.read_claude_state()
    if _running() or not final or final.get("overall") != "STOPPED":
        print("Claude 防护未确认主动停止；网络规则保持生效", file=sys.stderr)
        return 2
    print("Claude Native 防护已主动停止")
    return 0 if _stop_egress() else 2


def status() -> int:
    state = svc.read_claude_state()
    running = _running()
    if not state:
        print("Claude 驻守服务未运行过")
        return 1
    print(f"Claude 防护：{'运行中' if running else '未运行'}；固定版：{state['target_version']}")
    overall = state["overall"] if running or state["overall"] == "FAILED_CLOSED" else "STOPPED"
    print(f"当前状态：{overall}")
    print(f"模型路径验收：{state['coverage']['reason']}")
    print(f"虚拟机出口：{state['egress']['reason']}")
    print(f"记录目录：{state['run_dir']}")
    live = [row for row in state["processes"] if row["state"] != "EXITED"]
    if not live:
        print("当前未发现 Claude 进程")
    for row in live:
        label = row["state"] if running else "STALE_" + row["state"]
        print(f"  PID {row['pid']}: {label}；请求 {row['requests']}，"
              f"放行 {row['allowed']}，拒绝 {row['denied']}；{row['detail']}")
    return 0 if running else 1


def watch() -> int:
    """Show guard status without owning or stopping the supervisor."""
    print("只读监控 Claude 防护；按 Ctrl+C 仅关闭此窗口，不停止守护器。", flush=True)
    previous = None
    try:
        while True:
            state = svc.read_claude_state()
            running = _running()
            if state is None:
                current = (running, None)
                summary = "守护器状态文件尚未建立"
            else:
                processes = tuple(
                    (row["pid"], row["state"], row["requests"],
                     row["allowed"], row["denied"])
                    for row in state.get("processes", ())
                    if row.get("state") != "EXITED"
                )
                current = (running, state.get("overall"), processes,
                           state.get("coverage", {}).get("reason"),
                           state.get("egress", {}).get("reason"))
                summary = (f"守护器={'运行' if running else '未运行'} "
                           f"状态={state.get('overall', 'UNKNOWN')} "
                           f"模型={state.get('coverage', {}).get('reason', 'UNKNOWN')} "
                           f"出口={state.get('egress', {}).get('reason', 'UNKNOWN')}")
            if current != previous:
                print(f"{datetime.now():%H:%M:%S} {summary}", flush=True)
                if state is not None:
                    for pid, process_state, requests, allowed, denied in processes:
                        print(f"  PID {pid}: {process_state}；请求 {requests}，"
                              f"放行 {allowed}，拒绝 {denied}", flush=True)
                previous = current
            time.sleep(1)
    except KeyboardInterrupt:
        print("监控窗口已关闭；守护器未收到停止命令。", flush=True)
        return 0


def build() -> int:
    pin = svc.load_pin()
    binary = svc.installed_claude()
    try:
        print(svc.ensure_dll(pin, binary))
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Claude 固定版构建失败：{error}", file=sys.stderr)
        return 1


def install() -> int:
    try:
        pin = svc.load_pin()
        model_ready = svc.accepted_pin_valid(pin)
        egress_ready, egress_reason = svc._egress_health()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"拒绝安装未验收的常驻防护：{error}", file=sys.stderr)
        return 2
    if not model_ready or not egress_ready:
        print("拒绝安装日常自启：模型路径或工具出口尚未完整验收"
              f"（model={model_ready}, egress={egress_reason}）", file=sys.stderr)
        return 2
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    command = f'"{pythonw}" "{Path(__file__).resolve()}" start --background'
    if len(command) > 261:
        print("仓库路径过长，计划任务无法注册", file=sys.stderr)
        return 1
    try:
        subprocess.run(["schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED",
                        "/TN", TASK_NAME, "/TR", command], check=True, capture_output=True)
        subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], check=True, capture_output=True)
    except subprocess.CalledProcessError as error:
        print(f"注册 Claude 登录自启失败：{error.stderr.decode(errors='replace') if isinstance(error.stderr, bytes) else error.stderr}",
              file=sys.stderr)
        return 1
    print(f"Claude 驻守服务已设置登录自启；日志：{LOG_FILE}")
    return 0


def uninstall() -> int:
    stopped = stop() if _running() else (0 if _stop_egress() else 2)
    result = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
                            capture_output=True)
    print("已取消 Claude 登录自启" if result.returncode == 0 else "未设置 Claude 登录自启")
    return stopped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    command = commands.add_parser("start", help="监视固定版 Claude（默认）")
    command.add_argument("--background", action="store_true", help="无窗口运行")
    for name, help_text in (("status", "显示每个 Claude 进程状态"),
                            ("watch", "只读持续显示状态，关闭窗口不停止守护器"),
                            ("stop", "主动停止 Native 防护并撤销 VM 网络规则"),
                            ("build", "仅构建固定版 DLL"),
                            ("install", "注册登录自启"),
                            ("uninstall", "取消登录自启")):
        commands.add_parser(name, help=help_text)
    args = parser.parse_args()
    choice = args.command or "start"
    if choice == "start":
        return start(getattr(args, "background", False))
    return {"status": status, "watch": watch, "stop": stop, "build": build,
            "install": install, "uninstall": uninstall}[choice]()


if __name__ == "__main__":
    raise SystemExit(main())
