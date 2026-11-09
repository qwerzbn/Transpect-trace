"""Codex desktop guard: start, stop, status, build, install, uninstall.

Usually run through ./start.sh. `start` stays in the foreground and prints each
decision; Ctrl+C or closing the window stops the guard in a controlled way, after
which Codex requests pass again. A killed or crashed guard leaves attached Codex
backends denying requests until the guard is started again.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
from datetime import datetime
from pathlib import Path
import subprocess
import sys
import threading

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import desktop_service as svc  # noqa: E402

TASK_NAME = "TranspectTrace Desktop Guard"
LOG_FILE = svc.STATE_DIR / "guard.log"


def _console_log(message: str) -> None:
    print(f"{datetime.now():%H:%M:%S} {message}", flush=True)


def _file_log(message: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as stream:
        stream.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}\n")


def start(background: bool) -> int:
    log = _file_log if background else _console_log
    supervisor = svc.Supervisor(log=log)
    done = threading.Event()

    # Ctrl+C, Ctrl+Break and closing the console window all stop the guard in
    # a controlled way; Windows allows a few seconds after a close event.
    @c.WINFUNCTYPE(w.BOOL, w.DWORD)
    def on_console_event(_event):
        supervisor.stop.set()
        done.wait(4.5)
        return True

    if not background:
        c.windll.kernel32.SetConsoleCtrlHandler(on_console_event, True)
        _console_log("按 Ctrl+C 停止防护")
    try:
        supervisor.run()
    except RuntimeError as error:
        log(str(error))
        return 1
    finally:
        done.set()
    return 0


def stop() -> int:
    if svc.request_stop():
        print("已通知防护停止")
        return 0
    print("防护未在运行")
    return 1


def status() -> int:
    state = svc.read_state()
    running = _supervisor_running()
    if not state:
        print("防护未运行过")
        return 1
    print(f"防护：{'运行中' if running else '未运行'}（启动于 {state['started_at']}）")
    print(f"支持的 Codex 版本：{', '.join(state['supported_versions'])}")
    print(f"记录目录：{state['run_dir']}")
    live = [row for row in state["backends"] if row["state"] not in ("EXITED",)]
    if not live:
        print("当前没有 Codex 后端")
    for row in live:
        counts = f"请求 {row['requests']}，放行 {row['allowed']}，拒绝 {row['denied']}"
        detail = f"  {row['detail']}" if row["detail"] else ""
        print(f"  Codex {row['pid']}: {row['state']}  {counts}{detail}")
    return 0


def _supervisor_running() -> bool:
    k = svc._kernel()
    k.OpenMutexW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
    k.OpenMutexW.restype = w.HANDLE
    handle = k.OpenMutexW(0x100000, False, svc.SUPERVISOR_MUTEX)
    if handle:
        k.CloseHandle(handle)
    return bool(handle)


def build() -> int:
    pins = svc.load_pins()
    hashes = svc.ImageHashCache()
    built = 0
    for backend in svc.installed_backends():
        pin = pins.get(hashes.sha256(str(backend)))
        if pin:
            print(svc.ensure_dll(pin, backend))
            built += 1
    if not built:
        versions = ", ".join(sorted(p["codex_desktop_version"] for p in pins.values()))
        print(f"未找到受支持的 Codex 后端（支持：{versions}）")
        return 1
    return 0


def install() -> int:
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    command = f'"{pythonw}" "{Path(__file__).resolve()}" start --background'
    if len(command) > 261:
        print("仓库路径过长，计划任务无法注册；请把仓库放到更短的路径")
        return 1
    subprocess.run(["schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED",
                    "/TN", TASK_NAME, "/TR", command], check=True, capture_output=True)
    subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], check=True, capture_output=True)
    print(f"已设置登录自启并在后台启动，日志：{LOG_FILE}")
    return 0


def uninstall() -> int:
    svc.request_stop()
    result = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
                            capture_output=True)
    print("已取消登录自启" if result.returncode == 0 else "未设置登录自启")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command")
    run = commands.add_parser("start", help="启动防护（默认）")
    run.add_argument("--background", action="store_true", help="无窗口运行，日志写入文件")
    for name, text in (("stop", "停止防护"), ("status", "查看状态"), ("build", "仅构建 DLL"),
                       ("install", "登录自启并后台启动"), ("uninstall", "取消登录自启并停止")):
        commands.add_parser(name, help=text)
    args = parser.parse_args()
    command = args.command or "start"
    if command == "start":
        return start(getattr(args, "background", False))
    return {"stop": stop, "status": status, "build": build,
            "install": install, "uninstall": uninstall}[command]()


if __name__ == "__main__":
    sys.exit(main())
