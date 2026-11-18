# 双客户端常驻监视入口

默认入口同时运行 Codex 桌面后端和固定版 Claude CLI 的两个现有守护器，并打开独立的只读状态窗。状态窗不接管终端、不改变 Claude/Codex 主题、不重写请求，也不代替原有版本与验收门禁。

```powershell
.\guard-service.bat                          # 同时监视两个客户端
.\guard-service.bat start --claude-live-test  # 明示固定版实验接入
.\guard-service.bat status                   # 当前状态
.\guard-service.bat status --json            # 可机器读取的状态
.\guard-service.bat watch                    # 单独打开只读监视窗
.\guard-service.bat stop                     # 主动停止两个守护器
```

Windows 首次启动使用 uv 和仓库中的锁文件准备环境。已准备好的环境支持离线查询和停止。双击 `guard-service.bat` 也会执行默认启动，Git Bash 的 `./start.sh` 转交给同一个入口。

固定版实验模式只放宽 Claude 的模型路径验收要求，不跳过文件 SHA、入口字节与目标安装路径验证，不会将新版本自动视为支持。它显示 `HOOK_READY_LIMITED` 或具体失败状态，不能作为正式完整保护交付。已运行的独立守护器会被观察和接管恢复，不会因 hub 启动而重启；其启动环境保持原状。运行中的 hub 也不会因再次执行 start 改变模式。

窗口关闭按钮仅最小化，后台进程与两个守护器继续运行。状态窗口退出后由 hub 重开；两个守护器退出后按 2–30 秒退避重启。已加载相同 DLL 的后端按现有 lease/重连机制恢复。不同 DLL、版本不支持、验收失败保持可见告警，不自动关闭用户客户端。进程活着但心跳陈旧只告警，不强杀。

hub 自身异常退出后，独立监视窗检查其命名 mutex，并按先前明确的实验模式自动重启 hub。新 hub 接管仍存活的两守护器，不重复注入或启动服务。恢复入口同时核对观察到的 hub PID 和持久化停止意图；显式 stop 先写 `stop-request.json` 再发停止事件，因此不会被当成崩溃而反复重开。再次普通 start 才清除停止意图。这个恢复机制只针对当前登录会话，不安装每日自启；hub 与监视窗同时被结束或系统关机后仍需手动启动（或在完整验收后安装登录任务）。

## 状态含义

| 状态 | 含义 |
|---|---|
| `WATCHING` | 守护器在监视；尚无已接入的目标进程，不能推定保护成立 |
| `HOOK_READY_LIMITED` | 模型 Hook 已就绪，但模型覆盖或工具出口尚无完整验收 |
| `PROTECTED` | 守护器同时提供模型与工具出口通过验收的结构化证据，且每个当前目标均已接入 |
| `ATTENTION` | 至少一个目标不支持、接入失败或未获准接入；查看逐进程原因 |
| `STALE` / `OFFLINE` | 心跳过期或守护器不在；不能继续显示旧的受保护状态 |

旧 Codex supervisor 的 `PROTECTED` 只表示其模型 Hook 就绪，因此统一窗主动降为 `HOOK_READY_LIMITED`。只有状态内 `coverage.ready` 和 `egress.ready` 都为真，才允许显示完整 `PROTECTED`。本入口不默认启用实验性的工具 socket API 门闩，也不影响其他 `zbn` 程序。

## 兼容入口与自启

`./start.sh codex start|status|stop|build|install|uninstall` 保留原 Codex 单客户端命令。`./start.sh claude hook ...` 与 `./start.sh claude proxy ...` 保持原路由。hub 运行时如需停止某个单客户端，应先 stop hub；否则 hub 会按恢复策略重新启动它。

`./start.sh install` 注册当前用户的交互式登录任务，带失败重启；仅完整验收后允许安装。`./start.sh uninstall` 删除统一任务并停止 hub。实验模式不会写入日常登录自启配置。不要求管理员，不添加全局代理或更改信任区。

状态与诊断日志保存在 `%LOCALAPPDATA%\TranspectTrace\guard-hub`，原有两客户端的审计与归档目录保持不变。监视窗只展示 PID、计数、状态和原因，不展示请求正文或认证头。

**边界：** 此统一入口解决监视、进程恢复和状态展示，不消除“发现进程 → 注入完成”之前的启动空窗，也不替代内核出口控制。主动 stop 仍使用现有受控停止语义，停止后不再提供门控保护；不能宣称停止后仍有零外发保证。

## 恢复验证

`python -m pytest tests/test_guard_hub.py tests/test_guard_hub_windows.py tests/test_claude_resident_service.py -q` 验证退避、历史状态失效、验收降级、实验模式不被隐式继承，以及真实 Windows 子进程退出恢复。Windows 集成测试使用每次随机命名的私有 mutex 和仅等待的测试进程，不加载 DLL、不操作运行中的 Codex/Claude 或其守护器。

监视窗可先用 `powershell.exe -NoProfile -STA -File scripts/guard_monitor.ps1 -ValidateOnly` 校验控件构造而不显示窗口。启动 hub 后，`guard-hub/state.json` 的 `monitor_pid` 对应独立 PowerShell 窗口；用 `Get-Process -Id <monitor_pid>` 查看 `MainWindowHandle` 与 `MainWindowTitle`。验证监视窗故障恢复时，仅在核对该 PID 的命令行为本仓库 `scripts/guard_monitor.ps1` 后结束这个窗口进程，约 3–5 秒后应出现新的 monitor_pid，并且两个服务的 supervisor_pid 不变。不要为了展示恢复而杀死正在承载真实会话的守护器；服务崩溃恢复用上述隔离测试完成。
