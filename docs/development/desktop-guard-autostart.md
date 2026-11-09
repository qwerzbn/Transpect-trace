# Windows Codex 桌面进程自动发现

`scripts/manage_desktop_guard_autostart.py` 管理当前 Windows 用户的计划任务。任务在用户登录时启动 `desktop_guard_supervisor.py watch`，并可在安装时立即启动，因此可以发现已经运行和以后重启的 Codex 桌面 `app-server` 后端。它不写入 `hooks.json`，不使用 Codex 的应用级 Hook。

当前默认安装是**只读发现**：监督进程校验桌面包、后端映像、父进程、SID 和进程创建时间，并持续写出状态。`MODEL_EGRESS_NOT_COVERED` 表示尚未拦截模型请求；任务处于 `Running` 只说明监督进程在运行，不说明每个 prompt 已被采集。当前版本的 Native 实机激活门仍关闭，先前两次试运行曾让桌面出现用户可见错误。`--activate` 在准入门关闭时会在注册任务前拒绝。

在仓库目录运行：

```powershell
uv run --no-sync python scripts/manage_desktop_guard_autostart.py status
uv run --no-sync python scripts/manage_desktop_guard_autostart.py install
uv run --no-sync python scripts/desktop_guard_supervisor.py status
uv run --no-sync python scripts/manage_desktop_guard_autostart.py remove
```

`install` 注册一个仅限当前用户、交互令牌、有限权限的登录任务，并立即启动观察进程；`install --no-start` 仅注册下一次登录启动。它使用仓库 `.venv\Scripts\pythonw.exe` 隐藏控制台，任务的执行路径、参数、工作目录、SID 和登录触发器都会核对。任务名被其他配置占用时拒绝覆盖。`remove` 先请求监督进程停止，等待它确认所有控制器的 Native lease 已释放及 Hook 禁用，再移除任务；确认失败时保留任务并报告错误。

安装与自动发现不能消除 Codex 后端从启动到 Guard 注入之间的竞态，也不能证明现有聊天和未来每个 prompt 都被完整采集。桌面自动更新会使固定版本适配失效。只有在真实桌面前端验证、全局覆盖与启动竞态解决、准入门明确开启并观察到每个请求的 Native 决策证据后，才能使用 `install --activate` 并宣称模型外发受到保护。工具外发需要独立的系统级阻断证据。
