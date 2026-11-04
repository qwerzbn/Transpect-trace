# 固定版桌面后端的本机隔离实验

`scripts/probe_desktop_backend_lab.py` 直接启动从官方 MSIX `26.1029.7803.0` 归档的 `codex.exe app-server`，不启动、不附加当前正在使用的桌面端。脚本先核对后端文件 SHA-256 与静态候选适配器，使用临时 `CODEX_HOME`，经 `initialize`、`thread/start`、`turn/start` 提交随机合成标记。模型提供者指向 `127.0.0.1` 上**不转发**的 HTTP 接收器；接收器只保存正文长度、SHA-256 和合成标记是否出现。实验不读取真实用户请求或认证信息。

```powershell
uv run --no-sync python scripts/probe_desktop_backend_lab.py --with-frida `
  --report runs/desktop-backend-lab/report-with-frida.json
```

2026 年 11 月 4 日在本机复测：归档后端版本为 `codex-cli 0.166.0-alpha.6`，后端哈希 `925C7D0665FFA49B0DCF748E034A805A04DA984164AC92301432073B47789B99`。`app-server` 三步交互完成；本地接收器收到一次 `/v1/responses` 请求，正文为 41,001 字节，并包含合成标记。Frida 在 HTTP 静态候选入口观察到两次调用，在该函数的假定正文布局中找到两次标记；WSS 候选没有调用。本轮使用的本地提供者明确关闭 WebSocket，因此 `0` 次 WSS 命中不能说明真实桌面 WSS 路径不存在。完整 JSON 报告保存在被 Git 忽略的 `runs/desktop-backend-lab/`。

Frida 附加与脚本载入运行在独立子进程中，主程序等待就绪最多 10 秒；超时会终止子进程和本次归档后端。此前仅用线程包裹 Frida 调用曾在本机卡住，故不以线程超时作为可靠的终止边界。当前实验只做**只读观察**，没有拒绝请求、调用 DLP、打开 WFP 许可或验证源站零字节。候选入口中的 Rust 参数布局仍只是旧版 CLI 的假设；即使标记出现，也不能证明抓到了整个请求、桌面 UI 的所有路径或附件原始字节。下一步仍需在专用 Windows 账户运行固定版桌面界面，对 HTTP、WSS 和两类附件路径逐一做动态核验，然后才能验证发送前拒绝。
