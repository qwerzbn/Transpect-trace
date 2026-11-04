# 当前桌面客户端的合成请求观察

`scripts/probe_desktop_paths_current.py` 用于在当前 Windows 账户的**现用** Codex 桌面端上短时观察一个合成 Prompt。它只附加到该桌面端启动的 `codex.exe app-server` 后端，不附加 Electron 主进程或 NetworkService。研究脚本不调用 DLP 判定、不拒绝请求、不修改安装文件、不设置 WFP 规则，也不保存模型正文。Frida 会在目标进程内临时安装拦截器，**可能使正在使用的客户端或本会话中断**；因此只能在操作者接受这一影响时运行。

2026 年 11 月 4 日，本机当前账户的应用已从先前观察到的 `26.1027.6604.0` 变为 `26.1029.7803.0`。当前 `ChatGPT.exe` 和它启动的用户目录后端，与归档的官方固定版镜像哈希一致。此事实只证明此刻文件相同，不能保证以后不换版。每次运行探针前，它都会重新检查当前用户的 AppX 注册、签名归档包、桌面主程序与后端的 SHA-256、后端 Authenticode 签名、SID、父子关系、`app-server` 命令及进程创建时间。后端必须位于当前用户 `AppData/Local/OpenAI/Codex/bin/<十六进制目录>/codex.exe`，并与归档包内后端逐字节同哈希；版本或路径一变就停止。静态候选适配器仍保持 `candidate_unvalidated`。

先在本地准备全新的随机合成样本。`prepare` 也会生成一个未用于本轮观察的合成附件；本探针仅测试文字 Prompt。

```powershell
uv run --no-sync python scripts/probe_desktop_paths_current.py prepare `
  --output runs/desktop-current/fixtures-01
```

在当前账户用 `whoami /user` 取得 SID，找到 MSIX 桌面主进程的 PID 和它的 `codex.exe app-server` 子进程 PID。随后在本地 PowerShell 启动最多 120 秒的观察，以下占位符由本机实际值替换：

```powershell
uv run --no-sync python scripts/probe_desktop_paths_current.py trace `
  --active-current-client --observation-only `
  --msix runs/desktop-vm/ChatGPT-x64.msix `
  --adapter deploy/guard/desktop-candidate-26.1029.7803.0.json `
  --fixtures runs/desktop-current/fixtures-01/fixtures.json `
  --desktop-pid <当前-MSIX主进程PID> --backend-pid <其-app-server子进程PID> `
  --expected-sid <当前用户SID> --seconds 45 `
  --output runs/desktop-current/trace-01
```

探针打印 `ready` 后，在**另一个 Local（本机）Codex 任务**中仅提交 `text-prompt.txt` 里的合成文字。不要把真实密钥、企业文件或个人资料用于这一轮；也不要把当前聊天直接当作本地模型请求的已验证路径。`events.jsonl` 只保留合成标记命中时的函数名、长度、哈希和调用位置等元数据，丢弃没有标记的候选入口事件及所有其他 I/O 事件。Frida 附加和脚本载入在可终止子进程中运行，20 秒未就绪则停止。`summary.json` 始终声明 `coverage_status: unvalidated`、`can_enforce: false`。即使观察到命中，也只证明这一轮合成任务经过该候选入口；不能据此证明取得完整请求、所有 HTTP/WSS 路径、附件原始字节、拒绝发生于发送前，或源站零字节。

本机当前账户没有为 Agent 工具单独安装默认拒绝网络边界。现用桌面端的强制阻断测试可能中断普通任务；因此该探针只做有限观察。完整的采集、识别、阻断联调仍要分别验证模型请求、附件与工具进程的外发路径。

## 本机首次观察记录

2026 年 11 月 4 日，已对当时哈希匹配的当前 `app-server` 运行一次 120 秒观察。报告记录 HTTP 和 WSS 两个候选 Hook 安装成功、探针就绪、错误数为零，`model_marker_hits=0`。观察窗口内**没有收到合成 Prompt 已在另一个 Local 任务提交的确认**，因此零命中不能解释为该发送路径不存在或 Hook 漏报。这次没有执行阻断。原始元数据报告保留在 Git 忽略的 `runs/desktop-current/trace-01/`；`summary.json` 的 SHA-256 为 `9A09357BC33919F55A63BFB739895BC0325A51764B00B14F0B33169AF12B5ED1`。
