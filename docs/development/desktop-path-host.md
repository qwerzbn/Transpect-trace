# 本机固定版桌面端发送路径观察

本文件说明 `scripts/probe_desktop_paths_host.py` 的**只观察**研究模式。它用于在不改动当前 `zbn` 客户端的前提下，定位另一个本机账户安装的官方固定版桌面端发送路径。它不阻断请求、不设置 WFP 规则、不开放网络许可，也不把桌面适配器标记为 `validated`。独立账户安装步骤见 [本机准备说明](desktop-host.md)；原有 [虚拟机探针](desktop-path-trace.md) 及其 WFP 前提保持不变。

## 必须满足的身份和版本条件

- 在**专用普通 Windows 用户**的会话中运行探针，并为该用户单独注册官方 MSIX `26.1029.7803.0`。当前 `zbn` 会话的桌面端与专用用户的进程必须有不同 SID。安装相同包族的另一版本到 `zbn` 账户可能更新正在使用的客户端，故本流程不在该账户安装或附加探针。
- 指定归档的官方 MSIX；探针复核 SHA-256、Authenticode 签名、包清单，以及专用用户当前的 `Get-AppxPackage OpenAI.Codex` 注册。它还核对桌面 `ChatGPT.exe` 和 `codex.exe app-server` 的路径、哈希、SID、父子关系与进程创建时间；可选的 Electron NetworkService 同样核对。候选适配器必须保持 `candidate_unvalidated`。
- `--protected-sid` 是当前 `zbn` 账户的 SID，`--expected-sid` 是专用用户的 SID。先分别在对应用户会话运行 `whoami /user` 取得它们。探针要求自身运行身份等于 `--expected-sid`，且两者不同；目标进程还必须属于专用 SID，因此不会附加到 `--protected-sid` 所属客户端。`--protected-sid` 由操作者提供，探针本身无法证明该值确实是 `zbn` 的 SID；必须在切换用户前核对。PID 来自专用用户安装的进程，不能填当前会话的 PID。
- Frida 仅是研究依赖，由专用用户的 Python 环境提供。若应用保护或账户权限阻止附加，记录本次为**未观察到**；不要转而附加当前客户端。跨用户 Frida 附加可能需要管理员权限，本脚本明确不走跨用户附加路径。
- 探针把 Frida 附加和脚本载入放进可终止的子进程；主进程保持目标进程句柄，最多等待 20 秒取得所有角色的就绪事件。超时会终止子进程、记录错误并输出 `coverage_status: unvalidated`，不会继续等待或转向当前账户的客户端。子进程在每次附加前后重新核对账户 SID、固定文件哈希、进程创建时间及父子关系；研究完成时主进程关闭该子进程。

## 合成样本与运行

先在专用用户会话建立全新的样本目录。`prepare` 写入随机合成标记、文字 Prompt 和一个小的 `.txt` 附件。不要把真实密钥、企业文件或私人资料用于此探针。

```powershell
uv run --no-sync python scripts/probe_desktop_paths_host.py prepare `
  --output C:\demo\host-trace\fixtures
```

按 [桌面适配器说明](../desktop-guard-adapter.md)使用 `scripts/discover_desktop_guard.py` 对**相同归档 MSIX 和后端**生成静态候选。启动专用用户的固定版桌面端，在专用用户会话查明 `ChatGPT.exe`、其子进程 `codex.exe app-server` 和可选 NetworkService 的 PID。然后分别以新的空目录运行 `idle`、`text`、`upload` 三次：

```powershell
uv run --no-sync python scripts/probe_desktop_paths_host.py trace --observation-only `
  --msix C:\demo\archive\ChatGPT-x64.msix `
  --adapter C:\demo\adapter\desktop-candidate.json `
  --fixtures C:\demo\host-trace\fixtures\fixtures.json `
  --desktop-pid <专用用户-ChatGPT-PID> `
  --backend-pid <专用用户-app-server-PID> `
  --network-pid <专用用户-NetworkService-PID> `
  --expected-sid <专用用户-SID> --protected-sid <zbn用户-SID> `
  --case text --seconds 60 --output C:\demo\host-trace\text-01
```

`--network-pid` 可以省略，但结果就不能定位该进程中的附件路径。探针显示 `ready` 后，在专用桌面端的本地任务里仅输入 `fixtures/text-prompt.txt` 的合成文字；`upload` 轮仅添加 `fixtures/synthetic-attachment.txt`。`idle` 轮不提交请求，用来区分后台调用。若专用版无法登录或无法独立运行，保持静态分析状态，不对当前客户端代测。

## 输出如何解释

`events.jsonl` 只保留事件类型、进程角色、模块/RVA、调用栈位置、长度和 SHA-256。`summary.json` 固定写入 `observation_only: true`、`can_enforce: false`、`coverage_status: unvalidated`、`network_permit_opened: false`；还记录固定包、适配器、合成样本、探针代码和事件的哈希及命中计数。异常只记类型，不记可能包含请求内容的错误文本。合成标记原文只在 `fixtures` 中。

HTTP/WSS 候选入口命中只能说明本次任务经过该函数；合成标记命中可增强关联。`ReadFile`/`NtReadFile`/`WriteFile` 和 WinHTTP 的调用栈有助于定位附件进程，但可能漏掉内存映射、异步 I/O、共享内存或其他发送 API。这些结果**不能证明**完整请求已取得、附件发送点已受控、拒绝 ABI 正确或源站收到零字节。本机模式没有 Agent 工具的网络默认拒绝兜底；任何后续强制门控仍需独立实现和验证。
