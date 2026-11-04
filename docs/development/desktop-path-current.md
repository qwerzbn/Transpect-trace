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

探针打印 `ready` 后，在**另一个 Local（本机）Codex 任务**中仅提交 `text-prompt.txt` 里的合成文字。不要把真实密钥、企业文件或个人资料用于这一轮；也不要把当前聊天直接当作本地模型请求的已验证路径。`events.jsonl` 只保留 HTTP/WSS 候选函数的调用类型及接收时间、参数读取失败计数所需元数据，以及**合成标记命中时**的长度、哈希、调用位置和有界 JSON 结构检查结果；它不记录普通调用的参数、调用栈或正文，也不保留其他文件 I/O 事件。`summary.json` 提供每个候选函数的调用次数及首末接收时间，供与合成任务发送时间比较。**候选函数调用可能属于后台流量，单有调用计数不能证明它对应本轮测试请求。**Frida 附加和脚本载入在可终止子进程中运行，20 秒未就绪则停止。`summary.json` 始终声明 `coverage_status: unvalidated`、`can_enforce: false`。即使观察到命中，也只证明这一轮合成任务经过该候选入口；不能据此证明取得完整请求、所有 HTTP/WSS 路径、附件原始字节、拒绝发生于发送前，或源站零字节。

本机当前账户没有为 Agent 工具单独安装默认拒绝网络边界。现用桌面端的强制阻断测试可能中断普通任务；因此该探针只做有限观察。完整的采集、识别、阻断联调仍要分别验证模型请求、附件与工具进程的外发路径。

## 本机首次观察记录

2026 年 11 月 4 日，已对当时哈希匹配的当前 `app-server` 运行一次 120 秒观察。报告记录 HTTP 和 WSS 两个候选 Hook 安装成功、探针就绪、错误数为零，`model_marker_hits=0`。观察窗口内**没有收到合成 Prompt 已在另一个 Local 任务提交的确认**，因此零命中不能解释为该发送路径不存在或 Hook 漏报。这次没有执行阻断。原始元数据报告保留在 Git 忽略的 `runs/desktop-current/trace-01/`；`summary.json` 的 SHA-256 为 `9A09357BC33919F55A63BFB739895BC0325A51764B00B14F0B33169AF12B5ED1`。

随后同步运行的 `trace-02` 在探针就绪后向已建立的 Local 测试任务提交了一条合成 Prompt，任务在观察窗口内完成。该版探针只保留标记命中事件，报告仅有三个安装/就绪事件，`model_marker_hits=0`，无法区分候选函数未调用与旧参数布局未找到标记。报告 SHA-256 为 `7DC1A98F0F4BEEC9A6BFD7B9563E78D9FD14E47A3487E5B398C2DFA098FC4FE7`。

`trace-03` 改为记录候选函数调用次数，再于探针就绪后向同一个 Local 任务提交一条新合成 Prompt，任务在窗口内完成。`model.http` 调用数为 0，`model.wss` 为 3，其中两次发生在任务运行时间内；旧 WSS 布局没有得到合成标记，`model_marker_hits=0`、错误数为零。时间重叠只能提示下一步检查 WSS 候选参数，尚不能把这些调用归因于该测试任务，更不能声称取得完整请求。报告 SHA-256 为 `D786946534A13B4510A809FDF96F323DEED9CF65B53F50A292E2AFABCA4B46C8`。两轮均未执行阻断，也未保存模型正文。

固定版后端的离线反汇编确认，WSS 请求序列化函数成功时的结果标签为 `0x1f`，数据指针与长度位于结果区 `+16`、`+24`；旧探针沿用的 `0x1c` 会静默跳过该缓冲区。修改研究探针后，`trace-04` 在同一 Local 测试任务启动后约 0.27 秒，于 `model.wss` 序列化函数的返回处发现包含新合成标记的 2,629 字节缓冲区，标记偏移为 434；本次 Hook 安装及运行错误数为零。窗口后段另有一条 9,702 字节缓冲区包含该标记，不能确定它属于同一任务。`model.http` 调用数为 0，`model.wss` 为 11。报告仅保存长度、哈希、偏移和位置元数据，未保存正文；`summary.json` SHA-256 为 `D5AB5A02F5193478E716482724F2F63597B16254575B9FC97F499F99E0D1DF25`。

固定版 [Codex 源码中的 `response.create` 路径](https://github.com/openai/codex/blob/rust-v0.166.0-alpha.6/codex-rs/codex-api/src/endpoint/responses_websocket.rs#L714-L741)先序列化请求，再交给 [WebSocket 发送函数](https://github.com/openai/codex/blob/rust-v0.166.0-alpha.6/codex-rs/codex-api/src/endpoint/responses_websocket.rs#L974-L1005)。结合本次标记命中，可以认为当前固定版的一条 Local 模型请求在发送前经过了该序列化点；仍未把该缓冲区与服务端实际收到的逐字节正文对比，也未验证其他任务路径、错误返回 ABI、拒绝动作或 Agent 工具外发。适配器继续标为 `candidate_unvalidated`。

为核对请求结构，`trace-05` 增加了仅在合成标记命中后才运行的有界 JSON 解析，首次误按嵌套 `response` 对象判断，因而将两个有效 JSON 标为 `other-json`。固定版 [源码测试](https://github.com/openai/codex/blob/rust-v0.166.0-alpha.6/codex-rs/codex-api/src/endpoint/responses_websocket.rs#L1065-L1082)表明 `response.create`、`model` 和 `input` 位于同一层。修正后再次自动提交一条合成 Prompt，`trace-06` 在 WSS 候选点发现两条包含该标记的缓冲区，分别为 2,629 和 4,955 字节；两条均解析为扁平的 `response.create` 对象，且包含 `model` 与 `input`。第一条出现在测试任务启动后约 0.66 秒，第二条约 4.01 秒，后者可能是任务后续请求；报告没有保存正文或模型名称。HTTP 候选调用数为 0、WSS 候选调用数为 5、探针错误数为 0；`summary.json` SHA-256 为 `F14C4A490946A29521E7C8F855A9107B2658E6729E456F9A6B8AA1BA4C699B15`。这进一步验证了该 Local 路径的请求结构，仍不能证明整个 WSS 帧逐字节相同或阻断已经生效。

隔离的非转发本地 WSS 源站能够收到合成请求，但该隔离 `app-server` 路径没有调用当前桌面端命中的序列化候选函数；仅加入 `features.code_mode_host=true` 也未改变结果。另一次使用完全合成的 ChatGPT 登录资料时，隔离后端虽识别了登录状态，合成 Prompt 却没有到达本地源站，两个模型候选函数均没有调用。因此隔离实验尚不能用于证明该 Hook 的拒绝返回会使源站收到 0 字节。当前账户的正式桌面控制器还要求独立控制身份、已验证适配器、附件门控及 WFP 默认拒绝，均未在本次观察中启用。
