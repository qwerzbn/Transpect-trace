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

在同一 Local 合成测试任务中自动运行一次只读的 `whoami /user` 与进程查询，工具进程为 `pwsh.exe`，父进程 PID 为当前 `codex.exe app-server` 的 15312，Windows SessionId 为 3，用户 SID 末尾同为 `1001`。这证明该次工具调用没有独立于桌面端的账户身份。按 `zbn` 用户 SID 设置 WFP 默认拒绝会同时影响现用客户端及该账户其他程序，不能被当作已经实现的 Agent 子进程专用边界；完整工具外发控制仍需独立、可验证的子进程身份或等效的系统级隔离。

## 当前客户端的合成阻断尝试

`scripts/probe_desktop_current_deny.py` 是短时研究探针，只针对归档哈希一致的当前 `app-server`，安装 HTTP 和 WSS 两个候选 Hook，并限制为单个随机合成标记。它没有接入 DLP 判定，也没有受控源站的接收证据；报告始终标记 `production_ready=false`、`coverage_status=unvalidated`。当前客户端所有 Local 任务共用后端，因此探针出错可能影响本聊天。

首轮自动测试中，标记也出现在本聊天的工具输出里，探针把这些非目标请求误当成目标并拒绝，导致合成测试任务发生 `stream disconnected`。首轮报告中 WSS 与 HTTP 各有 6 次拒绝事件，但 12 次匹配均标记为 `marker_not_in_user_input`；这些事件**不能**作为目标 Prompt 成功阻断的证据。探针退出后后端 PID 仍存活。报告 `runs/desktop-current/deny-trace-20261104-01/summary.json` 的 SHA-256 为 `81BD4ED83F5D291E33AE8C844F4E91B6104EF116AD26C195793B678FBAF865FE`。

修订后，标记若只在非用户输入位置出现，就原样通过。第二轮重新生成并自动提交合成文字，两个 Hook 安装成功、错误数为零；HTTP 观察到 1 次非目标标记，WSS 未观察到目标匹配，拒绝数为零，报告为 `no_synthetic_denial_observed`。跨任务发送工具在测试任务 rollout 中把这次文字交付为 `function_call_output`，而研究探针仅把 `role=user` 内容视为目标。这轮同样不能证明当前桌面端已在发送前拦截用户 Prompt。报告 `runs/desktop-current/deny-trace-20261104-02/summary.json` 的 SHA-256 为 `C102E0F913F609FC51552E2AE265ED19172F68415B1E186438B79F4563A21FB8`。下一步需先以可靠的任务身份元数据关联目标请求，再进行拒绝测试；仅靠随机标记在共享后端中不足以归因。

随后用只读的 `scripts/probe_desktop_current_thread_metadata.py` 检查固定版请求中的任务归属。第三轮合成消息经跨任务发送工具进入测试任务，探针在 HTTP 候选点观察到一条 171,558 字节请求：`client_metadata.thread_id` 与固定测试任务 UUID 相等，标记位于 `function_call_output.output`，不在 `role=user.content`；WSS 未见该标记。两个 Hook 均已安装，错误数为零。脚本只保存这三个布尔结果、长度和哈希，不保存任务 ID 或正文。报告为 `metadata_attributed_to_test_thread`，`runs/desktop-current/thread-trace-20261104-01/summary.json` 的 SHA-256 为 `85B2DB20247190AA044F207D3228A85DB8877D88287DE3DCEF5AD03730596916`。此结果可用于后续**限定合成测试请求**的归因，仍不是阻断或完整路径覆盖的证明。

第四轮将该任务 ID 与 `function_call_output` 标记作为共同条件，短时运行修订后的拒绝探针。当前桌面端的 HTTP 候选点观察到 6 次归属于测试任务的合成请求及 6 次错误返回构造，长度为 172,465 字节及后续重试的 172,702 字节；未见 WSS 目标命中、非目标标记或探针错误。测试任务报告 `stream disconnected`，共享后端 PID 仍存活。报告状态是 `one_candidate_denial_observed_without_origin_proof`，`runs/desktop-current/deny-trace-20261104-03/summary.json` 的 SHA-256 为 `C484D3434B01BD422BE27137262EC88A35F9DD75D369018DC7FDF84C4FAAFDB5`。这验证了该次合成请求在当前客户端 HTTP 候选点的拒绝动作，**没有**把正文交给 DLP 或加密归档，也没有独立服务端接收证据；WSS、附件及 Agent 工具直连仍未覆盖。

## 当前客户端的合成 DLP 联调

`scripts/probe_desktop_current_dlp_bridge.py` 将固定版 HTTP/WSS 候选点接入 `DesktopDLPBridge`。探针只对根部 `client_metadata.thread_id` 等于固定 Local 测试任务、且 `input` 中同一条 `function_call_output` 或 `role=user` 项含本轮合成标记的完整请求启动同步判定；其余请求不导出正文并原样通过。进程内检查 JSON 重复键，Python 端再次验证任务 ID、来源、长度和 SHA-256。目标请求先加密归档并回读核对，再做本地四层判定；`REVIEW`、`BLOCK`、超时和检查失败均拒绝。归档是**完整模型请求**，可能包含系统及开发者指令和测试任务历史，不能把整个归档称作合成文本。现用账户下的 DPAPI 加密也不能隔离同一账户的 Agent 进程。

2026 年 11 月 4 日，在当前客户端自动向固定测试任务发送一条带 `password=FakeSecret12345` 的合成请求。两个 Hook 均已安装；HTTP 候选点记录 6 条目标请求，6 条均完成加密归档回读、命中 `ASSIGNED_SECRET` 和 `ENTROPY_TOKEN`，并逐条对应 Native 拒绝事件。目标放行数、未决数和探针错误数均为 0；固定测试任务出现 `stream disconnected`，后端进程仍存活。报告位于 `runs/desktop-current/dlp-trace-20261104-01/summary.json`，SHA-256 为 `5DAAE2AAE23397784632A93A42717AD3EEFAD3B2561F81A654EA67F5B5F290F9`。这些结果证明**这次已归因的合成 HTTP 候选调用**经过“归档→识别→Native 拒绝”；没有受控源站逐字节接收证据，也没有验证 WSS 目标调用。

随后在同一个测试任务提交另一条不带密钥的合成文字，6 条 HTTP 目标请求仍被拒绝。回读加密归档后确认：每条完整请求的 `input` 历史中仍有上一轮的假密钥，因而 `ASSIGNED_SECRET` 再次命中。这里不能把“当前新输入不含密钥”直接当作一个良性请求被误判；本策略检查的是**完整待发送正文**，其中包含历史内容。第二轮报告位于 `runs/desktop-current/dlp-trace-20261104-02/summary.json`，SHA-256 为 `81E08C91A5315D235097A5C086BA85670D90A400A0E8B22EB580B972F254C82B`。当前客户端的独立、无敏感历史的正常请求放行仍未验证。

两轮报告均保持 `coverage_status=unvalidated` 和 `remote_origin_zero_bytes_verified=false`。未能可靠归属到固定测试任务的请求会透传；没有建立桌面附件原字节 Hook、当前账户 Agent 工具进程的独立网络边界或常驻控制器。此前独立 CLI 的受控源站与 MXC 结果不能外推为现用桌面端的全路径保证。
