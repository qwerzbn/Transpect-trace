# 桌面无应用 Hook Demo：当前状态与验收边界

本页记录本机 Codex 桌面端 Local 任务的无应用 Hook Demo。截至 2026-11-08，已安装包为 `OpenAI.Codex_26.1103.3517.0_x64__2p2nqsd0c76g0`，本地 `codex.exe app-server` 报告 `codex-cli 0.167.0-alpha.3.2`，后端 SHA-256 为 `40ecc3d8b6899afd8f935a8cccb7d53ba41ffd7c199f679e186d30ddd0d0bf39`。桌面自动更新后须重新核对这些身份，旧版实验结果不能外推。

## 边界与当前状态

本 Demo 不使用网关代理，也不使用 Codex 自带的 `hooks.json` 命令 Hook（`UserPromptSubmit`、`PreToolUse`、`PostToolUse`、`PreModelRequest`）作为门控。模型正文只由本地 NativeHook 获取。截至上述日期，本机 `~/.codex/hooks.json` 已移除；原文件备份位于 `runs/scratch/demo-system/backup/hooks.json`。备份仅用于回溯，不参与 Demo。

| 路径 | 目标机制 | 当前可报告状态 |
| --- | --- | --- |
| 模型请求 | 只由当前后端的 NativeHook 在完整请求序列化后、发送前判定 | **`MODEL_EGRESS_NOT_COVERED`**。`0.167` 的隔离合成 HTTP/WSS 实验通过；三次真实桌面试运行均出现用户可见错误。当前后端的 DLL 仍映射，但租约已释放、Hook 已停用，控制器未运行；实机入口已暂停。完整路由覆盖和可持续使用的适配仍未验证。 |
| Agent 工具直接联网 | 桌面 Local 任务采用网络关闭的 MXC 受限权限；可选系统 API Hook 只能作补充 | **未验证**。旧测试任务的权限记录为 `danger-full-access`，其工具进程曾到达本机测试收件器；新的受限任务必须单独核验实际工具身份和接收端结果。 |
| 行为审计 | ETW 观察桌面 `app-server` 及采集开始后出现的后代进程 | **仅元数据**。可记录进程、文件与网络事件及采集缺口，不证明模型正文、文件读取成功或网络载荷已发送。 |

`runs/scratch/adapt-26.1103/portability.json` 是新后端的静态定位报告，结论为 `native_route=locator_only`；下述动态采集和三次实机试运行尚未形成可持续启用的桌面适配。`CODEX_ROLLOUT_TRACE_ROOT` 写出的完整请求体仅在隔离适配实验中作为比对真值；它不是生产内容源，也不能代替发送点 NativeHook。eCapture、SChannel、Winsock 和 ETW 的网络观察不作为当前桌面模型正文的替代来源。

## 隔离合成实验

在精确匹配上述后端 SHA-256 的独立 `codex.exe app-server` 上，以随机合成标记和本地不转发源站分别运行 HTTP 与 WSS。实验均未使用 Codex 命令 Hook。首轮 Native Frida 观察只记录目标正文的长度、SHA-256 和标记位置；比对的 trace payload 文件包含完整请求 JSON，不充当生产内容源。

| 路径 | 目标正文 | Native 捕获、trace 紧凑 JSON、本地源站三方结果 |
| --- | --- | --- |
| HTTP `/responses` | 40,987 字节 | SHA-256 均为 `fa58d56227e58233f223574dc582131d2b6aebf49c19b0654e62de46b158575d` |
| WSS `response.create` | 41,057 字节 | SHA-256 均为 `46dec80691183ccc42bce980d5c85cb29921ebe84d91c9ab819ac0e676bb7db0` |

首轮报告为 `runs/scratch/adapt-26.1103/current-capture-frida-lab-2.json` 和 `runs/scratch/adapt-26.1103/current-capture-wss-frida-lab-2.json`。后续 `current-capture-http-full-lab.json` 和 `current-capture-wss-full-lab.json` 又对各自的完整捕获体做了 DPAPI 保护的加密归档与独立回读：解密正文的长度、SHA-256 均与 trace 紧凑 JSON 和本地源站一致，且 collection envelope 明确标记 `decision_point=none`、`route_decision=not_enforceable`。这些仍是只读观察，没有执行拒绝。

再用单独的实验版 Native DLL、`PipeServer` 和 `NativeCollectionEngine` 运行四个合成用例。先固定后端哈希和 HTTP/WSS 入口前缀，再把 DLL 注入**独立子进程**并等到就绪，随后才发起 `thread/start`；本地源站不转发请求。注入器在用于加载 DLL 的同一个目标进程句柄上复核进程创建时间与映像路径，防止 PID 在身份检查与加载之间被复用。DLL 仅在本实验使用 `TTRACE_FAIL_STOP_DENY`：任何非放行决定使该子进程退出，代码为 76，不构造当前未验证的 Rust 错误返回，也不调用旧版 HeaderMap 析构函数。

| 实验用例 | 管道、归档与源站结果 |
| --- | --- |
| HTTP 放行 | 完整正文经管道及加密归档回读，与 trace 和本地源站长度、SHA-256 一致。 |
| HTTP DLP 拒绝 | 完整正文经管道及加密归档回读；实验子进程退出码 76，接收端未见目标请求连接，HTTP 模型正文接收计数为 0 字节。 |
| WSS 放行 | 37,456 字节的早期非目标请求和目标请求均经管道、归档回读，并与各自源站正文一致。 |
| WSS DLP 拒绝 | 早期非目标请求被放行、采集并归档；目标请求归档后被拒，子进程退出码 76，目标连接的升级后 WebSocket 帧接收计数为 0 字节；该连接另收到 2,972 字节 TLS 握手／重置流量。 |

加固注入器并移除实验驱动对旧 Hook 研究脚本的导入后，收件器在监听及连接处理线程结束后才汇总计数。最终四个用例重跑均报告 `validated=true`，汇总见 `runs/scratch/adapt-26.1103/current-integrated-guard-lab-quiescent-1/summary.json`，其中 `production_desktop_coverage_validated=false`。两个 DLP 拒绝用例的 `non_warmup_body_counter_verified=true` 且 `non_warmup_wire_body_bytes_received=0`；这证明本地源站未收到目标 HTTP 模型正文或升级后的目标 WSS 帧，不代表 TCP/TLS 连接完全没有传输字节。复现须使用同一精确后端和本机可解密的隔离归档证据；构建脚本读取并核验完整归档，后端哈希、入口前缀或 DPAPI 回读不符时拒绝构建。输出目录必须是新目录：

另在 `runs/scratch/adapt-26.1103/current-controller-loss-lab-quiescent-1/summary.json` 以同一加固注入器和收件器汇总方法复测控制器断连：HTTP/WSS 两条路径均在 DLL 和管道就绪后、目标轮次发起前停止 `PipeServer`。两次实验子进程均以代码 76 退出，接收端核验非预热模型正文／帧为 0 字节，且未收到目标请求。WSS 早期非目标预热请求已在断连前经管道检查并归档；目标连接仍可有 TLS 握手／重置流量。该结论只适用于独立合成后端，不能证明现用桌面进程已具备同样的断连保护。

```powershell
$pin = Get-Content 'runs/scratch/adapt-26.1103/portability.json' -Raw | ConvertFrom-Json
$backend = $pin.builds.'0.167.0-alpha.3.2 (40ec)'.path
uv run --no-sync python scripts/build_guard_failstop_current_lab.py --backend $backend
$runDir = "runs/scratch/adapt-26.1103/integrated-guard-$(Get-Date -Format yyyyMMdd-HHmmss)"
uv run --no-sync python scripts/probe_desktop_guard_failstop_current_lab.py --backend $backend --output $runDir
$lossDir = "runs/scratch/adapt-26.1103/controller-loss-$(Get-Date -Format yyyyMMdd-HHmmss)"
uv run --no-sync python scripts/probe_desktop_guard_failstop_current_lab.py --backend $backend --output $lossDir --cases controller_loss
```

这只验证固定后端的隔离合成路径。真实桌面中的 `app-server` 为共享进程，Native DLL 作用于同一进程的所有聊天和工作区；测试工作区只用于构造可控输入，不限定防护或故障范围。一次前台实采已捕获并拒绝 HTTP 请求，但仍未验证正常交互、HTTP/WSS 全路由及重试覆盖。本实验的进程终止拒绝不是平稳返回错误。

## 单请求拒绝候选：仅隔离实验

针对同一个后端 SHA-256，又构建了独立于失败即停 DLL 的 `return_rust_error_candidate` 实验件，DLL SHA-256 为 `365d61b01fd6e6c289f0a2b1d5b86014e7a979bfae26faa77294f62e8d5a43c1`。它在发送前返回当前版本的 Rust 错误布局；构建清单仍标记为 `lab_only=true` 和 `unvalidated_graceful_candidate_not_desktop_adapter`。以下隔离实验使用独立 `app-server`、合成假密钥和本地不转发源站。

`runs/scratch/adapt-26.1103/graceful-followup-2/summary.json` 的 HTTP/WSS 两项均为 `validated=true`：被拒正文与 trace 匹配，目标源站请求数、模型正文及非预热帧接收计数均为 0；拒绝回合状态为 `failed`，后端 PID 与映像身份保持稳定，同一 PID 的后续正常请求到达本地源站。WSS 拒绝后还出现一次 HTTP 回退尝试，Native 也拒绝了该请求，两次被拒正文均未到达源站。WSS 的连接仍有 TLS 握手／断开流量，零字节仅指目标模型正文／帧。HTTP 后续正常回合因本地源站返回 503 而显示失败，源站收到正常正文及进程存活才是该项的验证点；WSS 后续正常回合显示完成。

`runs/scratch/adapt-26.1103/graceful-repeat-1/summary.json` 在各自同一 PID 上重复两组“拒绝、正常请求”：所有请求的加密归档回读精确匹配，HTTP/WSS 被拒正文及 WSS 的 HTTP 回退仍是目标源站 0 字节，两次后续正常请求均到达源站，后端在第二组后仍存活。两份报告均写明 `synthetic_only=true`、`production_desktop_coverage_validated=false`。这些结果不能证明真实桌面中的连续聊天、全部路由或自动换版后的安全性。

## 两次前台试运行与暂停状态

2026-11-08 对当时的桌面 `app-server` PID `7776` 启动了失败即停控制器。`runs/scratch/desktop-live-trial-20261108-144405/status.json` 记录 Native DLL 与管道均就绪、观察到 1 条 HTTP 模型请求；`native-audit.jsonl` 记录请求 `7776-3`、正文 90,933 字节、决定为 `deny`。加密归档回读确认该请求的 `client_instructions` 完整包含合成测试工作区 `agents/AGENTS.md`，其中的假密钥触发 `GITHUB_TOKEN` 检测。该请求被拒后旧后端退出，桌面出现 GPT 错误。历史控制器随后查询已退出的 PID，把轮询错误写为 `WinError 87`；新代码会把有拒绝记录且以代码 76 退出的后端报告为 `blocked_backend_exit`，历史状态文件保持原样。

这次实采证明**一条**真实桌面 HTTP 请求进入本地采集与拒绝流程；没有独立的真实源站零字节测量，也没有 WSS 请求或重试的覆盖证据。单条审计无法证明用户看到的每次 GPT 错误都来自同一次拒绝。失败即停 DLL 的拒绝动作会结束共享后端，不能用它继续做正常聊天测试。

随后对 PID `24220` 加载单请求拒绝候选。`runs/scratch/desktop-graceful-live-20261108-gate-1/native-audit.jsonl` 记录 Native 与管道就绪后两次 HTTP 判定：两次正文长度均为 949,993 字节，但 SHA-256 不同。第一次采集耗时 6.058 秒，超过判定期限而拒绝；第二次以 `SENSITIVE_OR_AMBIGUOUS_CONTENT` 拒绝。桌面出现 ChatGPT 错误页面，用户随后手动关闭并重启 Codex；旧后端与控制器因此不再运行。`status.json` 停留在 `ready`，只是未完成收尾的快照，**不能**证明控制器仍运行或模型外发受到保护。这次没有独立的真实源站实收证据；同一旧后端曾处理第二次请求，未发现它被 DLL 杀死的证据。两种实机入口均已暂停。

### 实机故障后的采集改动与后续复测

大请求的本地排查发现 EMAIL 检测在长而不含 `@` 的用户名式字符串上反复尝试，且逐内容条目持久化归档使数百个条目产生重复写入。现已给 EMAIL 匹配加入边界，并让完整请求只持久化一次；条目记录以位置和摘要引用该加密归档，回读时验证条目位置与摘要。约 950 KB 请求的本地回放处理时间由 5.43 秒降至 0.486 秒。这是采集层回放耗时；上面的 `graceful-followup-2`、`graceful-repeat-1` 和 `graceful-large-http-*` 报告早于该改动。

改动后的隔离端到端验收另见 `runs/scratch/adapt-26.1103/graceful-shared-repeat-1/summary.json`：HTTP/WSS 各两轮“拒绝、正常请求”均为 `validated=true`，加密归档回读精确匹配，拒绝目标源站请求和模型正文／非预热帧均为 0；同一 PID 的后续正常请求到达本地源站，第二轮后进程仍存活。`runs/scratch/adapt-26.1103/graceful-shared-large-http-1/summary.json` 用 950,001 字节、542 个内容项的 HTTP 合成请求重跑，第一次拒绝判定耗时 462 毫秒，未触发 2 秒判定期限；目标源站仍为 0 字节，同一 PID 的后续正常请求到达源站。这两份报告均标记 `synthetic_only=true`、`production_desktop_coverage_validated=false`，没有证明真实桌面的大请求性能或覆盖。

控制器还增加仅用于试验的 `--protect-thread-id <UUID>`。Native DLL 仍装在共享 `app-server` 中，但管道只对请求顶层 `client_metadata.thread_id` 与目标 UUID 一致的聊天执行内容检查与归档；其他聊天和无法识别聊天 ID 的请求在管道入口直接放行，不进入 DLP 或内容归档。这明确留下**未保护的外发路径**，不能声称全局模型外发覆盖。当前聊天历史含合成假密钥，若选它为目标，后续请求仍可能被拒。后来的真实桌面限定聊天试用仍使范围外请求受阻，详见下文；`LIVE_TRIALS_PAUSED=True` 已重新锁住实机入口。

### 租约候选：控制器停止后放行，仅隔离实验

另一个测试候选将 Native DLL 与控制器线程持有的 Windows 互斥体租约绑定，DLL SHA-256 为 `768c07f709d83fbb8cd5d808e89b254cd96813a56c6ea6f2763f4dac9123de2d`。控制器主动释放租约或拥有者线程退出时，Hook 进入旁路并尝试停用；停用事件用作确认。`runs/scratch/adapt-26.1103/graceful-lease-2/summary.json` 对 HTTP/WSS 各执行主动释放与拥有者退出，共 4 项均为 `validated=true`：保护期间的合成敏感请求被拒且归档回读匹配；租约结束后均收到 `disabled_ack`，同一 PID 的后续正常请求不经管道判定而到达本地源站。此时的正确状态是**防护已停止，外发可通行**，不能把停用确认写成继续受保护。

用上述精确 DLL 又运行 `runs/scratch/adapt-26.1103/graceful-lease-content-repeat-1/summary.json` 与 `runs/scratch/adapt-26.1103/graceful-lease-content-large-http-1/summary.json`：HTTP/WSS 两轮拒绝与放行、950,001 字节 HTTP 大请求均通过，拒绝目标在本地源站的模型正文／非预热帧为 0 字节，拒绝后同一 PID 的正常请求到达源站，释放租约后收到停用确认。这些报告仍为 `synthetic_only=true`、`production_desktop_coverage_validated=false`。

租约丢失采用 **fail-open**：控制器停止或异常退出后，后续请求不再由 DLP 检查。上述基线 DLL 的 HTTP 低层拒绝还被 Codex 映射成可重试的 `Stream` 错误；隔离实验的进程存活不代表真实桌面不会重试或显示错误。该基线 DLL 未用于真实桌面试验，也未改变 `MODEL_EGRESS_NOT_COVERED`。

为消除 HTTP 重试而尝试过另一个独立候选；`runs/scratch/adapt-26.1103/nonretry-lease-smoke-2/http-release.json` 记录敏感请求的本地源站计数为 0，但回合仍以带拒绝标记的可重试 `Stream` 错误失败，且租约结束后 `disabled_ack=false`、`validated=false`，没有取得 Hook 完全停用或停止后正常请求到达源站的证据。该候选 DLL SHA-256 为 `d357e4b19e1c74c34ea79fdeca077f4ff547abbfa848cde3b0184c513defe8ea`；源码现已撤回，不能把这次实验写成非重试适配成功。上面的租约基线 DLL SHA-256 `768c07f7…` 及其通过的隔离报告不受此失败候选替代。

随后另做一版**独立的**非重试加租约候选，固定 DLL `build/guard-nonretry-current-lab-v2/ttrace-guard-nonretry-current-lab.dll`，SHA-256 为 `36dd35096ff05b8cfbd5e714aa8700ff26abd04471b7340132e3bb99d0a976ba`。冻结汇总报告 `runs/scratch/adapt-26.1103/nonretry-validation-summary-v3.json` 的 SHA-256 为 `fde28d6066d55a589e599a030dd7ab019f288e49325904b1c2fa477710595284`，其中固定 4 份租约报告、3 份内容深测报告、HTTP/WSS 各 1 份动态错误映射报告及 1 份正常 HTTP SSE 后续回合报告，共 10 份独立证据。映射输出是 `CodexErr::InvalidPrompt`（标记 `0x8000000000000012`）。

该汇总在独立 `app-server` 子进程与本地不转发源站上报告 `validated=true`：HTTP/WSS 各两个被拒回合，在请求与流重试上限均设为 2 时，每回合仅一条被拒请求，WSS 没有 HTTP 回退；包括 950,001 字节 HTTP 请求在内的拒绝正文源站计数为 0。同一 PID 的后续正常请求到达本地源站。内容深测中的源站返回错误，故只证明请求到达；另见 `runs/scratch/adapt-26.1103/nonretry-success-http-lab-2/report.json`，本地 HTTP 200 SSE 源站使同一 PID 的两次正常后续回合均以 `status=completed` 结束，同时两次敏感回合各仅一次 Native 拒绝且源站 0 字节。租约主动释放与拥有者退出均取得完整停用确认，停止后的请求无需策略管道即可到达源站，这也表示租约失效后不再防护。报告明确 `production_desktop_coverage_validated=false`、`live_desktop_injected=false`；前述失败候选记录仍保留。此后该候选有一次真实桌面试用，见下文。

`scripts/desktop_demo.py` 已有 `--guard nonretry_lease` 的只读精确证据准入，核对后端、DLL、构建清单、采集源码和上述 10 份报告。干净的 Local 聊天也与其他桌面聊天共享同一个 `app-server`，不足以隔离前台故障。真实前端的安全性须在独立 OS 会话或虚拟机中验证；本机未找到 `WindowsSandbox.exe`，Windows 可选功能状态查询在当前权限下需要提升，尚无可用的隔离桌面实测环境。

### 第三次前台试运行：范围外请求也受影响

2026-11-08 对当前桌面 `app-server` PID `23212` 加载上面的非重试租约候选，并限定到干净 Local 聊天 `01a1b9e7-0df6-7ad1-99a6-20ad6babb59c`。控制器在 `runs/scratch/desktop-scoped-nonretry-20261108-171821/status.json` 记录 `native_ready=true`、`pipe_ready=true`、2 条 HTTP 模型请求及 `scope_counts.bypassed=2`、`target=0`。随后管道记录两次 `ValidationError` 并触发控制器退出。开发中的聊天出现 `TTRACE_NATIVE_DENY_0167`；这证明按聊天限定仍可能干扰共享后端的其他聊天。历史日志只保存异常类名，无法从这份记录确定具体字段，后续必须在隔离子进程重现并修复。

控制器最终状态为 `state=failed`、`lease_released=true`、`native_hooks_disabled_attested=true`；后端 PID 仍存活，DLL 映射仍在，但 Native Hook 已停用。没有取得目标干净聊天的真实前端验收，也没有真实源站零字节证据。用户要求先完成开发再接入桌面，因此实机激活重新锁住，当前状态为 **`MODEL_EGRESS_NOT_COVERED`**。

管道现将 Pydantic 帧校验失败记为有限的字段名、错误类型、帧长度与安全的帧类型提示，不保存正文或无效输入；无效模型帧仍得不到放行回复，后续有效帧可继续处理。`runs/scratch/scoped-native-protocol-20261108-173236/report.json` 又在独立 `app-server`、精确非重试 DLL 与本地不转发 HTTP 源站中验证了范围外路径：正常回合完成，2 条 HTTP Native 请求被绕过，目标正常请求的 SHA 与源站实收一致，`validation.count=0`、`pipe_errors=[]`、租约停用确认成功。这没有复现真实桌面此前的两次 `ValidationError`，也不证明该修复已消除真实前端问题；旧日志没有字段级信息，具体原因仍未知。

进一步在 `runs/scratch/scoped-native-protocol-large-20261108/report.json` 用约 941 KB 的范围外请求重跑，正常回合仍完成，源站 SHA 一致。为区分“控制器写出放行”与“Native 实际接受放行”，管道新增有限的 QPC 时延、回复写入/刷新及后续 Native outcome 关联；在独立的**仅实验室**诊断 DLL 上，`runs/scratch/scoped-native-diagnostic-delivery-large-20261108/report.json` 的两条约 941 KB 请求均于 Native 捕获后 8 毫秒内写出放行，DLL 回报 `parsed_allow`，回合完成。该诊断件未加载到现用桌面，也不替换冻结生产候选。大正文和范围外分支单独重现不了之前的前端拒绝，真实故障原因仍待隔离桌面验证。

`runs/scratch/scoped-native-diagnostic-concurrent-20261108/report.json` 又在同一个独立后端同时发起两个不同聊天的约 941 KB 请求，两个回合均完成；4 条 Native 判定全部回报 `none/parsed_allow`，服务端回复写入 QPC 时延最长约 10.3 毫秒，两个源站正文分别与捕获 SHA 一致。该并发实验也未复现真实桌面的拒绝。历史实机记录仍不足以把故障归于响应超时、回复格式或后端映射中的任一环节。

随后用**真实出错时的冻结 DLL** 重跑双聊天范围外并发，`runs/scratch/scoped-native-frozen-concurrent-pipefix-20261108/report.json` 的两个回合均完成，约 941 KB 正文分别与本地源站 SHA 一致，4 次回复写入和刷新成功、管道校验错误为零。该 DLL 不发出放行的 `native.outcome`，因此不能从此报告声称已取得内部 `parsed_allow` 诊断；正常回合完成及源站实收只证明隔离环境的实际放行。

采集器现只对当前 `nonretry_lease` 控制器启用并行内容检查，避免一个请求的归档和检测占住其他请求的全局判定锁；旧策略引擎仍串行。`runs/scratch/scoped-native-global-concurrent-20261108/report.json` 首次在独立后端让两个约 941 KB 请求都进入完整内容检查：合成填充词触发既有检测限制，两个请求约 94–98 毫秒内被拒；完整加密归档回读与 Native 捕获 SHA 一致，本地源站收到 0 个请求。只调整合成填充文本后的 `runs/scratch/scoped-native-global-concurrent-benign-20261108/report.json` 中，两个不同聊天的正常回合均完成，4 次完整归档回读和源站正文 SHA 分别匹配，4 次回复写入与刷新成功，最迟约 479 毫秒，管道校验和处理错误均为零。这些仍是隔离实验，不能替代真实桌面正常请求与拒绝请求的前台验收。

`scripts/desktop_guard_supervisor.py` 已实现当前包、版本、哈希、父进程、SID 与进程实例的自动发现，以及控制器退出后不对同一进程重复注入；`scripts/manage_desktop_guard_autostart.py` 可注册当前用户登录时启动的观察任务。默认任务只读，**尚未安装**。进程轮询到 Native 就绪之间有启动空窗，故不能宣称“每次 prompt”已受保护。设计和操作边界见[桌面自动发现](desktop-guard-autostart.md)。

当前 PID `23212` 的只读状态检查显示 `live_guard_resident=true`、`native_hooks_disabled_attested=true`、`foreground_controller_active=false`、`ready_for_live_trial=false`。PID 和版本可能再次变化，检查时须重新核对。`status` 只读，不会加载 DLL：

```powershell
$appServerPid = [int](Read-Host '已核对的当前桌面 app-server PID')
uv run --no-sync python scripts/desktop_demo.py status --pid $appServerPid
```

Native DLL 的驻留范围是整个 `app-server`，不是指定工作区。上述按聊天 UUID 的试验范围只决定哪些请求进入内容策略；未选中的或无法识别的聊天直接放行。干净的 Local 聊天和工作区用于正常请求对照；含假密钥的 `AGENTS.md` 或聊天历史会进入后续请求并再次触发规则。当前聊天历史已含合成假密钥，不适合作为正常放行样本。

## 本轮可运行的只读审计

权限审计只读取指定 Local 任务 rollout 的 `turn_context` 权限元数据，不解析用户输入、工具结果或模型正文。省略 `--thread-id` 时仍使用固定合成测试任务；给出另一个 UUID 时只读取该任务的记录。即使出现受限策略，两项 `desktop_tool_*_attested` 仍为 `false`，直到实际沙箱和接收端验收完成。

```powershell
$threadId = '01a1a5ad-14de-7861-afe8-7670bfb99d3b'  # 可换成待核验的 Local 任务 UUID
uv run --no-sync python scripts/audit_desktop_local_permissions.py --thread-id $threadId
```

ETW 采集使用独立于 Guard 适配器的只读桌面身份固定值。先确认目标 PID 是当前安装包启动的本地 `codex.exe app-server`，从有 ETW 权限的终端运行有界采集；切换版本、身份不符或 PID 已被复用时应拒绝启动。以下命令中的 `$appServerPid` 是人工核对后的进程 ID，输出目录须是新目录。

```powershell
$appServerPid = 1234  # 替换为已核对的本地 app-server PID
$runDir = "runs/desktop-system-hook/etw-$(Get-Date -Format yyyyMMdd-HHmmss)"
uv run --no-sync ttrace behavior attach --channel desktop --pid $appServerPid --output $runDir --duration 30
```

`status.json` 是采集状态快照，`events.jsonl` 和报告的 `behavior_timeline` 提供按进程实例与 QPC 时间组织的行为元数据；`clock` 保存时钟锚点。桌面报告保持 `model_egress_status=MODEL_EGRESS_NOT_COVERED`、`llm_audit_binding=no_guard_audit`、`model_request_mapping=unvalidated` 和 `tool_execution_mapping=unvalidated_no_native_audit`。采集 `unavailable`、丢事件或解码错误必须显示为缺口，不能视为干净时间线。采集开始前已存在的工具子进程可能无法归入这次进程树。

## 2026-11-08 全局实机测试

按用户要求临时解除 `LIVE_TRIALS_PAUSED`，对重启后的干净后端以 `nonretry_lease` 全局模式接入，测试工作区为 `D:\ttrace-desktop-live-20261108-144405`，聊天均在新建的 Local 会话中发送。三轮控制器的记录分别为：
- `runs/scratch/desktop-live-test-20261108-pid8824/`
- `runs/scratch/desktop-live-test-20261108-pid19584/`
- `runs/scratch/desktop-live-test-20261108-pid21876/`

测试结束后暂停开关已恢复。

### 误拦根因：zstd 压缩正文二次经过发送点

ChatGPT 账号路径下，Codex 先把 JSON 正文交给 HTTP 发送点，随后把 zstd 压缩后的正文再次交给同一挂钩点。客户端日志对应行为 `Compressed request body with zstd pre_compression_bytes=99097 post_compression_bytes=33948`。

DLL 的 `quote()` 原样拷贝 0x80 以上的字节，压缩体形成非 UTF-8 帧。管道判为 `json_invalid` 后不回复，Native 按缺少判定拒绝请求，界面显示 `TTRACE_NATIVE_DENY_0167`。第三次试运行中的两次 `ValidationError` 与此同源。隔离实验的本地源站不触发压缩，因此未暴露。

`guard/pipe.py` 现以 `surrogateescape` 无损还原原始字节：完整的 zstd 正文在大小上限内解压为严格 UTF-8 后照常检查；其他二进制、截断流、WSS 及超限正文仍不回复。修复后，所有压缩调用都按与已判定 JSON 正文相同处理；三轮记录中的 `pipe_validation.count` 均为 0。

本机到 Responses WebSocket 的连接全天均有 5 次超时后回退 HTTP 的现象，在任何试运行之前已存在；本轮所有模型请求均经 HTTP 发送，**WSS 挂钩点未取得实机覆盖证据**。

### 场景结果

| 场景 | Native 记录 | 结果 |
|---|---|---|
| 正常对话 | `19584-3` 放行；压缩调用 `19584-4` 还原后识别为重复调用并放行 | 正常回答 |
| 粘贴合成 GitHub 令牌 | `19584-5` 命中 `GITHUB_TOKEN`，发送前拒绝 | 报错，客户端日志无压缩与发送记录，无重试 |
| 合成个人信息 | `19584-7` 命中 `CN_ID`、`PAYMENT_CARD` 等 6 条规则 | 报错 |
| 读取含令牌文件并回传 | 首次请求 `19584-11` 放行；携带工具结果的 `19584-15` 命中 `GITHUB_TOKEN` | 文件已在本机读取，模型未收到正文 |
| base64 编码后回传 | `19584-19` 命中 `GITHUB_TOKEN_DECODED` | 模型未收到编码结果 |
| 工作区为 `agents\` | `19584-9` 在 `client_instructions` 中命中 `AGENTS.md` 的合成令牌 | 首个请求即被拒 |
| 客户端后台建议 | `19584-13`：后台请求为当前项目生成建议，汇总了此前被拒会话中的令牌与个人信息 | 发送点拒绝 |
| curl 直接上传含令牌文件 | `21876-3`、`21876-5` 放行 | **未拦截**：本机回环收件端在 20:37:37 收到 64 字节，SHA-256 与文件一致 |

curl 场景暴露两点：
- **工具自身的网络连接不经过模型请求发送点。** 这些会话的权限为 `danger-full-access` 且联网开启，模型请求发送点看不到 curl 的连接。
- **`tool_policy` 的路径规则漏检。** 命令嵌在 code-mode `exec` 的 JS 字符串中，路径写作 `\"@file/secrets.txt\"`，右边界遇到反斜杠后未命中 `secrets_file`。

后续处理见 [开发计划](../../plan.md) 的 P0-1 与随行修复。

## 后续验收门槛

1. 固定后端的旧隔离合成 HTTP/WSS 采集、归档回读、放行、失败即停拒绝、控制器断连，以及单请求错误返回与同进程拒绝后放行均已通过；三次实机试运行出现用户可见错误，其中一次大请求判定超时已被实采记录。大请求采集优化后的 HTTP/WSS 连续拒绝与放行、950,001 字节 HTTP 请求，以及租约主动释放／拥有者退出后停用，也已通过新的隔离端到端验收。首次 HTTP 非重试候选失败，第二个独立候选在隔离实验中通过精确错误映射、无重试和同 PID 正常 HTTP SSE 回合；**真实桌面前台稳定性与覆盖仍未验证**。应先取得独立 OS 会话或虚拟机，再做前台安全验证。此处及任何换版后继续报告 `MODEL_EGRESS_NOT_COVERED`；按聊天试验范围及租约失效后的旁路均不能证明全局覆盖。
2. 在桌面界面为合成 Local 任务选用网络关闭的受限权限后，重新审计有效权限；再核对实际工具进程的 MXC 身份，并用本机非回环接收端验证 TCP/UDP、IPv4/IPv6 路径。单有权限字段或 ETW 网络事件不能声明工具离线。
3. 只有上述模型与工具路径分别取得动态证据后，才制作拒绝、放行和故障演示。ETW 时间线用于行为审计，不充当发送前拒绝或零字节收件证明。

旧版 [Hook 门控实验](codex-hook-gate.md)、[桌面 Native 探针](desktop-current-mainline.md)和[HTTPX 输入输出实验](../demo-io-audit.md)各有自己的版本与场景边界，均不证明当前无应用 Hook Demo 已覆盖模型或工具外发。
