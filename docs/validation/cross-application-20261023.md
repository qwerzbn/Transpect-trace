# 跨应用传播检测：2026-10-23 实现与验收

本轮在 `release` 工作树新增 `flow`，原 Codex 固定哈希、Guard v1、Observe v1、ECW2、UnifiedLLMRequest v1 与依赖锁保持兼容。未 commit／push。

阶段状态：文件与本地 Named Pipe 的固定受控场景及负例已阶段性完成。整个跨应用模块尚未全部验收；下文并发、改写、重连和故障联动待验收项继续保留。下一阶段扩展[跨 Agent 多步骤传播](../development/cross-agent-flow.md)，独立报告新结果。

## 交付

```text
显式登记 A / B（PID + 创建时间 + 映像哈希）
    ├─ Native I/O：A 源读取 → 文件写入 / 管道消息 → B 读取
    ├─ 多应用 ETW：独立成员的实际系统事件与健康
    └─ B / Schannel → 增强 eCapture → HTTP/1.1 正文重组
                                               ↓
                     普通外发检测 + 登记内容索引 + 候选传播关系
                                               ↓
                     正文哈希 / 次数 ↔ localhost HTTPS 源站回执
```

新增 `ttrace flow run/status/report`，四份证据模型与实验清单 Schema，Native I/O DLL、独立 WinHTTP B、多应用 ETW EXE、Python A、复现脚本和默认脱敏报告。构建接入 `scripts/build_native.py --component flow`；源码发布白名单、CLI 和 Schema 检查已更新。运行命令见[开发与复现说明](../development/cross-application-flow.md)。

所有新组件为 `can_enforce=false`。来源关系仍是证据支持的候选，不等于唯一来源或字节级污点追踪。测试真值、Native I/O、ETW、TLS 观察与源站回执分别保存。

## 首轮实采与保留的失败证据

完整联动记录位于本地忽略目录 `runs/cross-app/20261023-integration-06/`。该轮使用正常校验证书的 WinHTTP/Schannel，无代理、无 TLS 替换。证书租约结束后已确认清理。

| 场景 | Native 交接 | eCapture 正文与源站 | 检测 | ETW | 该轮结论 |
| --- | --- | --- | --- | --- | --- |
| 文件：敏感文本 | 完整 | 哈希／次数一致 | 命中 | 实采完整 | 通过 |
| 文件：读敏感、发普通 | 完整 | 一致 | no_match，不指认敏感内容外发 | 实采完整 | 通过 |
| 文件：大于 64 KiB 中文 JSON | 完整 | 一致 | 命中 | 实采完整 | 通过 |
| 文件：1 MiB | 完整 | 一致 | 命中 | 实采完整 | 通过 |
| 管道：敏感文本 | 完整 | 一致 | 命中 | 实采完整 | 通过 |
| 管道：读敏感、发普通 | 完整 | 一致 | no_match | 实采完整 | 通过 |
| 管道：大于 64 KiB 中文 JSON | 完整 | 一致 | 命中 | 实采完整 | 通过 |
| 管道：1 MiB | 完整 | eCapture 丢失 1 片，无法完整核对 | 不完整 | 实采完整 | 未通过 |

该轮 **7/8**。默认审计秘密扫描全部通过。丢片用例保留 `partial`，没有按 JSON 可解析、源站收到或单个元素匹配将其升级为完整。

原生 I/O 另通过实际分段文件／管道实验和半帧审计 IPC 关闭测试。Windows 管道 `ERROR_MORE_DATA` 的前两段与最后完整消息边界分别记录。文件覆盖、重建、多个同内容来源、PID 重用、管道重连歧义和重复正文等边界有自动测试；这些测试不替代相应真实业务应用验收。

## 本轮发现并修复

- Windows venv `python.exe` 可能只是重定向启动器。参与程序固定实际解释器并核对 ready PID，避免采集错误进程。
- Native IPC 初始化完成时钟、半帧取消、终态竞态及队列容量统计已修复。关闭观察器前参与程序保持存活。
- 多应用 ETW 原先仅用 Opcode 1 识别 ProcessStart，会把 WinHTTP ThreadStart 当成 PID 代次变化。现在同时核对 provider、事件 ID、Task 和 Opcode；没有降低实采覆盖要求。
- 直接管理员启动使用标准 `Popen.errors=None`，旧 eCapture 适配误将其当成错误列表。已兼容标准 Popen 与 UAC relay 的不同字段含义。
- 本地源站的 TLS 握手移到请求工作线程；未发送 ClientHello 或只发送半截正文时，关闭有 12 秒上限并记录缺口。新增真实 socket 回归验证正常中文大正文、两种中断及超限，客户端证书校验保持开启，测试不改系统信任库。
- 本地旧 eCapture 构建与当前补丁清单不符时，实验在释放数据前停止。旧产物未覆盖，重新构建到独立目录。
- 1 MiB 丢片暴露共享锁竞争风险。新增补丁 revision `2-context-queue-isolation`：拆分上下文／队列锁、锁外复制、保持提交顺序，并添加只含计数的诊断。ECW2 和上游 commit 不变。不能用新增诊断倒推旧失败的唯一原因。

新构建在 `build/flow-ecapture-v2/`；旧构建及 `integration-01` 至 `integration-06` 全部保留。固定竞争、真实 Context 竞争、队列容量、FIFO 和不确定性均有 Native fixture 测试。补丁更新后必须重新构建，旧产物仍会被严格身份校验拒绝。

## 新补丁重复实采：24/24 通过

用户允许 Windows UAC 后，预先固定的 8 种场景各重复 3 次，**24/24 通过**，没有排除失败尝试。本组实际采集时间为 2026-10-23 14:01:21–14:02:46（Asia/Shanghai），所有结果保存在 `runs/cross-app/20261023-integration-07/summary.json`。逐项复核记录及证据文件哈希位于同目录 `review.json`。

| 场景 | 文件链路 | Named Pipe 链路 | 实际结论 |
| --- | --- | --- | --- |
| 假凭据和登记机密文本 | 3/3 | 3/3 | 交接完整、外发命中、源站哈希／次数一致 |
| 读取敏感内容、上传普通文本 | 3/3 | 3/3 | 保留读取事实，外发 no_match，不建立敏感内容外发关系 |
| 大于 64 KiB 的中文 JSON | 3/3 | 3/3 | 分段重组完整、检测命中、源站一致 |
| 恰好 1 MiB 文本 | 3/3 | 3/3 | 上限内完整采集、检测命中、源站一致 |

独立核对得到：

- 24 组均有 3 条 Native 交接记录、1 个 eCapture 完整请求和 1 个源站回执。累计 504 条 Native I/O 事件、72 条完整传输记录、546 条 TLS 数据帧；逐次比较同层正文哈希及次数，共 6,941,256 字节，不以集合去重。48 次 `ERROR_MORE_DATA` 为正常的管道分段读取。
- 18 个敏感外发请求全部命中；6 个“读取敏感、发送普通”负例未被认定为敏感内容外发。
- A/B Native I/O、ETW、eCapture 共 96 份健康记录均有 ready／terminal，身份已核对，丢失、错误和健康缺口均为零。
- ETW 共采集 33,867 条实际事件，每组 1,353–1,511 条；每组均有 B 到当次受控源站地址和端口的实际网络事件。
- 按预定启动顺序，A/B 空闲进程先启动，ETW 随后就绪，所以本组没有它们的初始 ProcessStart 实采事件；48 条身份登记快照不能算作 ETW 启动事件。另有 48 条真实退出事件和 520 条 B 网络事件，其中 400 条匹配当次受控 IPv4 TCP 目标。
- eCapture 新增 9 类诊断计数在 24 组中均为零；各组加载同一已核验的新 DLL。此结果不倒推旧丢片的唯一原因。
- 两个参与程序各组均正常退出；独立扫描 360 个默认审计文件、33,389,856 字节，未发现测试秘密原文。中间假数据文件已清理。测试根证书 import／cleanup 成功，并再次查询确认已不在 CurrentUser Root 信任库。

本次通过的是固定实验程序、正文类型和大小范围内的两条链路及负例。特别是此前失败的 1 MiB 管道场景，本组连续三次完整通过；这不等于任意负载下永久零丢失。旧 `integration-06` 的失败结论不修改。

管道交接在本组报告中为 **Medium 候选关系**：端点和内容可核对，跨端局部连接代次尚无直接映射。源站与采集结果按次数及哈希一致，不宣称已建立请求 ID 的直接一一映射。所有新组件仍为 `can_enforce=false`，实际阻断次数为零。

管理员 PowerShell 的复现命令（输出目录必须尚不存在）：

```powershell
uv run --no-sync python scripts/probe_cross_application_flow.py --output runs/cross-app/20261023-integration-07 --prepare-test-trust --extended --repeat 3 --ecapture-dir build/flow-ecapture-v2
```

以下边界已建立自动测试，但还需要对应的真实联动实验，不能用 24 次独立重复替代：

| 边界 | 当前状态 |
| --- | --- |
| 文件覆盖、同路径重建、读取期间改写、多个同内容文件 | 模型反例通过，系统联动待验收 |
| 同正文并发、单客户端重试与连接复用 | 计数与关联测试通过，实际并发／重试待验收 |
| PID 重用、管道重连及重复消息歧义 | 身份和代次测试通过，实际联动待验收 |
| 传输中采集器退出、ETW 丢事件、队列溢出 | 故障与组件测试通过，完整联动待验收 |

两条受控链路、负例及大正文重复实采已完成；上述并发、改写和故障注入的完整系统联动仍未全部验收，因此不将它们纳入本次通过范围。

## 回归与工程检查

- 本轮全量自动测试 **468 passed**，报告：`runs/cross-app/20261023-final-checks/pytest.xml`。
- 原 Codex Guard：14/14 实际 HTTP/WSS 用例通过，包含允许、拒绝、凭据、失联、超时、畸形回复和读取后不携带敏感数据；拒绝用例源站零正文。
- 原 Native TCP 门控：20/20 实际受控用例通过，覆盖 IPv4/IPv6、connect/WSAConnect/ConnectEx、失联和错误回复等。
- `uv lock --check`、`uv pip check`、30 份 Schema 检查、工程入口与 wheel 内容检查通过；现有 25 份 Schema 无变更。
- Python wheel 排除 EXE/DLL、运行结果和私有输入。所有本地证据、证书、假数据和生成产物继续忽略，不加入源码白名单。
- 本轮没有重跑 GUI、真实浏览器、真实业务应用或 WFP 实采，不从自动测试推导这些能力通过。

## 边界

只覆盖登记的受控同步 Win32 I/O 程序、本地单向消息管道、UTF-8 文本／JSON 和 WinHTTP HTTP/1.1。Named Pipe 跨端本地代次不强行相等；重连有歧义时降级。文件存在未观察写入者的可能性，High 仍不是唯一来源证明。

异步／远程 IPC、剪贴板、共享内存、任意文件解析、浏览器和应用 B 发送前阻断仍未实现。采集器错误、丢事件、缺 terminal、正文缺片或身份失效都保留缺口；控制器退出后 `flow status` 不继续显示有效观察状态。
