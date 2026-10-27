# 2026-10-26 首条跨应用内容阻断验收

## 结论

范围更正：本文件记录的是“导出文件 → Codex 工具结果 → LLM 请求拒绝”回归，不包含“应用 A 读取并修改文件、独立应用 B 读取并上传文件”。后者有独立的 [文件修改与上传复现实验入口](../../scripts/probe_file_modify_upload.py)，两组结果不能互相替代。

本轮通过的完整链路是 **独立 Python 导出程序 → 普通 JSON 文件 → 官方 Codex CLI → PowerShell 正常读取 → 后续 LLM 请求 → Native Guard 按敏感内容拒绝**。

普通内容允许、敏感内容拒绝两组真实执行均通过。业务交接没有使用实验 Named Pipe。工单来源和模型源站是本地、不转发流量的受控服务；导出程序是测试程序，Codex 与 PowerShell 是实际客户端。该结果不认证真实 Jira、线上模型服务、任意业务应用或非 LLM HTTPS 上传。

| 用例 | 外部采集证据 | 实际结果 |
| --- | --- | --- |
| 普通工单 | Native I/O 观察到导出进程实际写入 90 字节，与工单源响应哈希／长度相同；工具结果包含同一测试标识 | 内容通过策略，模型源站收到标识，Codex 完成响应 |
| 含假机密工单 | Native I/O 观察到实际写入 92 字节；标识进入实际 Codex 工具结果和待发送请求 | 策略拒绝与 Native 执行回执均对应请求 `29364-5`；客户端得到拒绝错误；被拒正文在源站为 0 字节 |

“0 字节”针对被拒请求正文；前面正常请求仍可能发送。此次拒绝不是结束进程、断开已经完成的上传或固定目标黑名单。

## 数据传递与证据

```text
受控工单 HTTP 服务（假数据）
    ↓ 正常 HTTP GET
独立 Python 导出程序
    ↓ 普通文件写入；Native I/O 获取实际完成的写入范围
incident.json
    ↓ Codex 调用真实 PowerShell Get-Content
Codex 工具结果
    ↓ 后续 HTTPS 模型请求的完整正文
原固定版本 Native Guard + 原本地内容策略
    ├─ 普通内容：正常发送，源站接收
    └─ 敏感内容：block_request，Native 执行回执，源站未收到被拒正文
```

导出程序与 Codex 的身份独立登记，核对 PID、进程创建时间、映像哈希及实际父进程关系。两者是控制器分别启动的应用，互不为父子进程。写入证据来自 Native I/O，而不是导出程序自行报告的“已写入”。工具结果和拒绝结论来自既有 Native Guard 的实际请求入口。

普通组写入事件为 `io:19100:134374727533221180:3`；敏感组为 `io:9832:134374727655111454:3`。源站回执与写入事件独立核对。来源关系仍是内容支持的候选，不证明任意内存字节的因果传播或唯一来源。

固定官方 Codex SHA-256 为 `d13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec`，磁盘文件未改。此次验收为 HTTP 请求路径；没有以本轮结果重新认证 WSS streaming。

## 复现

在仓库根目录使用已锁定环境运行：

```powershell
uv run --no-sync python scripts/probe_cross_app_codex_guard.py `
  --codex C:/baselines/codex.exe `
  --output runs/cross-app-codex-acceptance/<新运行目录> `
  --fake-data-only
```

清单中的本机原始实验副本位于 `D:/code/transpect-trace/runs/guard-native/aslr-copy-reject-16/official-copy/codex.exe`；新机器须准备相同哈希的正式基线。默认复用 `build/guard` 和 `build/flow-linkage`，可用命令行参数指定已有、经构建清单校验的路径，不覆盖旧产物。

本轮成功记录在本地 `runs/cross-app-codex-acceptance/20261026-file-llm-01/summary.json`，每组包含独立 `chain-summary.json`、脱敏导出写入证据及固定 Native Guard 验收源站证据。`fixture/` 包含明确的原始假数据、受控模型通信及测试 CA 材料，不属于可默认上传的脱敏报告。

受控模型出口使用原客户端 TLS 和显式测试 CA 文件，保持证书验证；没有网络代理、TLS 替换或 Windows 根证书导入。测试 CA 只服务于该隔离源站。此次链路没有重跑 ETW/eCapture，不能把 Native 请求正文提取算作 eCapture 的 TLS 明文成功。

## Named Pipe 能说明什么

Named Pipe 是真实 Windows IPC，但已有自建业务管道实验只覆盖明确的同步、本地、单向消息模式。真实应用还可能使用字节流管道、overlapped I/O、匿名管道、共享内存、剪贴板、COM/RPC 或中间文件。同步与异步、字节流与消息边界会影响采集及重组方式。参见 [微软 Named Pipe 模式说明](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes) 和 [同步及 overlapped I/O](https://learn.microsoft.com/en-us/windows/win32/ipc/synchronous-and-overlapped-input-and-output)。

工程接入应观察应用原有的文件／IPC／网络通道，不要求业务改用我们创建的管道。本次已用普通文件验证这一方向。内部审计管道负责采集快照和策略消息，与应用间业务传递分开。

受控实验仍安排了观察器就绪窗口，源数据和参与应用也显式登记。它不意味着可以自动接管所有已运行应用。生产接入还需验证真实应用 API、启动接管、并发、重试、改写与故障行为。

## Webhook 尝试与未通过项

本轮最初尝试“工单导出 → Codex → PowerShell → HTTPS Webhook”，记录保留在 `runs/webhook-control/20261026-live-01` 至 `live-04`。这条路径没有通过完整验收，禁止把它计为实际非 LLM HTTPS 阻断成功。

- `live-01` 在受限 PowerShell 的 eCapture 审计管道就绪前失败，业务任务没有释放。
- `live-02` 启动就绪超时，ETW 同时触发事件上限与丢事件，未通过。
- 增加显式 `target-bound-v1` eCapture 权限覆盖补丁；旧 base pin、旧构建和 Companion DLL 哈希保留。`live-04` 的受限进程采集器取得 ready／terminal，零采集错误，但没有据此认证 TLS 请求正文。
- `live-03`／`live-04` 出现真实 PowerShell `System.Net.WebException`，`WebExceptionStatus=3`（ReceiveFailure），内层为 Win32Exception；实际上传没有通过，原因仍待定位。显式选择 TLS 1.2 没有使该路径通过。
- ETW 新增显式 `io-evidence` 范围和有界缓冲，保留进程、网络、文件读写事实，文件名称映射继续更新；其他文件元数据按处理计数记录。旧默认 `all` 保持原语义。该配置仍需单独实采认证，不用统计投影掩盖丢事件。
- 新 Native 连接门控构建的合成 TCP allow/block 回归通过（允许收到 16 字节；拒绝返回 `-1/10013`、源站 0 字节／0 连接），但合成结果不代替实际 PowerShell Webhook。

上述尝试创建的 4 张 localhost 测试根证书均按所有权清单清理；`live-03` 的首次删除曾被取消，之后单独恢复清理成功。原失败摘要保留原状态，后续恢复以该轮 `test-trust.json` 的 `cleanup_confirmed=true` 为准。

成功验收的文件到 LLM 链不依赖这些全局测试信任，使用独立隔离的测试 CA 文件。

## 工程检查

全量自动化 **1008 passed、0 failed、0 skipped**，147.62 秒，JUnit 位于本地 `runs/cross-app-codex-acceptance/20261026-engineering/pytest.xml`。依赖锁、已安装依赖、37 个 Schema、工程入口、308 项源码白名单和 `git diff --check` 均通过；明确选择 target-bound 补丁的 Native 构建前提检查通过。

原有 Guard v1、Flow v1、ECW2 和 UnifiedLLMRequest v1 的接口保持兼容；新实验脚本、权限覆盖补丁和验收测试进入源码白名单，生成物和实验正文不进入源码白名单。自动测试不替代本文件中未通过的 Webhook、TLS 明文或 ETW 实采验收。

本轮未提交或推送。
