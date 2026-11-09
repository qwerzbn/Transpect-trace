# 后续开发计划：P0 / P1

本计划以 [技术方案](docs/project-overview.md) 为目标形态，列出从当前实现到企业可部署版本之间的 P0、P1 工作。每项给出目标、方案、改动范围和验收标准；验收一律以本地收件端、加密归档回读和 Codex 客户端日志为证据，不以界面提示代替外发结果。

## 0. 当前基线

2026-11-08 在固定版本桌面端（包 `26.1103.3517.0`，后端 `codex-cli 0.167.0-alpha.3.2`，SHA-256 `40ecc3d8…`）完成实机测试，控制器为 `nonretry_lease`，全局模式：

| 场景 | 结果 |
|---|---|
| 正常对话 | 放行，回答正常 |
| 输入含凭据 / 个人信息 | 发送前拒绝，不重试 |
| 工具读取文件、base64 编码后回传 | 首次请求放行；携带工具结果的请求被拒 |
| `AGENTS.md` 注入、后台建议请求汇总敏感内容 | 发送点拒绝 |
| curl 直接上传文件 | **未拦截**，接收端收到完整文件 |

测试中修复了 zstd 压缩正文二次经过发送点导致的误拦（`guard/pipe.py`）、状态文件被占用导致控制器退出、实机预检永不通过三个问题。

其余已知缺口：工具外发不经过发送点；固定 RVA 随版本失效；控制器启动前与退出后均无防护，且每次接入都要重启 Codex；拒绝即整段会话不可用；模型请求以外的外发通道未盘点。

## P0-1 工具外发管控

**目标**：Agent 工具（shell、脚本、本地 MCP 服务器）发出的数据在离开主机前被拦截，接收端零字节。

**方案**：执行前门控与网络出口限制两层同时生效。命令检查可被编码、脚本或间接调用绕过，网络层负责兜底。

### A. 工具执行点 Hook

1. **定位进程创建路径（spike）**。用 ETW 进程树和 API 跟踪确认三种权限模式下工具进程由谁创建：
   - `danger-full-access`：app-server 直接创建；
   - `elevated` 沙箱：经 `codex-windows-sandbox-service` 创建；
   - MXC：创建路径待确认。

   同时确认 code-mode `exec`（JS 中的 `tools.exec_command`）最终在哪个进程落到 `CreateProcess*`。
2. **优先挂系统 API**。在创建工具进程的进程内挂钩 `kernelbase!CreateProcessW` / `CreateProcessAsUserW`。系统 API 与 Codex 版本无关，不需要随版本重定位。若工具经沙箱服务 RPC 创建，则在服务进程挂同一组 API，或在 app-server 的 RPC 发起点取参数。
3. **判定内容**：
   - 命令行与工作目录交给 `tool_policy` 和内容识别；
   - 命令引用的本地文件在执行前读取并做内容识别，覆盖 `@file`、`--data-binary @`、`-T`、`-InFile`、`Get-Content | ...` 等形式；
   - 网络工具的目的地址按白名单判定。
4. **拒绝方式**：API 返回失败（`ERROR_ACCESS_DENIED`），工具调用以错误结束，Agent 收到拒绝理由。确认 Codex 不把该错误当作可重试错误。
5. **管道协议**：新增 `tool.exec` 请求类型，`GuardRequest.kind` 与 `PipeServer` 同步扩展；审计记录挂钩点、工具调用 ID、进程创建参数摘要。

改动范围：`native/guard/guard.c`（新挂钩点），`src/transpect_trace/guard/policy.py`、`guard/pipe.py`（协议），`protect/tool_policy.py`（文件引用解析、目的地址判定），新增 `tests/test_tool_exec_gate.py`。

### B. 网络出口限制

1. **强制沙箱模式**。通过 Codex 托管配置把本地任务固定为联网受限的沙箱（MXC 或 `elevated`）。需要先确认 Windows 桌面端支持的托管配置项，并实测用户能否在界面上改回 `danger-full-access`。
2. **WFP 兜底**。对工具沙箱账户 SID 安装默认拒绝，只放行白名单目的地址，复用 `behavior/desktop_wfp.py` 与 `wfp_desktop.exe`。本地 MCP 服务器按同一规则处理。
3. 白名单按企业策略下发，变更写入审计。

### 验收

1. 复用 `scripts/probe_tool_egress_routes.py` 的非回环收件端，分别验证 TCP/UDP、IPv4/IPv6。外发工具覆盖 curl、PowerShell `Invoke-WebRequest`、Python socket、git push 到本地裸仓库。所有敏感样本接收端字节数为 0。
2. 良性命令（构建、测试、读取普通文件、访问白名单地址）放行率单独报告。
3. 实机重跑 2026-11-08 测试中的 curl 用例：工具未执行，接收端无记录。

## P0-2 版本适配

**目标**：Codex 升级后，在新版本首次发出模型请求之前完成适配；适配失败时客户端不能在无检查的状态下外发。

1. **控制更新节奏**。用企业策略控制 `OpenAI.Codex` MSIX 包的自动更新，由管理员按适配进度放行版本。本机当前已预装 `26.1104`、`26.1105` 两个运行时包，切换随时可能发生。
2. **特征定位替代固定 RVA**。为 HTTP 发送、WSS 发送、`drop_headers`、`api_error_map` 四个挂钩点建立特征码，要求在 `.text` 段内唯一命中，再用入口字节、调用关系和引用字符串二次确认。扩展 `scripts/check_collection_portability.py`，输出候选 pins。
3. **ABI 动态验证**。HTTP 拒绝 tag、`InvalidPrompt` 映射、WSS 结果布局等无法静态确认的项，由现有隔离实验自动核验：`probe_desktop_guard_*_lab.py` 加 `summarize_guard_nonretry_current_lab.py`。产出新版本的构建清单与证据汇总，作为 `desktop_demo.py` 的准入输入。
4. **流水线**。检测到新运行时包，依次执行静态定位、构建 DLL、隔离实验、汇总，最后得到准入或阻断结果，全流程自动执行，人工只审核结果。
5. **失配处理**。身份或特征不符时 supervisor 不注入；配合 P1-1 的启动门闩，codex.exe 保持断网并发出告警，不静默降级为无防护。

验收：对 `26.1103` → `26.1104` → `26.1105` 三个版本连续运行流水线，每个版本的 HTTP/WSS 放行、拒绝、拒绝后同 PID 正常请求均通过；人为篡改一个特征后，流水线判定失败且不产出可准入的 DLL。

## P1-1 防护连续性与防篡改

**目标**：从 Codex 启动到退出，任何时刻的模型请求都经过检查；控制器异常不导致放行；普通用户无法关闭防护。

1. **启动空窗**。实现 [启动网络门闩](docs/development/desktop-startup-egress-gate.md)：对固定 `codex.exe` 路径加用户 SID 设置持久 WFP 拒绝，Native 与管道就绪后由控制器会话添加动态许可，控制器退出时许可随 BFE 会话消失。
2. **失效即拒绝**。修改 `guard.c` 的租约语义：租约丢失时进入拒绝状态，不再旁路放行，由编译开关控制，企业版默认开启。
3. **控制器重连**。DLL 在拒绝状态下接受新控制器的租约后恢复检查。控制器重启不再需要重启 Codex，supervisor 可以对同一进程恢复防护。需要同时调整 `desktop_demo.py` 的驻留检查：`native_guard_already_resident` 改为可重连状态。
4. **服务化**。控制器与 supervisor 以 Windows 服务（SYSTEM）运行：
   - 管道 DACL 只授权目标用户的 app-server；
   - 状态与审计目录放在 `ProgramData` 下，设访问控制；
   - 服务停止需要管理员权限。

   替换当前的登录计划任务方案（`manage_desktop_guard_autostart.py`）。
5. **心跳与告警**。租约丢失、注入失败、身份不符、管道校验错误写入审计并上报。监视进程只读追加写入的审计文件，不打开 `status.json`。

验收：
- 在 Codex 启动后 0–5 秒内连续发请求，接收端不出现未经检查的正文；
- 强杀控制器后，请求被拒且接收端零字节；
- 重启控制器后，同一 PID 恢复放行；
- 普通用户 `taskkill` 服务失败。

## P1-2 脱敏放行与拒绝提示

**目标**：低风险敏感内容脱敏后继续对话；拒绝时用户知道原因；一次拦截不使整段会话永久不可用。

1. **策略分级**。按类别配置动作：凭据、私钥、登记的客户记录为 BLOCK；个人信息等可配置为 MASK。动作仍只有放行与拒绝两类，MASK 属于改写后放行。
2. **等长原位脱敏**。在发送点把命中片段按字节等长替换为 ASCII 掩码，不改变缓冲区长度，避开 Rust 分配器所有权问题：
   - **spike**：确认 HTTP 正文缓冲区（`Vec`/`Bytes`）在挂钩点可写且未共享，确认 WSS 帧缓冲区可写；
   - 替换只发生在 JSON 字符串值内，并避开转义序列，替换后重新解析校验；
   - `wire_items` 需要输出条目在原始正文中的字节区间。
3. **压缩二次经过**。脱敏发生在 JSON 首次经过时，随后的 zstd 正文由已脱敏内容生成；管道按脱敏后正文的摘要识别重复调用。
4. **会话可用性**。客户端本地历史仍保存原文，后续每轮请求都会被同样脱敏，会话可以继续。BLOCK 类内容留在历史中会使该会话持续被拒，拒绝提示需说明“请在新会话中重新提问”。
5. **拒绝提示**。管道回复携带命中类别；DLL 生成 `TTRACE_NATIVE_DENY: SECRET/GITHUB_TOKEN` 形式的错误字符串，沿用现有错误字符串分配路径。不在提示中回显命中内容。

验收：含手机号的 prompt 在 MASK 策略下得到正常回答，模型侧收到的正文（归档回读）不含原号码；同一会话下一轮仍可正常对话；含令牌的 prompt 显示带类别的拒绝提示。

## P1-3 外发通道盘点

**目标**：列出 Codex 桌面端全部可能携带用户内容的外发通道，逐项确定是检查、关闭还是只做审计。

1. **候选通道**：
   - 远程控制 WebSocket（`wss://chatgpt.com/backend-api/wham/remote/control/server`）；
   - 云端执行进程（`codex.exe exec-server --remote`）；
   - 附件与文件上传；
   - 反馈与日志上传；
   - analytics；
   - 本地 MCP 服务器；
   - 浏览器与 computer-use 插件。
2. **方法**：
   - ETW 网络事件按进程汇总目的地址；
   - 客户端日志（`~/.codex/logs_2.sqlite`）按 target 统计请求类型；
   - 在测试账号中逐项触发功能，用合成标记确认通道是否携带用户内容。
3. **处置**：
   - 携带内容的通道，优先确认是否经过现有 HTTP 发送点，否则新增挂钩点；
   - 不需要的功能通过托管配置关闭；
   - 其余记录到审计。

验收：产出通道清单，每项附触发方法、是否携带内容、处置方式与验证记录。

## 随行修复

| 问题 | 位置 | 修复 |
|---|---|---|
| 转义引号后的路径漏检（`\"@file/secrets.txt\"`） | `protect/tool_policy.py` 的 `_RIGHT` | 右边界加入反斜杠，或在匹配前还原 JSON/JS 转义 |
| Codex 生成的 `call_` / `ctc_` ID 与“密钥”字样同现时误报 | `protect/content_dlp.py` 熵规则 | 结构化字段中的客户端 ID 按前缀与位置排除；修改后按 `desktop_demo.py` 的源码哈希准入流程重新固定 |
| 实机开关需改源码常量 | `scripts/desktop_demo.py` 的 `LIVE_TRIALS_PAUSED` | 改为显式命令行参数，并记录到审计 |

## 执行顺序

| 阶段 | 内容 | 前置 |
|---|---|---|
| M0 | 冻结客户端更新；随行修复 | 无 |
| M1 | P0-1 spike：工具进程创建路径；P1-2 spike：缓冲区可写性 | M0 |
| M2 | P0-1 工具执行点 Hook 与沙箱网络限制 | M1 |
| M3 | P1-1 失效即拒绝、控制器重连、启动门闩 | M0 |
| M4 | P0-2 特征定位与适配流水线 | M3（重连能力缩短实验周期） |
| M5 | P1-1 服务化与告警；P1-2 脱敏与拒绝提示 | M2、M3 |
| M6 | P1-3 外发通道盘点与处置 | M2 |

每个阶段结束时在固定版本桌面端重跑 2026-11-08 的六个场景，并追加本阶段新增场景，结果记录到 `docs/development/desktop-system-hook-demo.md`。
