# 当前桌面任务的 Agent 工具外发状态

本文只评估当前 Windows 账户正在使用的固定版 Codex 桌面端 Local 任务，不对用户账户安装网络规则，也不改动客户端配置。结论依赖该任务的实际权限、工具进程身份和接收端测试，不能由模型请求 Hook 的阻断结果推导。

## 已核实的状态

2026-11-04 再次运行 `scripts/audit_desktop_local_permissions.py`，固定合成测试任务的 13 条 `turn_context` 中，最新一条仍为 `sandbox_policy.type=danger-full-access`、`permission_profile.type=disabled`、`active_permission_profile.id=:danger-full-access`、`approval_policy=never`。此前该任务中只读执行的 `pwsh.exe` 由当前 `codex.exe app-server` 启动，二者使用同一个 Windows 用户 SID。当前账户令牌中的 Administrators 组处于 `deny only` 状态。[权限核验方法](desktop-local-permission-audit.md)、[当前路径记录](desktop-path-current.md)。

随后用 `scripts/probe_desktop_tool_egress_current.py` 在本机已分配的非回环 IPv4/IPv6 地址建立受控 TCP/UDP 收件器，并先完成独立进程正向对照。再向固定 Local 测试任务自动发送一条只运行该脚本 `client` 子命令的合成指令。任务执行记录显示命令正常结束、客户端 PID 为 `20708`；本机客户端报告 PID 相同。收件器在 TCP4、UDP4、TCP6、UDP6 四路分别收到 66 字节合成标记，四路 `egress_reached_receiver`，没有一个达到 `blocked_at_receiver`。元数据报告在 `runs/desktop-current/tool-egress-active-20261104-01/report.json`，SHA-256 为 `7D294EA6A0B756DAC6703DD93CA76ABD2CFE459FCB60F9CA8DAF255BEDB3AFF3`。该实测证明**此固定测试任务的这四条工具直连路径当前可达本机非回环收件器**，不能将其标为已有默认拒绝网络边界；它不测真实外网地址，也不推断所有工具和协议。

[Codex 权限说明](https://learn.chatgpt.com/docs/permission-modes)明确，Full access 允许命令使用网络；审批策略只决定何时询问，不能替代沙箱边界。[Windows 沙箱说明](https://learn.chatgpt.com/docs/windows/windows-sandbox)指出，MXC 在支持的设备上无需管理员、新账户或本地防火墙规则即可隔离命令及其子进程，并由有效权限配置决定网络是否允许。本机用同一固定版后端的**独立 CLI** 已在 MXC 受限权限下完成 TCP/UDP、IPv4/IPv6 非回环接收端零字节及嵌套子进程测试；这是 MXC 在此设备上的可用性证据，不是当前桌面任务的外发证明。

## 为什么不能直接给现用账户装规则

当前工具与桌面后端共用 SID。按此 SID 设置 WFP 默认拒绝，会同时作用于现用桌面端和该账户其他进程；再给桌面端路径放行也不能保证同一进程中的任意代码只发送经 DLP 检查的请求。WFP 的 `ALE_APP_ID` 识别可执行文件路径，不是单个 PID；现有租约已明确标记 `pid_exact_filter=false`。[WFP 方案与安全边界](desktop-wfp.md)、[Microsoft WFP 权限模型](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)。

按常见程序名封禁 `curl.exe`、`python.exe`、`pwsh.exe` 也不能覆盖复制的程序、其他语言运行时、同一后端进程自己开 socket 或经本机服务代发。用户态拦截 `connect`、进程创建或工具分发可用于观测与辅助控制，但不能作为任意子进程网络零字节的系统级证明。当前非管理员令牌也不能被视为具有安装持久 WFP 规则所需权限。

## 不切换登录账户的可行验收路径

首选方案是在当前桌面端为**合成 Local 测试任务**选用网络关闭的受限权限模式，并确认实际工具进程由 MXC 启动。此方案保持同一 Windows 登录账户和桌面客户端，不需要另装 MSIX 或切换用户；但现有任务的 Full access 权限不能由本仓库脚本的只读探针自动变成受限权限。改变权限后，应按以下顺序验收：

1. 重新运行 `scripts/audit_desktop_local_permissions.py`，确认新一轮 `turn_context` 已不再是 `danger-full-access`，且有效网络权限为关闭。单凭配置文件或 UI 显示不足以验收。
2. 在该 Local 任务实际启动的工具进程内核对 MXC/受限令牌身份及父子关系；确认嵌套子进程继承隔离。固定 CLI 的结果只能用于选择测试方法，不能代替这一项。
3. 在本机非回环 IPv4/IPv6 接收端分别建立 TCP/UDP 正向对照；随后从该 Local 任务实际运行 Python、PowerShell、`curl` 和嵌套进程发送新的合成标记。每个路径均以接收端收到 **0 字节**、工具确实尝试发送、且没有其他未知连接为通过条件。UDP 本地 `send` 成功不等于接收端收到数据。可复用 `scripts/probe_codex_mxc_egress.py` 的收件器与分类规则，但需由桌面任务而非独立 CLI 执行客户端。
4. 同时确认桌面模型请求仍可经已验证的内容门控完成正常交互；若受限权限使模型或本机 IPC 停止，不能通过给整个账户临时放开网络来绕过该问题。

若必须让工具保持 Full access，或 MXC 无法作用于该桌面任务，则需要由管理员配置**实际工具进程专用身份**的默认拒绝规则，或等效的系统级进程隔离。Codex legacy `elevated` 沙箱能使用单独的低权限工具身份，但需要管理员预置；使用者无需反复切换登录账户。[Windows 沙箱说明](https://learn.chatgpt.com/docs/windows/windows-sandbox)。在上述动态证据完成前，当前桌面 Demo 的 `agent_tool_egress_covered` 必须保持 `false`。

## 当前任务的受控实测夹具

`scripts/probe_desktop_tool_egress_current.py` 提供 `serve` 与 `client` 两步，用于让当前 Local 任务的工具进程尝试连接**本机已分配的非回环地址**，不发送到外网。`serve` 先用独立本机进程对 TCP/UDP、IPv4/IPv6 每个可用路径完成正向对照，再打印本地 manifest 路径；只有此时才应向固定合成测试任务发送运行 `client --manifest <该路径>` 的指令。客户端拒绝不属于本机网卡的地址，逐条尝试发送新随机合成标记，并将尝试元数据写入同目录。收件器只记录长度、SHA-256 和错误类型，不保存收到的正文。

接收端报告按路径分别给出 `egress_reached_receiver`、`blocked_at_receiver` 或 `unvalidated_*`。`blocked_at_receiver` 必须同时有正向对照、客户端确实尝试发送及零接收记录；UDP 的本地 `send` 返回成功不是接收证据。`client-report.json` 可以由任何同账户本机进程写入，故**仅凭报告不能证明测试命令来自 Agent**；还要核对 Local 任务的工具调用记录与报告中的 `client_pid`。即使四路都为零接收，也只覆盖这些本机地址和协议，不代表所有网络出口；四路任一正向命中则足以否定该工具进程在该路径上的默认拒绝。
