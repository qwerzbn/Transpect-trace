# 独立虚拟机内的桌面端网络默认拒绝

本组件为固定版本 Codex 桌面端 Demo 提供**进程账户级的网络出口兜底**。它必须在独立 Windows 虚拟机中运行：先用单独的低权限本地账户运行桌面端，再由管理员安装针对该账户 SID 的 WFP 规则。构建或运行单元测试不会安装规则。

## 规则与调用顺序

1. 在虚拟机中构建 `uv run --extra native-build python scripts/build_desktop_wfp.py`，记录输出的 `wfp_desktop.exe` 和构建清单哈希。
2. 用管理员身份分别执行 `wfp_desktop.exe install <桌面账户SID> --isolated-vm` 和 `wfp_desktop.exe install <工具沙箱账户SID> --isolated-vm`；每个 SID 都执行 `status`，确认 IPv4、IPv6 出站和入站共四条持久规则。规则键由 SID 派生，因此不同账户的规则可以并存，删除一个账户的规则不会删除其他账户的规则。所有 SID 必须对应**专用本地低权限用户**，不能是管理员当前账户或内置账户。
3. 固定版演示明确选用 Codex Windows 的 legacy `elevated` 沙箱，并在虚拟机中验证其实际生效。该模式为沙箱工具使用独立的低权限账户；在真实工具命令里执行 `whoami /user` 取得实际 SID，再把所有实际工具 SID 传入 `WfpBoundary(..., tool_sids=[...])`。`assert_default_deny()` 先核对桌面 SID，再逐个核对工具 SID；任一缺失就拒绝启动租约。工具账户不获得临时放行。[官方 Windows 沙箱说明](https://learn.chatgpt.com/docs/windows/windows-sandbox)。如果实际运行的是 `mxc`、`unelevated` 或 full access，不能把本 Demo 的工具 SID 验证结论套用到它们。
4. 桌面端请求门控的 Native Guard 发出就绪事件后，才调用 `start_guarded_lease(...)`。放行范围是桌面账户 SID、固定文件路径（WFP APP_ID）、字面 IP、端口和 TCP 协议，最长 300 秒；租约进程退出即撤销该临时规则。租约同时监控控制器 PID 和创建时间；控制器退出后通常在 200 毫秒轮询周期内关闭租约进程，实际撤销时间还受系统调度影响。持久拒绝不随控制器崩溃消失。
5. 演示结束时停止桌面端和所有租约；确认无需继续隔离账户后，管理员对每个 SID 分别明确执行 `wfp_desktop.exe remove <对应SID> --isolated-vm`。程序不会在退出时自动删除默认拒绝规则。

持久拒绝覆盖 `ALE_AUTH_CONNECT_V4/V6` 和 `ALE_AUTH_RECV_ACCEPT_V4/V6`，包括 TCP 连接、首次发送的 UDP 等出站流量及入站授权。规则使用无服务提供者关联的持久子层，回读时拒绝已被 BFE 标记为 `DISABLED` 的过滤器。临时放行在桌面账户子层采用更高权重，但**只支持 TCP**；未验证的 QUIC/UDP 不放行。当前代码不在本机安装过规则，也尚未在独立虚拟机执行真实 WFP 阻断验证。最终报告须以虚拟机内 TCP/UDP、IPv4/IPv6 的接收端零字节测试和 BFE 规则回读为准。

## 虚拟机验证记录

`scripts/probe_desktop_wfp_vm.py` 提供不转发数据的本机 TCP/UDP、IPv4/IPv6 接收器。先在**未安装规则**时完成一次正向对照：管理员执行 `python scripts/probe_desktop_wfp_vm.py serve --directory C:\demo\wfp-before --duration-seconds 30 --isolated-vm`，等待它打印 manifest 路径；桌面专用账户执行 `python scripts/probe_desktop_wfp_vm.py client --directory C:\demo\wfp-before --isolated-vm`。检查 `receipts.json` 的四个 `received_bytes` 均大于 0。此举验证接收器和系统 IPv6 可用，避免把接收器故障误报为拦截成功。每次 `serve` 使用新的空目录，目录及 manifest 须允许测试账户读取。

安装并核验桌面及工具 SID 规则后，使用新目录 `C:\demo\wfp-after` 重复测试；分别从桌面账户和**实际的 Codex 工具沙箱账户**启动 `client`。四条接收路径的 `received_bytes` 都应为 0。UDP 的 `sendto` 成功只表示本地提交成功，拒绝结论必须看接收端记录。用 `curl.exe`、Python 和 PowerShell 发往同一测试端口时，也只能陈述这些程序在已测试账户、协议及目的地上的结果。运行中的已有连接、代发服务、其他 SID、其他网络通道和 full access 工具仍需单独验证。还要在租约激活、控制器退出及超时后各重复一轮，核对相应规则回读、收件计数与租约撤销。

`scripts/probe_desktop_origin_vm.py` 是独立的无转发 TLS 测试源站：管理员执行 `python scripts/probe_desktop_origin_vm.py --directory C:\demo\origin-001 --duration-seconds 60 --isolated-vm`，得到临时 CA、端口和合成标记。把**固定版测试客户端**的目标配置为该源站，在测试 VM 中明确信任该临时 CA。只发送合成请求和附件；源站为 HTTPS 正文、分块/multipart 上传及 WSS 首个消息记录长度、SHA-256 和标记命中，不保存正文。先用允许样本取得正向对照，再为每个拒绝样本启动全新的源站和空目录；拒绝样本要求 `complete_body_bytes == 0`、`synthetic_marker_received == false` 且 `unverified_connections == 0`。出现不完整连接时该次为未验证，不能判作零字节证明。源站只是记录器，不会替桌面端完成模型交互。

## 安全边界

WFP 的 `ALE_APP_ID` 指**可执行文件路径**，并非进程 ID。租约启动前会校验进程 PID、创建时间、文件 SHA-256、运行账户 SID 和 Guard 就绪事件，租约期间也监视进程与事件；这些检查约束租约生命周期，但同路径同账户的另一个进程仍可能匹配该放行规则。原生租约明确返回 `pid_exact_filter: false`，包装层和单元测试也保留这个声明。虚拟机中还应启动同一路径、同一 SID 的第二个未加 Guard 进程，尝试访问租约允许的相同 IP:端口，并记录接收端结果；只要存在共享放行，就不能宣称租约只授权第一个 PID。更强的进程级隔离需要独立网络身份、可核验的进程容器隔离，或自定义 WFP callout；本 Demo 未实现。工具进程使用不同的 `elevated` 沙箱 SID 且无放行，能缩小这一问题对工具外发的影响，但不能覆盖从桌面身份运行的任意代码。桌面账户若需要访问本机 app-server 的 TCP 端口，还需先实测再添加单独、有限的本机 IPC 放行；不能一概放行 loopback。服务代发、其他账户、已存在连接和虚拟机之外的网络通道也不在单条 SID 规则的证明范围内；虚拟机出口应另设独立限制。

Microsoft 文档：[按用户和应用过滤](https://learn.microsoft.com/en-us/windows/win32/fwp/permitting-and-blocking-applications-and-users)、[ALE 层](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)、[WFP 对象生命周期](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)。
