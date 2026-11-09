# 桌面 Local 任务的权限核验

下方 2026-11-04 的实测记录只针对合成测试任务 `01a1a5ad-14de-7861-afe8-7670bfb99d3b`。该任务曾用于发送随机测试标记，不代表用户其他任务的权限状态。脚本现在可用 `--thread-id` 只读核验指定 Local 任务；省略参数时仍使用这个合成测试任务。

## 固定测试任务的实测记录

2026-11-04 对该任务的本地 rollout 记录进行了只读核验。7 条 `turn_context`（08:29 至 12:02 UTC）均为 `sandbox_policy.type=danger-full-access`、`permission_profile.type=disabled`、`active_permission_profile.id=:danger-full-access`、`approval_policy=never`。因此，该桌面 Local 测试任务的工具命令当前以全权限模式运行，不能视作已启用 MXC，也不能视作已禁止 Agent 工具直接联网。单独固定版 CLI 的 MXC 非回环 TCP/UDP 零字节实验，不证明此桌面任务的权限。OpenAI 官方文档明确指出，全权限模式取消本地沙箱限制；桌面端需在输入框下方选择合适的权限模式，才会应用对应沙箱。[Windows 桌面端](https://learn.chatgpt.com/docs/windows/windows-app)、[权限模式](https://learn.chatgpt.com/docs/permission-modes)、[Windows 沙箱](https://learn.chatgpt.com/docs/windows/windows-sandbox)。

2026-11-08 再次只读核验同一 rollout：现有 14 条 `turn_context`，最新一条时间为 2026-11-04 13:51:34 UTC，仍是 `danger-full-access`、`permission_profile.type=disabled`、`active_permission_profile.id=:danger-full-access` 和 `approval_policy=never`；两项 `*_attested` 仍为 `false`。本次只确认权限元数据，没有进行工具外发测试。

## 复核方法

在 `zbn` 账户执行：

```powershell
& 'D:\code\transpect-trace\.venv\Scripts\python.exe' `
  'D:\code\transpect-trace\scripts\audit_desktop_local_permissions.py' `
  --thread-id '01a1a5ad-14de-7861-afe8-7670bfb99d3b'
```

`--thread-id` 必须是 UUID；脚本规范化大小写后，只定位 `~/.codex/sessions/**/rollout-*-<UUID>.jsonl` 中选定任务的记录。它跳过所有非 `turn_context` 记录，不解析用户 Prompt、工具输出或模型正文，也不修改配置和任务。输出只包含所选任务的权限字段、最近一轮判定和记录数量，并在成功或读取失败的 JSON 中写明 `thread_id`。rollout 缺失、重复或元数据异常时返回 `unvalidated`。即使以后记录到受限权限策略，脚本仍将 `desktop_tool_mxc_attested` 和 `desktop_tool_offline_attested` 保持为 `false`：还需要在该 Local 任务的实际工具进程中验证沙箱实现，并通过本机非回环测试源站分别验证 TCP/UDP、IPv4/IPv6 的零字节接收。该权限核验不判定模型请求是否受到保护；桌面 Demo 的模型覆盖状态另见[无应用 Hook Demo](desktop-system-hook-demo.md)。

命令退出码 `0` 只表示成功读取权限元数据，**不表示权限安全**；应检查 JSON 中的 `status` 与两项 `*_attested`。UUID 无效、读取失败或记录无法判定时退出码为 `2`。
