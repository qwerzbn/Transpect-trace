# 桌面 DLP 加密归档的七天清理

`EncryptedRequestArchive` 将完整模型请求和附件快照以 AES-GCM 加密落盘，密钥由当前 Windows 用户的 DPAPI 保护。归档记录内的创建时间经过认证；`read()` 在记录满七天后拒绝读取。`prune()` 只按**经过认证的创建时间**删除有效的过期记录，避免文件修改时间被改旧时提前删除新记录；已损坏且文件修改时间超过七天的记录也会清理。`dry_run=True` 只计数，不删除。

`scripts/prune_desktop_dlp_archives.py` 为闲置期清理提供独立入口。它默认只读，仅扫描本仓库 `runs/` 下指定目录中的 `encrypted-archive`，核对当前用户 SID、目录范围、DPAPI 密钥和链接类型，输出目录数、记录数及过期数，不输出正文、记录 ID 或摘要。明确传入 `--prune` 才执行删除。例如当前桌面实验的只读预检：

```powershell
.venv\Scripts\python.exe scripts\prune_desktop_dlp_archives.py --root runs\desktop-current --expected-sid 'S-1-5-21-2341826845-1812322924-2265560838-1001'
```

`scripts/register_desktop_archive_prune.ps1` 默认只预检；`-Install` 才以当前用户的交互令牌注册每小时及登录时运行的计划任务。它不会请求或保存账户密码。2026 年 11 月 4 日，已在当前 `zbn` 账户安装 `Transpect-Desktop-DLP-Archive-Prune-1001`，随后按 SID、执行文件、参数、工作目录和触发器重新核验为 `VerifiedInstalled`。手动触发一次后，任务返回码为 0；只读复查找到 2 个归档目录、12 条记录、0 条过期记录，没有删除文件。首次注册时 Windows 将完整账户名规范化为 `zbn`，旧校验因此误报失败；脚本已改为解析任务主体 SID，重复运行只核验现有任务，不重复注册。[Windows 计划任务触发器](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger)支持重复间隔。

即使安装每小时任务，物理删除也可能晚于精确七天到期时间：最长通常延迟一个运行间隔，注销、关机、任务失败或没有交互会延长延迟。逻辑读取限制仍在七天时生效；若制度要求到期时刻立刻物理删除，需要持续运行且受监控的独立清理服务。现用桌面实验中归档与 Agent 同属一个 Windows 用户，DPAPI 不构成对同用户进程的访问隔离；生产部署仍须独立控制账户和经过验收的权限边界。
