# 固定版桌面端：同一台 Windows 主机上的独立账户方案

## 已确认的本机状态

本机最初预检时，`zbn` 使用官方 `OpenAI.Codex` MSIX `26.1027.6604.0`；后续再次核对，当前注册及运行版本已经变为 `26.1029.7803.0`。归档的官方 x64 MSIX 也是 `26.1029.7803.0`，SHA-256 是 `19487892B7E27C74E75C6422088E91B35B4291ED485045F82A1984A13B22D128`，签名校验为 `Valid`；当前桌面主程序和后端文件哈希均与归档相同。两版属于相同 `OpenAI.Codex_2p2nqsd0c76g0` 包系列。**在 `zbn` 账户注册 MSIX 只会作用于正在使用的应用，不会产生第二个独立实例；本流程禁止在该账户执行安装。**微软将相同包系列的安装视作更新；不同版本可以在磁盘上暂存，但暂存不等于同一账户能同时使用两份应用。[MSIX 更新](https://learn.microsoft.com/en-us/windows/msix/app-package-updates)、[包暂存](https://learn.microsoft.com/en-us/windows/msix/package/package-volumes)。

官方提供的是 MSIX，不提供独立 MSI 或非商店 EXE。直接运行从 MSIX 解压的 `ChatGPT.exe` 会脱离正常的包身份，不能算已验证的官方桌面端运行模式。[OpenAI Windows 部署](https://learn.chatgpt.com/docs/enterprise/windows-deployment)、[微软包身份](https://learn.microsoft.com/en-us/windows/msix/detect-package-identity)。

运行只读预检：

```powershell
& .\scripts\prepare_desktop_host.ps1 | Format-List
```

脚本校验归档 MSIX 的哈希、签名、签名证书、包清单与固定版本，同时核对当前账户的已安装版本、包系列、运行进程和管理员权限。它不会创建账户、安装软件、关闭进程或更改防火墙。本机最新预检为 `ActivePackageVersion=26.1029.7803.0`、`ActiveVersionChangedSinceInitialPreflight=True`、`ActivePackageHashesMatchArchive=True`、`SafeToInstallInCurrentUser=False`。安装包与虚拟磁盘位于 Git 忽略的 `runs/desktop-vm/`；源码分支只保存哈希清单。若当前版本再次变化，预检会停止，需重新核对测试目标。

## 独立账户的准备和安装

微软说明，MSIX 的注册按 Windows 用户区分，同一台机器的不同用户可以保有不同应用版本。[多用户 MSIX 版本](https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/modern-apps-application-packages-reported-vulnerable)。因此在不使用虚拟机的前提下，选择专用**标准用户账户**运行固定版桌面端。当前 `zbn` 的非提升令牌不能执行账户管理；以下账户创建及成员调整步骤需要管理员 PowerShell。

1. 管理员在 **64 位 Windows PowerShell** 中创建专用本地用户。密码由管理员交互输入，不写入脚本、命令行或日志；创建后显式加入内置 `Users` 组，核对 SID 和组成员，并确认不属于本地 Administrators 组。下例中的账户名可按本机策略调整。用组 SID 而非显示名称，以免受系统语言影响。[New-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1)、[Add-LocalGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember?view=powershell-5.1)。

   ```powershell
   $demoName = 'ttrace-desktop-demo'
   $secret = Read-Host 'Set a password for the desktop demo account' -AsSecureString
   $demoUser = New-LocalUser -Name $demoName -Password $secret -Description 'Fixed Codex desktop DLP demo'
   Remove-Variable secret
   $usersSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-545'
   Add-LocalGroupMember -SID $usersSid -Member $demoUser
   $users = Get-LocalGroupMember -SID $usersSid
   if (-not ($users | Where-Object { $_.SID.Value -eq $demoUser.SID.Value })) { throw 'Demo account is not in Users' }
   $admins = Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
   if ($admins | Where-Object { $_.SID.Value -eq $demoUser.SID.Value }) { throw 'Demo account is an administrator' }
   $demoUser | Select-Object Name,SID,Enabled
   ```

   如果账户已由早期命令建立、但尚未加入内置 `Users`，管理员只需执行以下修复并核对结果，**不要重复创建账户**：

   ```powershell
   $demoUser = Get-LocalUser -Name 'ttrace-desktop-demo'
   $usersSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-545'
   if (-not (Get-LocalGroupMember -SID $usersSid | Where-Object { $_.SID.Value -eq $demoUser.SID.Value })) {
       Add-LocalGroupMember -SID $usersSid -Member $demoUser
   }
   Get-LocalGroupMember -SID $usersSid | Where-Object { $_.SID.Value -eq $demoUser.SID.Value } | Select-Object Name,SID
   ```

2. 将已校验的 `ChatGPT-x64.msix` 复制到该账户可读取的位置。通过 Windows **“切换用户”实际登录**专用账户；仅在 `zbn` 的桌面上新开 PowerShell、切换工作目录或提升为管理员，都不会改变运行账户。先运行 `whoami /user`，确认显示的是专用账户 SID，再运行 `scripts/install_desktop_host.ps1`。该脚本先核对当前账户 SID、账户名、普通用户权限、安装包哈希和签名；如果当前账户已经注册其他版本，就直接停止。默认调用只预检；通过后显式加 `-Install`，才会调用面向当前用户的 `Add-AppxPackage`。`ProtectedSid` 应填写事先在 `zbn` 会话取得的 SID，不要在当前账户安装，也不要使用 `-ForceApplicationShutdown`。[Add-AppxPackage](https://learn.microsoft.com/en-us/powershell/module/appx/add-appxpackage?view=windows-11)。

   ```powershell
   $package = 'C:\demo\archive\ChatGPT-x64.msix'
   $demoSid = '<在专用账户运行 whoami /user 得到的 SID>'
   $zbnSid = '<预先在 zbn 账户运行 whoami /user 得到的 SID>'
   & .\scripts\install_desktop_host.ps1 -MsixPath $package -ExpectedSid $demoSid -ProtectedSid $zbnSid
   & .\scripts\install_desktop_host.ps1 -MsixPath $package -ExpectedSid $demoSid -ProtectedSid $zbnSid -Install
   ```

3. 2026-11-04 已在 `ttrace-desktop-demo` 标准账户完成单用户离线注册：预检返回 `ReadyToInstall`，执行 `-Install` 后返回 `VerifiedInstalled`，包版本为 `26.1029.7803.0`，桌面主程序及后端文件哈希均通过固定值校验。安装前遇到的脚本执行策略限制，使用仅对当前 PowerShell 进程生效的 `RemoteSigned` 解决。此结果证明安装成功；仍需启动桌面端并验证实际模型发送路径。若其他主机的 `Add-AppxPackage` 因许可证或权限失败，应停止，不要在当前账户重试、不要自动改用 `Add-AppxProvisionedPackage -Online`。后者会为新用户预配该应用，不满足本 Demo 只针对专用账户的要求。[OpenAI 离线部署](https://learn.chatgpt.com/docs/enterprise/windows-deployment)、[预配作用范围](https://learn.microsoft.com/en-us/powershell/module/dism/add-appxprovisionedpackage?view=windowsserver2025-ps)。

4. 安装脚本会在注册后立即核对 `Get-AppxPackage -Name OpenAI.Codex` 的版本，以及 `app/ChatGPT.exe`、`app/resources/codex.exe` 的哈希。2026-11-04 已从 `zbn` 回查其注册版本仍为 `26.1029.7803.0`，桌面主程序及后端哈希仍与归档相同。后续分别记录进程用户 SID、可执行文件路径及后端哈希。固定版本会受应用内更新、Microsoft Store 或设备管理更新影响，运行期间必须持续核对实际文件哈希；关闭应用内更新需要受管策略，单纯保存 MSIX 不会自动固定已安装应用。[OpenAI 更新管理](https://learn.chatgpt.com/docs/enterprise/manage-app-updates)。

本机已创建并登录 `ttrace-desktop-demo`（SID 末尾 `1005`），固定版桌面端已注册并通过安装校验，尚未在该账户动态验证模型发送路径。当前分支中的 HTTP/WSS 地址仍是静态候选，附件原始字节 Hook 尚未实现；不得因此开放网络许可或宣称已拦截真实桌面请求。主机上的 WFP 规则如需继续验证，必须由管理员按**专用账户 SID** 单独安装并回读，先证明不会改变 `zbn` 的网络行为。

## 专用账户的 DeepSeek 模型配置

本 Demo 的测试模型为 DeepSeek `deepseek-v4-pro`，模型提供者地址为 `https://api.deepseek.com`，使用 Responses API。DeepSeek 官方说明该模型和桌面 Codex 的接入方式；Codex 的模型提供者配置属于 Windows 用户级配置，需要重启应用。此处只在 `ttrace-desktop-demo` 下配置，不改 `zbn` 的模型提供者。[DeepSeek Codex 接入](https://api-docs.deepseek.com/quick_start/agent_integrations/codex/)、[Codex Windows 提供者配置](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway)。

在该账户的**普通 PowerShell** 中，确认 `whoami /user` 的 SID 末尾是 `1005` 后运行：

```powershell
$demoBase = 'D:\code\transpect-trace'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
& "$demoBase\scripts\set_desktop_deepseek_secret.ps1"
& "$demoBase\scripts\configure_desktop_deepseek.ps1"
```

第一项命令在本机隐藏输入 API Key，并以当前 Windows 用户的 DPAPI 加密保存；配置文件只引用受保护的凭据读取程序，不保存明文密钥。第二项默认只预检，核对账户 SID、固定版安装文件哈希、模型目录与已有配置。若返回 `ReadyToConfigure`，再执行：

```powershell
& "$demoBase\scripts\configure_desktop_deepseek.ps1" -Install
```

成功状态为 `VerifiedConfigured`。若已有不同的 `config.toml`，脚本会拒绝覆盖，须先检查。归档后端已在临时 `CODEX_HOME` 下用本地不转发接收器验证：安全的模型目录可加载，合成 Prompt 进入 `/responses` 请求，命令式认证可提供 Bearer 头。这不等于专用账户桌面端已成功连接 DeepSeek；接下来还需在桌面窗口核对模型、实际发送路径及阻断动作。不要把 API Key 发到聊天或写入仓库。
