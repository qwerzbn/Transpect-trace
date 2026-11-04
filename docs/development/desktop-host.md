# 固定版桌面端：同一台 Windows 主机上的独立账户方案

## 已确认的本机状态

当前用户 `zbn` 正在运行官方 `OpenAI.Codex` MSIX `26.1027.6604.0`。归档的官方 x64 MSIX 为 `26.1029.7803.0`，SHA-256 是 `19487892B7E27C74E75C6422088E91B35B4291ED485045F82A1984A13B22D128`，签名校验为 `Valid`。两者的包名和发布者相同，属于 `OpenAI.Codex_2p2nqsd0c76g0` 包系列。**在 `zbn` 账户执行 `Add-AppxPackage` 会更新正在使用的应用，不会产生第二个独立安装。**微软将相同包系列的安装视作更新；不同版本可以在磁盘上暂存，但暂存不等于同一账户能同时使用两份应用。[MSIX 更新](https://learn.microsoft.com/en-us/windows/msix/app-package-updates)、[包暂存](https://learn.microsoft.com/en-us/windows/msix/package/package-volumes)。

官方提供的是 MSIX，不提供独立 MSI 或非商店 EXE。直接运行从 MSIX 解压的 `ChatGPT.exe` 会脱离正常的包身份，不能算已验证的官方桌面端运行模式。[OpenAI Windows 部署](https://learn.chatgpt.com/docs/enterprise/windows-deployment)、[微软包身份](https://learn.microsoft.com/en-us/windows/msix/detect-package-identity)。

运行只读预检：

```powershell
& .\scripts\prepare_desktop_host.ps1 | Format-List
```

脚本校验归档 MSIX 的哈希、签名、签名证书、包清单与固定版本，同时核对当前账户的已安装版本、包系列、运行进程和管理员权限。它不会创建账户、安装软件、关闭进程或更改防火墙。本机实测为当前账户非管理员、当前桌面端进程 14 个、`SafeToInstallInCurrentUser=False`。安装包与虚拟磁盘位于 Git 忽略的 `runs/desktop-vm/`；源码分支只保存哈希清单。若 Store 已更新现有应用，预检会因当前版本变化而停止，需重新核对隔离方案。

## 独立账户的准备和安装

微软说明，MSIX 的注册按 Windows 用户区分，同一台机器的不同用户可以保有不同应用版本。[多用户 MSIX 版本](https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/modern-apps-application-packages-reported-vulnerable)。因此在不使用虚拟机的前提下，选择专用**标准用户账户**运行固定版桌面端。当前 `zbn` 账户不具备管理员权限，以下管理员步骤尚未执行。

1. 管理员在 **64 位 Windows PowerShell** 中创建专用本地用户。密码由管理员交互输入，不写入脚本、命令行或日志；创建后核对其 SID，并确认不属于本地 Administrators 组。下例中的账户名可按本机策略调整。[New-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1)、[Get-LocalGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember?view=powershell-5.1)。

   ```powershell
   $demoName = 'ttrace-desktop-demo'
   $secret = Read-Host 'Set a password for the desktop demo account' -AsSecureString
   $demoUser = New-LocalUser -Name $demoName -Password $secret -Description 'Fixed Codex desktop DLP demo'
   Remove-Variable secret
   $admins = Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
   if ($admins | Where-Object { $_.SID.Value -eq $demoUser.SID.Value }) { throw 'Demo account is an administrator' }
   $demoUser | Select-Object Name,SID,Enabled
   ```

2. 将已校验的 `ChatGPT-x64.msix` 复制到该账户可读取的位置。通过 Windows **“切换用户”实际登录**专用账户；仅在 `zbn` 的桌面上新开 PowerShell、切换工作目录或提升为管理员，都不会改变运行账户。先运行 `whoami /user`，确认显示的是专用账户 SID，再运行 `scripts/install_desktop_host.ps1`。该脚本先核对当前账户 SID、账户名、普通用户权限、安装包哈希和签名；如果当前账户已经注册其他版本，就直接停止。默认调用只预检；通过后显式加 `-Install`，才会调用面向当前用户的 `Add-AppxPackage`。`ProtectedSid` 应填写事先在 `zbn` 会话取得的 SID，不要在当前账户安装，也不要使用 `-ForceApplicationShutdown`。[Add-AppxPackage](https://learn.microsoft.com/en-us/powershell/module/appx/add-appxpackage?view=windows-11)。

   ```powershell
   $package = 'C:\demo\archive\ChatGPT-x64.msix'
   $demoSid = '<在专用账户运行 whoami /user 得到的 SID>'
   $zbnSid = '<预先在 zbn 账户运行 whoami /user 得到的 SID>'
   & .\scripts\install_desktop_host.ps1 -MsixPath $package -ExpectedSid $demoSid -ProtectedSid $zbnSid
   & .\scripts\install_desktop_host.ps1 -MsixPath $package -ExpectedSid $demoSid -ProtectedSid $zbnSid -Install
   ```

3. **此单用户离线注册尚未在本机实测。** OpenAI 对离线 MSIX 给出的正式部署流程需要管理员，并使用面向系统的新用户预配命令。若专用账户的 `Add-AppxPackage` 因许可证或权限失败，应停止，不要在当前账户重试、不要自动改用 `Add-AppxProvisionedPackage -Online`。后者会为新用户预配该应用，不满足本 Demo 只针对专用账户的要求。[OpenAI 离线部署](https://learn.chatgpt.com/docs/enterprise/windows-deployment)、[预配作用范围](https://learn.microsoft.com/en-us/powershell/module/dism/add-appxprovisionedpackage?view=windowsserver2025-ps)。此时需由管理员选择能明确限定目标用户的部署工具或调整实验环境。

4. 安装脚本会在注册后立即核对 `Get-AppxPackage -Name OpenAI.Codex` 的版本，以及 `app/ChatGPT.exe`、`app/resources/codex.exe` 的哈希；随后回到 `zbn` 核对仍为 `26.1027.6604.0`。分别记录进程用户 SID、可执行文件路径及后端哈希。固定版本会受应用内更新、Microsoft Store 或设备管理更新影响，运行期间必须持续核对实际文件哈希；关闭应用内更新需要受管策略，单纯保存 MSIX 不会自动固定已安装应用。[OpenAI 更新管理](https://learn.chatgpt.com/docs/enterprise/manage-app-updates)。

专用账户尚未建立，桌面端也尚未在该账户注册或动态验证。当前分支中的 HTTP/WSS 地址仍是静态候选，附件原始字节 Hook 尚未实现；不得因此开放网络许可或宣称已拦截真实桌面请求。主机上的 WFP 规则如需继续验证，必须由管理员按**专用账户 SID** 单独安装并回读，先证明不会改变 `zbn` 的网络行为。
