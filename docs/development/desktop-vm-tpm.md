# Windows 11 Enterprise Eval 虚拟机的 TPM 方案

现有 Windows 版 QEMU 11.1.0 可通过 WHPX 启动虚拟机，但本地构建实测 `-tpmdev` 返回 `invalid option`，`-device tpm-tis,help` 返回 `Device 'tpm-tis' not found`。仅安装 `swtpm` 无法给这个二进制文件补上 TPM 功能。Windows 11 虚拟机需要 TPM 2.0 和具备安全启动能力的 UEFI；使用安装器注册表项跳过检查不满足该配置要求。[Microsoft Windows 11 虚拟机要求](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements)、[QEMU TPM 设备说明](https://www.qemu.org/docs/master/specs/tpm)。

## 已验证的替代路径

宿主机已有 Ubuntu 24.04 WSL2 和可访问的 `/dev/kvm`，KVM API 版本为 12。已在 **WSL 内**安装并固定如下软件包，没有启用新的 Windows 可选功能，也没有请求宿主机管理员权限：

| 组件 | WSL 内版本 | 用途 |
| --- | --- | --- |
| `qemu-system-x86` | `1:8.2.2+ds-0ubuntu1.18` | 用 KVM 运行 x86_64 客体；已验证 TPM 后端和 `tpm-tis` 设备存在。 |
| `swtpm` | `0.7.3-0ubuntu5.24.04.1` | 在 WSL 文件系统中保存客体的 TPM 2.0 状态。 |
| `ovmf` | `2024.02-2ubuntu0.10` | 使用 `OVMF_CODE_4M.secboot.fd` 与 Microsoft 预置密钥的 `OVMF_VARS_4M.ms.fd`。 |
| `qemu-system-gui` | `1:8.2.2+ds-0ubuntu1.18` | 通过已存在的 WSLg 显示安装界面。 |

预检已经实际启动 `swtpm`，并让无磁盘 QEMU 通过 KVM、Unix socket 和 `tpm-tis` 接口连接它；QEMU monitor 返回 `tpm0`。预检没有启动 Windows 安装，也**不打开**现有 `codex-desktop-win11.qcow2`。Linux QEMU、`swtpm`、OVMF 固件及变量模板的 SHA-256 固定在 [WSL 启动脚本](/D:/code/transpect-trace/scripts/start_desktop_dlp_vm_wsl.sh) 中。ISO 和客体媒体继续按 `runs/desktop-vm/pins.json` 校验；进入 `install` 或 `run` 时，脚本才检查虚拟硬盘头部至少声明 64 GiB，当前磁盘为 80 GiB。

## 运行命令

以下命令在 Windows PowerShell 中执行，`wsl` 启动的是已有的 Ubuntu 发行版。软件包只安装在 WSL 内；若需在另一个同版本 WSL 环境重建，先在 WSL 中执行：

```powershell
wsl -d Ubuntu-24.04 -u root -- sh -lc 'DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y qemu-system-x86=1:8.2.2+ds-0ubuntu1.18 swtpm=0.7.3-0ubuntu5.24.04.1 ovmf=2024.02-2ubuntu0.10 qemu-system-gui=1:8.2.2+ds-0ubuntu1.18'
```

下载尚未完成时，可只测 KVM 和 TPM 链路，跳过 ISO 哈希，也不打开虚拟磁盘：

```powershell
wsl -d Ubuntu-24.04 -- bash /mnt/d/code/transpect-trace/scripts/start_desktop_dlp_vm_wsl.sh preflight --skip-media-pin
```

下载完成且 `pins.json` 的 ISO 哈希已固定后，执行完整预检。此步会读取整个 ISO 校验 SHA-256，但不会启动客户机或写入虚拟磁盘：

```powershell
wsl -d Ubuntu-24.04 -- bash /mnt/d/code/transpect-trace/scripts/start_desktop_dlp_vm_wsl.sh preflight
```

只有完整预检通过后再运行安装。脚本会首次复制一份**新的** `desktop-uefi-vars-wsl-ms.fd`，保留现有 Windows QEMU 使用的 UEFI 变量文件；软件 TPM 状态位于同一 WSL 用户的 `~/.local/state/transpect-trace/desktop-vm/tpm2`。此后的 `run` 必须使用同一个 WSL 用户和这两份持久状态。安装默认不接客体网络，也不附加包含 Codex 包的客体媒体：

```powershell
wsl -d Ubuntu-24.04 -- bash /mnt/d/code/transpect-trace/scripts/start_desktop_dlp_vm_wsl.sh install
wsl -d Ubuntu-24.04 -- bash /mnt/d/code/transpect-trace/scripts/start_desktop_dlp_vm_wsl.sh run --package-media
```

`--network` 是显式选项，只在客体内的网络隔离和内容门控已装好并验证后使用。运行 Windows 11 安装器后，在客体内检查 `tpm.msc` 显示 TPM 2.0、`msinfo32` 显示安全启动状态，再记录 ISO、Linux QEMU、固件、桌面 MSIX 和后端文件哈希。2026-11-04 已完成 ISO 哈希、KVM/TPM/OVMF 完整预检，并以离线模式启动安装器；因任务转向 CLI，虚拟机随后已停止。**未确认客体安装完成**，也未完成桌面端模型交互与网络阻断实测。

## WHPX 路径的备选说明

当前 Windows QEMU 构建没有 TPM 后端，无法作为符合 Windows 11 要求的首选方案。若仅为临时隔离实验坚持使用该 WHPX 二进制文件，可在**客体 Windows 安装器**中按 `Shift+F10`，执行 `reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f` 后重试安装。该注册表项只改动客体安装环境，绕过 TPM 检查，不会提供 TPM 2.0，也不应把该客体当作满足 Windows 11 虚拟机要求的最终 Demo。若固件检查另行失败，不应静默再添加其他绕过项；先核查 UEFI 和安全启动配置。
