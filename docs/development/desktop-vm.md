# 固定版桌面 DLP 虚拟机环境

本 Demo 使用独立 Windows 11 Enterprise Evaluation 虚拟机。宿主机当前运行的 ChatGPT/Codex 客户端不参与采集、注入或测试。虚拟机文件保存在被 Git 忽略的 `runs/desktop-vm/`，不进入源码提交；对应的版本与介质哈希清单保存在 `deploy/guard/desktop-vm-pins.json`。在新工作区运行启动脚本前，先将该清单复制为 `runs/desktop-vm/pins.json`，再取得与清单匹配的安装介质。

| 归档对象 | 固定值 |
| --- | --- |
| Windows 11 Enterprise Eval 26H2 简体中文 ISO | SHA-256 `B37A06D5121EEE017826C0B133250BBD21BEC694C2D607C60EDD29090E667A84`（[微软校验表](https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file)） |
| QEMU Windows 安装包 `qemu-w64-setup-20260811.exe` | SHA-512 `5BCF9EED634E8575A37B74F445AF41A2FE4106DA512D0C30C368301D4C105037FDFAB40A5287367A28A957624CDDEBBC8C07E16C88AB6634F554CDF3D16BF543`；以便携方式解压到 VM 目录，未在宿主机安装 |
| 官方 `ChatGPT-x64.msix` | SHA-256 `19487892B7E27C74E75C6422088E91B35B4291ED485045F82A1984A13B22D128`；包版本 `26.1029.7803.0`；签名状态 `Valid`；证书指纹 `B0429F3569607833179400E29D6D641B363CA6A4` |
| 归档桌面主程序 | `app/ChatGPT.exe`，SHA-256 `74DCBC67421C5D5406EA5E4CC80D9C8D8A05D0DF62F1D7BE5690F090F182E71F` |
| 归档后端 | `app/resources/codex.exe`，`codex-cli 0.166.0-alpha.6`，SHA-256 `925C7D0665FFA49B0DCF748E034A805A04DA984164AC92301432073B47789B99` |

桌面 MSIX 来自[官方 Windows 部署说明](https://learn.chatgpt.com/docs/enterprise/windows-deployment)中的 x64 链接。该链接会变动为最新包，所以本 Demo 只使用上述已归档字节。安装后仍须在虚拟机中核对 `Get-AppxPackage` 的 `PackageFullName` 和后端实际进程哈希。静态分析只发现 HTTP/WSS 候选函数位置；不能据此认定请求或附件已被完整采集。

## 启动方式

镜像下载完成且 SHA-256 核对后，首选在已有 Ubuntu 24.04 WSL 中运行 `scripts/start_desktop_dlp_vm_wsl.sh preflight`，确认 KVM、软件 TPM 2.0、OVMF 和介质哈希；随后运行 `install` 安装系统。脚本默认**不连接虚拟机网卡**。安装完成后以 `run --package-media` 从虚拟磁盘启动，并挂载已校验的只读安装媒体 `guest-media.iso`。该媒体由 `scripts/build_desktop_vm_media.py` 从固定 MSIX、离线许可证和 WFP 程序构建；虚拟机可以在联网前取得它们。只有在虚拟机内完成账户、WFP 和桌面门控配置后，才使用显式的 `--network` 参数。WSL 软件包、哈希、命令和实际预检结果见 [TPM 与启动说明](desktop-vm-tpm.md)。

已归档的 Windows QEMU 11.1.0 仍用于版本留档，但该 Windows 构建实测没有 TPM 后端和 `tpm-tis` 设备，因此 `scripts/start_desktop_dlp_vm.ps1` 的 WHPX 路径不能作为符合 Windows 11 虚拟机要求的首选安装方式。WSL 路径使用另一组已固定版本和哈希的 Linux QEMU、OVMF 与 `swtpm`，无需修改宿主机的虚拟化功能或防火墙规则。

安装与演示账号分开：管理员账号运行本地判定服务并保存 DPAPI 加密快照；固定的低权限账号运行桌面端；Codex 的 Windows `elevated` 沙箱为工具进程使用另一个低权限身份。对桌面账号和工具沙箱账号分别安装并回读 WFP 默认拒绝规则。模型进程的短时许可只有在固定版本模型和附件门控均有动态验证证据且实时就绪时才可创建。具体规则和身份校验见 [WFP 说明](desktop-wfp.md)与[桌面适配器说明](../desktop-guard-adapter.md)。

## 当前验收状态

固定包归档、静态候选、四层内容判定、加密归档、二进制附件判定管道和 WFP 组件均可离线验证。2026-11-04 已校验微软 ISO 哈希，通过 WSL KVM/TPM/OVMF 完整预检，并离线启动安装器；任务转向 CLI 后已停止虚拟机，未确认 Windows 安装完成。**桌面端实际 Hook、附件上传 Hook、虚拟机内 WFP 行为、真实模型交互和受控源站零字节证明尚未完成动态验收。**在这些证据齐全前，桌面控制器保持网络许可关闭，不把静态候选计入覆盖率。
