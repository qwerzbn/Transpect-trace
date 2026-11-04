# 固定桌面端的发送路径动态探测

`scripts/probe_desktop_paths_vm.py` 用于回答两个尚未验证的问题：桌面界面的本地 Codex 任务是否进入归档后端的 HTTP/WSS 候选函数，以及界面附件的原始字节首先在哪个进程、哪个调用栈出现。它是 **Frida 研究探针**，不修改 Codex 安装文件，不安装或开放 WFP 网络许可，不执行阻断。输出始终标记 `coverage_status: unvalidated`。

探针只接受隔离 QEMU Windows 虚拟机、归档的 `26.1029.7803.0` 官方 MSIX 和 `codex-cli 0.166.0-alpha.6` 后端。运行时要求 `--isolated-vm`、QEMU 机器身份、不同于 Codex 专用账户的控制器账户、固定进程哈希与父子关系，以及已经安装的 WFP IPv4/IPv6 入站和出站默认拒绝。版本或进程身份不符时，不挂载探针。Frida 仅是此实验的依赖；正式门控仍使用固定版原生 Hook。

## 准备与执行

在虚拟机中，将归档 MSIX、固定后端、候选适配器与仓库放入专用演示目录。候选适配器必须由 `scripts/discover_desktop_guard.py` 对该 MSIX 和后端生成，状态保持 `candidate_unvalidated`。先为桌面专用账户及实际使用的工具账户安装 WFP 默认拒绝规则，再运行以下命令；`--wfp-exe` 指向本仓库构建的虚拟机 WFP 工具，脚本会核对其构建清单、可执行文件和本地源码哈希。Frida Python 包需单独装入虚拟机的研究环境，探针不会自动下载或安装它。

```powershell
python scripts/probe_desktop_paths_vm.py prepare `
  --output C:\demo\desktop-trace\fixtures

python scripts/probe_desktop_paths_vm.py trace --isolated-vm `
  --adapter C:\demo\desktop-adapter\candidate.json `
  --fixtures C:\demo\desktop-trace\fixtures\fixtures.json `
  --desktop-pid <ChatGPT.exe-PID> --backend-pid <codex.exe-app-server-PID> `
  --network-pid <ChatGPT-network-service-PID> `
  --expected-sid <Codex-专用账户-SID> `
  --wfp-exe C:\demo\build\desktop-wfp\wfp_desktop.exe `
  --case text --seconds 60 --output C:\demo\desktop-trace\text-01
```

为 `idle`、`text`、`upload` 各运行一次，使用不同的空输出目录。`text` 阶段只在桌面端本地任务输入 `fixtures/text-prompt.txt` 的合成文字；`upload` 阶段只上传 `fixtures/synthetic-attachment.txt`。`--network-pid` 应指向经过身份核对的 Electron NetworkService；省略时，报告无法定位该进程中的附件路径。不要将测试标记替换成真实密钥或内部文件。

探针在后端的 HTTP body 候选 RVA 和 WSS serialization 候选 RVA 记录入口命中；它还把**旧 CLI 的参数和返回布局当作只读假设**，仅在可读取的有界缓冲区中查找合成标记，并在进程内计算缓冲区 SHA-256。该假设失败时只记录 `read_hypothesis_failed`，不推断 ABI。桌面主进程、后端和指定 NetworkService 同时观察 `CreateFileW`、完成的 `ReadFile`/`NtReadFile`、`WriteFile` 与可用的 WinHTTP 写入入口；标记命中时保存进程角色、模块名、RVA、长度、SHA-256 和短调用栈。没有正文、路径或附件字节进入事件文件。

`summary.json` 包含适配器、探针源码、合成文件和事件文件的哈希，固定进程镜像与创建时间、命中计数、错误以及 Frida 版本；`events.jsonl` 只含经过字段白名单处理的元数据。原始合成标记只保存在 `fixtures` 里，便于操作者手动触发桌面交互。

## 如何判读

HTTP/WSS 候选入口在 `text` 阶段命中，说明本次桌面任务执行到了该函数；缓冲区里同时找到合成标记与 SHA-256，则为该次请求的更强关联证据。`ReadFile` 等入口命中附件标记和调用栈，可用于继续定位上传字节形成的位置。`idle` 阶段用于辨别后台预热或与任务无关的调用。

这些结果不能单独证明请求正文完整、拒绝返回 ABI 正确，或阻断发生在网络发送之前。`ReadFile` 探针也可能漏掉内存映射、异步完成、共享内存传递及其他网络写入路径。若 WFP 默认拒绝使界面在组装请求前停止，未观察到命中只能记为**未确认**。后续仍须在同一固定虚拟机内以受控源站做允许样本正向对照、拒绝样本零字节验证，并核对文件 ID 的响应绑定；任一未验证路径继续保持默认拒绝。参见 [桌面适配器状态](../desktop-guard-adapter.md)和[受控源站与 WFP 测试](desktop-wfp.md)。
