# 跨应用与跨 Agent 复杂联动验收

在[跨应用文件／管道](cross-application-flow.md)及[跨 Agent](cross-agent-flow.md)固定实验基础上，检查并发、重复消息、请求重试、文件改写、管道重连和采集器中途停止。新组件继续观察运行，`can_enforce=false`。

验收成功与采集完整性分别表达：正常路径须完整，已知歧义或缺失路径须正确保留 `partial/Unknown`。报告的 `accepted` 表示该实验符合预期，不代表该路径已完整追踪或阻断。

## 构建与运行

在既有 uv 环境、Windows x64 和增强 eCapture 上运行。复杂实验使用带 `FIO1-ACK1` 审计确认的新 Native I/O 构建；FIO1 事件及原业务返回语义不变。ACK 仅确认观察器收到帧，不是应用操作授权。等待发生于独立审计工作线程，超时仍记录丢失／错误。

保留旧产物，在新目录构建：

```powershell
uv run --no-sync python scripts/build_native.py --component flow --output-root build/linkage
```

产物位于 `build/linkage/flow/`。管理员 PowerShell 执行：

```powershell
$runTag = Get-Date -Format 'yyyyMMdd-HHmmss'
uv run --no-sync python scripts/probe_flow_linkage.py --output "runs/linkage/$runTag" --prepare-test-trust --native-dir build/linkage/flow --ecapture-dir build/flow-ecapture-v2
uv run --no-sync python scripts/probe_flow_file_mutation.py --fake-data-only --full-chain --output "runs/flow-file-mutation/$runTag" --prepare-test-trust --native-dir build/linkage/flow --ecapture-dir build/flow-ecapture-v2
```

本地独立构建 `build/flow-linkage` 可通过 `--native-dir build/flow-linkage` 指定。eCapture 目录必须包含当前固定补丁构建；README 默认路径为 `build/observe/ecapture-enhanced`，按实际构建目录替换。已有可信证书可传 `--certificate` 和 `--private-key`，不传 `--prepare-test-trust`。

运行目录必须为新目录，不覆盖先前证据。测试信任仅服务 localhost，正常证书校验始终开启；本次信任结束后清理本次证书。证书及 UAC 系统确认由用户处理。

## 实验与预期

| 实验 | 预期 |
| --- | --- |
| 三个独立任务并发，两敏感、一普通输出 | 实际业务时间重叠；任务和进程身份各自独立；负例不继承其他任务命中 |
| 同消息三次发送 | 三个实际请求、三个回执、三个独立 attempt；不去重 |
| 源站 503 后应用重试 | 两个实际发送和回执，响应顺序 503/200；新 attempt ID |
| 同名管道关闭重连，唯一消息 ID | 内容保留；跨端代次未直接映射时显式降级 |
| 重复消息 ID、同 ID 不同内容 | 保留所有观察，明确歧义；不强制串为唯一传播链 |
| 重复 attempt ID 与相同正文 | 回执和请求次数均保留；协议 ID 冲突为缺口 |
| 上传正文发送一半时停止 eCapture／ETW／Native I/O | 明确记录观察范围结束；之后的普通发送继续，整个链为不完整 |
| B 半读文件时 A 原地改写后半 | 记录真实完成长度和偏移；合法 JSON 也不能作为稳定版本证明 |

故障模式使用明确的采集器停止请求，等待其退出或终态，发生在真实 HTTP 前缀发送之后。它验证运行中观察缺口的联动；不能外推为所有崩溃、系统重启或硬件故障均已验证。

文件探针不带 `--full-chain` 时只检查 Native I/O 组件；其基础 Flow 报告会因缺少 ETW／TLS／网络证据保留 partial。不要把纯组件通过计为全链认证。

## 证据与兼容

原始 Native、ETW、TLS 摘要和源站回执分别保存；Agent ID 来自实际重组消息和正文，测试程序的步骤输出独立标记。健康缺口、文件版本不稳定、空管道代次或 ID 冲突均可降低关联等级；High／Medium 也不证明唯一来源或字节因果。

默认只保存脱敏摘要、长度、哈希、次数与证据引用。假数据输入单列，认证头、Cookie 和原文不进入默认审计。实验仅使用固定同步 Win32 I/O、Named Pipe、WinHTTP／Schannel 和 HTTP/1.1。

原 `ttrace flow run/status/report`、`flow agents run/status/report`、Guard、Observe 和 Protect 接口保持原有语义；不扩展浏览器、剪贴板或共享内存。

具体本轮通过项和未通过项见[联动验收记录](../validation/flow-linkage-20261023.md)。
