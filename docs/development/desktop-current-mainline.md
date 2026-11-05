# 本机 Codex 桌面端 DLP 开发主线

本分支以**本机当前使用的 Codex 桌面端 Local 任务**为目标，不修改 Codex 源码，不使用转发代理。固定版为 MSIX `26.1029.7803.0`、内置后端 `codex-cli 0.166.0-alpha.6`；每次研究探针运行前核对安装包、进程、版本与文件哈希。[固定版候选适配器](../../deploy/guard/desktop-candidate-26.1029.7803.0.json)仍标记为 `candidate_unvalidated`，因此当前实现是短时研究 Demo，**不是常驻运行的桌面防护**。

## 主链路

```text
Codex 组装并序列化模型请求
    ↓
在已核对版本的 HTTP/WSS 候选函数取得完整请求字节
    ↓
AES-GCM 加密落盘，立即回读并核对长度、SHA-256
    ↓
本地四层 DLP 扫描完整请求及可检查的内联内容
    ├─ ALLOW：调用原发送函数
    └─ REVIEW / BLOCK / 检查失败：构造错误返回，拒绝本次发送
```

| 环节 | 当前实现 | 本机验证范围 |
| --- | --- | --- |
| 采集 | [短时 Frida 探针](../../scripts/probe_desktop_current_dlp_bridge.py)在 `codex.exe app-server` 的 HTTP 正文准备入口和 WSS `response.create` 序列化返回点取字节；先核对根部 `client_metadata.thread_id` 和本轮合成标记。 | 现用桌面端的**指定 Local 测试聊天**已在 HTTP 候选点取到完整序列化 JSON。跨聊天自动发送的测试文字在请求里是 `function_call_output`，不是桌面输入框提交的 `role=user`。未归因请求原样通过。 |
| 加密归档 | [归档模块](../../src/transpect_trace/protect/archive.py)使用 Windows DPAPI 保护 AES-GCM 密钥，写盘并回读核对；首版上限 16 MiB。 | 六次匹配的合成请求均归档且回读一致。满七天后拒绝读取；当前用户已安装每小时及登录时运行的清理任务。它不隔离同一 Windows 账户的其他进程，物理删除可能晚于七天到期时刻。[保留说明](desktop-archive-retention.md) |
| 内容识别 | [本地引擎](../../src/transpect_trace/protect/content_dlp.py)融合规则与校验、熵分析、EDM 精确数据匹配、内部文档及源码指纹；`BLOCK`/`REVIEW` 都不授权发送。 | 合成假密钥在现用桌面端命中 `ASSIGNED_SECRET`。公开语料 13,000 行仅使用基础规则与熵层；完整四层另由合成登记夹具测试。[评测](desktop-dlp-evaluation.md) |
| 发送点拒绝 | HTTP 候选函数收到拒绝后返回错误而不调用原函数；WSS 候选点将序列化结果改成错误。策略最多等待 2 秒，目标决策失败时拒绝。 | 现用桌面端六次**已归因的 HTTP 合成请求**均对应拒绝事件；没有 WSS 目标命中，也没有桌面端受控源站零字节证明。[实验记录](desktop-path-current.md) |

加密归档的是**完整待发送模型正文**，可能包含系统指令、开发者指令、工具结果和聊天历史。第二轮不带密钥的新测试文字仍被拒绝，因为同一聊天的完整请求历史里保留了上一轮假密钥；这一轮不能作为“干净普通请求”的误报测试。模型请求里的 `file_id`、路径等引用也不能代替文件原字节；无法绑定已检查快照的引用在桥接判定中拒绝。

## 尚未完成的桌面路径

- **普通桌面输入。** 需要对从桌面输入框提交的 `role=user` 请求，分别验证 HTTP、WSS 以及重试路径。现有短时探针只针对固定测试聊天与合成标记，生产 DLL 尚未为桌面端启用。
- **界面附件。** [文件提取与附件桥接](../../src/transpect_trace/protect/desktop_bridge.py)可处理原字节、内联内容和已批准引用；[当前附件探针](desktop-attachment-current.md)仅提供观察能力。真实界面添加文件的原字节 Hook、发送点拒绝和源站零字节仍未验证。
- **Agent 工具外发。** 当前 Local 任务为 `danger-full-access`。[本机受控实测](desktop-current-agent-egress.md)中，工具进程的 TCP/UDP、IPv4/IPv6 四条路径均到达本机非回环收件器。模型请求 Hook 不控制工具进程直接开 socket；需要在同一桌面端让工具使用网络关闭的受限环境，或建立经过验证的独立进程网络边界。
- **全路径验收。** 对每条模型及附件路径核对 Hook 字节、加密快照和受控源站实际收到的字节；补齐无敏感历史的普通请求放行、失效与换版测试。未验证路径不得写成已覆盖。公开数据集尚无独立策略真值和盲测结果。

现有 [CLI Native Guard](../../native/guard/guard.c)、隔离 [HTTP/WSS 后端实验](desktop-backend-lab.md)及独立 CLI 网络沙箱实验可作为技术参考，不能替代本机桌面客户端的动态验收。本文是当前开发入口；逐轮原始事实和报告哈希见[本机实验记录](desktop-path-current.md)。
