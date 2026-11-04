# Codex CLI 用户 Prompt 内容检查 Demo

## 范围与工作链路

本分支只检查用户在 Codex CLI 中提交的**文字 Prompt**。Codex 的官方 `UserPromptSubmit` Hook 在该文字进入本轮处理前向本地脚本提供 `prompt` 字段；脚本同步返回 `{"decision":"block","reason":"..."}` 时，Codex 拒绝本次提交。[Codex Hooks 官方文档](https://learn.chatgpt.com/docs/hooks)给出了事件字段和阻断响应格式。此处使用官方扩展点，不修改 Codex 二进制，也不经过转发代理。

```text
用户提交 Prompt
    → UserPromptSubmit Hook
    → DPAPI 加密留存原文
    → 本地四层内容识别
    → 元数据审计
    → ALLOW：Hook 返回空输出，Codex 继续
      REVIEW/BLOCK：Hook 返回 block，Codex 拒绝本次提交
```

`scripts/cli_prompt_dlp_hook.py` 从标准输入读取单个 Hook JSON 事件，只取其中的 `prompt` 字符串。它限制事件大小为 1 MiB；事件格式错误、归档失败、识别异常或审计写入失败均返回拒绝。`ALLOW` 才会输出空内容。`REVIEW` 在本 Demo 中也拒绝，不提供人工放行流程。

## 本地识别和留存

`scripts/cli_prompt_detector.py` 只扫描文字，不打开 Prompt 中提到的文件路径。四层识别分别是：

| 层 | 在文字中寻找什么 |
| --- | --- |
| 规则、校验和上下文 | 常见密钥格式与个人信息；对银行卡号做校验，并检查可解码的 Base64、十六进制文本。 |
| 熵分析 | 格式未知、但像随机密钥的长字符串。 |
| EDM 精确匹配 | 与演示用合成记录同一行的多个字段；多个字段共同出现提高置信度。 |
| 文档和源码指纹 | 与演示用内部文字、源码样本重合的片段及部分代码结构特征。 |

四层结果按类别合并为 `ALLOW / REVIEW / BLOCK`。登记数据和规则是**合成演示样本**，不是企业生产规则库；词面与结构识别可能漏掉语义改写。`Finding.evidence` 可能包含命中的文字片段，Hook 不把它写入审计或阻断理由。

每次提交先以 Windows 当前用户范围的 DPAPI 将 Prompt 原文加密为 `<archive_id>.dpapi`，再写一条 `audit.jsonl`：时间、归档 ID、Prompt 的 SHA-256、字节数、判定和命中类别/层名。默认位置为 `%LOCALAPPDATA%\TranspectTrace\cli-prompt-demo`，可用 `TTRACE_CLI_PROMPT_DEMO_DIR` 指向测试目录。审计不包含 Prompt 明文；当前 Demo **没有自动清理期限**。同一 Windows 用户身份可以解密其 DPAPI 归档，所以这不是把内容与同账户运行的 Codex 进程隔离的安全边界。

## 配置与验证

`deploy/guard/cli-prompt-hooks.example.json` 是 `hooks.json` 示例；实际 Hook 命令需使用该机器可用的 Python 和脚本绝对路径。Codex 要求非托管 Hook 先经过审查与信任，改动 Hook 定义后需要重新审查；CLI 可用 `/hooks` 查看状态。[官方 Hook 信任说明](https://learn.chatgpt.com/docs/hooks)。

先在本分支运行 Hook 和隔离探针的定向测试：

```powershell
uv run --no-sync pytest tests/test_cli_prompt_dlp_hook.py tests/test_probe_cli_prompt_hook.py -q
```

这些测试调用脚本与检测器，不代替真实 Codex CLI 的阻断验证。

本分支的隔离验证脚本使用固定版本 `codex-cli 0.163.0`，并核对二进制 SHA-256 `2692C8C7BB2CF8B0AEFE638741FC90236F4B824C59578CE84994F9DE58200993`。它创建临时 `CODEX_HOME`，只为测试子进程配置 Hook 和本机不转发的接收器；不读取或复制当前用户的 Codex 登录凭据。运行：

```powershell
uv run --no-sync python scripts/probe_cli_prompt_hook.py
```

报告默认写入 `runs/cli-prompt-probe/report.json`。脚本也接受 `--codex-exe <固定版本原生 exe>` 和 `--report <路径>`。本机固定版本的实测结果如下；两种 Prompt 都是合成样本：

| 场景 | Hook 与归档 | 本机接收器 | CLI 结果 |
| --- | --- | --- | --- |
| 敏感 Prompt | 审计 `BLOCK`，1 份 DPAPI 加密快照 | 0 个请求，0 字节正文 | 退出码 0；事件中有 item error 和 `turn.completed`；报告的 token 用量均为 0 |
| 普通 Prompt | 审计 `ALLOW`，1 份 DPAPI 加密快照 | 1 个请求，正文 41,057 字节 | 退出码 1；接收器故意返回 HTTP 503，导致 `turn.failed` |

接收器只记录到达字节并返回测试响应，**不会转发到真实模型**。普通 Prompt 的失败说明请求到达本机测试源站，不代表真实模型交互成功；敏感 Prompt 的零请求、零字节与零 token 用量是这次固定 CLI、已启用 Hook 的发送前阻断证据。

## 已知限制

此 Hook 取得的是用户提交的文字，**不是** Codex 随后组装的完整模型请求。它不读取附件原始字节、不扫描本地文件、不检查 Agent 工具调用，也不控制工具直连网络。用户关闭 Hook、尚未信任 Hook，或直接使用未配置该 Hook 的 CLI 时，脚本不会执行；脚本内部的“异常即拒绝”不能代替对 Hook 是否实际运行的验证。这个 Demo 只证明已启用并已执行的 Hook 对所见 Prompt 的处理结果。
