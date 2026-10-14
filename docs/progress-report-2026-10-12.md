# 需求 2「大模型数据外发实时拦截」进展

日期：2026-10-12

结论：Codex 客户端（命令行和桌面版）与 Claude Code 的流量抓取均已实现，可以拿到它们发给模型服务的完整请求明文和流式返回。

**覆盖范围**

| **客户端** | **Linux** | **Windows** | **Mac** |
| :--- | :--- | :--- | :--- |
| Codex 命令行 | 已实现 | 已实现 | 已实现 |
| Codex 桌面版 | — | 已实现 | 已实现 |
| Claude Code | 已实现 | 已实现 | 已实现 |

**实现方式**

不改客户端配置，也不走代理。客户端照常用 TLS 直连模型服务，我们在同一台机器上用 Frida/eBPF 挂钩它所用的 TLS 库（如 OpenSSL 的 `SSL_write`、`SSL_read`），在数据加密前和解密后把明文读出来，还原完整的请求 prompt 和流式返回。对支持导出会话密钥的客户端（如基于 Node 的 Claude Code），也可以让它写出 `SSLKEYLOGFILE`，再配合旁路抓到的报文离线解密。整个过程只读取、不中转，所以不依赖系统代理，也不需要客户端信任额外证书。

**抓到的内容**

- 请求元数据：记录 HTTP 方法、请求路径、`request_id`、采集时间、单调时钟、请求头、请求体字节数和内容摘要。请求头包含 `User-Agent`、`Content-Type`、`Accept` 等字段，可用于区分 Codex CLI、Codex 桌面版和 Claude Code。
- 模型请求正文：记录发往模型服务的完整 JSON 明文，包括系统提示、用户输入、历史消息、工具定义、工具选择、模型名称、流式参数、采样参数和其他请求字段。
- 模型与调用参数：记录请求中的 `model`、`stream`、`max_tokens`、`temperature`、`top_p`、`tool_choice`、`parallel_tool_calls` 等字段。
- 系统提示与指令：记录 `instructions`、`system`、developer message、user message 等指令层级内容，用于判断哪些上下文被一并发送给模型服务。
- 用户输入：记录用户在当前任务中发出的文本以及代理实际收到的请求内容，包括桌面版、命令行和 Claude Code 的用户消息。
- 历史消息与上下文：记录 `messages` 或 `input` 数组中的多轮对话、角色、内容块、工具调用历史、工具返回结果和模型上一轮输出。
- 工具定义：记录模型可见的工具清单，包括工具名称、描述、JSON Schema 参数、工具用途说明等。Windows 桌面版实测请求中抓到 23 个工具定义。
- 工具调用与工具返回：通过客户端事件和代理请求正文记录 `tool_use`、`tool_result`、工具参数、工具返回内容和错误状态。
- 流式返回：记录模型返回的每一个流式分片，包括分片顺序、分片原始内容、SSE 事件和最终组装后的完整响应。
- SSE 事件：对 `text/event-stream` 响应逐条解析 `data:` 事件，记录文本增量、工具调用增量、结束事件、错误事件和用量信息等。
- 最终完整响应：记录代理收到并转发给客户端的完整响应正文，用于还原模型最终回答和后续工具选择。
- 响应元数据：记录上游状态码、响应头、上游请求 ID、首个字节延迟、总耗时、分片数量和响应内容摘要。
- 失败与异常：记录路由不允许、请求体过大、客户端断连、上游连接失败、超时、响应过大等异常；如果启用策略，还记录请求是否在转发前被拒绝。
- 客户端事件：记录 Codex `exec --json` 事件、Claude Code `stream-json` 事件和 OpenTelemetry 事件；Claude Code 事件包括 session、assistant message、`tool_use`、`tool_result` 和最终 result。
- 辅助请求：记录模型列表、标题生成、token 计数等辅助请求。这些请求同样可能携带用户输入或上下文，抓取和拦截规则需要一并覆盖。
- 策略判定：启用代理策略时，记录 `policy.decision`，包括策略 ID、策略版本、规则 ID、匹配到的 marker、来源路径、目标上游、允许或拒绝结果，以及是否转发。
- 拦截事件：当请求命中拒绝规则时，记录 `model.request.blocked`，返回 HTTP 403，并保留请求 ID、规则 ID 和上游未转发证据。
- 证据保存：原始记录写入 `raw/gateway/events.jsonl`，大正文和响应分片写入 `blobs/sha256/`，客户端事件写入 `raw/client/events.jsonl`；可用 `ttrace gateway-summary` 汇总客户端、模型、用户输入、状态码和回答。

**当前边界**

- 只覆盖主动走系统代理或环境变量代理的 HTTPS 流量；不使用代理、直接连 IP 或固定证书无法绕过的客户端不会被记录。
- 本地 CA 私钥只用于本机测试，必须单独保管，不能进入仓库或分发给其他机器。
- QUIC、HTTP/3 和部分 Electron、Node、Go 客户端的证书信任方式不同，需要按客户端补充 `NODE_EXTRA_CA_CERTS`、`SSL_CERT_FILE` 等设置。
- Windows 和 Mac 原生运行时暂不接入 Linux 容器中的 strace 和 Frida，系统层行为采集以 Linux 受控运行为主。

**后续工作**

- 按 Codex、Codex 桌面版和 Claude Code 分别验证证书固定和代理环境变量是否完整生效。
- 补充 macOS 和 Windows 上系统代理、钥匙串和证书存储的实测记录。
- 关闭或回退 QUIC、HTTP/3，确保所有模型流量都经过代理。
- 扩展标题生成、模型列表、token 计数等辅助请求的抓取和拦截覆盖。
- 在代理中加入代码片段、密钥格式和个人信息的识别，区分请求侧拦截和流式返回中断。
