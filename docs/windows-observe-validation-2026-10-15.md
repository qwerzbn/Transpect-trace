# Windows Observe 验收记录：2026-10-15

只认证各条已实测路径；观察结果不认证为阻断结果。

| 能力／对象 | 结果 | 本地证据目录 |
|---|---|---|
| 环境与客户端盘点 | 完成，版本／哈希／扩展包均记录 | `runs/observe-baseline/inventory-final.json` |
| eCapture Windows 原始源码与 CLI/DLL 构建 | 成功，固定 commit 和构建清单 | `build/observe/ecapture-build.json` |
| eCapture 实际采集 | 未验收，非管理员被拒绝；120 字节预览不能认证完整正文 | `runs/ecapture-probes/windows-01/` |
| Native OpenSSL HTTP/1.1 gzip／中文／分段／双连接 | 正文匹配源站，审计不含明文秘密 | `runs/observe-probes/release-http-09/` |
| Native OpenSSL HTTP/2，ALPN h2，多路复用；公开 CLI | 审查修复管道时序后，三次独立运行均各匹配 4 条源站 SHA-256 | `runs/observe-probes/review-h2-14/`、`review-h2-15/`、`review-h2-16/` |
| Native OpenSSL WSS 文本分片 | 两条完整观察匹配源站，握手 Accept 已校验 | `runs/observe-probes/release-wss-11/` |
| 补充 Native Schannel／WinHTTP | 审查后复测正文匹配，原 TLS Alert 排除仍有效 | `runs/observe-probes/review-schannel-17/` |
| Codex 扩展附带后端 HTTP | 两次构造入口观察匹配实际源站正文 | `runs/observe-backend/release-http-04/` |
| Codex 扩展附带后端 WSS | 预热和真实假数据请求分别匹配 | `runs/observe-backend/release-wss-05/` |
| Chrome 独立 headless 页面 | 源站确认收到假请求；没有稳定 BoringSSL 入口，采集未通过 | `runs/observe-chrome/isolated-01/` |
| ETW 真实文件／网络证据 | 未验收，权限错误 5 | 公开 CLI 的 status.json / etw.jsonl |
| Guard 观察器冲突 | 最终观察 DLL 拒绝重复 Hook，原 Guard 仍拒绝敏感正文且源站零字节 | `runs/guard-native/observe-coexist-deny-28/` |
| Guard 正常放行／请求拒绝／显式终止 | HTTP/WSS 回归通过，磁盘哈希不变 | `observe-allow-23/`、`observe-regression-19/`、`observe-terminate-21/`（均在 `runs/guard-native/`） |
| Guard 会话持续拒绝、同 PID 存活 | HTTP/WSS 回归通过 | `runs/guard-tui/observe-session-http-19/`、`observe-session-wss-20/` |
| Guard 超时／失联／错 ID／畸形回复 | 拒绝，无自动升级终止 | `runs/guard-native/observe-timeout-22/`、`observe-disconnect-24/`、`observe-stale-25/`、`observe-malformed-26/` |

序列化观察可能在一次逻辑请求中命中多次，不能把观察条数当作源站请求条数。完整 VS Code UI、真实 ChatGPT 网站、任意 Python SDK、QUIC 和文件／截图保护都尚未认证。

调试运行，包括 IPC 创建竞争、配置应答未 flush、TLS Alert 被误当应用字节的失败样本，保留为失败证据，未用于提升能力等级。修复后通过的目录以上表为准。JSON 元数据汇总由 `scripts/report_observe_validation.py` 生成，包含输入 summary 的校验和，并将可见性、控制、来源分别输出。

当前实际来源保持 Unknown。模拟 ETW 的测试覆盖 High/Medium/Low/Unknown、PID 复用、读取时间与证据引用，仅是软件规则验收，不能替代权限环境中的真实系统事件。

最终 Native 观察 DLL SHA-256：`527d33235f20b91b503657f52928fd7c25657cb96edf8e58f9f5183c0f6d0914`。六条最终观察实验均记录该构建身份。队列／IPC 丢失计数在停止时读取，目标先行退出时终端健康无法确认，输出缺口；这不改变已获得正文的哈希事实。

复现元数据汇总：`uv run python scripts/report_observe_validation.py`，输入清单是 `deploy/observe/validation-inputs-20261015.json`，输出 `runs/observe-validation/20261015/report.json`。清单含既有 TUI 请求拒绝后恢复实验；不将这两项表述为本次重新运行。其余 Guard 故障、会话与共存回归均有本次独立目录。

初次实现自动测试为 `105 passed, 1 skipped`；审查修复后为 `116 passed, 1 skipped`。跳过的是可选 pyarrow 导出测试；另有两条既存 `utcnow()` 弃用警告。新增测试覆盖 zstd 尾校验、采集器意外退出、独立清理、幂等关闭、管道 EOF 时序和 benchmark 动态依赖提示。

`runs/observe-probes/review-h2-13/` 是本次审查复现的失败样本：源站收到四个请求，但采集被管道 flush 竞争停用。该样本保留为失败，未用于认证正文获取。详情和依赖精简说明见 [审查与精简记录](review-and-cleanup-2026-10-15.md)。
