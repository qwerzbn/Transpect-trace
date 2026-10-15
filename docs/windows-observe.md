# Windows 多通道 LLM 明文观测

`ttrace observe` 是独立的异步观察链路。它复用敏感内容检测和 ETW 来源关联，但**不执行阻断**。`RiskAssessment.recommended_action=block_request` 表示建议；`effective_action=audit`、`can_enforce=false` 表示实际仅审计。既有 `ttrace guard` 的同步 IPC、固定哈希和阻断动作保持独立。

## 实际验证结果

| 对象 | 正文获取 | 发送前控制 | 来源证据 |
|---|---|---|---|
| Python 3.12 / OpenSSL 3.0.16 | Native SSL API 已验证 HTTP/1.1 gzip、HTTP/2 多路复用、WSS 文本分片；正文哈希匹配源站 | 无 | ETW 不可用时 Unknown |
| WinHTTP/Schannel 合成基准 | 补充 Native SSPI Hook 已验证完整 HTTP JSON | 无 | Unknown |
| VS Code Codex 扩展所带后端 | 独立启动其真实 app-server，通过 RPC 发起 HTTP/WSS 请求，序列化正文哈希匹配源站 | 无；不认证此后端为 Guard 目标 | Unknown |
| 完整 VS Code＋Codex UI 通道 | 尚未认证；后端实验不能代替 UI、账号及其他辅助进程的覆盖 | 未认证 | 未认证 |
| Chrome 155.0.8059.41 | 隔离 headless 页面成功向源站 POST；网络进程已识别，但没有经过验证的 BoringSSL 入口，正文采集未通过 | 无 | 行为证据不等于正文 |
| eCapture Windows | 源码、Go CLI 和配套 DLL 构建成功；当前账户缺少管理员权限，元数据／明文实采未验收 | 无 | 未验收 |

所有真实 AI 服务通道的 `actual_ai_channel_certified` 均为 false。当前完成的是受控源站与实际客户端／后端的局部实验，不宣称已验证真实 ChatGPT 网页、完整 IDE UI 或所有 SDK。

## eCapture 的实测边界

固定 [Windows 分支 commit 7fb8347](https://github.com/gojue/ecapture-windows/tree/7fb8347b7a3c28d2a094e35af38b1c471d194ebf)，没有修改其源码。本次编译使用官方 Go 1.25.12 Windows amd64 工具链，下载校验 SHA-256 为 `d5dc82da351b00e5eedd04f41356817d674cc4308131f0f638a5b14c5c3af4cb`。

实际代码与旧文档有区别：

- SSPI companion DLL 使用本机 TCP 和临时端口文件，不是文档描述的 Named Pipe。
- 帧包含 PID、TID、方向和数据，没有 TLS 连接身份或可靠的源序列。
- `WindowsTLSEvent.String()` 只输出 120 字节预览；`--hex` 读取的是另一个 userData 字段，不能据此恢复完整 SSPI 正文。
- SSPI 基准仍需启动 ETW，当前非管理员账户直接拒绝运行。

因此适配器不将 eCapture 文本输出伪装成完整请求。预览只在内存中解析，默认落盘为哈希和长度；缺少连接身份或截断时输出 `coverage_gap`。编译成功、探针就绪、零个观察事件都不是完整明文获取的证明。相关来源是固定 commit 的 `internal/probe/openssl/event_windows.go` 和 `pkg/util/hook/sspi_pipe_windows.go`。

## Native 观察适配

`native/observe/observer.c` 构建成单独的 DLL，使用已有固定校验和的 MinHook。它复制 TLS 成功接收／发送的应用缓冲区，保留原函数返回值和 Windows 错误状态；对 Schannel 在加密前复制、成功后输出，排除 `SECQOP_WRAP_OOB_DATA` 的 TLS Alert。[微软接口说明](https://learn.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--schannel)

- OpenSSL：`SSL_write[_ex]`、`SSL_read[_ex]`、`SSL_free`，按已加载模块的文件哈希和 PE 导出校验。
- Schannel：`EncryptMessage`、`DecryptMessage`、`DeleteSecurityContext`，仅 Windows x64、显式 PID 和固定进程哈希。
- Codex：已登记映像的 HTTP 正文准备和 WSS 序列化观察入口。观察时不修改 Rust 对象、不构造拒绝结果。
- MSVC 合法的同映像 E9 导出 thunk 可以解析；指向私有内存的已有 detour 拒绝接管。已安装 eCapture companion DLL 或本观察器时拒绝第二个控制器。

进程身份为 PID＋创建 FILETIME。Named Pipe 拒绝远程连接，DACL 限当前用户和 SYSTEM；逐帧核对真实客户端 PID 和创建时间。每个 TLS 上下文有独立连接代次和双向序列；地址重用不会直接拼入旧连接。

每条管道连接承载一帧。控制器读完后等待写入方完成 flush 并关闭连接，再断开服务端，避免“帧已经被读取，但 flush 因过早断连报错”而意外停用后续采集。采集进程提前退出或控制线程失效会终止观察并记录失败；各组件独立清理，ETW 清理失败时不使用其未完成的证据提升来源等级。

模型流量继续走客户端原连接和 TLS。本地 IPC 只承载观察数据，不转发模型流量。TLS 回调只向 8 MiB 有界队列复制，IPC 在独立工作线程；单帧上限 64 KiB，超限明确标记。HTTP 重组正文上限 16 MiB、全连接待重组数据上限 64 MiB、并行连接／HTTP2 stream 数上限 128。丢失、未知编码、RST 或不完整关闭均输出缺口，隔离后续无法可靠重组的片段。

停止采集调用本观察 DLL 的关闭接口，关闭内容复制并清理队列；不会卸载／关闭 Guard 或终止目标进程。观察 DLL 仍驻留并调用原函数，本原型重新接管需重新启动目标。采集器异常离线时观察线程停用后续复制；不提供生产级抗篡改或持续健康证明。

Native 单调丢失计数覆盖队列不足、分配失败、IPC 失败及关闭时丢弃的剩余帧，防止最后一次丢失没有后继帧而被遗漏。停止时核对该计数；目标已退出、不能读取最终健康状态时，明确记录 `terminal_capture_health_unavailable`，不认证完整覆盖。

## 构建、盘点和启动

```powershell
uv sync --extra native-build --extra observe --dev
uv run python scripts/build_observe_native.py
uv run ttrace observe inventory --output runs/observe-baseline/inventory.json
```

eCapture 构建需要先在 `.external/ecapture-windows` 获取上述固定 commit，并安装 Go 1.25.12；项目不会自动执行上游安装脚本：

```powershell
git clone https://github.com/gojue/ecapture-windows.git .external/ecapture-windows
git -C .external/ecapture-windows checkout 7fb8347b7a3c28d2a094e35af38b1c471d194ebf
uv run python scripts/build_ecapture_windows.py --go C:\path\go\bin\go.exe
```

构建产物与清单在 `build/observe/`。eCapture 运行前核对 CLI 和 companion DLL 哈希及源码 pin，工作目录固定为产物目录，避免从其他工作目录加载同名 DLL。

先在进程已加载 TLS 模块时盘点。只有找到经过支持的入口才生成可用 profile：

```powershell
uv run ttrace observe inventory --pid 12345 --application python-api --profile-output runs/python-profile.json
uv run ttrace observe run --pid 12345 --profile-file runs/python-profile.json --duration 30
uv run ttrace observe report runs/observe/<run-id> --output runs/observe/<run-id>/report.json
```

对已确认的 Schannel 测试进程，盘点增加 `--mode schannel`。eCapture 使用 `--provider ecapture-windows`。不要根据 UI 根进程名称猜测网络进程；Chrome 网络服务和扩展后端要单独盘点。过早附加、模块尚未加载、版本变化、权限或进程缓解策略不兼容均不得认证为已覆盖。

## 检测、协议与输出

支持 HTTP/1.1 请求、HTTP/2 HPACK 与按 stream 重组、经双向 Upgrade 确认的 WSS 文本及标准消息分片。支持 gzip、deflate、zstd；未知编码／WebSocket 扩展记录未覆盖。QUIC 不解析，Chrome 隔离测试源站仅支持 HTTP/1.1，不认证浏览器默认 AI 通道协议。

zstd 必须通过完整帧、校验和和尾部检查；损坏或多帧输入不认证完整正文。HTTP/2 运行解析依赖 `observe` extra 的 hpack/hyperframe；默认开发组另含构造测试请求的 h2。凭据实验使用的 cryptography 属于开发／研究依赖，不进入最小运行环境。

硬命中包括私钥、配置凭据、配对 AWS 凭据、marker 和登记文本。`ObservationPolicy` 可配置弱关键词、应用哈希和既有 upstream 白名单：弱信号或目标／应用不匹配产生 warning，凭据／登记机密命中保持 critical，不因来源 Unknown 降级。AST、embedding 和语义模型未启用，也不会把内容发送给外部分类服务。

独立观察策略示例；原有 GuardPolicy 文件也可在 observe 中复用：

```json
{
  "schema_version": "transpect.observe.policy/1.0",
  "content_policy": {"credential_rules": true, "allowed_upstreams": ["approved.example"]},
  "warning_keywords": ["internal draft"],
  "allowed_application_hashes": []
}
```

新增语言无关 JSON Schema：`observe-capture`、`observe-request`、`observe-risk`、`observe-source`、`observe-policy` 和 `observe-profile`。Guard v1 wire shape 未改变。Native 二进制输入帧为 little-endian 的固定 64 字节头 `4s III QQQQQ II`，随后是有界数据；`NativeCollector` 转换为 CaptureEvent。原始 `data_b64` 默认不参与模型序列化。

每个目录包含：

```text
status.json                  # 文件快照，不是持续存活证明
capture-metadata.jsonl        # 字节数量、哈希、进程／连接／序列，无原文
observations.jsonl           # 正文哈希、协议、完整性和语义标签
assessments.jsonl            # 建议与实际动作分开
coverage-gaps.jsonl          # 丢失、截断、解析和覆盖缺口
etw.jsonl                    # 若权限允许，目标及后代的系统证据
source-relations.jsonl       # 异步来源候选、Confidence、方法、事件引用
report.json                  # 可见性／控制／来源三个视图
```

HTTP 目标只保留 scheme、host、port，不落盘请求查询、认证头或 Cookie。`send_evidence=accepted_by_tls` 表示 TLS API 成功接受应用数据；`constructed` 表示序列化入口观察，均不等于源站已收到。`no_match` 只表示当前检测器未命中，不表示数据安全。

附件引用、内嵌图片和独立上传分别需要进一步适配；当前附件语义标记为未检查，OCR 和上传前门控未实现。ETW 关联使用已有 Confidence 逻辑，永不宣称字节级污点追踪。当前 ETW 权限不足，真实采集保持未验收，实际来源为 Unknown；单元测试中的 High 仅验证规则逻辑。

## 实验与回归

以下全部是独立配置、假数据、本地不转发的 TLS 源站；完整假正文和源站密钥只存在这些明确的实验目录。Schannel 合成程序仅对 localhost 临时证书放宽 CA 校验，不安装系统 CA，不改变真实客户端证书配置。

```powershell
uv run python scripts/probe_ecapture_windows.py
uv run python scripts/probe_observe.py --protocol http
uv run python scripts/probe_observe.py --protocol h2 --launcher
uv run python scripts/probe_observe.py --protocol wss
uv run python scripts/probe_observe.py --client schannel
uv run python scripts/probe_observe_appserver.py --transport http
uv run python scripts/probe_observe_appserver.py --transport wss
uv run python scripts/probe_observe_chrome.py
uv run python scripts/report_observe_validation.py
uv run pytest
```

VS Code 扩展实验安装在 `.external/observe-vscode-extensions` 与独立 user-data 目录，未修改用户默认扩展目录或账号。后台实验程序是该扩展所带的真实 codex.exe；RPC 客户端是测试驱动，不是 VS Code UI。下一步实际 UI 验收必须人工在隔离配置中触发假数据任务，并逐项核对进程和源站。

**哈希变化注意：**本机更新后的 Codex 和扩展附带版本虽然仍显示同一 CLI 版本，文件 SHA-256 已变为 `f552…487b`。其 .text/.rdata 与原基线一致，且已单独通过只读后端观察实验；这不改变 Guard 仅接受 `d139…aec` 的限制。门控回归使用此前保存、哈希完全一致的官方 EXE 副本；新文件不能自动启用保护。

本次具体实验索引见 [2026-10-15 验收记录](windows-observe-validation-2026-10-15.md)。
