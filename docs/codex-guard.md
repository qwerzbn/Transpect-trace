# Windows 官方 Codex CLI 发送前门控

本实现是固定版本的能力验证和 Native 原型。官方 EXE 磁盘文件不修改；在目标进程内安装 Native Hook，通过本地 Named Pipe 同步调用语言无关的策略接口。允许后继续调用原客户端、原连接和原 TLS；模型流量不经过策略服务。Frida 仅用于定位和实验，运行 `ttrace guard` 不依赖 Frida。

只接受 Windows x64 `codex-cli 0.162.0-alpha.17.2`，SHA-256：

```text
d13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec
```

Python 控制器先校验版本、架构、进程创建时间和磁盘哈希；DLL 再独立校验哈希与入口指令。不匹配时不启用适配。保护范围为 `codex exec` 和显式 PID 附加的 `--no-daemon` TUI。默认 daemon、app-server、Codex Desktop 和 GUI ChatGPT 不在范围内。

## 已验证的入口与边界

| 层级 | 固定版本入口 | 结果 |
|---|---|---|
| 请求构造 | 基于字符串引用、PE unwind 信息建立候选 | 仅定位，未认证独立门控点 |
| WSS 序列化 | RVA `0x03d6daa0` | `response.create` JSON 明文、发送前判定及现有错误路径通过 |
| HTTP 正文准备 | RVA `0x09d96b10` | `EncodedJsonBody` 压缩前明文、发送前判定及现有错误路径通过 |
| 低层候选 | Schannel、Winsock | 观察研究入口，未认证为完整 Prompt 门控点 |
| 接收事件反例 | RVA `0x03d703f0` | 对应接收事件，不是发送 Prompt，未纳入保护 |

能力声明见 [固定版本适配描述](../deploy/guard/codex-windows-x64.json)。适配代码仍有固定 RVA 和经实验确认的 Rust 数据布局，不能移植到其他版本。

HTTP 入口的现有错误 tag 为 `3`，拒绝时构造由该版本分配器可释放的 String，并通过原函数释放移入的 HeaderMap。WSS 序列化成功 tag 为 `0x1c`；拒绝时复用其自有 String 缓冲区，返回已验证的 `ApiError::Stream(String)`（tag `0x0d`）。正常路径调用原函数，不重新实现 HTTP 或 TLS。

这是依赖固定 Rust ABI 的实验适配。企业终端的代码完整性、动态代码限制、CFG/CET 配置及 EDR 可能阻止加载或插桩；本次没有验证所有终端策略组合，也不会为适配关闭这些系统保护。长期压力、内存压力、极端并发和持续 Hook 完整性检测尚待生产化验证。

源码名称、静态字符串命中和“Hook 已安装”都不是覆盖证明。实际允许样本以 Hook 内容哈希与源站正文哈希一致作证；拒绝样本检查源站收到的正文以及原始 TLS 捕获流的离线解密结果。

**WSS 只认证已验证的 `response.create` 消息与发送路径，不承诺完整 streaming 覆盖。**响应流可正常完成，不等于所有上行流式、分片和扩展路径都受保护。raw/multipart 上传、外部附件引用、其他 WSS 消息、任意子进程公网外发和全系统防绕过均未覆盖。参考引擎对已捕获 JSON 中的附件引用返回 `unknown` 并拒绝；这不能替代附件上传入口的保护。

目标 URL 提取尚未验证，当前请求契约中 `destination=null`。ETW 网络地址是独立行为证据，不能冒充请求级 URL。配置 `allowed_upstreams` 时，参考引擎对未知目标拒绝，不静默放行。

## 构建与使用

Native 工具链与 Frida 研究依赖分开安装。Windows Guard 不需要 Docker。

```powershell
uv sync --extra native-build --dev
uv run python scripts/build_guard_native.py
uv run ttrace guard baseline
```

构建产物在 `build/guard/`：`ttrace-guard.dll`、`etw.exe`、独立 C 示例 `policy_fixture.exe` 和构建哈希清单。MinHook v1.3.4 与 jsmn v1.1.0 的许可及固定源码校验和已随源码保存；构建先检查依赖完整性。

启动正式 CLI，继承现有账号、模型配置与 TLS：

```powershell
uv run ttrace guard codex --policy-file tests/fixtures/guard-policy.json -- exec --json --ephemeral "说明当前项目"
```

可用 `--codex C:\path\codex.exe` 指定已验证的 EXE。启动器使用该固定版本已验证的 `exec` 等待 stdin EOF 边界，先建立策略服务和 Native 就绪状态，再释放 EOF。启动失败时保持新 CLI 暂停，报告 PID，不释放未经保护的请求、不自动杀进程。此时需要操作者结束或处理该暂停进程；不能把失败状态当作保护成功。

附加到已运行 CLI：

```powershell
uv run ttrace guard attach --pid 12345 --policy-file tests/fixtures/guard-policy.json
```

指定 PID 必须是该固定版本的 `exec` 或 `--no-daemon` TUI；进程身份采用 PID＋创建时间。保护从 `protected_since_unix_ns` 开始，接管前和在途请求不受保证。控制器退出不会卸载 resident hooks；后续失去策略服务的已覆盖请求拒绝发送。

```powershell
uv run ttrace guard status runs/guard/<run-id>
```

`status` 明示是文件快照；`active_limited` 也只表示声明的局部入口。它不是持续完整性检测或抗 Hook 卸载能力。

默认策略动作是 `block_request`。会话错误会显示在 CLI；`exec` 自然以错误码 1 结束，不等于控制器执行了 terminate。TUI 中敏感 Prompt 仍在会话上下文里，继续输入普通文本可能仍命中；使用 `/new` 创建无关上下文后可以继续发送。`block_session` 则在该进程保护实例内持续拒绝，即使 `/new` 也不解除。只有配置 `deny_action=terminate_process` 才终止目标，实验退出码为 76；服务超时、未知内容或失联不会自动升级终止动作。

## 同步策略接口

Named Pipe 名为 `\\.\pipe\ttrace-guard-<PID>`；参考服务 DACL 只允许当前用户和 SYSTEM，拒绝远程管道客户端，并核验客户端真实 PID。当前实现不提供针对同用户恶意进程或管理员的完整抗绕过能力。

每次发送单独判定。Native 端等待最多 2000 ms；失联、超时、错误请求 ID、解析失败和畸形回复均通过已验证的错误路径拒绝。参考服务有四个独立 IPC 工作线程；ETW 来源关联不进入请求判定的等待链。检测结果必须到达后才调用原发送路径。

帧格式是 `u32 little-endian JSON字节长度 + UTF-8 JSON`，不是 pickle。正文限制 16 MiB；请求帧因 JSON 转义限制为 100 MiB，判定帧最多 8192 字节。每个连接处理一组请求/判定后关闭。Native 只接受单个 JSON 对象、六个唯一的字符串判定字段，拒绝多根 JSON、缺少分隔符和重复字段。

Schema：

- [GuardRequest](../schemas/guard-request-v1.schema.json)：请求 ID、保护实例、PID/TID、协议、目标、正文完整性、UTF-8 正文、QPC 时间与可选执行结果引用。
- [GuardDecision](../schemas/guard-decision-v1.schema.json)：`schema`、`request_id`、`decision`、`action`、`reason`、`policy_version`。
- [GuardPolicy](../schemas/guard-policy-v1.schema.json)：动作、凭据规则、marker、登记文件和已有 Gateway 兼容字段。

`allow/none` 才放行；`deny` 执行指定的已验证动作；`unknown` 按请求拒绝。控制帧 `native.initialize`、`native.ready`、`native.outcome` 没有模型正文。Native 通过独立命名事件证明 hooks 已就绪，外部引擎不需要输出特殊 Python 握手信息。

参考策略引擎只是一个实现，初步检查私钥、配置凭据、配对 AWS 凭据、marker 与登记文本片段。它不是通用源码/个人信息分类器，也不覆盖任意变换、编码或语义泄露。登记文件在加载策略时建立快照；命中快照本身不是读取证明。完整正文不保存到默认审计。

外部语言实现可通过 `--engine-command-file engine-argv.json` 接入，文件包含 argv JSON 数组，不经 shell；支持 `{pid}`、`{pipe}`、`{policy_file}` 占位符，也提供 `TTRACE_GUARD_PID`/`TTRACE_GUARD_PIPE` 环境变量。例如：

```json
["D:\\code\\transpect-trace\\build\\guard\\policy_fixture.exe", "{pid}", "FAKE_SECRET_ONLY", "block_request"]
```

C 示例仅实现 ASCII marker 实验规则，不是生产策略服务。外部引擎应负责契约校验、同步判定和脱敏审计；控制器只保存白名单中的 JSON 元数据字段，丢弃任意 stdout 记录和 stderr，避免把原始正文复制进审计。

## ETW 与 Evidence Confidence

`etw.exe` 使用 Windows Process/File/Network manifest providers 和 TDH，输出已声明的进程、文件与网络元数据；不输出命令行或任意事件正文。Python 适配层将事件归入目标 PID 及后代，再写入证据。网络事件不提供 Prompt，文件访问事件也不证明读取成功或字节流向。

派生来源记录保留候选路径、方法、事件 ID、证据缺口及下列等级：

| 等级 | 含义 |
|---|---|
| High | 登记内容匹配，且有可靠进程链和对应文件访问支持 |
| Medium | 有可靠进程/文件证据，但无内容匹配、多个来源无法区分，或丢事件/快照可能变化 |
| Low | 主要是时间/路径候选，进程身份不完整 |
| Unknown | 证据不足或无法建立来源关联 |

High 仍不是唯一来源证明或字节级因果证明。读取时间晚于请求的证据不能支持该次来源；PID 重用不能加入旧运行实例；候选重复不强行择一。事件丢失、缓冲区丢失和解码缺口降低关联等级，不更改原始事件事实。

当前执行账户启动 ETW 返回 `ERROR_ACCESS_DENIED (5)`。自动集成明确记录 `etw.state=unavailable`，来源保持 Unknown，内容门控继续工作。已完成编译、事件归一化/范围过滤/置信度测试；**尚未完成具备 ETW 权限的真实 Windows 采集验收，M4 不宣称通过。**可以在具备相应权限的终端复现：

```powershell
uv run ttrace guard etw --pid 12345 --output runs/guard-etw/events.jsonl
```

来源关系在结束时从内容审计与系统事件异步补全到 `source-relations.jsonl`；已确认敏感内容无需等待来源关联才能拒绝。仅观察到文件访问不自动判定泄露。

## 复现与验收证据

以下脚本仅用独立配置、假数据和不转发流量的本地 TLS 测试源站。测试 CA 只作用于子进程；不安装系统 CA，不修改真实账号。测试源站导出的会话密钥用于离线判据，不能被解释为客户端密钥提取或生产 TLS 破解。

```powershell
uv sync --extra native-build --extra guard-probe --dev
uv run python scripts/discover_codex_hooks.py
uv run python scripts/probe_codex_hook.py --help
uv run python scripts/probe_guard_native.py --launcher
uv run python scripts/probe_guard_native.py --launcher --action block_request
uv run python scripts/probe_guard_native.py --action block_request --scenario tool_read
uv run python scripts/probe_guard_native.py --action block_request --fault timeout
uv run python scripts/probe_guard_native.py --action block_request --fault disconnect
uv run python scripts/probe_guard_native.py --action block_request --fault stale_reply
uv run python scripts/probe_guard_native.py --action block_request --fault malformed_reply
uv run python scripts/probe_guard_native.py --engine c --action block_request
uv run python scripts/probe_guard_native.py --action terminate_process
uv run python scripts/probe_guard_native.py --copy-baseline --launcher --action block_request
uv run python scripts/probe_guard_tui.py --transport wss --controller
uv run python scripts/probe_guard_tui.py --transport http --action block_session --controller
uv run ttrace guard validate runs/guard-native/<run-id> --output runs/guard-native/<run-id>/capabilities.json
uv run pytest
```

Native fixture 超时后的合成进程清理被单独标记，不能用于证明安全拒绝；正常请求阻断验收要求没有清理终止。TUI fixture 在完成存活与后续请求观察后显式关闭合成测试进程，这与门控动作分开记录。原始正文、终端屏幕和测试密钥只保存在这些明确的假数据实验目录；不属于默认真实运行审计。

本次结果索引见 [验收报告](codex-guard-validation-2026-10-14.md)。报告按协议分开认证观察、门控、错误路径和 Native 迁移，局部成功不会自动扩展为完整 WSS、附件或全系统保护。
