# Codex 桌面端固定版本适配器

桌面端由 MSIX `ChatGPT.exe` 启动单独的 `codex.exe app-server`。现有 CLI Guard 的已验证地址和错误返回布局不能直接用于桌面端。桌面适配器将 MSIX、桌面主进程、后端和每条发送路径分别固定；静态发现结果只生成 `candidate_unvalidated`，不能构建或启用门控。

本轮归档的官方 x64 包版本为 `26.1029.7803.0`，MSIX SHA-256 为 `19487892b7e27c74e75c6422088e91b35b4291ed485045f82a1984a13b22d128`。清单同时固定 `app/ChatGPT.exe` 的 SHA-256 `74dcbc67421c5d5406ea5e4cc80d9c8d8a05d0df62f1d7be5690f090f182e71f`、`app/resources/codex.exe` 的 SHA-256 `925c7d0665ffa49b0dcf748e034a805a04da984164ac92301432073b47789b99`，以及后端版本 `codex-cli 0.166.0-alpha.6`。发现程序要求 Windows 验签为 `Valid`、签名证书主题与包清单 Publisher 都为 `CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B`，证书 SHA-1 指纹为 `B0429F3569607833179400E29D6D641B363CA6A4`。证书或二进制换版都需要重新审查适配器。

## 在独立 Windows 虚拟机中生成候选

先保存官方签名的 x64 MSIX 与该安装启动的后端二进制，取得 `Get-AppxPackage OpenAI.Codex` 的 `PackageFullName`。以下命令分析归档二进制、运行该后端的 `--version` 并写候选清单，不接触桌面应用的运行进程：

```powershell
uv run --no-sync python scripts/discover_desktop_guard.py `
  --msix C:\demo\archive\ChatGPT.msix `
  --package-full-name OpenAI.Codex_<version>_x64__<publisher-id> `
  --backend C:\demo\archive\codex.exe `
  --output C:\demo\adapter\desktop-candidate.json
```

工具先检查 MSIX 签名与包身份，再记录包、桌面可执行文件和后端的 SHA-256，并用 PE 字符串锚点寻找 HTTP/WSS **候选** RVA。它不会推断桌面附件上传函数或假定桌面请求经过 CLI 的旧 Hook。

对该归档后端的离线静态扫描找到 HTTP body 候选 RVA `0xb117de0`、WSS serialization 候选 RVA `0x41e3330`。这只能说明二进制中存在相似函数，不能说明桌面界面提交的实际请求经过这些地址。

虚拟机内的研究探测步骤见[发送路径动态探测](development/desktop-path-trace.md)。探测报告只记录候选命中、合成标记缓冲区哈希和附件读写调用栈；不自动将候选适配器提升为 `validated`。

## 附件原始字节的本地判定协议

`DesktopUploadPipe` 提供固定进程专用的本地命名管道 `\\.\pipe\ttrace-desktop-upload-<pid>`。管道 ACL 只允许控制器、系统和指定的桌面账户；连接后再次核对客户端 PID、进程创建时间、用户 SID、进程镜像哈希及其桌面父进程。请求为 4 字节小端头长度、最多 8192 字节的 UTF-8 JSON 头、随后是 `body_bytes` 指定的**原始二进制字节**。`upload.bytes` 最多 16 MiB，头部声明 SHA-256；服务读取全部字节并复算哈希后，调用 `DesktopDLPBridge.evaluate_attachment()` 加密归档和四层识别。只有 `ALLOW` 才回传批准 ID；`REVIEW`、`BLOCK`、归档或解析失败一律回传拒绝。

`upload.reference` 只把返回的文件 ID 与已批准快照的批准 ID、文件名和原始 SHA-256 绑定。`upload.ready` 是连接握手，不能单独证明 Hook 安装；实时就绪检查还要求固定上传 DLL 确实载入指定进程。每次请求的读取、判定、审计及回包共用 5 秒截止时间；管道使用可取消的 overlapped I/O，回复由原生调用方完整读取并以单字节 `0x06` 确认。原生调用方必须自己执行相同的截止时间，并在超时、断连、格式错误或拒绝时停止发送。服务端未完成审计落盘前不发出允许。

当前只有这个判定协议和本机回环测试，**没有**能够从该固定 Electron 版本发送点调用它的原生上传 Hook，也没有证明上传文件 ID 来自已门控的响应。因此 `attachment.upload` 仍为未覆盖，不能以管道测试代替真实桌面上传的零字节证明。

## 动态验证和启用条件

在该虚拟机中，逐项验证 `model.http`、`model.wss`、`attachment.upload` 的实际调用路径、原始字节完整性、函数参数与拒绝后的返回布局。每项需要保存可复核的动态证据，并用不转发的受控源站确认拒绝时正文到达字节数为零。只有在确认 HTTP 的 owned-headers 清理地址、两个模型 Hook 的 ABI，以及附件上传进程与发送前 Hook 后，才可将清单标为 `validated` 并填入各路径证据摘要。当前仓库**没有**完成这些桌面动态验证，也没有桌面附件上传 Hook 实现。

| 外发路径 | 已有代码 | 必需的独立实测 | 当前可否放行 |
| --- | --- | --- | --- |
| `codex.exe app-server` HTTP 模型请求 | CLI 的 EncodedJsonBody Hook 可按固定二进制重新编译；桌面端仅有静态候选 RVA | 桌面 UI 请求确实到达该函数、正文与发送字节一致、拒绝后源站零正文、HTTP 错误及清理布局正确 | 否 |
| `codex.exe app-server` WSS 模型消息 | CLI 的 `response.create` 序列化 Hook 可按固定二进制重新编译；其他消息和流式路径未覆盖 | 枚举所有携带输入的 WSS 消息与重试路径；逐条证明拦截发生在帧发送之前，拒绝后源站零正文 | 否 |
| 桌面界面添加文件 | 只有 `DesktopDLPBridge.evaluate_attachment()` 判定接口，没有 Electron 上传 Hook | 确定实际上传进程及原始字节形成位置；证明文件读取、multipart/流式上传和 `file_id` 返回均受同一发送前门控约束，检查字节与发送字节相同 | 否 |
| 模型正文里的内联文件或 `file_id` | 桥接层能检查内联字节；引用只接受已批准快照 | 用真实桌面附件流程证明引用与预检文件一一绑定；未知引用拒绝 | 尚不能作为独立附件上传保护 |
| Agent 子进程直连 | WFP 专用 SID 默认拒绝组件已实现 | 在虚拟机测试 TCP/UDP、IPv4/IPv6、子进程与控制器退出时的实际到达字节 | 仅在 VM 规则实测后 |

**开放网络许可的全部条件：** 固定 MSIX 与后端哈希匹配；专用低权限账户的 WFP 出站和入站默认拒绝已先于桌面端启动；模型 HTTP/WSS 及附件三条路径都持有该固定版本的动态证据；模型 DLL、桌面附件 Hook 和本地判定服务均实时就绪；只对已确认的进程和字面 IP/端口发放短时许可。任一项失败即保持默认拒绝；新增的 WSS 类型、文件流或重试路径在验证前同样拒绝。

**目的地校验缺口：** 当前模型 Hook 发给本地判定服务的 `destination` 固定为 `null`。HTTP 的 `request` 参数与 WSS 连接对象尚未验证可安全读取主机名，因此不能在 C 代码中猜测结构偏移来声称“只 Hook 模型域名”。WFP 目前只能把网络许可缩小到固定进程和字面 IP/端口；它不能分辨同一 TLS 目的地上的其他请求正文。虚拟机动态验证必须证明所有被许可的内容发送路径都经过对应 Hook，或者保持该进程离线。只有取得经验证的请求/连接布局后，才能在 GuardRequest 中提供可核对的目的地字段。

**WFP 进程匹配缺口：** 当前许可过滤器使用 APP_ID（镜像路径）与用户 SID、字面 IP 和端口，Windows 过滤器本身未精确绑定 PID。控制器在每次许可前枚举并拒绝同路径、同 SID 的第二个后端进程；这是时点检查，不能排除检查后新进程出现。该许可的持续时间内仍需虚拟机监测和零字节实测，不能把 PID 启动校验表述为 PID 级网络隔离。桌面账户和工具账户的 IPv4/IPv6 入站、出站默认拒绝也必须持续存在。

控制器在许可期间以 200 ms 间隔启动看门狗，复核模型判定服务、附件门控、进程创建时间与镜像哈希、同镜像同 SID 进程以及 WFP 默认拒绝状态；检查失败即关闭已登记的短期许可。上传管道检测到错误时还会直接通知控制器撤销许可。WFP 许可子进程另外监测控制器退出。看门狗属于运行期补救，检查与撤销存在时间窗；只有真实虚拟机测试能量化这一时间窗及源站到达字节。

`build_guard_native.py --adapter <validated.json>` 会拒绝候选清单。构建产物写入适配器哈希与目标后端哈希；桌面控制器在注入前还会核对 DLL 构建清单、MSIX 进程父子关系、用户 SID、PE Hook 入口字节、WFP 默认拒绝规则以及附件门控的实时就绪状态。任一条件缺失时，不开放桌面网络许可。

模型 Guard 的 `ready` 事件可能在 DLL 卸载后仍留在内核中；控制器因此在发放许可前及许可期间复核目标进程的模块列表，要求固定路径的模型 DLL 仍已加载且文件 SHA-256 与构建清单一致。模块在场仍不能代替 HTTP/WSS 路径和拒绝时序的动态实测。

这些检查仅为固定构建 Demo 的启动条件；换版必须重新发现并动态验证，不能把 CLI 的既有测试结果作为桌面端证据。
