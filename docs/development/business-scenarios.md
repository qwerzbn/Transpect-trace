# 多应用业务场景开发与复现

本模块在 `codex/development` 上增加两条真实工具链路和一个浏览器可行性入口。工单、模型服务、Webhook 和 Git 接收端均为不转发流量的本地测试服务；只使用假数据。

| 场景 | 链路 | 验收对象 |
| --- | --- | --- |
| 6 | 工单导出 → 官方 Codex → PowerShell → HTTPS Webhook | 实际工具、文件读取、正文采集、检测与源站接收 |
| 1 | 工单导出 → 官方 Codex → Python → Git → HTTPS bare 仓库 | 文件版本、提交及接收对象、TLS 正文与接收回执 |
| 9 | 假附件 → 隔离 Chrome → 受控页面 → HTTPS 接收端 | eCapture 探测与浏览器请求层观察，分别认证 |

新业务关联与浏览器组件均为 `can_enforce=false`。不会把观察结果传入既有 Guard 作为新的阻断判定，也不据此认证真实 SaaS、任意浏览器上传或唯一数据来源。

本轮执行代码、组件和准备阶段检查，未启动 Chrome 人工加载扩展、未重跑 Chrome eCapture、未触发实采 UAC。下面的人工浏览器操作和提权业务命令是后续复现步骤，不代表本轮已通过这些实采场景。

本轮测试结果、独立能力矩阵和已知限制见 [组件验证记录](../validation/2026-10-25-business-components.md)。

2026-10-26 已通过“独立导出程序 → 普通文件 → Codex → LLM 内容阻断”的实际正负例，见 [跨应用内容阻断验收](../validation/2026-10-26-cross-app-control.md)。PowerShell HTTPS Webhook 的完整验收仍未通过，两者分别报告。

## 业务传递与实验管道的区别

Named Pipe 是 Windows 的真实 IPC 机制，自建管道适合验证消息边界、端点身份和内容采集，但只能认证该实验使用的同步、本地、单向消息模式。真实应用可能使用异步 I/O、RPC、匿名管道、共享内存或中间文件，应用自己的管道也可能已有多客户端及重连行为。现有受控管道结果不能直接推广到这些路径。

业务接入应观察应用原有的传递方式，不要求应用改用测试管道。当前 Webhook 场景采用独立导出程序正常写 `incident.json`，Codex 调用 PowerShell 正常读取、转换并通过 `Invoke-RestMethod` 上传；业务数据按文件与 HTTPS 的原路径传递。采集组件自身使用的受限审计管道只传观察快照和控制消息，与业务交接通道分开。

因此，管道实验保留为采集器协议测试，真实应用验收另行核对其实际文件或 IPC、进程身份和最终外发正文。没有采到中间内容时，报告保留候选关系，不把同一任务或时间邻近当作数据已经传递的证明。

## 环境与公共入口

在仓库根目录运行，使用 Python 3.12 x64 和已锁定 uv 环境：

```powershell
uv sync --locked --dev --extra observe --extra native-build
uv run --no-sync python scripts/build_native.py --component flow
uv run --no-sync python scripts/build_native.py --component behavior
uv run --no-sync python scripts/build_native.py --component guard

uv run --no-sync ttrace flow scenarios --help
uv run --no-sync ttrace flow scenarios run --manifest runs/business/experiment.json
uv run --no-sync ttrace flow scenarios status runs/business/audit
uv run --no-sync ttrace flow scenarios report runs/business/audit
```

示例中的 `experiment.json` 必须是实际冻结后的实验清单；不要直接创建空文件运行。清单锁定参与程序、采集器及证书文件哈希，并要求输出目录尚不存在。官方 Codex 固定为原 `0.162.0-alpha.17.2` 基线。PowerShell 执行策略、浏览器沙箱和证书校验保持启用。

ETW 与 eCapture 需要提升权限。localhost 测试证书应先由受控环境建立信任，源站私钥只保存在本地忽略目录。准备、编译或探针进程启动成功均不代表采集验收通过。

业务报告分别展示系统行为、内容检测、传播关联和源站接收；`fixture_truth` 单独标识测试程序自报的阶段与结果。Git 传输正文哈希和仓库 blob 哈希是不同层次，不能混用。服务器接收到 pack 数据和 ref 更新成功也分别记录。

## Webhook 与 Git 受控实验

两条场景由固定实验清单选择，不接受任意 shell 命令作为清单内容。Webhook 包含原文、嵌套 JSON、摘录、普通统计和重试；Git 包含敏感提交、普通提交、未跟踪文件、旧提交、删除前历史、ref 拒绝和重复推送。

批量探针可以先冻结依赖和生成清单，准备模式不导入测试信任、不启动客户端和采集器：

```powershell
$runTag = Get-Date -Format 'yyyyMMdd-HHmmss'
$codexExe = 'C:/baselines/codex.exe'
uv run --no-sync python scripts/probe_business_scenarios.py --output "runs/business-scenarios/$runTag-prepared" --codex $codexExe --fake-data-only --prepare-only --prepare-test-trust --case webhook:plain --case git:deleted_history --repeat 1
```

首次实际采集使用另外的新目录，明确请求 UAC。这里的提升适用于整个假数据实验，包括 fixture 客户端后代，与正常 Codex 使用普通权限的建议分开：

```powershell
# 后续人工实采步骤；本轮未执行。默认所有用例各3次，Git默认与Schannel分别测试。
uv run --no-sync python scripts/probe_business_scenarios.py --output "runs/business-scenarios/$runTag-live" --codex $codexExe --fake-data-only --prepare-test-trust --elevate
```

默认 Native Flow 路径为 `build/flow-linkage`，增强 eCapture 路径为 `build/flow-ecapture-v2`。新机器根据实际构建位置传入 `--native-dir`、`--ecapture-dir`；参数详情见 `scripts/probe_business_scenarios.py --help`。实采结果保存在新目录，保留失败轮次。生成的单用例清单也可以用 `flow scenarios run/status/report` 独立复现。

完成要求是实际客户端执行、采集器 ready/terminal、无缺失正文、源站哈希及次数核对全部满足。仅有 Python/PowerShell 自行提供的发送快照时，完整场景仍未通过。对于 Git 默认 TLS 后端和显式 Schannel 设置，应分别建立报告；设置项和模块装载不能替代实际调用证据。

## 浏览器准备与手动加载

浏览器组件只观察显式登记 localhost origin 的 `/upload`、`/chat` 两个路由。使用官方 Chrome 隔离用户目录，手动加载 MV3 扩展；不使用 `--load-extension`、CDP、关闭沙箱或忽略证书错误的参数。

先启动受控 HTTPS 页面，以下证书路径应替换为已建立测试信任的 localhost 证书：

```powershell
$runTag = Get-Date -Format 'yyyyMMdd-HHmmss'
$browserRun = "runs/browser-business/$runTag"
$sourceRun = "runs/browser-source/$runTag"
$chromeExe = 'C:/Program Files/Google/Chrome/Application/chrome.exe'

# 在独立终端保持运行。端口应选未占用的回环端口。
uv run --no-sync python scripts/probe_browser_business.py serve --output $sourceRun --certificate runs/test-trust/localhost.pem --private-key runs/test-trust/localhost.key --port 19443 --seconds 600
```

源站提供 `/` 受控页面和 `/attachment.txt` 假附件，接收 POST/PUT 正文只保存哈希、长度、独立回执 ID。没有代理或转发功能。另一终端准备扩展：

```powershell
uv run --no-sync python scripts/probe_browser_business.py prepare --output $browserRun --origin https://localhost:19443 --chrome $chromeExe --install-host
$prepared = Get-Content "$browserRun/experiment.json" -Raw | ConvertFrom-Json
& $chromeExe "--user-data-dir=$($prepared.profile_directory)" --no-first-run --no-default-browser-check chrome://extensions/
```

在这个隔离 Chrome 的扩展页开启开发者模式，选择“加载已解压的扩展程序”，加载 `experiment.json` 指向的 `extension_directory`。固定扩展 ID 为 `mdgfhbilljhgcgklilfdnildpgdlpkeg`。确认扩展图标显示 `OBS` 后，在同一隔离浏览器中打开 `https://localhost:19443/`，人工提交假数据；可选择普通文本、中文假事件、70 KiB、1 MiB 和未支持的文件类型测试。

扩展 Native Messaging 主机使用每次实验的独立名称，注册到 HKCU，允许来源只有固定扩展 ID；已有注册项不会被覆盖。私有实验目录保存本地登记令牌与固定程序路径，不应提交 Git。原生 launcher 从源代码编译到实验目录，用固定 Python 解释器启动本地检测服务；消息帧长度、请求体、队列和请求数量均有上限。

准备过程固定源码和程序哈希。之后若修改模块或扩展源代码，应新建实验目录重新准备，不修改旧目录来绕过校验。

## 浏览器采集与结果核对

每次请求分开记录 request ID 摘要、阶段序号、tab/frame/document 身份；相同正文不去重。标签页身份不是网络进程 PID。默认报告的 `network_process` 为 null，只有独立采集到的进程与连接事实另行展示。

如需 eCapture 探测，先使用隔离 Chrome 根 PID 发现后代进程，再选择实际发现的 Network Service PID。根进程必须同时匹配固定 Chrome 哈希与隔离 profile 参数：

```powershell
# PID 必须来自本次隔离 Chrome，不使用日常浏览器 PID。
uv run --no-sync python scripts/probe_browser_business.py discover --output $browserRun --browser-pid 1234
uv run --no-sync python scripts/probe_browser_business.py ecapture --output $browserRun --browser-pid 1234 --network-pid 5678 --ecapture build/observe/ecapture-enhanced/ecapture.exe --seconds 30 --elevate-ecapture
```

等待 `ecapture-probe/ready.json` 后，在观察时段提交页面请求。模块列表只是 TLS 后端线索；零事件仍可能是未覆盖入口、采集失败或没有请求，不直接判为 BoringSSL 或不支持。eCapture 结果单独位于 `ecapture-probe/report.json`，浏览器扩展结果不计入 eCapture 成功率。

完成测试后，从扩展弹窗选择“Finish observation”，等待 `STOP`，然后生成报告并清理本次主机注册：

```powershell
uv run --no-sync python scripts/probe_browser_business.py status --output $browserRun
uv run --no-sync python scripts/probe_browser_business.py report --output $browserRun --receipts "$sourceRun/receipts.json"
uv run --no-sync python scripts/probe_browser_business.py uninstall-host --output $browserRun
```

清理只删除登记值与所有权记录一致的本次 HKCU 条目，实验文件和浏览器 profile 保留。窗口关闭或组件断开但缺少 terminal 时，报告保持 partial。先正常结束采集，再关闭隔离 Chrome；不要清理日常浏览器进程或目录。

首版浏览器接口仅接受可完整取得的 UTF-8 文本／JSON POST/PUT 请求层快照，真实 Chrome 认证仍待人工验收。`raw.file` 只作为未检查的文件引用；formData、未知编码、超限和缺段保持不完整。浏览器 API 本身不能证明 JavaScript 正文源是 String、Blob 还是其他构造，也不证明实际 TLS 发送、底层每次网络尝试或服务端接收。

正文与源站按哈希、长度、次数相符时只得到内容多重集合一致性；如果存在相同正文并发，仍不认定唯一请求映射。真实 ChatGPT、其他站点、完整附件、WSS 消息、WebTransport 与发送前拒绝不在本轮浏览器认证范围。

## 工程检查

```powershell
uv lock --check
uv pip check
uv run --no-sync pytest
uv run --no-sync python scripts/generate_schemas.py --check
uv run --no-sync python scripts/check_repository.py
uv run --no-sync python scripts/audit_release.py --working-tree
git diff --check
```

Node 用于浏览器请求提取与事件顺序的离线 JavaScript 测试；没有 Node 时该部分显式跳过。离线 JS、Python 测试、HTTPS 接收端测试及 Native Messaging 主机组件测试均不能替代官方 Chrome 人工实采认证。
