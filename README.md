# Transpect Trace

面向 Windows 官方 Codex CLI 的数据安全项目，提供用户请求内容检测、系统行为追踪、LLM 请求阻断和网络出口控制。

## 原理与架构

系统由四个模块组成：

- **Native Guard：** 在 Codex HTTP/WSS 请求发送前获取 Prompt、上下文和工具结果，调用本地策略引擎检测敏感内容，并按策略允许或拒绝发送。
- **eCapture：** 采集受支持 TLS 路径的通信明文，重组网络请求，提取 Prompt、上下文和工具结果。
- **ETW：** 采集进程启动/退出、文件访问和网络活动，关联 Codex 及其后代进程，形成工具执行与数据来源的行为链。
- **WFP：** 根据已配置的网络过滤规则控制工具进程的网络连接，支持连接阻断与撤销规则后的恢复。

工具后代另可启用 Native TCP 连接门控，按目标 IP 和端口执行策略；WFP 保留独立验证入口。

```text
官方 Codex CLI
   ├─ Native Guard → 请求内容 → 本地策略引擎 → 允许 / 发送前拒绝
   ├─ Tool Calling → Shell / 工具进程 → 文件访问与网络活动
   │                                   └─ Native 连接门控 / WFP → 网络过滤
   ├─ eCapture → TLS 明文观察 → 协议重组与请求语义提取
   └─ ETW → 进程 / 文件 / 网络事件 → 行为链与来源关联
```

采用运行时插桩，保留官方客户端磁盘文件和原有 TLS 连接，不使用网络代理。

## 快速开始

准备 Windows x64、Git、uv（[安装说明](https://docs.astral.sh/uv/getting-started/installation/)，CI 使用 `0.12.18`）和 Python 3.12 x64。以下命令在 PowerShell 中执行；首次运行 Guard 使用普通终端即可，不必将 Codex 作为管理员运行。

客户端须自行准备，仓库不包含官方二进制。当前适配 `codex-cli 0.162.0-alpha.17.2 Windows x64`，必须使用原生 `codex.exe`，不能传入 npm 的 `codex.cmd`、`.ps1` 等启动脚本。同版本也需通过文件哈希校验，基线见 [客户端配置](deploy/guard/codex-windows-x64.json)。

```powershell
git clone --branch release https://github.com/qwerzbn/Transpect-trace.git
cd Transpect-trace

# 已有 Python 3.12 可跳过此行。
uv python install 3.12
uv sync --locked --dev --extra observe --extra native-build --extra tui

# 先构建最小请求门控；此步骤不需要 Go 或 eCapture。
uv run --no-sync python scripts/build_native.py --component guard
```

Python 依赖通过 `pyproject.toml` 与 `uv.lock` 管理，Native 编译器由锁定的 `ziglang` 依赖提供，构建产物保存在 `build/`。无需手动激活虚拟环境，后续均通过 `uv run --no-sync` 执行。

先用相同 Windows 用户确认 Codex 可以独立完成请求，并已配置登录账号、模型或模型服务。启动器沿用现有 Codex 配置和 `CODEX_HOME`，自动创建本地策略服务，无需另起代理或策略进程。

```powershell
# 替换为实际存在的原生 EXE 和项目目录；项目应为可供 Codex 使用的 Git 工作目录。
$codexExe = 'C:/baselines/codex.exe'
$projectDir = 'D:/work/my-project'
$policyFile = (Resolve-Path 'tests/fixtures/guard-policy.json').Path

# 输出 supported=true 才继续；不匹配时请更换正确客户端，不要修改基线校验。
uv run --no-sync ttrace guard baseline --codex $codexExe
if ($LASTEXITCODE -ne 0) { throw 'Codex 客户端基线不匹配' }

# 第一次先验证普通请求和响应。
uv run --no-sync ttrace guard codex --codex $codexExe --policy-file $policyFile -- exec --cd $projectDir '只回复 OK，不读取文件，不执行命令'

# 受控交互会话：Native 就绪后才开放用户输入。
uv run --no-sync ttrace guard codex --codex $codexExe --policy-file $policyFile -- --no-daemon --cd $projectDir
```

保持 PowerShell 位于本仓库根目录，用 Codex 的 `--cd` 指向业务项目。这样不会因切换目录而找不到 uv 项目、策略或 DLL；`--` 后的参数交给 Codex。

## 策略配置

默认使用 [Guard 策略示例](tests/fixtures/guard-policy.json)。可复制到已忽略的 `runs/local-config/guard-policy.json`，修改后将 `$policyFile` 指向副本，避免把本地企业配置提交到 Git。

| 配置 | 用途 |
| --- | --- |
| `credential_rules` | 启用凭据、私钥等内容规则，示例默认开启。 |
| `pii_rules` | 个人信息规则，默认关闭；需要时在 JSON 中增加 `"pii_rules": true`。 |
| `registered_files` | 登记需要保护的 UTF-8 源码或文档；示例为空，不会自动将任意源码判为机密。相对路径基于**策略文件所在目录**。 |
| `deny_action` | 默认 `block_request`；另支持 `block_session` 和显式 `terminate_process`。 |

## 可选模块

按需要构建；基础 Guard 不依赖下面三个 Native 组件。

```powershell
uv run --no-sync python scripts/build_native.py --component observe
uv run --no-sync python scripts/build_native.py --component behavior
uv run --no-sync python scripts/build_native.py --component egress

# 对 Codex 后代进程启用明确目标的 TCP 连接策略。
uv run --no-sync ttrace guard codex --codex $codexExe --policy-file $policyFile --egress-policy-file deploy/behavior/native-egress-policy.example.json -- exec --cd $projectDir '请分析当前项目结构'
```

[出口策略示例](deploy/behavior/native-egress-policy.example.json) 仅拒绝回环地址的 TCP 端口 `1`。实际使用时按目标 IP、端口修改副本；启用该参数不会自动封禁全部公网，也不会自动安装 WFP 规则。

eCapture 增强版额外需要 Go（已验证 `1.25.12`）和固定上游源码，Go 不由 uv 安装：

```powershell
git clone https://github.com/gojue/ecapture-windows .external/ecapture-windows
git -C .external/ecapture-windows checkout --detach 7fb8347b7a3c28d2a094e35af38b1c471d194ebf

# 替换为本机 go.exe 的实际路径；保留上游源码为干净状态。
$goExe = 'C:/tools/go/bin/go.exe'
uv run --no-sync python scripts/build_native.py --component ecapture --ecapture-variant enhanced --source .external/ecapture-windows --go $goExe
```

增强版位于 `build/observe/ecapture-enhanced/`。直接使用 `ttrace observe run` 时，应通过 `--ecapture build/observe/ecapture-enhanced/ecapture.exe` 显式选择它。

## 受控验证

以下实验使用假数据和不转发流量的本地源站，不需要真实模型服务。先完成对应模块构建；每轮重新生成 `$runTag`，避免覆盖已有证据。带 `--elevate` 的命令会请求 Windows UAC，仅提升采集或过滤 worker。

```powershell
$runTag = Get-Date -Format 'yyyyMMdd-HHmmss'

# Codex HTTP/WSS 请求允许、拒绝与故障处理。
uv run --no-sync python scripts/probe_codex_guard_regression.py --codex $codexExe --output "runs/check-$runTag/guard"

# Codex 请求层的 Prompt / Context / Tool Call / Tool Result 提取，无需 eCapture 或提权。
uv run --no-sync python scripts/probe_request_semantics.py --only codex --codex $codexExe --output "runs/check-$runTag/codex-semantics"

# 增强 eCapture 的受控 Schannel 明文采集；此结果不等于 Codex TLS 路径认证。
uv run --no-sync python scripts/probe_request_semantics.py --only schannel --output "runs/check-$runTag/schannel" --elevate

# 合成工具的 ETW/WFP 阻断与恢复，规则范围为指定程序路径、IPv4 回环 TCP。
uv run --no-sync python scripts/probe_codex_child_egress.py --codex $codexExe --native-dir build/behavior --output "runs/check-$runTag/egress" --elevate
```

## 运行结果与排障

Guard 记录保存在 `runs/guard/<运行ID>/`：`status.json` 为状态，`audit.jsonl` 为策略及执行审计，`capture/` 为请求层采集摘要。默认不保存完整 Prompt；状态文件是快照，不等于实时 Native 认证。

```powershell
# 查看最近一次 Guard 运行；首次运行完成后再执行。
$runDir = (Get-ChildItem runs/guard -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
uv run --no-sync ttrace guard status $runDir
uv run --no-sync ttrace guard validate $runDir
```

- **基线不匹配：**核对原生 EXE、版本和 SHA-256；不要使用 PATH 中的 npm 启动脚本代替。
- **找不到 DLL：**在仓库根目录构建相应组件；自定义产物目录时显式传 `--dll`、`--egress-dll` 或 `--ecapture`。
- **ETW/eCapture 权限不足：**采集会显示 `unavailable`，不等同于 Native Guard 失败；用对应实采探针的 `--elevate` 提升 worker。
- **提示 `held suspended`：**启动失败的目标 PID 被保留挂起。核实该次任务后手动结束该进程，修正策略或构建问题再重试。

## 测试

```powershell
uv lock --check
uv pip check
uv run --no-sync pytest
```

其他参数可通过 `uv run --no-sync ttrace --help` 及各模块的 `--help` 查看。
