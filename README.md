# Transpect Trace

面向 Windows 官方 Codex CLI 的数据安全项目，提供用户请求内容检测、系统行为追踪、LLM 请求阻断和网络出口控制。

## 原理与架构

系统由四个模块组成：

- **Native Guard：** 在 Codex HTTP/WSS 请求发送前获取 Prompt、上下文和工具结果，调用本地策略引擎检测敏感内容，并按策略允许或拒绝发送。
- **eCapture：** 采集受支持 TLS 路径的通信明文，重组网络请求，提取 Prompt、上下文和工具结果。
- **ETW：** 采集进程启动/退出、文件访问和网络活动，关联 Codex 及其后代进程，形成工具执行与数据来源的行为链。
- **WFP：** 根据已配置的网络过滤规则控制工具进程的网络连接，支持连接阻断与撤销规则后的恢复。

```text
官方 Codex CLI
   ├─ Native Guard → 请求内容 → 本地策略引擎 → 允许 / 发送前拒绝
   ├─ Tool Calling → Shell / 工具进程 → 文件访问与网络活动
   │                                   └─ WFP → 网络过滤
   ├─ eCapture → TLS 明文观察 → 协议重组与请求语义提取
   └─ ETW → 进程 / 文件 / 网络事件 → 行为链与来源关联
```

采用运行时插桩，保留官方客户端磁盘文件和原有 TLS 连接，不使用网络代理。

## 安装与构建

环境：Windows x64、Python 3.12、Git、uv。当前客户端基线为 `codex-cli 0.162.0-alpha.17.2 Windows x64`。

```powershell
git clone --branch release https://github.com/qwerzbn/Transpect-trace.git
cd Transpect-trace

uv sync --locked --dev --extra observe --extra native-build
uv run --no-sync python scripts/build_native.py --component guard
uv run --no-sync python scripts/build_native.py --component observe
uv run --no-sync python scripts/build_native.py --component behavior
```

依赖通过 `pyproject.toml` 与 `uv.lock` 管理，Native 构建产物保存在 `build/`。

eCapture 另需 Go 1.25.12 和固定上游源码：

```powershell
git clone https://github.com/gojue/ecapture-windows .external/ecapture-windows
git -C .external/ecapture-windows checkout --detach 7fb8347b7a3c28d2a094e35af38b1c471d194ebf

# 将路径替换为本机 go.exe 的实际位置。
uv run --no-sync python scripts/build_native.py --component ecapture --ecapture-variant enhanced --source .external/ecapture-windows --go C:/tools/go/bin/go.exe
```

## 运行

准备已登录并完成模型配置的官方 Codex CLI，将下面的路径替换为实际客户端路径。

```powershell
$codexExe = 'C:/baselines/codex.exe'

# 校验客户端基线。
uv run --no-sync ttrace guard baseline --codex $codexExe

# 启动 Codex 任务，进行请求检测与发送前门控。
uv run --no-sync ttrace guard codex --codex $codexExe --policy-file tests/fixtures/guard-policy.json -- exec "请分析当前项目结构"

# 查看各模块命令。
uv run --no-sync ttrace --help
uv run --no-sync ttrace observe --help
uv run --no-sync ttrace behavior --help
```

策略示例位于 `tests/fixtures/guard-policy.json`，可配置凭据检测、登记内容和拒绝动作。运行记录保存在 `runs/`。

以下命令使用假数据和本地测试源站运行四模块受控验证。每次使用新的输出目录；`--elevate` 会触发 UAC，以取得采集和网络过滤所需权限。

```powershell
# Codex HTTP/WSS 请求允许、拒绝与故障处理。
uv run --no-sync python scripts/probe_codex_guard_regression.py --codex $codexExe --output runs/codex-guard

# eCapture 明文采集及 Codex 请求语义提取。
uv run --no-sync python scripts/probe_request_semantics.py --codex $codexExe --output runs/request-semantics --elevate

# Codex 工具进程的 ETW 行为追踪与 WFP 阻断、恢复。
uv run --no-sync python scripts/probe_codex_child_egress.py --codex $codexExe --native-dir build/behavior --output runs/codex-egress --elevate
```

## 测试

```powershell
uv lock --check
uv pip check
uv run --no-sync pytest
```
