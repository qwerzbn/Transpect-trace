# Transpect Trace

面向企业 Agent 的外发数据防护。当前主线为 Codex 桌面端：在 Codex 本地后端进程内以本地 Hook 采集模型请求与工具调用，经本地内容识别后在发送前放行或拒绝，并以 ETW 记录 Agent 子进程的文件与网络行为。方案不使用系统代理，也不使用 Codex 内置 Hook。

完整设计见 [技术方案](docs/project-overview.md)，后续开发见 [开发计划](plan.md)。

## 架构

~~~text
Codex 客户端（codex.exe app-server）
  ├─ 本地 Hook（模型请求发送点 HTTP / WSS · 工具执行点）
  │    └─ Native 组件 ──命名管道──> 本地门控服务
  │         ├─ 解析请求条目 → 加密归档 → 内容识别与工具动作策略
  │         ├─ 返回放行或拒绝决定
  │         └─ 写入决策审计与 ETW 关联事件
  └─ Codex 子进程 ──进程 / 文件 / 网络事件──> ETW 采集器
                                                  └─ 行为关联与审计报告
~~~

| 层 | 作用 | 主要实现 |
|---|---|---|
| 采集层 | Native DLL 加载到 `codex.exe app-server`，在请求序列化完成后、发送前取得完整正文；客户端 zstd 压缩的正文还原后检查 | `native/guard/guard.c`、`src/transpect_trace/guard/`、`src/transpect_trace/protect/wire_items.py` |
| 内容识别层 | 规则与校验、熵分析、EDM 精确匹配、文档与源码指纹；检查原文、解码内容和规范化内容 | `src/transpect_trace/protect/content_dlp.py`、`protect/tool_policy.py` |
| 拦截层 | 判定只有放行与拒绝；拒绝以客户端原生错误返回，不触发重试 | `src/transpect_trace/protect/native_collection.py`、`guard/pipe.py` |
| 审计与行为关联 | 判定记录与 AES-GCM 加密归档（DPAPI 保护密钥）；ETW 进程、文件、网络元数据 | `src/transpect_trace/protect/archive.py`、`src/transpect_trace/behavior/` |

发送点采集的是客户端实际上行的内容，包括用户输入、系统与项目指令（含 `AGENTS.md`）、历史消息、工具结果，以及客户端后台请求。

## 适配版本

本地 Hook 按固定版本适配，注入前核对以下身份，不符时不加载：

| 项 | 值 |
|---|---|
| 桌面包 | `OpenAI.Codex_26.1103.3517.0_x64__2p2nqsd0c76g0` |
| 后端 | `codex-cli 0.167.0-alpha.3.2` |
| 后端 SHA-256 | `40ecc3d8b6899afd8f935a8cccb7d53ba41ffd7c199f679e186d30ddd0d0bf39` |

## 快速开始

环境：Windows x64、[uv](https://docs.astral.sh/uv/getting-started/installation/)、Python 3.12 x64。以下命令在仓库根目录的 PowerShell 中执行。

```powershell
uv python install 3.12
uv sync --locked --dev --extra observe --extra native-build
```

### 1. 构建 Native DLL

构建脚本读取当前桌面后端，核对哈希与挂钩点入口字节，并要求隔离采集实验的证据存在于 `runs/scratch/adapt-26.1103/`。证据的生成步骤见 [桌面 Demo 记录](docs/development/desktop-system-hook-demo.md)。

```powershell
uv run --no-sync python scripts/build_guard_nonretry_current_lab.py
```

### 2. 检查准入

`status` 只读，不加载 DLL。它核对桌面进程身份、DLL 与构建清单、隔离实验证据及控制器源码哈希。

```powershell
$appServerPid = (Get-CimInstance Win32_Process -Filter "Name='codex.exe'" |
  Where-Object CommandLine -match ' app-server ').ProcessId
uv run --no-sync python scripts/desktop_demo.py status --pid $appServerPid --guard nonretry_lease
```

### 3. 接入与停止

```powershell
$runDir = "runs/scratch/desktop-live-$(Get-Date -Format yyyyMMdd-HHmmss)"
uv run --no-sync python scripts/desktop_demo.py run --pid $appServerPid --guard nonretry_lease --seconds 3600 --output $runDir
uv run --no-sync python scripts/desktop_demo.py stop --output $runDir
```

- **前提**：实机接入受 `scripts/desktop_demo.py` 中 `LIVE_TRIALS_PAUSED` 开关控制。
- **运行记录**：输出目录中，`native-audit.jsonl` 记录每次请求的判定，`collection.jsonl` 记录逐条目的识别结果，`archive/` 保存加密正文，`status.json` 是控制器状态快照。
- **重新接入**：控制器停止后 Hook 停用，DLL 仍驻留在该进程中；要再次接入，需先完全重启 Codex。

### 4. 行为审计

从有 ETW 权限的终端对已核对的后端 PID 运行有界采集：

```powershell
uv run --no-sync ttrace behavior attach --channel desktop --pid $appServerPid --output runs/desktop-system-hook/etw-001 --duration 30
```

### 5. 测试

```powershell
uv run --no-sync python -m pytest -q
```

## 目录

| 路径 | 内容 |
|---|---|
| `native/guard/` | Native DLL 源码（MinHook） |
| `src/transpect_trace/guard/` | 注入、命名管道服务、请求与判定协议 |
| `src/transpect_trace/protect/` | 请求解析、内容识别、工具动作策略、加密归档、采集记录 |
| `src/transpect_trace/behavior/` | ETW 采集、桌面进程身份、行为报告 |
| `scripts/desktop_demo.py` | 桌面端控制器：准入检查、接入、停止 |
| `scripts/desktop_guard_supervisor.py`、`scripts/manage_desktop_guard_autostart.py` | 桌面进程自动发现与登录启动 |
| `scripts/build_guard_*_lab.py`、`scripts/probe_desktop_*_lab.py` | DLL 构建与隔离实验 |
| `docs/` | 技术方案与开发记录 |

## 文档

- [技术方案](docs/project-overview.md)
- [开发计划](plan.md)
- [桌面 Demo 记录](docs/development/desktop-system-hook-demo.md)：实验证据、实机测试记录
- [桌面进程自动发现](docs/development/desktop-guard-autostart.md)
- [启动网络门闩设计](docs/development/desktop-startup-egress-gate.md)
- [WFP 网络出口兜底](docs/development/desktop-wfp.md)

## 其他内容

仓库还保留了以下两部分，不属于当前主线：
- **Codex CLI 路线：** Native Guard、eCapture、ETW、WFP，见 [CLI 使用说明](docs/cli-guard.md)；
- **内置 Hook 门控实验：** 见 [Hook 门控记录](docs/development/codex-hook-gate.md)。
