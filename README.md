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
| 采集层 | Native DLL 加载到 `codex.exe app-server`，在请求序列化完成后、发送前取得完整正文；客户端 zstd 压缩的正文还原后检查 | `native/guard/desktop_guard.c`、`src/transpect_trace/guard/`、`src/transpect_trace/protect/wire_items.py` |
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

环境：Windows x64、已安装 Codex 桌面端 `26.1103.3517.0`、[uv](https://docs.astral.sh/uv/getting-started/installation/)、Git Bash。在仓库根目录的 Git Bash 中执行：

```bash
./start.sh
```

首次运行会按锁定的依赖安装并在本机编译 Native DLL，实测约 1 分钟；后续启动复用构建产物。默认在当前窗口持续运行，可另开一个 Git Bash 窗口执行 `./start.sh status` 查看状态。防护每 250 ms 扫描当前用户的 `codex.exe app-server`：
- 已在运行的进程自动接入，实测约 765 ms；
- 之后启动或重启的进程自动接入，实测从进程创建到受保护约 1.1 秒；
- 所有后端哈希与版本固定文件匹配的进程都会被接管，包括独立启动的同版本 `app-server`；版本不匹配的进程显示 `UNSUPPORTED_VERSION`。

在 `status` 输出中确认目标进程为 `PROTECTED` 后再发送需要防护的请求。新进程创建与接入之间仍有时间窗口；WFP 启动门闩尚未实现。

每次判定打印一行：

```text
14:33:04 [Codex 7408] 已接入防护（已重连，0 ms）
14:36:09 [Codex 7408] 拒绝  wss 97 KB  658 ms  ENTROPY_TOKEN, GITHUB_TOKEN
```

| 命令 | 作用 |
|---|---|
| `./start.sh` | 在当前窗口启动防护，Ctrl+C 或关闭窗口即停止 |
| `./start.sh status` | 查看防护和各 Codex 后端的状态与计数 |
| `./start.sh stop` | 停止正在运行的防护 |
| `./start.sh build` | 只构建已安装且受支持版本的 Native DLL |
| `./start.sh install` | 注册登录自启计划任务，并立即在后台启动 |
| `./start.sh uninstall` | 取消登录自启并停止 |

登录自启尚未完成手工验收。需要使用时，依次执行 `./start.sh install`、`./start.sh status`、`./start.sh uninstall` 验证；计划任务注册可能受本机权限策略限制。

- **停止行为**：通过 Ctrl+C、关闭窗口或 `stop` 停止后，已接入的 Codex 恢复直接发送。防护进程被强制结束或崩溃时，Codex 的请求一律被拒，直到防护重新启动。
- **重新接管**：防护重启后会接管已注入的 Codex 进程，无需重启 Codex。
- **运行记录**：保存在 `%LOCALAPPDATA%\TranspectTrace\desktop-guard\runs\<启动时间>\`。`native-audit-<PID>.jsonl` 是逐请求判定，`collection.jsonl` 是逐条目识别结果，`archive/` 是加密正文。
- **版本不符**：Codex 版本不受支持时不接入，状态显示 `UNSUPPORTED_VERSION`，此时需关闭应用商店的自动更新。

### 行为审计

从有 ETW 权限的终端，对已核对的后端 PID 运行有界采集：

```powershell
uv run --no-sync ttrace behavior attach --channel desktop --pid <app-server PID> --output runs/desktop-system-hook/etw-001 --duration 30
```

### 开发与验证

```bash
uv run --no-sync python -m pytest -q
uv run --no-sync python scripts/probe_desktop_guard_production_lab.py --backend <codex.exe 路径> --output runs/scratch/prod-lab
```

隔离实验在独立的 `app-server` 子进程和本地不转发源站上，依次验证注入、主动停止、重连、控制器丢失、恢复五个阶段。运行前需先停止防护，否则防护会接管实验进程。

## 目录

| 路径 | 内容 |
|---|---|
| `start.sh` | 一键启动入口 |
| `deploy/desktop-guard/` | 版本固定文件：每个受支持版本的后端哈希、挂钩点与 ABI |
| `native/guard/desktop_guard.c` | 生产版 Native DLL 源码（MinHook）；`guard.c` 为冻结的实验版本 |
| `src/transpect_trace/guard/` | 注入、命名管道服务、请求与判定协议 |
| `src/transpect_trace/protect/` | 请求解析、内容识别、工具动作策略、加密归档、采集记录 |
| `src/transpect_trace/behavior/` | ETW 采集、桌面进程身份、行为报告 |
| `src/transpect_trace/guard/desktop_service.py` | 生产防护：本机构建、进程扫描、注入、租约与重连 |
| `scripts/desktop_guard.py` | `start.sh` 调用的命令行入口 |
| `scripts/probe_desktop_guard_production_lab.py` | 生产版 DLL 的隔离生命周期实验 |
| `scripts/desktop_demo.py`、`scripts/build_guard_*_lab.py`、`scripts/probe_desktop_*_lab.py` | 开发期的实验控制器、实验 DLL 构建与隔离实验 |
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
