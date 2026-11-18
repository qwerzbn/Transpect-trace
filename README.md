# Transpect Trace

Windows 上的 Agent 数据防泄漏工具。常驻监视器管理 Codex 桌面端和 Claude Code CLI 的守护进程。受支持的请求在本机完成内容检查和审计，当前轮次命中敏感策略时直接拒绝。

## 启动

在 Windows x64 上安装 Git 和 [uv](https://docs.astral.sh/uv/getting-started/installation/)，然后在项目根目录的 PowerShell 或命令提示符运行：

```powershell
.\guard-service.bat
```

首次启动按 `uv.lock` 准备环境。监视窗独立运行，关闭启动终端后仍可查看状态。重复运行命令会识别已有实例。Git Bash 可用 `./start.sh`。[监视、状态和主动停止](docs/development/unified-monitor.md)

| 操作 | Windows 命令 |
|---|---|
| 启动或连接到已有监视器 | `.\guard-service.bat` |
| 查看双客户端状态 | `.\guard-service.bat status` |
| 获取 JSON 状态 | `.\guard-service.bat status --json` |
| 打开只读监视窗 | `.\guard-service.bat watch` |
| 停止统一守护 | `.\guard-service.bat stop` |

## 版本与覆盖

| 客户端或路径 | 已验证范围 | 部署状态 |
|---|---|---|
| Codex 桌面包 `26.1111.2228.0` | 真实后端、普通 HTTP、zstd HTTP 和 WSS。在同一对话直接拒绝当前敏感请求，下一轮正常消息可继续，历史令牌未到达本机接收端 | 本版使用隔离验收的候选配置。日常守护仍显示 `UNSUPPORTED_VERSION` |
| 此前已发布的 Codex 固定版本 | 后端身份、发送点与接入状态由各版本记录约束 | 运行状态以监视窗中的进程记录为准。[版本配置](deploy/desktop-guard/) |
| Claude Code CLI `2.1.317` | 固定版进程内门控、显式本地代理。代理可以返回本地策略拒绝文案 | 模型路径和工具出口均验收后才显示完整保护。实验接入显示 `HOOK_READY_LIMITED` |

启动成功说明监视器和守护器已运行。版本失配时不会接入该进程。覆盖范围按实际验收的版本、协议和发出请求的进程计算。工具进程启动检查与工具后代的网络边界分别验收。[Codex 实机验收记录](docs/validation/2026-11-18-codex-compression-and-session.md)

## 架构与代码位置

| 层 | 职责 | 代码 |
|---|---|---|
| 启动和运维 | 加载锁定环境、管理两个守护器、显示状态并恢复异常退出的组件 | [Windows 入口](guard-service.bat) · [监视器](src/transpect_trace/guard/hub.py) |
| 客户端接入 | 核对版本和身份，在受支持的发送点向本机门控提交请求 | [Native 组件](native/guard/) · [守护与管道](src/transpect_trace/guard/) |
| 内容策略 | 拆解请求条目、识别敏感内容、确定当前轮次和历史条目的处理方式 | [内容引擎](src/transpect_trace/protect/content_dlp.py) · [请求判定](src/transpect_trace/protect/native_collection.py) · [Claude 共享策略](src/transpect_trace/protect/claude_policy.py) |
| 证据与审计 | 加密归档请求，按请求或工具调用关联决策记录及 ETW 进程、文件、网络事件 | [归档](src/transpect_trace/protect/archive.py) · [行为审计](src/transpect_trace/behavior/) |
| 发布与验证 | 按清单审计暂存代码和二进制测试样本，验证结构、公开接口与测试 | [发布清单](release-files.json) · [持续集成](.github/workflows/python-checks.yml) |

长文本检查在一次请求内复用相同文本块的预筛结果。原文和规范化文本只在少量位置有差别时，共同的部分可以复用。某条规则出现候选特征时，引擎仍在完整文本上匹配。会话内复用已检查条目的机制独立于这项分块优化。[实现与基准](docs/validation/2026-11-18-codex-compression-and-session.md)

## 开发与验证

```powershell
uv sync --locked --dev --extra observe --extra tui --extra python-protect --extra guard-probe --extra claude-proxy
uv run --no-sync python -m pytest
uv run --no-sync python scripts/check_repository.py
uv run --no-sync python scripts/audit_release.py
```

原始审计与请求归档留在本机。仓库收录源码、测试、版本配置和验收汇总。[技术方案](docs/project-overview.md) · [内容识别文档](docs/content-recognition-dlp.md) · [开发计划](plan.md)
