# Windows 跨应用传播实验

`flow` 为独立、观察性质的受控实验模块，复用现有内容检测、增强 eCapture 与 ETW 解码。当前路径是 Python A → 文件／本地消息 Named Pipe → 独立 WinHTTP B → localhost HTTPS 源站。两程序由实验控制器分别启动，不把同会话误记为父子关系。所有新组件 `can_enforce=false`。

## 安装和构建

使用 README 中的 Windows x64、Python 3.12、uv 开发环境，以及增强 eCapture 的固定上游／补丁构建。Python 依赖仍由 `uv.lock` 管理，无新增依赖。

```powershell
uv sync --locked --dev --extra observe --extra native-build
uv run --no-sync python scripts/build_native.py --component flow --check
uv run --no-sync python scripts/build_native.py --component flow
```

产物为 `build/flow/ttrace-flow-io.dll`、`flow_uploader.exe`、`flow_etw.exe`、`native-build.json`。构建验证 MinHook 固定源码；清单记录来源哈希、工具链与产物哈希。旧 Codex Native、WFP、ECW2 及其构建清单无需修改。

## 运行受控实验

本轮联动实验在**管理员 PowerShell**中运行，以启动 Native ETW 和 eCapture。正常证书校验保持启用。以下显式选项会创建 localhost 专用测试证书、导入当前用户信任、结束时清理本轮根证书；如果 Windows 弹出确认框，由用户确认。

```powershell
$runTag = Get-Date -Format 'yyyyMMdd-HHmmss'
uv run --no-sync python scripts/probe_cross_application_flow.py --output "runs/cross-app/$runTag" --prepare-test-trust --extended
```

已有预先可信的 localhost 证书时，改用 `--certificate <证书PEM> --private-key <私钥PEM>`，不传 `--prepare-test-trust`。独立构建的增强 eCapture 可用 `--ecapture-dir <包含ecapture-build.json的目录>` 指定；仍须通过原有校验，不能编辑哈希来绕过拒绝。

默认两条链各执行敏感正文与“读取敏感内容、上传普通文本”负例。`--extended` 增加超过 64 KiB 的中文 JSON 与恰好 1 MiB 文本。`--scenario file` 或 `pipe` 可单独复现。

生成的清单固定 Python 实际解释器（避开 venv 重定向启动器）、参与程序、Native 产物、eCapture 构建清单、登记索引、假数据及证书哈希。路径以清单位置解析。运行目录必须不存在，已有证据不会被覆盖。

```powershell
uv run --no-sync ttrace flow run --manifest <实验清单.json>
uv run --no-sync ttrace flow status <audit目录>
uv run --no-sync ttrace flow report <audit目录>
```

重放清单前需提供新的 output 目录，以及当前有效、可信、哈希匹配的测试证书。脚本创建的信任会在实验后移除，不能将过期清单直接当作新实验。异常中断时使用生成的 `test-trust/test-trust.json` 所列精确清理命令；仅撤销该清单拥有的新证书。

## 数据和启动顺序

1. 启动不转发流量的源站与空闲 A/B，核对 ready PID、创建时间和映像哈希。
2. 加载两端 Native I/O Observer，等待 ready；再等待多应用 ETW 与 B 的增强 eCapture ready。
3. 文件场景先释放 A，写完关闭后释放 B；管道场景先让 B 建立服务端，再释放 A。
4. 收到 B 请求完成记录后，两进程保持存活，先排空 eCapture 和 Native I/O terminal，再结束参与程序与 ETW。
5. 独立核对系统事件、内容检测、候选传播和源站哈希／次数。

初始化失败时不释放数据任务，报告 unavailable。中途失效标 partial；采集器不能通过延迟长时间阻塞应用来维持观察。参与程序的 ready、received、sent 是测试真值，不能替代 Native I/O、ETW 或 TLS 实采。

## 审计与限制

`audit/flow-evidence.json` 输出四类证据；`audit/etw/` 保存系统元数据；`audit/observe/` 保存兼容 Observe 报告。HTTP `/upload` 可以传输完整且检测命中，同时 LLM 分类为 UNKNOWN，两者互不替代。

默认审计不含正文、认证头、Cookie 或明文令牌。内容关联报告不保存原始路径；ETW 元数据可包含受控文件路径。源站只保存正文哈希和字节数；中间文件位于独立临时假数据目录，运行后清理。输入假数据单列 `explicit-fake-inputs/`，不会加入源码发布白名单。只有清单显式 `export_fake_bodies=true` 时才导出 `observe/synthetic-bodies/`，不要对真实数据启用。

文件身份来自句柄的卷与文件 ID，写版本及读范围来自已观察的同步操作。管道记录端点 PID＋创建时间、局部连接代次和消息边界。跨端代次映射未证实时保留限制。相同哈希和时间相近不证明唯一来源；High 也不是字节级因果或污点证明。

首版设计范围为固定实验程序的同步 Win32 文件 I/O、本地单向消息管道、UTF-8 文本／JSON、WinHTTP HTTP/1.1，以及 1 MiB 以内内容。实际通过项以[本轮验收矩阵](../validation/cross-application-20261023.md)为准。异步 I/O、远程／匿名管道、共享内存、浏览器、任意业务应用和发送前阻断不在此模块能力范围。

## 回归

```powershell
uv lock --check
uv pip check
uv run --no-sync pytest
uv run --no-sync python scripts/generate_schemas.py --check
uv run --no-sync python scripts/check_repository.py
git diff --check
```

自动测试覆盖模型、隐私、丢片、身份和关联边界；实采结论需要本轮源站、外部采集器与终端健康证据，不能由测试数量替代。
