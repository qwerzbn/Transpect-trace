# 真实 Agent 信息流追踪 Demo

## 运行

在项目目录执行（需要 Docker Desktop Linux engine 和已有的 `.env` 模型配置）：

```powershell
uv run ttrace demo
```

这会启动真实 Codex CLI，通过当前配置的 DeepSeek 兼容 Responses API 完成周报任务。工作目录含虚构的 `project.txt`、`progress.csv`、`budget.csv` 和无关的 `archive.txt`。

主 Agent 读取项目和进展，调用 `delegate_budget` 启动独立 Codex 子 Agent 读取预算、计算合计，再把周报写入 `output/report.md`，调用 `submit_report`。后者只将接收到的参数写入本地证据日志，返回本地回执，不发送邮件。

运行完成后终端打印证据目录和 `Report:` HTML 路径。双击 HTML 即可离线查看，无需启动 Web 服务。旁边的同名 JSON 是图形使用的结构化数据。

## 演示顺序

1. 展开“输入任务与追踪边界”，说明使用真实模型执行、文件内容是虚构数据。
2. 在“Agent 调用树”查看主 Thread、独立子 Thread、工具调用及模型请求。
3. 点击 `budget.csv`：成功读取由系统调用返回值证明；模型请求和工具传递由唯一标记/原文匹配证明内容出现。匹配的来源标为候选，不声称证明模型的语义推导。
4. 点击 `submit_report` 的本地接收节点，查看实际参数和回执。
5. 点击 `archive.txt`，查看是否有读取或内容匹配证据。“未观察到”不等于绝对没有发生。
6. 切换系统进程树，展开 shell、读取程序和 Codex 子进程。默认折叠系统线程、隐藏 Gateway；勾选后可查看。点击节点可查看 PID、fork 证据和执行命令。
7. 在时间线回看事件；右侧显示原始事件、证据 ID、请求 blob 路径及有限正文预览。

## 输入真实 prompt

```powershell
uv run ttrace trace --workspace D:\demo\my-project --prompt "阅读 README 和 src，解释程序入口并生成一份说明"
```

较长 prompt 建议放在 UTF-8 文件中：

```powershell
uv run ttrace trace --workspace D:\demo\my-project --prompt-file D:\demo\task.txt
```

不要求 `TRANSPECT_MARKER`。若需要本 Demo 的独立子 Agent 和本地接收工具，加 `--demo-tools`。真实任务中没有唯一标记时，对初始快照 UTF-8 文件中至少 24 字符的原文行做匹配；新生成文件使用最终快照，仅匹配最后一次观察到写入之后的事件，并单独标注为最终快照匹配。改写、短片段、二进制或编码内容可能无法归因。

`trace` 启动新的受控 Thread，在工作目录副本执行。产物留在证据目录下的 `workspace`，不自动回写原目录。快照排除 `.git`、`.venv`、`node_modules`、缓存、`.env`/`.env.*`、符号链接及当前输出目录所在分支。依赖这些资源的任务可能需要另行准备工作目录。

输入和模型请求正文会完整保存在本地证据中；实际模型请求发送至配置的模型服务。报告也包含正文预览。运行环境的 Agent 只能通过受控 Gateway 访问模型，不是用户日常桌面 Agent 的全部联网环境。

## 从已有证据生成报告

```powershell
uv run ttrace report runs\demo\<run-id>
uv run ttrace verify runs\demo\<run-id>
```

报告默认位于与 run 同级的 `trace-reports/<run-id>/index.html`，不修改或重新封存原证据。历史包只能展示当时实际采集的信息；缺失的子任务身份不会按时间猜造出来。

## 实现范围

- 系统进程树来自 strace 的 fork/clone/exec，不把一个工具调用直接当成一个进程。Gateway 与 Agent 的 PID 命名空间分开。线程折叠时沿真实父链展示最近可见祖先。
- Demo 子 Agent 是显式 MCP 工具启动的独立 Codex subprocess；当前镜像原生 `multi_agent` 是默认关闭的实验特性。本版不会将 subprocess 委派冒充原生 `spawn_agent`。
- 各独立 Agent 使用 Gateway 的 `/agents/<id>/...` 路由前缀，前缀在转发上游前去除，用来确定模型请求属于哪个 Agent。这是受控环境中的关联字段，不是身份认证。
- 原文出现、实际读取、上游响应、本地接收回执分别展示。路径参数不算文件内容外发，连接记录不等于某文件已经上传。
- 首版为任务结束后自动生成的交互式回放，不是持续刷新的实时监控，也不能从历史聊天文本补出未采集的系统行为。
- 后续接入日常会话应复用 `normalized` 事件与报告数据格式，再增加长驻采集、原生子线程事件、更多工具接收端以及增量页面刷新。
