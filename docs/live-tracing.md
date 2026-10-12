# 文件输出与持续追踪

默认不用网页。`uv run ttrace trace --workspace PATH --prompt "任务"` 执行期间持续输出到
`runs/tasks/trace-reports/RUN_ID/live/`，结束后最终版本在其父目录。
`agent-tree.json/txt` 是 Agent 与工具调用树；`process-tree.json/txt` 是系统进程树；
`data-flow.json` 保存匹配边和来源标签；`trace.json` 保存完整投影。
原始证据仍在 RUN_ID 的 raw、blobs、normalized 中，派生文件不改变封存校验。
`uv run ttrace trees RUN_PATH` 可给已有运行补导出；加 `--html` 才生成网页。
旧 `report` 命令保留用于手动网页回放。

## 本机原生运行（Windows / macOS）

`uv run ttrace host-codex --workspace PATH --prompt "任务"` 在本机直接运行 Codex CLI，不用 Docker。
未指定 `--codex` 时，先找 PATH 里的 `codex`，Windows 上再找桌面版自带的
`%LOCALAPPDATA%\OpenAI\Codex\bin\*\codex.exe`。
运行器在 127.0.0.1 随机端口起 Gateway，用临时 `CODEX_HOME` 把模型地址指过去，使用 `.env` 里的
DeepSeek Key；日常的 `~/.codex` 不会被修改，临时目录在运行结束后删除，生成的配置副本存在
`input/codex-config.toml`。默认 `sandbox_mode = "read-only"`；Windows 上另外写
`[windows] sandbox = "unelevated"`，否则 `approval_policy = "never"` 会拒绝所有 shell 命令。
证据包在 `runs/host/RUN_ID/`，格式与容器运行相同，可用 `ttrace verify` 校验。
这种模式只采集客户端事件和 Gateway 明文，没有 strace 和 Frida 的系统行为证据。

macOS 上执行 `bash scripts/macos-host-trace.sh`：没有 `codex` 时用 npm 安装指定版本
（默认 `CODEX_VERSION=0.114.0`），跑一条 `host-codex`，再用 `ttrace verify` 校验。
没有 Mac 时，可把仓库推到 GitHub 私有仓库，在仓库 Secrets 里加 `API_KEY`（可选 `BASE_URL`、`MODEL_ID`），
在 Actions 里手动运行 `macOS host trace`；证据包作为 `macos-host-trace` 附件下载。
运行器是 GitHub 托管的真实 macOS，请求正文会经过该运行器，建议使用单独的低额度 Key，工作区只放假数据。

## 日常桌面聊天

运行 `uv run ttrace desktop-watch`，然后在 Codex 桌面输入正常 prompt。
监听器发现启动后新建或更新的本地 rollout 日志，自动更新 `runs/desktop/THREAD_ID/`。
监听所有会话会记录它们的工具参数、返回、消息；这些文件只保存在本地，但可能包含任务数据。
也可限定一条聊天：
`uv run ttrace desktop-watch --thread THREAD_ID`。
若日志显式提供父 Thread 身份，该选项也监听其后代。
`--once` 导出一次；`--no-sample-processes` 关闭 Windows 进程轮询；Ctrl+C 停止。
监听器依赖当前本地日志格式，不修改 Codex 全局配置。日志格式变化需要更新适配器。
完整源事件按行存入 `events.jsonl`，`cursor.json` 记录恢复位置。
Windows 可用 `powershell -ExecutionPolicy Bypass -File scripts/desktop-start.ps1` 在后台启动；
`powershell -ExecutionPolicy Bypass -File scripts/desktop-stop.ps1` 校验进程身份后停止。
该参数仅作用于当前脚本进程，不修改系统执行策略，也不会设置开机自启动。
异常退出在日志追加与 cursor 提交之间可能产生重复行，可按 source/generation/line 去重。
聚合树放在 `runs/desktop/`；只有日志明确给出 parent_thread_id/parent_session_id 才连接父子 Thread。
Windows 树保留共享 Codex 进程的历史采样和最近出现时间，不把日志 execution_handle 当 PID。
短命进程可能遗漏，进程与具体 Thread 的归属仍未知。

## 改写传播

受控模式先从请求中原文匹配建立文件来源，再把同一 Agent 后续输出、工具调用、
显式 demo 子 Agent 与回传标记为 `possible_dependency`。
桌面模式从工具返回建立来源，后续摘要、改写、工具输入继承可能依赖。
即使字面已变化也保留标签，但这是一种保守暴露策略，会误报；不是语义来源证明。
桌面模式未观测内核文件读取和上游请求，不能把工具命令中的路径视为实际读取，
也不能声称记录中的内容已上传。
成功的工作目录写入可记录对应 Agent 的暴露候选，但不能证明写入字节携带了该来源。
当前不提供编码转换的逐字节追踪、生成文件的精确版本来源、任意原生子线程完整关联。
要证明这些，需要在真实客户端工具执行边界和网络出口部署采集器；单靠 rollout 日志无法补齐。

`status.json` 先标记 writing，全部文件完成后标记 ready；读者只接受 ready，
并在读取多份文件前后核对 revision，变动时重读。
更新采用轮询与原子文件替换；大型历史会话会增加刷新耗时。
