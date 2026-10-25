# 跨 Agent 多步骤传播实验

本阶段在现有 Flow 上增加两个固定行为的测试 Agent，验证查询、委派、确定性转换和最终外发的关联。二者为独立 Python 进程，由同一控制器显式登记，不互为父子，也不代表已经接入真实 Agent 框架或生成式摘要服务。原文件／Named Pipe 受控场景已阶段性完成；[原验收记录](../validation/cross-application-20261023.md)中并发、改写、重连和故障联动的待验收项继续保留。

```text
假 JSON 数据 → Agent A 查询选定字段 → 本地消息 Named Pipe
                                               ↓
                                   Agent B 接收并执行确定性转换
                                               ↓
                                WinHTTP / Schannel → localhost HTTPS

Native I/O：源读取、消息写入、消息读取
ETW：显式登记进程的文件和网络事实
eCapture：B 的 TLS 明文 → HTTP/1.1 重组 → 最终正文检测
AgentEvidence：观察到的任务 / 消息 / 工具 / 发送尝试 ID 与内容证据
```

全部新组件保持 `can_enforce=false`，实际阻断数为零。使用假数据、本机受控源站、正常证书校验，无网络代理、无外部模型调用。新适配无需改写已有 Native DLL 或 Guard 接口。

## 安装与运行

按照 [Flow 构建说明](cross-application-flow.md)准备 Windows x64、Python 3.12、uv、Flow Native 及增强 eCapture；使用实际基础解释器，不使用 venv 重定向 EXE 作为被观察对象。依赖仍由既有 `uv.lock` 管理。

在管理员 PowerShell 运行下面的实采探针。`--prepare-test-trust` 显式创建并临时信任本机测试证书，运行结束撤销本次证书。Windows 的系统确认由用户处理。

```powershell
$runTag = Get-Date -Format 'yyyyMMdd-HHmmss'
uv run --no-sync python scripts/probe_cross_agent_flow.py --output "runs/cross-agent/$runTag" --prepare-test-trust --repeat 3 --ecapture-dir build/flow-ecapture-v2
```

`--ecapture-dir` 必须指向当前补丁构建且身份匹配的目录。若采用 README 默认构建路径，改为 `build/observe/ecapture-enhanced`。已有可信 localhost 证书可改用 `--certificate <PEM> --private-key <KEY>`。每轮使用新输出目录，旧证据不会被覆盖。

探针为五个场景生成固定哈希清单：原文复制、JSON 嵌套、确定性摘录、A 仅委派普通字段、B 仅上传普通字段。前三种保留假机密，后两种应保留敏感读取事实而不判定敏感内容已经外发。`public` 是测试程序的字段选择，不是检测器的豁免标签。

```powershell
uv run --no-sync ttrace flow agents run --manifest <新实验清单.json>
uv run --no-sync ttrace flow agents status <audit目录>
uv run --no-sync ttrace flow agents report <audit目录>
```

清单固定实际解释器、测试程序及其本地导入脚本、Native／eCapture 产物和构建清单、数据源、登记索引及证书。重放需要新的 output 和有效且可信的证书，不允许通过修改固定产物哈希绕过原校验。原 `flow run/status/report` 与 `guard/observe/protect` 不改变语义。

## 就绪与证据

1. 启动空闲 A/B，核验实际 PID、创建时间及映像哈希。相同 Python EXE 不意味着同一进程实例。
2. 先加载 Native I/O，再等待 ETW 和 B 的 eCapture ready；禁止重复覆盖 Hook。
3. 释放 B 创建消息模式本地管道，确认服务端就绪后释放 A 查询及委派。
4. B 完整接收消息，执行指定转换，调用 WinHTTP 工具上传；参与程序保留存活直到采集器排空并提供 terminal。
5. 独立核对 Native 内容交接、ETW 实际事件、TLS 正文及源站回执。任一健康缺口、丢片或身份变化均降级，零事件不算成功。

输出 `agent-evidence.json` 包含四种观察：`source_read`、`message_write`、`message_read`、`outbound`。任务、消息和发送尝试标识从 Native 重组字节或 eCapture 正文解析，审计只保存其哈希。参与程序 stdout 仅作为 `fixture_truth` 对照，不参与传播认证。

| 关联 | 依据与边界 |
| --- | --- |
| 源读取 → A 委派 | 同进程、成功读取、顺序及登记内容重叠；进程内转换未观测，为 Low 来源候选 |
| A 写入 → B 读取 | 实际管道端点、Native 交接、消息 ID 与完整正文一致；跨端局部代次未直接映射，为 Medium |
| B 读取 → 最终外发 | 外发正文携带父消息 ID，且实际检测内容重叠情况单独呈现；父引用属于应用协议声明，不证明字节因果 |
| TLS 正文 ↔ 源站 | 按同层哈希、长度和次数核对；不凭时间或相同哈希强行合并请求，不冒充源站 ID 直接映射 |

每次实际外发保持独立观察和 attempt。工具调用 ID 仅认证本测试协议的 WinHTTP 上传动作，不把普通 `/upload` JSON 伪装成 LLM Tool Call。LLM 分类可以为 UNKNOWN，同时普通正文检测和源站核对通过。

## 隐私与范围

默认审计只保存长度、哈希、字段位置、登记条目 ID、检测命中与证据引用；不保存 Prompt、消息原文、认证头或 Cookie。正文仅在受限内存和本地 IPC 内处理。明确的假数据源放在独立 `explicit-fake-inputs` 目录，不进入源码白名单。正常 HTTP 失败信息不输出原始载荷。

源文件、完整消息 envelope 及上传正文分别不超过 1 MiB；JSON 包装后的总大小也计入上限。超限、未知格式、缺字段及重复 JSON key 拒绝解析，不截断后标完整。仅支持同步 Win32 I/O、本地单向消息 Named Pipe、UTF-8 JSON／文本、HTTP/1.1。

生成式摘要、真实数据库／邮件系统、任意 Agent 框架、跨主机消息队列、IPC 并发、管道重连、文件改写、浏览器及新的发送前阻断尚不认证。最终通过范围见[本阶段验收记录](../validation/cross-agent-20261023.md)。

后续有限并发、重连歧义、文件改写和采集停止的独立结果见[复杂联动验收](../validation/flow-linkage-20261023.md)；它补充本记录，不将此首版结果扩展为任意负载保证。

```powershell
uv run --no-sync pytest
uv lock --check
uv pip check
uv run --no-sync python scripts/generate_schemas.py --check
uv run --no-sync python scripts/check_repository.py
git diff --check
```

自动测试验证接口、关联和故障降级；真实 Windows 采集必须另有本轮健康、内容和源站证据。
