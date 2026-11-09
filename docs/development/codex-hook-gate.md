# 用 Codex 自带 Hook 做发送前 DLP 门控

本文保留 2026-11-04 前后针对固定旧版的独立 Hook 实验及其安装命令；它**不参与当前无应用 Hook Demo**。本机已经更新，以下实测结论不能外推到当前后端；当前状态见[桌面无应用 Hook Demo](desktop-system-hook-demo.md)。

当时的 Codex 客户端提供命令 Hook 机制。它不需要 Frida、不修改 Codex 源码、不使用转发代理；装好并经用户批准信任后，可对该 `CODEX_HOME` 下的提交持续生效。本文只写该固定版本**在本机实测确认**的行为，并明确标出未闭合的缺口。

固定对象：MSIX `OpenAI.Codex 26.1029.7803.0`，内置后端 `codex-cli 0.166.0-alpha.6`，`codex.exe` SHA-256 `925c7d0665ffa49b0dcf748e034a805a04da984164ac92301432073b47789b99`。换版后以下 RVA 无关的结论仍需重新核对。

## 1. 客户端提供的 Hook 事件与契约

后端内嵌 draft-07 JSON Schema，[提取脚本](../../scripts/extract_codex_hook_schemas.py)按固定哈希从镜像读出，共 23 份（11 个事件的 `command.input`／`command.output`）。因此门控是**按客户端自己的契约**写的，不是按我们的猜测。门控用到的三组契约（`UserPromptSubmit`、`PreToolUse`、`PostToolUse`）固定在 [tests/fixtures/codex_hooks/pinned-hook-schemas.json](../../tests/fixtures/codex_hooks/pinned-hook-schemas.json)，由[契约测试](../../tests/test_codex_hook_contract.py)校验门控的每个回复，包括入口脚本和原生客户端里的兜底拒绝。

事件枚举共 15 个（`PreModelRequest`、`PostModelRequest`、`PreToolUse`、`PermissionRequest`、`PostToolUse`、`PreCompact`、`PostCompact`、`SessionStart`、`SessionEnd`、`UserPromptSubmit`、`SubagentStart`、`SubagentStop`、`Stop`、`Interrupt`、`SettingsImport`）。与外发防护相关的四个，实测能力如下：

| 事件 | 本机实测结论 | 角色 |
| --- | --- | --- |
| `UserPromptSubmit` | 返回 `{"decision":"block","reason":...}` 后，客户端打印 `hook: UserPromptSubmit Blocked`，该轮**没有任何模型请求**，也没有到达源站。 | **执行**：真实输入框提交的内容门控 |
| `PreToolUse` | 返回 `hookSpecificOutput.permissionDecision = "deny"` 加非空 `permissionDecisionReason` 即拒绝该次工具调用。本版**拒绝** `permissionDecision: allow/ask`、`decision: approve`、`continue:false`、`stopReason`、`suppressOutput`；`updatedInput` 必须配 `permissionDecision: allow`，因此也用不了。Shell 调用在 Hook 里叫 `Bash`，参数是 `{"command": ...}`。 | **执行**：Agent 工具调用的内容与动作门控 |
| `PostToolUse` | 载荷带 `tool_response`（命令输出、`view_image` 的图片 data URL、MCP 结构化结果）。返回 `{"decision":"block","reason":...}` 后客户端打印 `PostToolUse Blocked`，**下一次模型请求里该工具输出被替换为 `reason`**，原输出不上行。`continue:false` 同样替换但会结束本轮。 | **执行**：工具输出回流到模型这条路 |
| `PreModelRequest` | 每次模型请求前都触发（含重试）。载荷**只有元数据**（`session_id`、`turn_id`、`cwd`、`model`、`transcript_path`），**没有请求正文**。返回 block、`continue:false` 或退出码 2，客户端都照常发送。 | **观察**：请求计数、附件计数与取证，不能拦 |

`PostToolUse` 这一行是本轮新增的，用一个**不转发的本地脚本化源站**验证：它按脚本让模型发起工具调用，再记录每个请求正文实际收到了什么，判定只看源站收到的字节，不看控制台（[探针](../../scripts/probe_codex_hook_coverage.py)）。

## 2. Hook 主线能覆盖什么——按"一次模型请求里装了什么"逐项核对

一次模型请求的 `input` 由下列部分拼成。下表逐项说明 Hook 能否**拿到它的内容**、能否**在上行前拦住**：

| 请求里的内容 | 能拿到内容 | 能拦 | 依据 |
| --- | --- | --- | --- |
| 用户在输入框提交的文本 | 是（`UserPromptSubmit.prompt`） | 是 | 实测，含桌面界面输入 |
| Agent 发起的工具调用参数（Shell 命令、MCP 参数、子 Agent 消息） | 是（`PreToolUse.tool_input`） | 是 | 实测 |
| 工具输出（命令输出、文件内容、MCP 结果） | 是（`PostToolUse.tool_response`） | 是，替换为拒绝理由 | 实测 |
| 长时运行命令在让出（yield）前返回的**中间输出** | 否 | **否** | 实测：`PostToolUse` 只在进程结束那次轮询触发，此前已返回的输出块已经上行 |
| 工具返回的图片（`view_image`） | 只拿到像素的 data URL | 能拦，但无法判断内容 | 实测；默认记为 `IMAGE_UNINSPECTED` 不拦，可配置为一律拦 |
| 用户附件（`-i` 图片、桌面端添加的文件） | 否（无事件） | **否** | 实测：`UserPromptSubmit` 只有文本；`PreModelRequest` 时 transcript 里已有附件，可计数取证 |
| 客户端注入的系统／开发者指令、`AGENTS.md` 等项目说明 | 否 | **否** | 由客户端自行拼装，不经过任何 Hook |
| 之前轮次的历史 | 当轮已检查 | — | 历史里的内容在进入时都经过对应事件 |

结论：**Hook 主线覆盖了"人输入的"和"Agent 读到的"两大类外发内容**，缺口集中在三处：附件、长时命令的中间输出、客户端自行注入的项目说明文件。这三处都不在 Hook 契约里，只能靠观察（附件计数、对账）发现，或者换到网络／进程层去补。

## 3. 配置、信任与两个硬约束

Hook 从 `<CODEX_HOME>/hooks.json`（JSON）或 `config.toml` 的 `[hooks]` 表（TOML，键名为 `user_prompt_submit` 等蛇形）读取。JSON 形状经客户端自身报错逐层确认：

```text
{ description?, hooks: { <Event>: [ { matcher?, description?,
    hooks: [ { type: "command", command, commandWindows?, async?,
               statusMessage?, additionalContextLimit? } ] } ] } }
```

**约束一：必须经用户批准信任。** 未信任的 Hook 被**静默跳过**——没有告警、没有日志，请求照常发出。`--dangerously-bypass-hook-trust` 可为单次调用绕过信任；常态启用必须在 Codex 界面接受一次 Hook 审阅提示（客户端以内容哈希记录在 `config.toml` 的 `hooks.state` 下）。**装好 ≠ 生效**。另外，信任哈希针对的是 `hooks.json` 里的条目，**不覆盖它所调用的代码**：门控源码改了，客户端不会重新提示——[健康检查](#7-健康检查与对账发现门控失效)用安装清单补上这一点。

**约束二：`command` 按空白切分，不认引号。** 实测六种写法，带双引号的那一种失败。因此命令行里**任何路径都不能含空格**；[安装脚本](../../scripts/install_codex_hook_gate.py)在写入前校验。

`async = true` 的处理器不阻塞；需要决定的事件会被降级为同步执行。`PreModelRequest` 以 `async` 注册——它拦不住，不该给每次请求都加延迟。

**Hook 进程失败即放行。** 实测：命令指向不存在的程序，或进程以退出码 2 结束，客户端打印 `Failed` 后照常发送。所以门控进程**永远以 0 退出并自己写出拒绝**：入口脚本先用标准库读完事件，门控包连导入都失败时也写出拒绝；原生客户端在服务和 Python 都不可用时，按事件名写出内置拒绝。

## 4. 门控的处理顺序

[门控实现](../../src/transpect_trace/protect/codex_hook_gate.py)对每个可执行事件：

```text
读取 stdin 上的完整 Hook 事件（上限 8 MiB；超限或解析失败时按可恢复的事件名拒绝）
    ↓
取出该事件真正能上线的字节：
  UserPromptSubmit 取 prompt（剥离 #dlp-approve 行，理由文字照样检查）
  PreToolUse 取工具名 + tool_input 里的每个字符串叶子（含键名）
  PostToolUse 取 tool_response 里的每个字符串叶子（图片 data URL 只计数）
    ↓
AES-GCM 加密落盘（DPAPI 保护密钥），得到记录 ID
    ↓
本地四层 DLP 扫描 + 工具动作策略（仅工具调用）
    ↓
按部署策略归并证据 → ALLOW：输出空，放行
                   REVIEW：拒绝，附一次性批准码
                   BLOCK／任何异常：拒绝
    ↓
审计行（加锁追加，按大小轮转）；写不进去则拒绝
```

**取叶子而不是取序列化串**是本轮修掉的一个真实漏洞：原来把 `tool_input` 整体 `json.dumps` 后扫描，`password="x"` 变成 `password=\"x\"`，`ASSIGNED_SECRET` 因此漏掉——同一个密钥写在输入框里会拦，放进 Shell 命令就放行。

## 5. 识别与动作策略

### 5.1 内容引擎的修补

本轮对[内容引擎](../../src/transpect_trace/protect/content_dlp.py)做了以下修补，每一条都有对应测试：

- **规范化形式。** 在原文、base64／hex 解码形式之外增加一种"改写形式"：NFKC 折叠全角、删除零宽与方向控制字符、去掉 Shell／JSON 转义和引号。它不是解码，命中仍用原规则编号、不加解码分。修之前，`password＝…`（全角等号）、`AKIA` 中间插零宽空格、`{"password": "…"}`（JSON 配置，引号挡在键名和冒号之间）三种写法**全部放行**。
- **厂商凭据前缀规则。** GitHub、OpenAI、Anthropic、`sk-` 系（含 DeepSeek 等国内厂商）、Slack、Google、阿里云、腾讯云、Stripe、JWT、`Bearer`、带密码的连接串。修之前 `ghp_…`、`sk-proj-…` 只命中仅记录的 `ENTROPY_TOKEN`，门控放行；`mysql://root:密码@host` 只命中 `EMAIL`。
- **中文 PII。** 新增带标签的姓名（须以常见姓氏开头）与省市区门牌地址；单独出现低于 REVIEW 阈值，与手机号等组合后按 noisy-OR 升为拒绝。
- **压误报。** 浮点数小数部分（`"score": 0.4111…`）不再当作卡号／身份证；高熵上下文词改为整词匹配（`tokenizer/…`、`max_tokens` 不再算 `token`），三段以上路径和超过 256 字符的串不被上下文词提升；`token = self.config.api_token` 这类右侧是代码引用的赋值不算密钥。

### 5.2 工具动作策略

[工具策略](../../src/transpect_trace/protect/tool_policy.py)判断调用**会触达什么**，补内容引擎看不到的动作：

- `SENSITIVE_PATH`：SSH 私钥、`.aws/credentials`、`.git-credentials`、`.codex/auth.json`、浏览器凭据库等强规则直接拒绝；`.env`、`*.pem`、`secrets.*`、`.npmrc`、`*.tfstate` 等弱规则给 REVIEW。`.env.example` 和写 `.gitignore` 不算。
- `NETWORK_EGRESS`：按数据方向判断，而不是"用了网络工具就拦"。HTTP **上传**到非白名单主机、`scp`/`ssh`/`rsync` 到公网主机、`python -c`／`node -e` 联网、`Send-MailMessage`、`npm publish`、`git remote add`、`git push <URL>` 会拦；私网、回环、CGNAT 地址和 SSH 别名不算。初版"有网络工具且目的地非白名单或不可识别就拦"在本机工具历史上拒绝了 **14%** 的调用（几乎全是 `ssh` 到 SSH 别名和普通下载），按方向重写后出口规则只涉及 33/30,143 次调用（0.11%）。
- `GATE_TAMPER`：命令里出现 `hooks.json`、`config.toml`（信任状态所在）或门控目录，直接拒绝——Agent 改掉这几个文件就能关掉后续所有门控。

这些是词面规则，脚本落盘后再执行、字符串拼接、未列出的程序都能绕过；它们缩小明显路径，不替代网络边界。

### 5.3 分类别动作

引擎报告**全部**证据，门控只对其中一部分动作。默认执行类别：`SECRET`、`PII`、`INTERNAL_DOC`、`SOURCE_CODE`、`INSPECTION_ERROR`、`SENSITIVE_PATH`、`NETWORK_EGRESS`、`GATE_TAMPER`；仅记录的规则：`CODE_STRUCTURE`、`ENTROPY_TOKEN`、`IMAGE_UNINSPECTED`。理由同前：编码助手天天收到源码，无佐证的高熵串在开发流量里大多是哈希。

### 5.4 REVIEW 的一次性批准

`REVIEW` 表示"常见合法、但不确定"。原来它和 `BLOCK` 一样无路可走，现在[拒绝理由里附一个 6 位批准码](../../src/transpect_trace/protect/review_override.py)：

- 输入框被拦：在原文末尾另起一行写 `#dlp-approve <码> <理由>` 重新发送；
- 工具调用或工具输出被拦：用户回复 `#dlp-approve <码> <理由>`，再让 Agent 重试同一操作。

批准码与**内容的带密钥摘要**、会话、事件类型绑定，10 分钟过期，只能用一次（原子重命名消费）。`BLOCK` 永远不发码，伪造的码对 `BLOCK` 无效。只有 `UserPromptSubmit` 能兑现或授权批准码——模型在拒绝理由里能看到码，但它无法替用户提交输入。理由文字本身也经过检查，并写入审计。

## 6. 误报与检出：用本机真实历史量

### 6.1 输入框（`UserPromptSubmit`）

[测量脚本](../../scripts/measure_codex_gate_false_positives.py)回放本机 rollout 里全部 `role=user` 文本，只输出计数。早先 262 个会话、2,847 条 prompt 上的调整过程（37.41% → 0.63%）见下表；本轮复测时历史已增至 291 个会话、2,943 条：

| 阶段 | 门控拒绝率 | 主要来源 |
| --- | ---: | --- |
| 初始规则 | 37.41% | `ENTROPY_TOKEN` 1,027、`PAYMENT_CARD` 73 |
| `ENTROPY_TOKEN` 改为仅记录 | 3.62% | `PAYMENT_CARD` 71 |
| 银行卡增加发卡行号与分组校验 | 1.12% | `ENTROPY_TOKEN_CONTEXT` 20、`ASSIGNED_SECRET` 12 |
| 高熵上下文词改为凭据短语 | **0.63%**（18/2,847） | `ASSIGNED_SECRET` 13、`ENTROPY_TOKEN_CONTEXT` 6 |
| 本轮修改前，扩大后的历史 | 1.05%（31/2,943） | — |
| **本轮修改后** | **0.92%**（27/2,943） | 与修改前同盐摘要逐条比对：**没有新增**被拒 prompt，4 条原被拒的不再拒绝（来自整词上下文匹配） |

### 6.2 工具调用与工具输出（新增）

[工具测量脚本](../../scripts/measure_codex_gate_tool_false_positives.py)把 rollout 里的每次工具调用和输出重建成客户端会发的 Hook 事件，走与门控相同的 `inspection_target` 和动作判定。桌面端 code-mode 的 `exec` 是一段 JavaScript，客户端为其中每个嵌套调用各触发一次 Hook，脚本按此拆出嵌套的 `cmd`。

| 事件 | 条数 | 初版拒绝率 | 本轮最终 | 其中：其他项目 | 其中：本仓库会话 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `PreToolUse` | 30,143 | 14.56% | **0.47%** | 0.36% | 0.49% |
| `PostToolUse` | 32,105 | 5.12% | **2.88%** | 1.68% | 5.50% |

本仓库会话的输出拒绝率偏高是预期的：这些会话一直在读 DLP 测试夹具和合成密钥。其他项目的工具输出 1.68%（370/22,007）是需要继续压的部分，按决定性规则拆开：`ENTROPY_TOKEN_CONTEXT` 183、`ASSIGNED_SECRET` 161，其余为零星的证件与卡号。这里的"拒绝"是**候选误报**，不是已确认的误报——工具输出里本来就可能有真实凭据，需要按会话和摘要逐条复核。在复核完成前，建议对 `PostToolUse` 先用 `observe` 模式运行一段时间。

### 6.3 固定公开语料复测

对[评测记录](desktop-dlp-evaluation.md)中的四套固定语料做了修改前后对照（两侧均强制导入各自版本的引擎）。没有任何标注类别的检出下降；中文语料检出显著上升（中文正式文本中有地址标注、却被放行的行从 537 降到 104，银行卡从 110 降到 0）；英文留出集 ai4privacy 的门控动作**完全不变**（7.90%，脱敏副本 1.54%）；Gretel 脱敏副本的拒绝从 12 升到 17（0.24% → 0.34%），新增命中来自规范化后才匹配的 JSON 式赋值。合成夹具混淆矩阵不变。

## 7. 健康检查与对账：发现门控失效

客户端有三种**静默**失效：未信任的 Hook 被跳过、Hook 进程启动失败后照常发送、`hooks.json` 被改或被删。[健康检查](../../scripts/check_codex_gate_health.py)逐项检查：

| 检查 | 内容 |
| --- | --- |
| `install` | `hooks.json` 里每个门控事件都有本门控的组，命令与安装时一致 |
| `trust` | `config.toml` 里对应组都有信任条目 |
| `integrity` | 门控源码与原生客户端的 SHA-256 与安装清单一致（信任哈希不覆盖代码） |
| `tamper` | 当前用户能否改门控代码、解释器、配置和 `hooks.json`；能改即判 FAIL，避免报告被读成"防篡改" |
| `service` | 常驻服务是否应答 |
| `coverage` | **对账**：transcript 中每个由人发起的轮次都必须有本门控的 `UserPromptSubmit` 审计行；每个有工具调用的轮次都必须有 `PreToolUse` 行；被放行的调用还必须有 `PostToolUse` 行。缺一个，就是一个门控没看到内容的轮次 |

对账依赖审计行里新增的 `session_id`、`turn_id`、`tool_use_id`（只有 ID，不含内容）。实测：在同一私有 `CODEX_HOME` 里跑 6 个用例，其中 1 个故意不带信任绕过参数（Hook 被跳过），对账**恰好**标出这 1 个轮次，其余 5 个全部对上。

## 8. 常驻服务与延迟

原来每个事件冷启动一次 Python。加上 `PostToolUse` 后，每次工具调用要过两个事件。现在 Hook 命令改为一个[原生小客户端](../../native/protect/codex_gate_client.c)，把事件通过命名管道交给[常驻服务](../../src/transpect_trace/protect/codex_gate_service.py)：

| 事件 | 每事件 Python | 原生客户端 + 服务 | 服务不在时（回退到 Python） |
| --- | ---: | ---: | ---: |
| 一条 prompt | 110 ms | **20 ms** | 142 ms |
| 20 KB 工具输出 | 123 ms | **46 ms** | 149 ms |

（端到端进程启动到退出，p50，15 次。）

失败语义：服务不可达、超时或应答异常 → 客户端改跑每事件 Python 门控（同一策略，故障即拒）→ Python 也起不来 → 客户端按事件名写出内置拒绝。**服务停掉只多花时间，不会放行。**服务首个管道实例用 `FILE_FLAG_FIRST_PIPE_INSTANCE` 创建，名字已被占用就拒绝启动；管道 DACL 只允许当前用户和 SYSTEM。它挡不住**同一用户**的其他进程抢先占用管道名——这与门控文件对当前用户可写是同一条信任边界。

## 9. 本机联调证据

### 9.1 覆盖面实测（本轮）

[覆盖探针](../../scripts/probe_codex_hook_coverage.py)：私有 `CODEX_HOME`，固定后端，原生客户端 + 常驻服务，脚本化本地源站。判定看**源站实际收到的字节**：

| 用例 | 客户端 | 源站收到 | 结论 |
| --- | --- | --- | --- |
| 普通文件读取 | 三个事件都 `Completed` | 2 个请求，文件内容在内 | 正常放行 |
| prompt 带假 GitHub 令牌 | `UserPromptSubmit Blocked` | **0 个请求** | 拦住 |
| 无害命令读出含令牌的文件 | `PreToolUse Completed`，`PostToolUse Blocked` | 2 个请求，**标记和令牌都没上行** | 工具输出被替换 |
| `Get-Content .env` | `PreToolUse Blocked` | 2 个请求，文件内容未上行 | 动作被拒 |
| `view_image` 带标记的 PNG | `PostToolUse Completed` | 图片上行 | 按设计放行，审计记 `IMAGE_UNINSPECTED` |
| 未信任 Hook | 没有任何 Hook 行 | 2 个请求，内容上行 | 静默失效；**健康检查标出该轮** |

### 9.2 受信任路径实测（真实 `CODEX_HOME`、真实凭据、无 bypass；上一轮）

| 用例 | 时间 (UTC) | 门控判定 | 客户端 | 模型是否应答 |
| --- | --- | --- | --- | --- |
| 合成假密钥 prompt | `09:09:57` | `BLOCK`，`ASSIGNED_SECRET`+`ENTROPY_TOKEN`，16 ms | `hook: UserPromptSubmit Blocked` | 无模型轮次 |
| 普通 prompt | `09:10:56` | `ALLOW`，零命中，16 ms | `hook: UserPromptSubmit Completed` | 模型回 `OK`，`tokens used 9,366` |

同一审计文件里 `09:08:23` 有一条来自桌面界面输入框的 `UserPromptSubmit` `ALLOW`，解密后是界面里敲的中文 prompt，说明界面输入也在门控内。弱点照实记下：界面路径只验证了"检查并放行"，没有观测到界面侧的一次拦截；`PostToolUse` 与常驻服务目前只在 `codex exec` 上验证，桌面界面上尚未重做。

## 10. 没有闭合的缺口

- **界面附件**：Hook 里没有附件事件。`PreModelRequest` 记录 `ungated_attachments` 计数，只能发现，不能拦。
- **长时命令的中间输出**：命令在 yield 窗口内已返回的输出块，在 `PostToolUse` 触发前已经上行。
- **客户端注入的项目说明**（`AGENTS.md` 等）：不经过任何 Hook。
- **Hook 启不动时客户端故障放行**：门控把自身所有失败都转成拒绝，但门控进程如果根本不存在（`hooks.json` 被删或不被信任），就没有门控。健康检查能发现，不能阻止。
- **防篡改**：门控代码、解释器、配置和 `hooks.json` 对当前用户可写，这是按策略执行，不是安全边界。把它们放到管理员拥有的目录需要管理员权限，本轮未做；健康检查的 `tamper` 项如实报告。
- **机器级强制层本版不可用**：`hooks.windows_managed_dir` 指向 Hook 目录后既不加载任何 Hook，也不报诊断。
- **工具进程自建连接**：`NETWORK_EGRESS` 只是词面规则。进程级网络边界见 [WFP 方案](desktop-wfp.md)，该方案要求在独立虚拟机里用专用账户运行，本轮**没有**接到本机桌面端——在本机现用账户上装默认拒绝规则会切断该账户的网络。
- **语义改写**：四层识别都是词面／结构层，纯语义改写的内部文档抓不到。

## 11. 安装与撤销

```powershell
# 构建原生客户端（一次）。
uv run --no-sync python scripts/build_codex_gate_client.py

# 写入 <CODEX_HOME>/hooks.json（含 PostToolUse），记录安装清单；
# --register-service 注册当前用户登录时启动的常驻服务计划任务。
uv run --no-sync python scripts/install_codex_hook_gate.py --layer user --mode enforce --client native --register-service

# 先量误报再开 enforce；--mode observe 只记录不拦。
uv run --no-sync python scripts/measure_codex_gate_false_positives.py
uv run --no-sync python scripts/measure_codex_gate_tool_false_positives.py

# 健康检查与对账（定期运行，失败退出码 1）。
uv run --no-sync python scripts/check_codex_gate_health.py --service

# 覆盖面实测。
uv run --no-sync python scripts/probe_codex_hook_coverage.py `
  --backend $env:LOCALAPPDATA\OpenAI\Codex\bin\<id>\codex.exe `
  --output runs/codex-hook-coverage-live-$(Get-Date -Format yyyyMMdd-HHmmss)

# 撤销。
uv run --no-sync python scripts/install_codex_hook_gate.py --remove
```

装好或改动 `hooks.json` 后**必须**重启 Codex 并接受 Hook 审阅提示，否则 Hook 被静默跳过。`--registration <目录>` 可接入私有 EDM 记录与文档／源码指纹，启用完整四层；不传则只有规则与熵两层生效。
