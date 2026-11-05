# 用 Codex 自带 Hook 做发送前 DLP 门控

本机现用 Codex 客户端自带一套**受支持的命令 Hook 机制**。它不需要 Frida、不修改 Codex 源码、不使用转发代理，也不是短时研究探针：装好并经用户批准信任后，它对该 `CODEX_HOME` 下的每次提交持续生效。本文只写**在本机实测确认**的行为，并明确标出未闭合的缺口。

固定对象：MSIX `OpenAI.Codex 26.1029.7803.0`，内置后端 `codex-cli 0.166.0-alpha.6`，`codex.exe` SHA-256 `925c7d0665ffa49b0dcf748e034a805a04da984164ac92301432073b47789b99`。换版后以下 RVA 无关的结论仍需重新核对。

## 1. 客户端提供的 Hook 事件与契约

后端内嵌 draft-07 JSON Schema，[提取脚本](../../scripts/extract_codex_hook_schemas.py)按固定哈希从镜像读出，共 23 份（11 个事件的 `command.input`／`command.output`）。因此门控是**按客户端自己的契约**写的，不是按我们的猜测。契约夹具固定在 [tests/fixtures/codex_hooks/pinned-hook-schemas.json](../../tests/fixtures/codex_hooks/pinned-hook-schemas.json)，由[契约测试](../../tests/test_codex_hook_contract.py)校验门控的每个回复。

事件枚举共 15 个（`PreModelRequest`、`PostModelRequest`、`PreToolUse`、`PermissionRequest`、`PostToolUse`、`PreCompact`、`PostCompact`、`SessionStart`、`SessionEnd`、`UserPromptSubmit`、`SubagentStart`、`SubagentStop`、`Stop`、`Interrupt`、`SettingsImport`）。其中与外发防护相关的三个，实测能力如下：

| 事件 | 本机实测结论 | 角色 |
| --- | --- | --- |
| `UserPromptSubmit` | 返回 `{"decision":"block","reason":...}` 后，客户端打印 `hook: UserPromptSubmit Blocked`，该轮**没有任何模型请求**，也没有到达源站。 | **执行**：真实输入框提交的内容门控 |
| `PreToolUse` | 返回 `hookSpecificOutput.permissionDecision = "deny"` 加非空 `permissionDecisionReason` 即拒绝该次工具调用。本版**拒绝** `permissionDecision: allow/ask`、`decision: approve`、`continue:false`、`stopReason`、`suppressOutput`；`updatedInput` 必须配 `permissionDecision: allow`，因此也用不了。 | **执行**：Agent 工具调用的内容门控 |
| `PreModelRequest` | 每次模型请求前都触发（含重试）。载荷**只有元数据**（`session_id`、`turn_id`、`cwd`、`model`、`transcript_path`），**没有请求正文**。返回 block 决定时客户端打印 `Completed` 并照常发送。 | **观察**：请求计数与取证，不能拦 |

没有任何事件对应**界面附件**。桌面端添加文件这条路径在 Hook 机制里不存在，本门控不覆盖。

## 2. 配置、信任与两个硬约束

Hook 从 `<CODEX_HOME>/hooks.json`（JSON）或 `config.toml` 的 `[hooks]` 表（TOML，键名为 `user_prompt_submit` 等蛇形）读取。JSON 形状经客户端自身报错逐层确认：

```text
{ description?, hooks: { <Event>: [ { matcher?, description?,
    hooks: [ { type: "command", command, commandWindows?, async?,
               statusMessage?, additionalContextLimit? } ] } ] } }
```

**约束一：必须经用户批准信任。** 未信任的 Hook 被**静默跳过**——没有告警、没有日志，请求照常发出。本机实测：装好 `hooks.json` 后直接 `codex exec`，带假密钥的 prompt 原样发往模型且工具正常执行。`--dangerously-bypass-hook-trust` 可为单次调用绕过信任；常态启用必须在 Codex 界面接受一次启动时的 Hook 审阅提示（客户端内部以内容哈希记录在 `hooks.state` 下）。**装好 ≠ 生效**，这一步不能省。

**约束二：`command` 按空白切分，不认引号。** 实测六种写法，带双引号的那一种失败，其余五种（`.cmd` 包装、正反斜杠、`cmd /c`）都正常。因此命令行里**任何路径都不能含空格**；[安装脚本](../../scripts/install_codex_hook_gate.py)在写入前校验这一点并拒绝带空格的路径。

`async = true` 的处理器不阻塞；需要决定的事件会被降级为同步执行。因此 `PreModelRequest` 以 `async` 注册——它拦不住，不该给每次请求都加延迟。

## 3. 门控的处理顺序

[门控实现](../../src/transpect_trace/protect/codex_hook_gate.py)对每个可执行事件的顺序是：

```text
读取 stdin 上的完整 Hook 事件（上限 8 MiB）
    ↓
取出该事件真正能上线的字节：UserPromptSubmit 取 prompt；
PreToolUse 取 tool_name 加确定性序列化的 tool_input
    ↓
AES-GCM 加密落盘（DPAPI 保护密钥），得到记录 ID
    ↓
本地四层 DLP 扫描
    ↓
按部署策略归并证据 → ALLOW：输出空，放行
                   REVIEW/BLOCK/任何异常：输出客户端接受的拒绝 JSON
```

门控**自身**对每条路径故障即拒：事件读不出、配置缺失、归档失败、扫描异常、审计日志写不进去，都返回拒绝。审计行只写规则编号、类别分数和归档记录 ID，不写任何被检内容；[测试](../../tests/test_codex_hook_gate.py)直接断言假密钥不出现在审计文件里。

## 4. 分类别动作：为什么不能把引擎判定直接当成拦截

引擎报告**全部**证据，门控只对其中一部分动作。两者必须分开报，否则会把拦截率说高。默认：

- 执行类别：`SECRET`、`PII`、`INTERNAL_DOC`、`SOURCE_CODE`、`INSPECTION_ERROR`
- 仅记录不拦的规则：`CODE_STRUCTURE`、`ENTROPY_TOKEN`

理由是实测出来的，不是拍的。`CODE_STRUCTURE` 是"这看起来像源码"的结构启发式——编码助手本来就天天收到源码，用它拦等于拦掉一切；**已登记**源码的指纹命中（`FINGERPRINT:*`，类别 `SOURCE_CODE`）仍然拦，那才是自有代码外流的信号。`ENTROPY_TOKEN` 是无佐证的高熵串，在开发流量里绝大多数是 commit SHA、包哈希和不透明 ID；带凭据词的 `ENTROPY_TOKEN_CONTEXT` 以及只在解码后才出现的 `ENTROPY_TOKEN_DECODED` 仍然拦。

## 5. 用本机真实 prompt 历史调出来的误报率

启用 enforce 之前必须知道它会拦掉多少正常工作。[测量脚本](../../scripts/measure_codex_gate_false_positives.py)读本机 `~/.codex/sessions` 的 rollout 记录，取出全部 `role=user` 文本，用与门控完全相同的引擎和策略回放，**只输出计数**：报告里没有 prompt 原文，也没有片段，每行只有随机盐的摘要加命中的规则编号。

262 个会话、2,847 条真实 prompt：

| 阶段 | 门控拒绝率 | 主要来源 |
| --- | ---: | --- |
| 初始规则 | **37.41%**（1,065 条） | `ENTROPY_TOKEN` 1,027、`PAYMENT_CARD` 73 |
| `ENTROPY_TOKEN` 改为仅记录 | 3.62% | `PAYMENT_CARD` 71 |
| 银行卡增加发卡行号校验 | 2.49% | 仍有 `PAYMENT_CARD` |
| 银行卡增加分组格式校验 | 1.12% | `ENTROPY_TOKEN_CONTEXT` 20、`ASSIGNED_SECRET` 12 |
| 高熵上下文词改为凭据短语 | **0.63%**（18 条） | `ASSIGNED_SECRET` 13、`ENTROPY_TOKEN_CONTEXT` 6 |

两处规则修复的依据都是实测出来的具体误报：

- **银行卡。** 仅靠 Luhn 太弱——随机数字串约十分之一能过。实测的 160 条误报形如 `2265123456-7890`：前四位落在 Mastercard 2 系区间且 Luhn 通过，但它是"十位加四位"的业务编号，不是卡号。现在同时要求**发卡行号**和**卡号书写分组**（连写、四位分组、或 Amex 的 4-6-5）。
- **高熵上下文。** 原来把裸词 `key`、`password` 当凭据上下文；开发者散文里 `primary key`、`key name` 遍地都是。换成 `api key`、`secret key`、`access_key`、`bearer`、`密钥` 等凭据短语后，上下文高熵命中从 59 条降到 6 条。

**这两处修改没有牺牲检出。** 在固定公开语料上，银行卡类标注的行级拒绝数完全不变：Gretel 549/571、中文正式 752/862、中文聊天 333/504。详见[评测记录](desktop-dlp-evaluation.md)。

同一轮还修掉一个**真实检出缺陷**：熵分析原先只扫原始文本，不扫 base64/hex 解码后的形式。`hex_encoded_secret` 这个对抗样本以前"被拦住"，其实是解码前的十六进制串里偶然出现一段 13 位数字通过了 Luhn——换句话说是靠误报蒙对的。修掉银行卡规则后它立刻变成 ALLOW。现在熵分析对所有规范化形式都跑，解码后才出现的高熵串单独计为 `ENTROPY_TOKEN_DECODED`（分数更高），base64 与 hex 包装的假密钥都是**真正**被拦。`ASSIGNED_SECRET` 的正则也从"关键词紧贴等号"放宽到允许关键词出现在更长的标识符里，这样 `aws_secret_access_key=`、`GITHUB_TOKEN=` 才会命中——原先这两种最常见的真实写法是漏的。

## 6. 本机联调证据

[实测探针](../../scripts/probe_codex_hook_gate.py)用私有 `CODEX_HOME` 跑固定后端，每个用例交叉核对三件独立事实：客户端自己打印的 Hook 结果、门控的审计行、以及该轮是否真的发出过模型请求（按门控 `PreModelRequest` 审计行计数，不看控制台，因为 async 处理器不打印）。

| 用例 | 门控判定 | 客户端 | 模型请求数 | 源站 |
| --- | --- | --- | ---: | --- |
| 合成假密钥 prompt | `BLOCK`，命中 `ASSIGNED_SECRET`、`ENTROPY_TOKEN` | `UserPromptSubmit Blocked` | **0** | 未接触 |
| 普通 prompt | `ALLOW` | 未拦 | 8 | 返回 401 |

两个用例在同一套配置里只差 prompt 内容。普通用例确实发出了请求并被真实源站以 401 拒绝，这说明被拦用例的"零请求"不是环境坏掉的假象。源站侧的零字节仍**没有**独立证明：请求是否发出是按客户端自身的事件和报错推断的，不是由收件端确认的。

### 6.1 受信任路径实测（真实 `CODEX_HOME`、真实凭据、无 bypass）

上面的探针用的是私有 `CODEX_HOME` 加 `--dangerously-bypass-hook-trust`，只证明了契约正确，没有证明常态部署生效。信任批准落盘后（`config.toml` 的 `hooks.state."<hooks.json 路径>:<event>:0:0".trusted_hash`，三个事件各一条）补了一次**不带任何 bypass 参数**的实测，用默认 `CODEX_HOME`（`~/.codex`，已登录凭据）跑同一个固定后端：

| 用例 | 时间 (UTC) | 门控判定 | 客户端 | 模型是否应答 |
| --- | --- | --- | --- | --- |
| 合成假密钥 prompt | `09:09:57` | `BLOCK`，`ASSIGNED_SECRET`+`ENTROPY_TOKEN`，类别 `SECRET`，16 ms | `hook: UserPromptSubmit Blocked` | 无模型轮次，`tokens used` 未出现 |
| 普通 prompt | `09:10:56` | `ALLOW`，零命中，16 ms | `hook: UserPromptSubmit Completed` | 模型回 `OK`，`tokens used 9,366` |

良性对照拿到了真实应答并计费，所以被拦那条的未送达不是环境失效。两条相隔 59 秒，配置完全相同。

**桌面界面本身也在门控内**，这一条是从归档内容反查确认的：同一审计文件里 `09:08:23` 有一条 `UserPromptSubmit` `ALLOW`，解密后是界面输入框里敲的中文 prompt（88 个汉字，UTF-8 无损，无替换字符），不是任何 `codex exec` 用例发出的。界面输入会被逐条检查并归档。

两处取证弱点，照实记下：

- **界面路径只验证了"检查并放行"，没有观测到界面侧的一次拦截。** 命令行通道的拦截是直接证据，界面通道的拦截目前是按同一事件同一处理器推断的。
- **"本轮零模型请求"不能从审计切片独立得出。** 实测期间桌面会话同时在跑，共用同一个 `audit.jsonl`，那一分钟里的 `PreModelRequest`／`PreToolUse` 行大部分属于界面会话。本轮无请求的依据是客户端自身输出：block 后会话直接结束，没有模型轮次也没有 token 计费。

## 7. 没有闭合的缺口

- **界面附件完全没覆盖。** Hook 机制里没有附件事件，`UserPromptSubmit` 的 `prompt` 只有文本。桌面端添加的文件绕过本门控。
- **Hook 启不动时客户端是故障放行。** 实测把命令指向不存在的脚本：客户端打印 `UserPromptSubmit Failed` 后照常发送。门控内部故障即拒，但**门控进程本身跑不起来就等于没有门控**。防护依赖于门控代码与解释器所在路径的 ACL；本机这两个路径对当前用户可写，因此这是**按策略执行**，不是防篡改。
- **机器级强制层本版不可用。** `%ProgramData%\OpenAI\Codex\requirements.toml` 确实被读取（在里面放不被支持的键会报 ``requirements (...): `model` is ignored``），`hooks.windows_managed_dir` 也在客户端自己的 requirements 结构里，但指向 Hook 目录后既不加载任何 Hook 也不报任何诊断。因此**无法**在本版用本地文件做"用户不可绕过"的常驻强制；当前可靠路径仍是用户层加一次信任批准。安装脚本已把该层标为未验证。
- **工具进程直接开 socket 不受内容门控。** `PreToolUse` 按工具调用的内容拦，拦不住工具进程自己建立的连接。客户端另有 `[permissions.<name>.network]` 与 `[network_proxy]` 机制，`codex sandbox -P <profile>` 可在不调用模型的情况下验证；本轮只确认了默认配置下沙箱内命令**可以**连通本机收件器（1 次连接、164 字节），受限 profile 因需要 elevated Windows sandbox 后端尚未跑通。这条仍记为未闭合。
- **延迟。** 每个事件一个 Python 冷启动进程，实测端到端 p50 约 140 ms（裸解释器 43 ms；已把 `pypdf` 改为按需导入，省掉 53 ms）。`UserPromptSubmit` 每条消息一次可接受；`PreToolUse` 每次工具调用一次，在工具密集的任务里会累加。常驻门控服务加轻客户端是下一步，本轮没做。
- **语义改写仍是诚实漏检。** 四层都是词面／结构层，纯语义改写的内部文档抓不到。

## 8. 安装与撤销

```powershell
# 写入 <CODEX_HOME>/hooks.json；保留无关的既有 Hook。
uv run --no-sync python scripts/install_codex_hook_gate.py --layer user --mode enforce

# 先量误报再开 enforce；--mode observe 只记录不拦。
uv run --no-sync python scripts/measure_codex_gate_false_positives.py

# 本机联调证据。
uv run --no-sync python scripts/probe_codex_hook_gate.py `
  --backend $env:LOCALAPPDATA\OpenAI\Codex\bin\<id>\codex.exe `
  --output runs/codex-hook-gate-live-$(Get-Date -Format yyyyMMdd-HHmmss)

# 撤销。
uv run --no-sync python scripts/install_codex_hook_gate.py --remove
```

装好后**必须**重启 Codex 并接受 Hook 审阅提示，否则 Hook 被静默跳过。`--registration <目录>` 可接入私有 EDM 记录与文档／源码指纹，启用完整四层；不传则只有规则与熵两层生效。
