# Demo：AI 工具输入输出审计与拦截

本文给出四层内容识别引擎的可复现离线 Demo，并按**时效性、拦截成功率、性能、防绕过**四个维度报告合成样本结果。实际请求采集与发送前阻断由独立的门控组件负责；本 Demo 尚未将四层引擎接入这些组件。

脚本直接检查内置合成文本，并自行创建一个本地 `.py` 文件供文件检查。它不读取真实 Codex 请求，也不执行文件上传。另有已独立验证的 HTTPX 发送前门控，但该门控目前使用原有 `ProtectionEngine`，没有调用本 Demo 的 `ContentDLPEngine`。整体项目模块见 [README](../README.md)。

## 运行

```powershell
# 四维度报告：检出矩阵 + 对抗矩阵 + 本地文件样本 + 性能基准
uv run --no-sync python scripts/demo_io_audit.py --iterations 3000

# 内容识别 DLP 引擎（本地多层：规则+校验+上下文 / 熵 / EDM / 指纹）
uv run --no-sync python scripts/demo_content_dlp.py
```

Demo 报告写入 `runs/demo-io-audit/report.json`（UTF-8）。

旧 HTTPX 门控的独立验证可通过以下入口查看；这些结果不证明四层引擎已接入：

```powershell
# 单元：Python 出站桥接的发送前门控
uv run --no-sync python -m pytest tests/test_python_outbound_bridge.py

# 端到端：Codex 读知识库→写邮件→HTTPX 门控（放行入 Mailpit / 拒绝被拦）
# 见 docs/development/knowledge-mail.md
uv run --no-sync python scripts/probe_knowledge_mail.py --help
```

## 技术通道

本 Demo 的采集方式是直接把合成字符串传给 `ContentDLPEngine.inspect()`，以及将脚本生成的本地文件传给 `inspect_file()`。这里没有安装 Codex Hook，也没有启动网络请求。

独立的 `python-httpx-native/1` 适配器在受控 CPython/HTTPX 进程的 `handle_request` / `handle_async_request` 处取得 JSON 请求正文，并在发送前调用旧 `ProtectionEngine` 判定。它的拦截验证说明该门控位置可以阻断相应 Python 请求，但不能作为新四层引擎已经拦截真实请求的证据。

## 四个维度的结果与口径

### 1. 时效性（离线判定耗时与独立门控证据）

四层引擎同步返回判定；本 Demo 没有传输调用，因此不能测量真实请求从提交到阻断的完整时延。旧 HTTPX 门控另有以下发送前验证：

- **构造上**：`src/transpect_trace/protect/python_bridge.py` 中 `authorize()` 在
  `original_sync(...)` 之前执行，拒绝时不调用原传输函数。该路径尚未接入四层引擎。
- **独立证据**：`probe_protect_python.py` 用一个受控 TLS 源站做 oracle，核对被拒
  请求在源站侧收到的字节数为 `0`（`denied_origin_body_bytes == 0`）。该探针属
  “experimental_controlled_start”，有受控启动祖先校验前置条件，对解释器启动方式
  敏感；请按上文命令**直接运行**，不要在其它脚本里嵌套调用。

下文性能数字仅测量合成内容的进程内检查耗时，不包含请求采集、跨进程判定或传输。

### 2. 拦截成功率

Demo 用一个带标注、覆盖四类敏感数据的合成语料跑检出矩阵（`scripts/demo_content_dlp.py`）：

| 类别 | 样本 | 命中层 | 期望 |
| --- | --- | --- | --- |
| 密钥 SECRET | AWS 密钥对、PRIVATE KEY 块、未知格式高熵 token | 规则/熵 | `BLOCK` |
| 内部文档 INTERNAL_DOC | 已知内部文档片段 | 指纹 | `BLOCK` |
| 源代码 SOURCE_CODE | 专有函数片段 | 指纹/代码启发 | `BLOCK` |
| 个人信息 PII | 员工姓名+工号+SSN（同一条记录佐证） | EDM | `BLOCK` |
| 良性 | 公开中文文本、公开单行代码、掩码口令 `********`、占位符 `${API_KEY}`、单独常见人名 | — | `ALLOW` |

当前实测：敏感 6/6 识别（全部 `BLOCK`）、良性 5/5 放行。这是**覆盖内检出率**的小样本
展示，不等于总体检出率；正式盲测与更多数据类别需单列。非 UTF-8/二进制上传记为
`REVIEW`（OCR/二进制解析不在本轮范围），属安全动作，不计入检出成功。

### 3. 性能

Demo 对内容识别引擎 `ContentDLPEngine.inspect()` 做进程内延迟基准（64 KiB 主负载，
预热后 N 次）：报告 P50/P95/P99 与试点预算（P95 ≤ 50 ms，P99 ≤ 100 ms）对照。
多层融合比单一正则重，参考机实测 P95 约 20–45 ms，达标。

口径诚实边界：该数字是**内容检查**耗时，不含跨进程 IPC 与 TLS。方案要求的
“输入新增门控耗时”为含复制/IPC/审计的端到端值，需在真实设备上单列压测；
本基准只刻画检测流水线本身的分布。

### 4. 防绕过（重点）：内容识别为什么不止正则

纯正则一改写/一编码就失效。本 Demo 的内容识别是**本地多层融合**（`scripts/demo_content_dlp.py`），
对标现代 DLP（Purview / Google Sensitive Data Protection / Nightfall），四层互补：

1. **规则 + 校验器 + 上下文**：正则命中结构化标识后，用校验位（信用卡 Luhn）压假阳性、
   用**邻近关键词**（附近出现 `secret`/`身份证`/`ssn` 等）加权；并先对 **base64/hex 规范化
   解码**再匹配，抹掉"换个编码就绕过"。掩码 `********`、占位符 `${API_KEY}` 识别为良性。
2. **熵分析**：长高熵 token 即使**不符合任何已知格式**也判为疑似密钥——抓正则抓不到的新密钥。
3. **EDM 精确数据匹配**：把企业**自有记录**（员工表）本地哈希后比对；要求**同一条记录的多个
   字段同时命中**（姓名+工号+SSN 的佐证）才给高分，既准又少误报，原始数据不出本地。
4. **文档/源码指纹（IDM）**：对已知内部文档/源码做 k-gram shingle，检测**片段/部分拷贝**；
   另有结构启发式标记未登记的新源代码。

各层输出按 **noisy-OR 融合**成每类置信度，再按阈值给 `BLOCK` / `REVIEW` / `ALLOW`；任一检查器
抛异常即判 `BLOCK`（**故障即拒**，绝不静默放行）。全部本地执行——**不把内容送到云端分类器，
避免"为了识别而先外泄"的数据暴露悖论**。

**必须声明的漏检（Demo 不掩盖）**：**纯语义改写/转述**（把机密内容换一套词重写）不改字面，
①-④ 都是词面/结构层，因此**漏检**（对抗矩阵中 `paraphrased_internal_doc` 明确标 MISS）。这需要
**语义层**——向量相似度（Sentence-BERT）或本地微调 LLM 分类器——是**下一轮**要补的能力。
此外 OCR/二进制附件解析不在本轮范围，非 UTF-8 上传记为 `REVIEW`。

## 为什么没把官方 Codex CLI 作为 Demo 主通道，以及重钉流程

Codex 原生门控（`ttrace guard`）把发送路径的函数地址（RVA）与精确 SHA-256 固定在
`codex-cli 0.162.0-alpha.17.2`。本机已升级到 `0.163.0`，旗舰通道因此失效——
`npm update` 即构成一次绕过。因此 Demo 主通道选在已独立验证、与具体客户端版本无关的
HTTPX 门控上。

本轮把 Codex 通道改造成**可维护的重钉流程**（数据驱动，不再改 C 源）：

1. **静态发现**：对新 `codex.exe`（`scripts/discover_codex_hooks.py` 会自动把 npm
   启动壳 `codex.cmd` 解析为真实 PE）用版本稳定字符串锚点 + PE unwind 范围定位发送
   路径函数，产出候选适配器：

   ```powershell
   uv run --no-sync python scripts/discover_codex_hooks.py `
     --emit-adapter deploy/guard/codex-windows-x64-<version>.json `
     --version-label "codex-cli <version>"
   ```

   候选适配器 `status=candidate_unvalidated`，`validation_required` 列出仍需确认项。

2. **动态校验**：对新二进制跑动态 Frida 夹具（受控 TLS 源站、合成标记、无真实账号），
   确认函数布局、错误路径标签与 `owned_headers_drop_rva`；通过后把 drop RVA 写入
   适配器并将 `status` 置为 `validated`。

3. **受限重建**：`scripts/build_guard_native.py --adapter <validated.json>` 从适配器取
   RVA/哈希作 `-D` 编译定义构建 DLL；该步骤**拒绝**未验证候选，防止用占位地址构建出
   Hook 错位代码的 DLL。

`native/guard/guard.c` 的默认 RVA 用 `#ifndef` 保护（默认仍是 0.162 固定点）；
`deploy/guard/codex-windows-x64.json` 为已验证适配器，`deploy/guard/codex-windows-x64-0.163.0.json`
为本机 0.163 的候选（HTTP 入口前缀与旧点一致、WSS 函数已位移，待动态校验）。覆盖见
`tests/test_guard_repin.py`。完成 0.163 重钉仍需上述动态校验——这属于固定版本方案
固有的脆弱点，也是不把它作为一次性 Demo 主通道的原因。
