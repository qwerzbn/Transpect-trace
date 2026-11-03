# Demo：AI 工具输入输出审计与拦截

本文给出一个可复现的交付 Demo，业务目标是**对 AI 工具实际发送给模型的数据进行审计并拦截**，并按四个要求维度给出结果与边界：**时效性、拦截成功率、性能、防绕过（重点）**。

本 Demo 只覆盖**已独立验证**的一条同步门控路径（G1 请求发送前，HTTPX 通道），
其余通道（输出交付、工具执行、浏览器/桌面 UI、任意出口）仍为设计或未验证项，
Demo 不声称覆盖。所有样本均为合成假密钥。整体项目模块与边界见 [README](../README.md)。

## 运行

```powershell
# 自包含部分：检出矩阵 + 性能基准（确定性、可复现）
uv run --no-sync python scripts/demo_io_audit.py --iterations 3000
```

Demo 报告写入 `runs/demo-io-audit/report.json`（UTF-8）。

发送前拦截的独立证明在本分支由以下提供：

```powershell
# 单元：Python 出站桥接的发送前门控
uv run --no-sync python -m pytest tests/test_python_outbound_bridge.py

# 端到端：Codex 读知识库→写邮件→HTTPX 门控（放行入 Mailpit / 拒绝被拦）
# 见 docs/development/knowledge-mail.md
uv run --no-sync python scripts/probe_knowledge_mail.py --help
```

## 技术通道

被门控对象是 `python-httpx-native/1` 适配器：在受控启动的 CPython 3.12.10 +
HTTPX 0.28.1 进程内，于标准传输层 `handle_request` / `handle_async_request`
之前，对完整不可变请求正文做一次快照并提交本地 Native 门控判定；判定为拒绝时
在**调用原传输之前**抛出 `PermissionError`，原请求因此不出进程、不进 TLS。
身份绑定 CPython/libssl/HTTPX 的固定哈希（门控由 `scripts/build_python_gate.py` 构建并登记）。

## 四个维度的结果与口径

### 1. 时效性（发送前，同步）

门控是**同步**的，在传输调用之前完成判定——拒绝即正文不发送。这由两部分证明：

- **构造上**：`src/transpect_trace/protect/python_bridge.py` 中 `authorize()` 在
  `original_sync(...)` 之前执行，拒绝时直接抛错；Demo 的检出矩阵显示敏感正文在
  发送前即得到 `BLOCK` 判定。
- **独立证据**：`probe_protect_python.py` 用一个受控 TLS 源站做 oracle，核对被拒
  请求在源站侧收到的字节数为 `0`（`denied_origin_body_bytes == 0`）。该探针属
  “experimental_controlled_start”，有受控启动祖先校验前置条件，对解释器启动方式
  敏感；请按上文命令**直接运行**，不要在其它脚本里嵌套调用。

时延口径遵循方案第八节：以“完整不可变正文可供门控使用”为起点，不把等待模型
生成的时间计入门控耗时。

### 2. 拦截成功率

Demo 用一个带标注的小型合成语料跑检出矩阵（`scripts/demo_io_audit.py`）：

| 类别 | 样本 | 期望 |
| --- | --- | --- |
| 敏感 | AWS 密钥对、MySQL 口令、PRIVATE KEY 块、client_secret | 全部 `BLOCK` |
| 良性 | 公开中文文本、公开代码、掩码口令 `********`、占位符 `${API_KEY}` | 全部 `ALLOW` |

当前实测：敏感 4/4 拦截、良性 4/4 放行。这是**覆盖内检出率**的小样本展示，
不等于总体检出率；凭据/登记文本的正式盲测与其它数据类别需按方案第九节单列。
“因不支持而拒绝”（未知编码、二进制附件等）记为安全动作，不计入检出成功。

### 3. 性能

此前仓库没有任何基准；Demo 补上了对 `ProtectionEngine.evaluate()` 的进程内
延迟基准（64 KiB 主负载，预热后 N 次）：报告 P50/P95/P99 与试点预算
（P95 ≤ 50 ms，P99 ≤ 100 ms）对照。参考机实测 P95 约 3–9 ms，达标。

口径诚实边界：该数字是**内容检查**耗时，不含跨进程 IPC 与 TLS。方案要求的
“输入新增门控耗时”为含复制/IPC/审计的端到端值，需在真实设备上单列压测；
本基准只刻画检测流水线本身的分布。

### 4. 防绕过（重点）

**已设计的措施（在声明范围内）**：

- **故障即拒**：策略超时、解析失败、未知编码/内容类型、正文超限（16 MiB）均
  拒绝或保持未决，绝不静默放行（见 `python_bridge.py` 的 `envelope()` 与
  `pipe.py` 的 2 秒判定截止）。
- **身份绑定**：门控只对哈希匹配的 CPython/libssl/HTTPX 启用；快照绑定正文哈希、
  字节数与进程身份，防止检查后替换。

**必须声明的边界（Demo 不掩盖）**：

- 这是**进程内 Hook**。同一用户下换一个别的 HTTP 客户端、或直接 curl/脚本外发，
  就不经过本门控——内容门控本身不是不可绕过的出口控制。
- 只认证 HTTPX 0.28.1 标准传输；任意自定义传输、SDK、上传/附件均未覆盖。
- 客户端版本漂移会使适配器身份不匹配而拒绝启用（固定版本前提）。

**与版本无关的不可绕过方向**是对受控运行身份做默认拒绝的网络出口（WFP），
再只放行到受控 broker——这是方案第六节的 G4，仓库中仍为合成路径的未验证实验
（`native/behavior/wfp_lease.c`、`scripts/probe_wfp_lifecycle.py`），其“先连接
后装规则”窗口已记录到数据到达源站，不能当作已完成的防绕过能力。

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
