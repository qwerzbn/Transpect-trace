# Codex 桌面版流量抓取：Windows 记录与 Mac 测试步骤

日期：2026-10-12

## 目标

需求 2「大模型数据外发实时拦截」的第一步，是抓到真实大模型客户端发给模型服务的请求明文。本文记录 Windows 上已经完成的工作，给出 Mac 上照做一遍的步骤，并列出后续开发。

## 做法

把客户端的模型地址改到本机的 Gateway。客户端用明文 HTTP 把请求发给 `127.0.0.1` 上的 Gateway，Gateway 记下完整正文，再用 TLS 转发给 DeepSeek。模型和 Key 用项目根目录 `.env` 里的配置，`.env` 不进仓库。

这样做不需要旁路破解 TLS。代价是客户端改用 `.env` 里的 DeepSeek Key，不再走原来的账号和模型。

## Windows 已完成的工作

**Windows 原生 Codex CLI。** `uv run ttrace host-codex` 直接运行桌面版自带的 `codex.exe`（`codex-cli 0.162.0-alpha.2`），用临时 `CODEX_HOME` 指向本机 Gateway，不改日常配置。运行 `runs/host/2d394a68` 完整：2 次 `/responses` 请求都返回 200，第二次请求里带着 Codex 读取的 `public.txt` 内容，`ttrace verify` 结果为 complete。同一次请求里还带上了本机 PowerShell 配置文件 `profile.ps1` 的报错，说明运行环境本身的内容也会进入模型请求。

**Codex 桌面版。** 把 `~/.codex/config.toml` 的模型地址改到 Gateway 后，重启桌面版（`Codex Desktop 26.1002.52244`）。启动时请求模型列表、对话请求和生成标题的请求，都经过了 Gateway，`User-Agent` 为 `Codex Desktop/0.162.0-alpha.2 (Windows 10.0.26200; x86_64)`。在窗口里发出「用一句话介绍你自己」后，抓到两次 `/responses` 请求：

| 请求 | 模型 | 结果 |
|---|---|---|
| 对话 | `deepseek-flash`，正文 184 KB，23 个工具定义 | 200，回答「我是 Codex，一个在终端里陪你写代码、调试和解决工程问题的 AI 编程助手。」 |
| 生成标题 | 桌面版固定使用 `gpt-6-luna`，请求里同样带着这句输入 | 400，DeepSeek 不认识这个模型 |

除了正式对话，桌面版还会把用户输入发给生成标题这类辅助请求，抓取和拦截都要覆盖它们。启动时的模型列表请求也会报解析错误，因为 DeepSeek 的列表格式和 Codex 预期不同，不影响对话。证据在 `runs/desktop-gateway/desktop-gateway-20261012/`（`runs/` 不进仓库）。

**当前这台 Windows 的状态。** 桌面版配置仍指向 Gateway，Gateway 常驻在 `127.0.0.1:9100`，新证据写入 `runs/desktop-gateway/gateway-20261012-134737/`。原配置备份在 `~/.codex/config.toml.ttrace-backup-20261012-134735`。恢复方法见下文。

## 新增命令

| 命令 | 作用 |
|---|---|
| `uv run ttrace gateway --port 9100` | 在 `127.0.0.1` 起常驻 Gateway，Key 和上游来自 `.env`，Ctrl+C 停止 |
| `uv run ttrace codex-config gateway --port 9100` | 先备份 `~/.codex/config.toml`，再把模型换成 `.env` 的 `MODEL_ID`，模型地址指向 Gateway；其余配置不动 |
| `uv run ttrace codex-config restore` | 用最新的备份恢复配置，并校验 SHA-256 |
| `uv run ttrace gateway-summary 证据目录` | 列出 Gateway 抓到的请求：客户端、模型、用户输入、回答和状态 |
| `uv run ttrace host-codex` | 本机原生运行 Codex CLI，请求经过临时 Gateway，生成完整证据包 |

## Mac 测试步骤

### 准备

需要 git、[uv](https://docs.astral.sh/uv/)、Codex 桌面版。CLI 测试另外需要 Codex CLI，可以用 `npm install --global @openai/codex` 安装。

```bash
git clone https://github.com/qwerzbn/Transpect-trace.git
cd Transpect-trace
uv sync
```

在项目根目录新建 `.env`，内容和 Windows 上的一致：

```text
API_KEY=你的 DeepSeek Key
BASE_URL=https://api.deepseek.com
MODEL_ID=deepseek-flash
```

### 测试一：Codex CLI

```bash
uv run ttrace host-codex
```

最后一行输出证据目录。再执行：

```bash
uv run ttrace verify runs/host/<run-id>
```

结果应为 `"status": "complete"`。Mac 上不需要 Windows 的 `[windows] sandbox` 配置，Codex 会用 macOS 自带的沙箱。如果 PATH 里找不到 `codex`，用 `--codex /path/to/codex` 指定。也可以直接执行 `bash scripts/macos-host-trace.sh`，它会在缺少 `codex` 时自动安装，再跑一次并校验。

### 测试二：Codex 桌面版

1. 终端 A 启动 Gateway，保持窗口打开：

   ```bash
   uv run ttrace gateway --port 9100
   ```

   输出里的 `Evidence:` 就是本次证据目录。

2. 终端 B 切换配置：

   ```bash
   uv run ttrace codex-config gateway --port 9100
   ```

   记下输出里的备份路径。

3. 用 Cmd+Q 完全退出 Codex 桌面版，再重新打开。
4. 新建一个对话，不要选带真实资料的项目目录，发一条简单消息，例如「用一句话介绍你自己」。
5. 终端 B 查看抓到的内容：

   ```bash
   uv run ttrace gateway-summary runs/desktop-gateway/<gateway-run-id>
   ```

   成功的判断标准：

   - `user_agent` 以 `Codex Desktop/` 开头，并带有 macOS 的系统标识。
   - 有一条 `POST /responses`，`model` 为 `deepseek-flash`，`user_text` 是刚发的消息，`status` 为 200，`answer` 有内容。
   - 可能还有一条 `gpt-6-luna` 的标题请求返回 400，以及模型列表请求，这两项和 Windows 上一样，属于预期。

6. 测完恢复：

   ```bash
   uv run ttrace codex-config restore
   ```

   再用 Cmd+Q 退出并重新打开桌面版，最后在终端 A 按 Ctrl+C 停掉 Gateway。

### 结果记录

| 项目 | Windows | Mac |
|---|---|---|
| Codex CLI 原生 | 成功，`runs/host/2d394a68` | 待测 |
| 桌面版对话请求 | 成功，200 | 待测 |
| 桌面版标题请求 | 被抓到，400（模型名不兼容） | 待测 |
| `User-Agent` 系统标识 | `Windows 10.0.26200; x86_64` | 待测 |

## 注意事项

- 切到 Gateway 期间，桌面版所有对话都走 DeepSeek，正文完整记录在本机 `runs/` 下。不要在这期间处理真实敏感资料。
- Gateway 没开时，桌面版发不出请求。不用 Gateway 时记得恢复配置。
- 本阶段只抓流量，没有采集系统行为。Linux 容器里的 strace 和 Frida 不能用于 Windows 或 Mac 原生运行。

## 后续开发

1. **Mac 实测**：按上面的步骤完成两项测试，把结果填进记录表。
2. **保留账号登录时的抓取**：改模型地址会丢掉原来的账号和模型。要在不改地址的情况下抓到明文，需要评估 HTTPS 中间人代理：自建根证书、本地代理，并逐个确认客户端是否信任系统证书、是否做了证书固定。
3. **辅助请求**：标题生成、模型列表这类请求同样携带或可能携带用户数据，抓取和拦截规则都要覆盖，不只看正式对话。
4. **Claude 客户端**：用当前代码重跑 Claude Code；Windows 和 Mac 上通过 `ANTHROPIC_BASE_URL` 指向 Gateway 再测一遍。
5. **拦截第二步**：在 Gateway 加入代码片段、密钥格式和个人信息的识别，区分请求侧拦截和流式返回中断。目前只有按事先登记标记、在转发前返回 403 的原型。
