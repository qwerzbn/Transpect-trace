# 固定版桌面后端的本机隔离实验

`scripts/probe_desktop_backend_lab.py` 直接启动从官方 MSIX `26.1029.7803.0` 归档的 `codex.exe app-server`，不启动、不附加当前正在使用的桌面端。脚本先核对后端文件 SHA-256 与静态候选适配器，使用临时 `CODEX_HOME`，经 `initialize`、`thread/start`、`turn/start` 提交随机合成标记。模型提供者指向 `127.0.0.1` 上**不转发**的 HTTP 接收器；接收器只保存正文长度、SHA-256 和合成标记是否出现。实验不读取真实用户请求或认证信息。

```powershell
uv run --no-sync python scripts/probe_desktop_backend_lab.py --with-frida `
  --report runs/desktop-backend-lab/report-with-frida.json
```

2026 年 11 月 4 日在本机复测：归档后端版本为 `codex-cli 0.166.0-alpha.6`，后端哈希 `925C7D0665FFA49B0DCF748E034A805A04DA984164AC92301432073B47789B99`。`app-server` 三步交互完成；本地接收器收到一次 `/v1/responses` 请求，正文为 41,001 字节，并包含合成标记。Frida 在 HTTP 静态候选入口观察到两次调用，在该函数的假定正文布局中找到两次标记。新增的长度与 SHA-256 比对显示：这两次候选缓冲区均为 41,001 字节，哈希与接收器收到的正文完全相同，报告字段为 `http_candidate_body_comparison.status = exact_byte_match`。比对要求只有一次带合成标记的源站请求；多次请求、未观察到候选正文或哈希不同时，会分别报告不可比、未观察到或不匹配。WSS 候选没有调用；本轮使用的本地提供者明确关闭 WebSocket，因此 `0` 次 WSS 命中不能说明真实桌面 WSS 路径不存在。完整 JSON 报告保存在被 Git 忽略的 `runs/desktop-backend-lab/`。

Frida 附加与脚本载入运行在独立子进程中，主程序等待就绪最多 10 秒；超时会终止子进程和本次归档后端。此前仅用线程包裹 Frida 调用曾在本机卡住，故不以线程超时作为可靠的终止边界。上述 `app-server` 实验只做**只读观察**，没有拒绝请求或调用 DLP。其 HTTP 缓冲区比对仅限这一条合成请求，不能证明真实桌面 UI 的完整覆盖。

## 已序列化请求的同步判定实验

`scripts/probe_desktop_wss_deny_lab.py` 用同一归档后端启动独立的 `codex.exe exec -`，使用临时 `CODEX_HOME`、合成 Prompt 和本机不转发的 TLS 源站。它先核对后端哈希、HTTP/WSS 候选入口字节，并在两个 Hook 均安装后提交 Prompt。WSS Hook 在序列化函数返回后读取 `response.create` 正文；HTTP Hook 在编码正文准备函数入口读取 fallback 正文。Hook 把目标正文交给本地 `DesktopDLPBridge`，同步等待加密归档与 DLP 判定，再继续发送或构造错误返回。归档读取校验、Hook 缓冲区 SHA-256 和源站正文 SHA-256 分别记录。实验不连接外部模型服务，也不附加正在使用的桌面端。

固定版后端的隔离实测得到：WSS 成功结果标签为 `0x1f`，String 指针与长度位于结果对象的 `+16/+24`；拒绝使用错误标签 `0x0d` 并沿用已拥有的 String 缓冲区。HTTP 正文指针与长度位于 body 对象的 `+8/+16`；拒绝前调用该版本的 HeaderMap 析构函数 RVA `0xa6320`，然后返回标签 `3` 与空 String。两种拒绝均在目标内容到达源站前完成。仅拦截 WSS 会触发 HTTP fallback，所以两条路径必须同时门控。上述 ABI 只在这一个归档 CLI 路径上动态验证，不能推定桌面 UI 路由相同。

复测命令（在项目根目录执行）：

```powershell
.venv\Scripts\python.exe scripts\probe_desktop_wss_deny_lab.py --mode bridge --case benign
.venv\Scripts\python.exe scripts\probe_desktop_wss_deny_lab.py --mode bridge --case secret
.venv\Scripts\python.exe scripts\probe_desktop_wss_deny_lab.py --mode bridge --case benign --transport-allow-control
.venv\Scripts\python.exe scripts\probe_desktop_wss_deny_lab.py --mode bridge --case secret --simulate-bridge-loss
.venv\Scripts\python.exe scripts\probe_desktop_wss_deny_lab.py --mode bridge --case secret --simulate-wss-capacity-failure
```

2026 年 11 月 4 日的三项主要结果：

| 场景 | 本地判定与发送动作 | 独立源站结果 |
| --- | --- | --- |
| 合成普通 Prompt，标准 DLP | WSS、HTTP 都为 `REVIEW`，均拒绝。开发者指令中的一个技能文件路径片段触发熵规则；报告保留 `benign_allow_passed=false`，表明普通请求仍有误报。 | 目标正文 0 字节；`enforcement_passed=true`。 |
| Prompt 含合成密钥 | WSS、HTTP 都为 `BLOCK`，命中 `ASSIGNED_SECRET`，两份正文各自先加密归档，再由 Hook 拒绝。 | 目标正文 0 字节；报告 `passed=true`。 |
| 明确标记的传输放行对照 | 仅本机合成普通请求使用 **stub ALLOW**，验证 Hook 收到允许后执行原发送函数。这不代表标准 DLP 已放行。 | 目标 WSS 正文 41,126 字节；源站哈希与归档及 Hook 正文哈希一致。 |

上述“目标正文 0 字节”不表示源站整个实验期间没有数据。后端先发送一条**未带目标标记的 WSS 预热消息**，正文为 37,483 字节。拒绝报告明确记录 `total_origin_body_bytes=37483`、`unmarked_warmup_body_bytes=37483`，并要求只有这一条非空预热正文、目标 WSS 连接收到 0 帧字节、HTTP fallback 没有非空源站正文。控制器不回复时，目标发送线程等待，外部测试看门狗约 4 秒后终止隔离进程；人为将 WSS 容量校验置为失败时，隔离进程以退出码 `76` 终止。两项故障实验均未向源站发送目标正文。

可核查的最新报告位于被 Git 忽略的目录；文件 SHA-256 用于固定这次结果：

| 结果 | 报告 | SHA-256 |
| --- | --- | --- |
| 标准 DLP 普通请求 `REVIEW` | `runs/desktop-backend-lab/wss-deny-4d52d82f/summary.json` | `a5330036861763ee3c6c7e7a47cc33303c8952e2756a2f05393ed3d33a8226c6` |
| 合成密钥 `BLOCK` | `runs/desktop-backend-lab/wss-deny-0e7c013b/summary.json` | `4594b4619b8dea3c00825be6c0623f64f86add58b1939c98860036a881da5751` |
| stub 放行对照 | `runs/desktop-backend-lab/wss-deny-a63284a4/summary.json` | `a78e00bd56fd690b77d514076c2c9e8ccab95461452812a99a70ea263012de97` |

报告只包含路径、长度、哈希、判定、规则编号与错误类型；正文经 Windows DPAPI 保护的密钥和 AES-GCM 加密归档。此隔离实验的模型进程与归档进程仍在同一 Windows 用户下，不能把加密落盘当作对该用户进程的访问隔离；正式部署还需独立控制账户。临时 TLS wire、证书私钥和会话密钥在实验结束时删除。`native/guard/guard.c` 已加入该固定版所需的 WSS 标签、HTTP 空 String 和 HeaderMap 入口字节检查编译宏，同时保留旧 CLI 构建默认值。桌面候选适配器仍标记为 `candidate_unvalidated`，构建脚本拒绝用它生成桌面 DLL。桌面 UI 的真实模型路径、附件上传和 WFP 网络规则尚未由本实验验证。
