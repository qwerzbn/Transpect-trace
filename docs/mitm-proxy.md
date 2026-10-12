# HTTPS 中间人代理：保留账号登录抓取流量

日期：2026-10-12

## 为什么需要这个方式

此前的做法是把客户端的模型地址改到本机 Gateway，缺点是必须改用项目的 API Key，客户端不能再用原来的账号和模型。中间人代理解决这个缺点：客户端保留自己的账号和模型，代理在本机解开 TLS，拿到明文后再用真实 TLS 转发给模型服务。这正是需求里「利用网关代理解密 SSL/TLS 流量并抓包」的做法。

## 做法

用成熟的 mitmproxy 做代理引擎，自己只写一个插件，把截到的请求按现有证据格式落盘。代理只解密大模型域名，其他流量原样放行、不解密。

```text
客户端 ──HTTPS（代理用自己根证书签发的证书）──> 本机 mitmproxy ──真实 TLS──> 模型服务
                                              └─ 插件：记录明文，只保留安全请求头
```

- 代理：`uv run ttrace mitm`，监听 `127.0.0.1:8080`。默认只拦截 `chatgpt.com`、`api.openai.com`、`api.anthropic.com`、`api.deepseek.com`。
- 根证书：mitmproxy 首次启动在 `~/.mitmproxy/mitmproxy-ca-cert.pem` 生成，私钥只留在本机。
- 让客户端信任证书：Codex 用 `CODEX_CA_CERTIFICATE` 指定该证书，只对这个进程生效，不装进系统；Claude Code 用 `NODE_EXTRA_CA_CERTS`。
- 把流量引到代理：设置 `HTTPS_PROXY=http://127.0.0.1:8080`。
- 插件只记录 `accept`、`content-type`、`user-agent` 三个请求头，不记录 `Authorization`、Cookie 等凭据。

## Windows 实测结果（Codex 命令行，账号登录）

用本机 ChatGPT 账号登录的 Codex（`codex-cli 0.162.0-alpha.2`），经过代理、信任 mitmproxy 证书后正常完成任务，没有报证书错误，说明 Codex 没有做证书固定。代理抓到了它发往 `chatgpt.com` 后端的全部流量：

- 账号校验、插件列表、用户设置等接口。
- 遥测：多次 `analytics-events` 上报，以及一次约 660 KB 的 OTLP 指标上报。
- 模型对话：走 `/backend-api/codex/responses`，返回 101 升级为 WebSocket，prompt 和回答在 WebSocket 帧里。

插件加上 WebSocket 帧记录后，完整抓到了对话正文。例如发送「请用一句话回答：中国的首都是哪里？」，在客户端发往服务器的帧里抓到原始 prompt，在服务器返回的帧里抓到回答「北京」。证据在 `runs/mitm/<run-id>/`。

两点值得注意：

- 客户端除了对话，还会把大量遥测和指标发往同一后端，抓取和拦截都要覆盖这些接口，不只看对话。
- 账号登录的对话走 WebSocket，不是普通的 POST 请求，拦截方案要能处理 WebSocket 帧。

## 复现步骤

```powershell
# 1. 启动代理（首次会生成根证书）
uv run ttrace mitm --port 8080

# 2. 另一个终端，让 Codex 走代理并信任证书，用你自己的账号
$env:HTTPS_PROXY = "http://127.0.0.1:8080"
$env:CODEX_CA_CERTIFICATE = "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.pem"
codex exec --json "请用一句话回答：中国的首都是哪里？"

# 3. 查看抓到的内容
uv run ttrace gateway-summary runs\mitm\<run-id>
```

macOS 把 `$env:...` 换成 `export`，证书路径为 `~/.mitmproxy/mitmproxy-ca-cert.pem`；桌面应用不读终端环境变量时，改用系统代理设置，或把证书装进钥匙串。

## 两种方式对比

| | 改模型地址 | 中间人代理 |
|---|---|---|
| 账号和模型 | 改用项目的 API Key | 保留原账号和原模型 |
| 抓到的接口 | 只有模型接口 | 客户端访问的所有大模型域名，含遥测、WebSocket 对话 |
| 本机改动 | 改客户端配置 | 设代理、信任根证书 |
| 主要风险 | 低 | 根证书私钥不得泄露；只解密白名单域名 |

## 安全与清理

- 只解密白名单内的大模型域名，其余流量不解密。
- 根证书私钥只在本机 `~/.mitmproxy`，不提交、不外传。
- 插件不记录凭据请求头；证据目录仍应按内部资料管理。
- 用完后：停掉代理，清除 `HTTPS_PROXY`，按进程信任的方式不改系统，无需额外卸载；如装过系统证书，记得删除。

## 后续

1. Codex 桌面版：用用户级环境变量或系统代理，验证不改模型地址也能抓到窗口对话。
2. Claude Code：用 `HTTPS_PROXY` 加 `NODE_EXTRA_CA_CERTS` 测一遍。
3. macOS：按钥匙串信任加系统代理重复测试。
4. 把转发前 403 的拦截规则移到代理插件里，覆盖对话和 WebSocket，接上需求第二步。
