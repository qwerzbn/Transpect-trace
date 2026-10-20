# Transpect Trace — Windows Codex DLP

面向固定版本 Windows 官方 Codex CLI 的请求检测、系统行为追踪与网络出口控制原型。官方磁盘文件不修改，不使用网络代理，不替换 TLS。

## 核心模块

| 模块 | 职责与范围 |
| --- | --- |
| Native Guard | 已验证 HTTP/WSS 请求发送入口获取正文，检查 Prompt、实际携带的 Context 和工具结果，通过原客户端错误路径拒绝发送 |
| eCapture | 固定 Windows 上游与 ECW2 补丁；观察受支持 Schannel TLS 路径，重组协议并提取请求语义；不是系统全部 TLS 旁路解密 |
| ETW / Behavior | 进程启动/退出、文件与网络事件；用 PID＋创建时间追踪 Codex 后代，关联候选来源并记录证据缺口 |
| WFP | 当前控制原型仅支持指定合成程序路径、IPv4 回环 TCP 地址/端口；验证动态规则、阻断与恢复 |

```text
Codex → Native Guard → 本地策略 → 原 TLS 发送 / 请求拒绝
Codex → Shell / 子进程 → 文件与网络活动 → ETW → 候选来源证据
合成工具 → 已安装的限定 WFP 规则 → 连接阻断 / 撤销后恢复
受支持 Schannel 路径 → eCapture → 协议重组 → 统一请求与语义摘要
```

`protect` 保留 Codex 策略桥接及共享检测、索引、关联接口；`observe` 始终是观察能力，不能把建议阻断显示为已阻断。共享模型保留的其他通道枚举不构成客户端支持声明。

## 安装与构建

需要 Windows x64、Python 3.12、Git、uv。依赖由 `pyproject.toml` 和 `uv.lock` 管理。

```powershell
uv sync --locked --dev --extra observe --extra native-build
uv run --no-sync python scripts/build_native.py --component guard
uv run --no-sync python scripts/build_native.py --component observe
uv run --no-sync python scripts/build_native.py --component behavior
uv run --no-sync ttrace --help
```

Native 输出保存在 `build/`，不随源码提交。增强 eCapture 另需 Go 1.25.12 和固定上游源码：

```powershell
git clone https://github.com/gojue/ecapture-windows .external/ecapture-windows
git -C .external/ecapture-windows checkout --detach 7fb8347b7a3c28d2a094e35af38b1c471d194ebf
# 使用本机实际的 Go 路径。
uv run --no-sync python scripts/build_native.py --component ecapture --ecapture-variant enhanced --source .external/ecapture-windows --go C:/tools/go/bin/go.exe
```

补丁和协议说明见 [patches/ecapture-windows](patches/ecapture-windows/README.md)。ETW、WFP 和 eCapture 受控探针需要相应权限，可使用其 `--elevate` 参数触发 UAC；权限不足必须记录为 unavailable。

## 固定客户端与运行

只支持 `codex-cli 0.162.0-alpha.17.2 Windows x64`，SHA-256：

```text
d13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec
```

官方副本需自行准备，仓库不分发客户端。版本或入口不匹配时拒绝接管。

```powershell
$codexExe = 'C:/baselines/codex.exe'
uv run --no-sync ttrace guard baseline --codex $codexExe
uv run --no-sync ttrace guard codex --codex $codexExe --policy-file tests/fixtures/guard-policy.json -- --help
uv run --no-sync ttrace protect run --channel cli --binary $codexExe --policy-file deploy/protect/default-policy.json -- --help
```

Guard v1 与 Protect v1 策略格式分别使用对应入口。示例仅含假数据，不代表完整企业策略。默认只保存脱敏元数据、哈希和证据引用，实验正文保留在本地被忽略的 `runs/`。

## 检查与受控复现

```powershell
uv lock --check
uv pip check
uv run --no-sync pytest
uv run --no-sync python scripts/generate_schemas.py --check
uv run --no-sync python scripts/check_repository.py
uv run --no-sync python scripts/audit_release.py
uv run --no-sync python scripts/probe_codex_guard_regression.py --codex $codexExe --output runs/local-guard
uv run --no-sync python scripts/probe_request_semantics.py --codex $codexExe --output runs/local-semantics --elevate
uv run --no-sync python scripts/probe_wfp_lifecycle.py --native-dir build/behavior --output runs/local-wfp --elevate
uv run --no-sync python scripts/probe_codex_child_egress.py --codex $codexExe --native-dir build/behavior --output runs/local-child-egress --elevate
```

每次实验使用新的输出目录。单元测试和构建成功不能代替真实 Hook、ETW 或 WFP 验收。Python wheel 只含 Python 包；Native、Schema 和模板需要本源码 checkout 与本机构建。

## 限制

- eCapture 的受控 Schannel 成功不代表 Codex 私有 TLS 已覆盖；Codex 内容主要由 Native Guard 获取。
- ETW 文件访问、工具调用和网络连接只提供证据；时间邻近不证明文件已经外发，High 来源置信度也不是字节级因果证明。
- WFP 不自动继承 Codex 进程树，同路径无关进程可能受到规则影响。真实 Git、curl、Python、SCP 上传是后续应用场景，不由合成工具实验认证。
- 5 项 strict xfail 保留已知检测缺口：Bearer、个人信息、带凭据连接串、嵌套 JSON、登记文本换行变形。xfail 不算保护通过。
- 不覆盖任意文件解析、OCR、完整 WSS streaming、QUIC、多版本、其他客户端或全系统防绕过。

源码目录：`src/transpect_trace/{guard,observe,behavior,protect}`；Native：`native/`；契约：`schemas/`；构建及探针：`scripts/`。本分支不包含历史 Trace/Gateway 和多客户端主动适配。文件白名单由 `release-files.json` 定义；原始实验、生成二进制和本机配置不上传。
