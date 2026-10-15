# 2026-10-15 审查、精简与 uv 核对

审查范围包含本次未提交的 Observe 改动、既有 Guard 调用链、项目命令／测试／脚本的引用、Python 依赖以及 Docker 和 CI 安装路径。下面列出已经修复的具体问题；不把局部实验扩展成生产保护承诺。

## 发现与修复

| 级别 | 问题及实际影响 | 修复与证据 |
|---|---|---|
| P1 | Native 管道服务端读完帧就断开，可能使 Native 写端 flush 报错并停用之后的采集。真实 HTTP/2 复测出现源站收到四个请求、观察零条的情况 | 一帧一连接，等写端 EOF 后再断开；保留 `runs/observe-probes/review-h2-13/` 失败记录。修复后三次独立 H2 公共 CLI 实验均匹配四条源站哈希，见 `review-h2-14/15/16` |
| P1 | 三个 Dockerfile 手写 pip 安装列表，绕过 uv.lock，并漏装 python-dotenv 等实际运行依赖；镜像行为与本机环境可能不同 | 都改为固定 uv 0.12.18、复制 uv.lock、`uv sync --locked --no-dev`。独立最小环境安装、所有 CLI 模块导入和 Observe help 通过；Docker 实际构建未验收，因为本机引擎未运行 |
| P2 | zstd stream_reader 在缺少尾部校验时仍返回完整 JSON，正文可能被错误标成 complete | 先有界解码，再验证 EOF／校验和／多余帧；未知长度帧额外校验，处理 cext 对 allow_extra_data 的差异；截断和多帧输入测试通过 |
| P2 | eCapture 就绪后意外退出，原循环只观察目标进程存活，可能继续显示 observing | 加入采集器健康检查，连正常退出码的提前退出也算采集失败；原始诊断不落盘 |
| P2 | 一个组件清理异常会跳过其他组件清理和证据关联；重复关闭还可能重复释放资源 | 独立清理 Collector、ETW、Pipeline；ETW 清理失败时来源降为 Unknown；Native 关闭幂等，异常信息仅记录类型 |
| P2 | 默认开发环境缺少 H2 测试依赖，报告生成缺少声明的 python-docx；部分测试隐含本地 LivePI checkout | H2 放入 dev，解析器直接依赖放入 observe extra，文档生成使用 reports extra；两项外部 LivePI 测试在未安装固定源码时明确跳过 |

默认审计仍不保存正文、认证头或 Cookie。观察适配仍是 `can_enforce=false`，Guard v1 同步契约与官方二进制支持哈希未改变。Native 观察 DLL 本次未修改，SHA-256 仍为 `527d33235f20b91b503657f52928fd7c25657cb96edf8e58f9f5183c0f6d0914`。

## 精简清单与依据

- 移除 `Collector`、`Normalizer`、`Correlator` 三个未被调用或继承的抽象骨架；保留 Codex／Claude 实际使用的 `ClientAdapter`。
- 移除没有命令、构建流程或文档引用的 `deploy/agent/Dockerfile.overlay`。该文件使用旧 base 镜像，并通过 no-deps 安装绕过依赖核对。
- 移除未使用的 capstone 和 Observe 中未使用的 imports。nltk 被官方 InjecAgent 解析器动态引用，因此从通用 dev 移到按需 benchmarks extra，并增加缺依赖提示；cryptography、jsonschema 移入实际使用它们的开发／研究范围。
- 89 个 `reports/qa_render*` 渲染产物，以及未压缩的 Frida Gadget，从 Git 跟踪中移除并加入 ignore。本地缓存副本保留。移除跟踪的数据共 45,758,878 字节，约 43.6 MiB；源 DOCX、原始实验报告和压缩 Gadget 均保留。
- 已比较未压缩 Gadget 和 `.so.xz` 解压结果，字节完全一致，SHA-256 为 `21594a4807fb00a598417c79c54f82eda32a0ebf74742702f4a0114dc0ebb295`。Docker 继续由该校验过的压缩包生成运行库。
- `.dockerignore` 排除 `.external`、build、dist 和 reports，避免实验源码、工具链和报告缓存进入镜像构建上下文。

Gateway、mitm、桌面追踪、Linux Frida 和 benchmark 仍有 CLI、测试、构建或报告调用，不能仅因当前 Windows 方案不用代理而认定它们已废弃。本次保留这些独立实验链路。

## uv 的管理边界

Python 版本选择由 `.python-version` 固定为 3.12，uv 可复用符合版本的系统解释器或安装解释器。声明入口是 pyproject.toml，解析版本及哈希在 uv.lock；没有并行的 requirements 文件或 Docker 手写 pip 列表。Docker 和 macOS workflow 固定 uv 0.12.18。

| 依赖范围 | 内容 |
|---|---|
| 最小运行环境 | aiohttp、h11、pydantic、python-dotenv、typer、zstandard |
| dev | pytest／coverage、H2 测试客户端、凭据／证书实验、JSON Schema 验证 |
| observe | hpack、hyperframe；仅运行 HTTP/2 解析时需要 |
| native-build | 固定 ziglang 0.13.0 |
| guard-probe | Frida、凭据／TLS 实验、Windows TUI 研究工具 |
| export / mitm / reports | 按需安装 pyarrow、mitmproxy、python-docx |
| benchmarks | 官方 InjecAgent 输出解析器动态使用的 nltk |

uv 管理 Python 包和 Python 环境。Go、Node/npm 的官方客户端、Docker、Windows 系统接口和 Native 第三方源码使用各自的版本或校验和机制。uv 镜像使用方式依据 [Astral 官方 Docker 指南](https://docs.astral.sh/uv/guides/integration/docker/)；已向官方 GHCR 核实 0.12.18 存在 Linux amd64 映像。

## 验证结果与限制

- `uv sync --locked --dev` 后运行 `uv run --locked pytest`：116 passed，1 skipped；可选 pyarrow 未安装，两个既存 utcnow 弃用警告来自固定外部 LivePI 代码。
- `uv lock --check` 与 `uv pip check` 均通过。
- 独立 `build/review-runtime-20261015` 环境以 `--no-dev --no-editable` 安装成功，最小依赖的 CLI、Gateway、Guard、Observe 导入及 Observe help 通过。
- 修复后的三个真实 H2 实验分别为 `runs/observe-probes/review-h2-14/`、`review-h2-15/`、`review-h2-16/`；每个均有四条完整正文匹配独立源站，且无 Native 采集错误。后两个并发运行，同时执行单元测试与 Schannel 实验。
- `runs/observe-probes/review-schannel-17/` 复测通过，完整正文匹配源站。其他通道的既有证据见 [Windows 验收记录](windows-observe-validation-2026-10-15.md)。
- 本机 Docker 引擎未运行，镜像构建、Linux 容器和 macOS workflow 未在本次执行；最小 Python 环境测试不能代替容器验收。
- Chrome 稳定 Hook、完整 IDE UI、eCapture 实采与真实 ETW 仍未验收，来源等级保持 Unknown。剩余范围见 [Windows Observe](windows-observe.md)。
