# 2026-10-25 多应用业务场景：代码与组件验证

本轮在 `codex/development` 实现业务编排和浏览器观察组件。根据本轮用户确认，执行范围收敛到代码、组件测试和实验准备：不触发 UAC、证书信任确认或 Chrome 人工加载。因此，场景 1、6 的整链实采及场景 9 的真实浏览器采集均未认证。

## 交付内容

| 模块 | 已实现 | 当前证据边界 |
| --- | --- | --- |
| 业务编排 | `flow scenarios run/status/report`、冻结清单、独立进程登记、受控就绪与取消 | 编排代码与失败路径测试；未完成真实 Codex 工具链实采 |
| Webhook | 独立导出程序、固定 PowerShell 任务、正常校验证书的 HTTPS 源站、原文／嵌套／摘录／普通统计／503 重试 | HTTPS 源站组件测试通过；PowerShell＋ETW＋eCapture 联合验收待补 |
| Git | 真实 Git HTTPS 接收端、quarantine 对象检查、commit/tree/blob 关系、ref 更新与接收事实分离 | 真实 Git 组件测试；Codex→Python→Git 与外部采集器组合待补 |
| 传播证据 | 文件身份、实际 I/O 范围、读写时钟、登记内容候选、独立发送次数 | 并发改写、身份变更、证据丢失等组件负例；不认证唯一来源或字节级因果 |
| 浏览器 | MV3 扩展、受限 Native Messaging、独立请求 Schema、隔离页面、显式网络进程发现、eCapture 探测入口 | JS／协议测试、实际编译主机组件通过；真实 Chrome 扩展及 eCapture 未执行 |

所有新增业务和浏览器记录均为 `can_enforce=false`。Guard v1、Flow v1、ECW2 和 UnifiedLLMRequest v1 保持兼容；旧 Guard 和连接门控没有新增生产保护声明。

## 关键实现边界

1. 编排器固定执行假数据任务，清单不接收任意命令。导出程序是测试程序，Codex、PowerShell、Python 和 Git 是实际客户端，模型及工单服务是本地受控服务。
2. Codex 使用原固定二进制哈希，仍启用隔离工作区沙箱。观察实验单独配置允许假数据的本地 Guard 策略；不更改正常保护策略。工具输入在身份、观察器及 ETW 进程链就绪后释放。
3. Native I/O 对受限子进程的审计管道采用显式开关，核对前后进程创建时间和映像哈希，并复用既有受限 SID 访问机制。目标令牌和沙箱不变，默认 Flow 路径不变；真实受限子进程兼容性待实采确认。
4. Git 的假凭据回调只在受控 401 之后、推送正文之前暂停真实辅助进程。首次公开发现请求发生在此接管之前，不能据此宣称从进程启动起全覆盖。重复推送中无 POST 的辅助进程能否取得 terminal，需实测确认。
5. 源站在 pre-receive 的 quarantine 存活期间检查实际对象，提交后删除的历史 blob 仍在检查范围。ref 拒绝不代表源站未收到数据。TLS 传输体与 blob 使用各自的哈希。
6. 源站与采集端正文按哈希、长度、次数作多重集合核对；记录 `ordered_body_multiset`，不将其解释为运行时请求 ID 的直接映射。相同正文不去重。
7. 文件交接需要不同进程实例、相同文件身份／偏移／完整范围和正确读写顺序。窗口中的竞争写入会降级。单次 I/O 分片边界不一致、缺失身份或内容时保留部分关联，不自动还原为完整文件。
8. 默认审计只存摘要、脱敏检测和证据引用。假输入、隔离工作副本及源站测试仓库位于明确的实验目录，包含假正文，不能把这些目录当作脱敏审计上传。

## 本轮验证记录

最终自动化结果在本文件结尾记录。主要覆盖：模型调用 ID、PowerShell 路径与 1 MiB 上限、源站长度与 chunked 边界、中文／并发／重复正文、503 重试、模型请求压缩解码、Git 历史对象与 ref 拒绝、来源候选降级、Native Messaging 序列／失联／队列丢失、审计缺行、隐私和旧接口回归。

实际编译并运行了 Native Messaging launcher，验证 3 个 ACK、1 条请求及 ready/terminal；记录位于本地 `runs/browser-business/20261025-component-03/component-result.json`。这是直接输入协议帧的组件实验，没有启动 Chrome，不算真实浏览器采集。

准备模式冻结了 Webhook plain、Git deleted_history 默认后端和 Schannel 三份真实依赖清单，位于 `runs/business-scenarios/20261025-prepared-01/`。状态为 `prepared`，实采用例数为 0，测试根证书未导入。后续代码变化后应重新生成新的实验目录，不修改旧清单。

全量回归曾记录 `1 failed, 922 passed`：ref 拒绝用例的 quarantine 检查未完成。失败样本及当轮 XML 已保存在本地 `runs/business-scenarios/20261025-git-race-01/`。之后该用例和 Git 组件组重复运行均通过，最终全量也通过，但原始根因仍未定位；增加了脱敏检查阶段、异常类型及 Git 输出长度／哈希诊断，没有放宽路径或完整性断言，也没有加入掩盖失败的自动重试。该间歇问题保留为已知限制。

## 实采与产品能力矩阵

| 能力 | 本轮状态 | 后续验收 |
| --- | --- | --- |
| Webhook 完整链路与正负例各 3 次 | 未执行 | 普通与受限进程兼容、真实正文、ETW 文件／网络事件、源站次数一致 |
| Git 默认后端与 Schannel 双组 | 未执行 | 实际 TLS 后端、客户端信任、辅助进程接管、pack 与对象两层证据 |
| Chrome eCapture | 未执行 | 隔离 Network Service 身份、ready/terminal、实际请求；零事件保持 Unknown |
| Chrome 文本／JSON 请求 | 组件通过，UI 待验收 | 手动加载扩展，两个标签、导航、取消及受控源站回执 |
| 附件／multipart／Blob／流式正文 | 未认证 | 文件引用不能作为完整附件；扩展不承诺 JavaScript 正文构造来源 |
| 新业务路径发送前阻断 | 未实现 | 本轮仅观察；不借用既有 Codex Gate 的结论 |
| 既有 Codex HTTP/WSS、连接门控和 Flow 实采 | 本轮未重跑 | 自动化回归不代替真实 Native／ETW／eCapture 实采 |
| 真实 SaaS 与完整 IDE UI | 未执行 | Jira、GitHub、ChatGPT 等各自独立人工验证 |

## 复现与剩余工作

安装、冻结依赖、运行实验、浏览器加载和清理命令见 [开发说明](../development/business-scenarios.md)。实采默认需要管理员 ETW/eCapture 环境；探针的 `--elevate` 会提升整个假数据实验及客户端，须明确选择。本轮未调用它。

本机默认构建预检未找到当前 worktree 的 `.external`；传入现有固定上游和 Go 的显式路径后，六个 Native 组件的构建前提全部通过。没有复制或修改原工作区上游，也没有覆盖已固定的 DLL、EXE 或构建清单。新机器应按构建文档准备依赖，不能依赖本机路径。

待实采验证的重点是 PowerShell／Python 实际文件 API、Codex 受限子进程的审计管道、Git 默认 TLS 信任及辅助进程退出时的完整健康记录。无法取得完整证据时，业务报告维持 `partial/unavailable`，不认证整链通过。

本轮不自动提交或推送，不新增发布文档。

## 最终工程结果

| 检查 | 本轮最终结果 |
| --- | --- |
| 全量自动测试 | **925 passed，0 failed，0 skipped**，199.19 秒 |
| 依赖锁 | `uv lock --check` 通过，未修改 `uv.lock` |
| 已安装依赖 | `uv pip check` 通过 |
| Schema | 37 个生成结果无漂移；34 个原有 Schema 未修改 |
| CLI 与工程检查 | 通过，`flow scenarios run/status/report` 已注册 |
| 源码白名单 | 295 项通过，启发式秘密扫描未报告问题；仅当前白名单内容，不扫描历史 |
| Python wheel | 构建成功，98 个成员；无 EXE/DLL、运行结果、虚拟环境或秘密文件 |
| Native 构建前提 | 显式指定现有固定上游及 Go 后，六个组件检查通过；未重建或替换原有 Native 产物 |
| 工作区格式 | `git diff --check` 通过 |

最终 JUnit、工程检查和 wheel 位于本地 `runs/business-scenarios/20261025-code-validation-02/`。这些自动化和组件结果不替代本文件矩阵中未执行的 Windows 实采或真实浏览器验收。
