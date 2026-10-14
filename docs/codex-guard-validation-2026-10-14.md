# Codex Guard 验收记录：2026-10-14

固定 Windows x64 官方 `codex-cli 0.162.0-alpha.17.2`；磁盘 SHA-256 为 `d13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec`。只在隔离配置和假数据源站中验证，不使用代理、不替换客户端 TLS、不修改官方磁盘文件。运行时使用 Native DLL，Frida 不参与这些 Native 验收。

| 能力 | HTTP EncodedJsonBody | WSS response.create | 证据目录（相对仓库根目录） |
|---|---|---|---|
| 正文观察与允许 | 通过 | 通过 | `runs/guard-native/aslr-installed-allow-17/`；Hook 哈希与源站正文哈希一致 |
| 请求错误路径与拒绝 | 通过 | 通过 | `runs/guard-native/launcher-request-14/`；被拒敏感正文在源站零字节，exec 自然退出 1 |
| Agent 实际读取后的工具结果拒绝 | 通过 | 通过 | `runs/guard-native/final-tool-18/`；公开启动命令，真实 exec_command 读取假文件，下一次内容命中并拒绝 |
| 请求拒绝后同 PID 正常请求恢复 | 通过 | 通过 | `runs/guard-tui/final-http-request-12/`、`public-wss-request-15/`；需新建不含敏感内容的会话 |
| 会话持续拒绝、进程存活 | 通过 | 通过 | `runs/guard-tui/public-http-session-18/`、`final-wss-session-11/`；进程保护实例中的 `/new` 不能清除 block_session |
| 显式 terminate | 通过 | 通过 | `runs/guard-native/explicit-terminate-05/`；策略显式选择，退出 76 |
| 失联/超时/错 ID | 通过 | 通过 | `runs/guard-native/fault-disconnect-07/`、`fault-timeout-06/`、`fault-stale-08/` |
| 畸形策略回复 | 通过 | 通过 | `runs/guard-native/strict-malformed-12/`；貌似 allow 的多根 JSON 被拒绝 |
| Native＋独立 C 引擎 | 通过 | 通过 | `runs/guard-native/strict-c-13/`、`launcher-c-allow-15/` |
| 不同 EXE 加载地址 | 通过 | 通过 | 原 EXE `0x7ff6e19a0000`；字节相同副本 `0x7ff6eaa60000`，`aslr-copy-reject-16/` |
| ETW 真实采集 | 未通过验收 | 未通过验收 | 公开启动状态保存 StartTrace 权限错误 5；采集代码已编译，关联逻辑已测试 |
| 完整 WSS streaming / raw 附件 / daemon | 未覆盖 | 未覆盖 | 不纳入能力声明 |

每个目录有 `summary.json`，Native exec 实验还保存分协议的审计、原始密文和源站离线解密对照；TUI 实验保存同 PID 存活及后续请求证据。`native.outcome=native_error_constructed` 只证明构造了现有错误对象；源站判据才证明受测敏感正文没有发送。

同时运行了多个独立 CLI/策略实例，未见串用请求 ID 或实例状态；重复运行及两个加载地址没有出现崩溃、死锁或错误释放。仍不等于长期压力、全部 Rust 对象路径或生产稳定性认证。

最终元数据报告写入 `runs/guard-validation/20261014/report.json`，可用 `scripts/report_guard_validation.py` 对显式指定的实验目录重新生成。失败/调试运行保留，但不以其“未看到请求”证明没有外发。旧实验缺少新的完整约束字段时，验证器保守返回 `not_verified`，不补造证据。

ETW 只提供进程链、文件访问和网络证据；本次实际来源置信度为 Unknown。登记匹配与真实工具结果命中已通过内容验收，不能代替真实 ETW 文件证据。High/Medium/Low/Unknown 的关联测试通过，但 High 也不表示字节级污点追踪。

详细运行方式与能力边界见 [Codex Guard](codex-guard.md)。本阶段交付固定版本 Native 原型和可复现能力报告，尚非生产级全覆盖组件。

最终 Python 测试结果为 82 passed、1 skipped；跳过的是缺少可选 pyarrow 的导出测试。Native DLL、独立 C 引擎和 ETW collector 构建成功，源码及产物 SHA-256 保存在 `build/guard/build-manifest.json`。`git diff --check` 通过。
