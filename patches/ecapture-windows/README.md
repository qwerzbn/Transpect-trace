# eCapture Windows 增强补丁集

以 `7fb8347b7a3c28d2a094e35af38b1c471d194ebf` 的干净源码为基线。`manifest.json` 固定补丁文件字节哈希；`.gitattributes` 禁止对这些文件转换换行。

这是可追溯的 overlay 补丁集：构建器复制基线 Git 跟踪文件，将 Go 入口新增为 `enhanced_entry_windows.go`，将 companion C 文件替换为此处版本；不编辑 `.external` 中的原版源码。增强版另用已有固定校验和的 MinHook，保留其许可证和来源记录。

原版默认构建在 `build/observe/`，增强版显式构建在 `build/observe/ecapture-enhanced/`：

```powershell
uv sync --locked --extra native-build --extra observe --dev
uv run --no-sync python scripts/build_ecapture_windows.py --variant upstream
uv run --no-sync python scripts/build_ecapture_windows.py --variant enhanced
```

Windows 会锁定已映射的 DLL；重建前先结束该产物的实验子进程，不并行重建正在采集的同一 DLL。

增强入口只有经适配器设置 `TTRACE_ECAPTURE_ENHANCED=ECW2` 时启用；否则执行原 CLI。适配器另传目标 PID 和预期创建时间，避免 PID 重用后注入错误对象。增强入口仍要求提升权限并启动 Schannel ETW，不提供绕过权限的运行开关。

## ECW2 链路

```text
SSPI companion → 受限本地 Named Pipe → eCapture Go → 专用二进制 stdout → Python 内存解析
                                                    stderr：固定诊断
```

管道限制当前用户和 SYSTEM、拒绝远程连接、核对客户端真实 PID 和创建时间，使用中完整性标签以适配同用户中完整性实验子进程。跨完整性部署仍需具备相应权限的环境实测，不宣称具备生产抗篡改能力。

头部为 little-endian `<4s7I10Q`，112 字节，后跟 `length` 个原始字节：

- magic=`ECW2`，length、PID、TID、kind、direction、flags、reserved。
- 创建 FILETIME、随机 session low/high、SSPI context low/high、context generation、单方向 sequence、QPC、QPC frequency、累计 lost。
- kind：0=data、1=ready、2=closed、3=terminal health、5=configuration（仅服务端发往 DLL）。
- direction：0=send、1=recv；flags：256=truncated、512=ordering uncertain。
- payload 上限 64 KiB；DLL 队列上限 8 MiB；上下文表上限 128。

连接键由采集会话、上下文值和代次组成，不是 socket 身份。删除后复用会产生新代次。同方向重入会标为顺序不确定；分配/队列/IPC 失败记录累计丢失。TLS 控制消息不作为应用数据。加密前复制、成功后输出不等于网络已发送。

采集器通过 stdin 通知 Go 停止，Go 向 DLL 发送 `STOP`。DLL 停止新复制，排空有界队列，等待在途回调并发送终端健康帧。断开或未取得健康帧必须记录覆盖缺口。DLL 驻留但停止采集；重新接管需重新启动目标。

原版预览不会转为 ECW2，也不会因短请求少于 120 字节而被认证为完整请求。增强版没有 Chrome BoringSSL、跨进程 OpenSSL 或请求阻断能力。
