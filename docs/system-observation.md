# Transpect 系统层观测设计

## 当前结论

系统层用两份同时成立的证据描述同一次 Agent 运行：

1. `strace` 跟踪整个进程树，记录实际进入内核的进程、文件、网络和 FD 操作。
2. Frida Gadget 17.18.0 通过 `LD_PRELOAD` 进入动态链接进程，记录 libc 函数参数、返回值、最多 4 KiB 的文件读写摘要，以及 `open`、`connect`、`execve` 的用户态调用栈。

Gadget 不占用 ptrace。strace 因此可以同时跟踪同一进程。两边分别保存原始证据，再转换成统一 `TraceEvent`。模型明文仍由 Gateway 记录。

静态链接程序，以及主动清掉 `LD_PRELOAD` 的进程，不会出现在 Frida 里。它们保留在 strace 中，并在质量报告里标成 `strace_only_pids`。缺记录不会被当成“没有发生”。

## 启动方式

```text
Agent entrypoint
├── strace -ff Codex/Claude 及其子进程
│     输出 raw/system/strace.<pid>
└── LD_PRELOAD=/opt/transpect-frida/libgadget.so
      脚本模式，进程自行继续执行
      输出 raw/frida/events.<pid>.jsonl
```

脚本在安装挂钩之前打开日志文件，只对该 FD 做短追加写。管道、套接字、`/proc`、`/dev` 和证据目录只计数，不写正文。调用栈不加在高频读写上。

## 两层分别能证明什么

| 证据源 | 观测位置 | 当前采集 | 优点 | 主要盲区 |
|---|---|---|---|---|
| strace | 用户态与内核的系统调用边界 | exec/fork/open/read/write/connect/send/recv/FD | 覆盖整个进程树，包括静态二进制 | 缺少用户态调用来源；解析文本较脆弱 |
| Frida Gadget | 已加载 Gadget 的进程内部 | libc open/read/write/connect/exec/exit、文件内容前缀、少量调用栈 | 参数和调用来源更具体 | 进不去静态链接进程；直接 syscall 可绕过 libc |
| Gateway | TLS 终止后的模型协议 | 完整请求、响应、SSE | 能证明模型实际收到什么 | 只覆盖经过受控 Gateway 的模型流量 |

证据判定顺序：

1. 用 strace 证明文件或网络操作实际进入内核。
2. 用 Frida 补充成功注入进程的函数、缓冲区和调用栈。
3. 用 Gateway 证明最终外发给模型的协议正文。
4. 用文件快照、Hash 和 Marker 建立内容来源关系。

Frida 和 strace 结果不一致时保留两份证据，并在 `quality/trace-quality.json` 的 `strace_only_pids` 与 `frida_only_pids` 中写出进程号。

## 保存位置

```text
runs/<run-id>/
├── raw/system/strace.<pid>
├── raw/frida/events.<pid>.jsonl
├── normalized/events.jsonl
└── quality/trace-quality.json
```

没有 `system.frida.loaded` 时，整轮质量状态为 `incomplete`。

## 其他成熟方案

| 方案 | 合适场景 | 与当前版本的关系 |
|---|---|---|
| eBPF：Tracee、Tetragon、Inspektor Gadget | 宿主机上按 cgroup 观察容器 | 当前运行环境是 Windows 上的 Docker Desktop，宿主机没有可用的 eBPF。有 Linux 宿主机后再加第三份证据 |
| bpftrace/BCC | 内核 tracepoint 原型 | 适合研究，不作为这轮采集器 |
| Linux Audit/auditd | 主机合规审计 | 语义有限，可作以后的补充 |
| Falco | 运行时威胁检测 | 不作为原始 Trace 采集器 |

## 主要资料

- Frida Gadget: https://frida.re/docs/gadget/
- Frida modes: https://frida.re/docs/modes/
- strace manual: https://man7.org/linux/man-pages/man1/strace.1.html
- Tracee: https://aquasecurity.github.io/tracee/latest/
