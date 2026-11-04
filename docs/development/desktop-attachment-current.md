# 当前桌面端附件路径观察准备

固定版 MSIX `26.1029.7803.0` 的静态代码表明，本机任务的附件管理器可能直接传递本地路径，也可能先把浏览器 `File` 分块写入暂存目录。静态结论见 [desktop-attachment-static.md](desktop-attachment-static.md)。因此，模型请求中的文件路径、界面暂存副本和最终读取的原字节必须分别核对；观察到文件被打开，不能推断它已经作为附件外发。

新增的 `scripts/probe_desktop_current_attachment.py` 是**观察工具**。它在运行前核对归档 MSIX、当前注册包、桌面主进程和 `codex.exe app-server` 的版本、哈希、SID、父子关系与启动时间；可选核对桌面端的 NetworkService 子进程。Frida 只在这些已核对的进程内短时观察 `CreateFileW`、`ReadFile`、`NtReadFile`、`WriteFile`、WinHTTP 写入候选，以及后端 HTTP/WSS 模型正文候选。进程内最多扫描 256 KiB 的单个缓冲区，仅在出现本轮随机合成附件标记时报告缓冲区匹配；模型候选调用另记不含内容的计数。报告保存进程角色、API、长度、标记位置、模块名与相对代码偏移；不保存文件路径、任意缓冲区 SHA、正文或文件原字节。只有整个匹配缓冲区的长度、哈希和标记位置均等于合成文件，才标记 `exact_fixture_buffer=true`。

`prepare` 生成固定校验的文字与附件夹具；`trace` 需要 `--active-current-client --observation-only --synthetic-file-only` 三个显式参数。脚本本身**没有桌面端界面上传触发器**，也不会自动向模型提交文件。当前 Codex 连接工具只能给测试任务发送文字，不能附带本地文件；Windows Computer Use 技能禁止自动化 Codex 桌面界面。因此本轮仅完成可复用的观察代码及离线测试，**未在当前客户端运行附件实验**。不应让使用者为这一步切换 Windows 账户，或把“给 Agent 一个文件路径让其读取”写作“界面上传文件”。

即使将来在观察窗口内看到 `ReadFile`、`WriteFile`、WinHTTP 和模型候选点的标记，报告也固定为 `coverage_status=unvalidated`、`attachment_upload_covered=false`、`remote_origin_zero_bytes_verified=false`。单次缓冲区标记不能证明所有文件字节已采集、暂存副本与原文件相同、文件引用已绑定到检查过的快照，也不能证明 Native 拒绝发生在实际上传发送前。要完成附件门控，还需要一个可自动触发的真实界面附件提交入口，随后分别验证本地路径与浏览器 `File` 两条路径，并以受控源站和文件哈希核对拒绝时收到的字节数。
