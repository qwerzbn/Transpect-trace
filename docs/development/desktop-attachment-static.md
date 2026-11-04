# 固定版桌面端的本地附件路径：静态检查记录

本记录只分析官方 `OpenAI.Codex` MSIX `26.1029.7803.0` 内的打包代码，未运行该版本的桌面界面，也未观察到实际模型请求。安装包 SHA-256 为 `19487892B7E27C74E75C6422088E91B35B4291ED485045F82A1984A13B22D128`；解出的 `app/resources/app.asar` SHA-256 为 `77ED4DDC5B388AC8B29F5035F9C98F982B095DF55AAD6FA6C27BB80D763B9691`。以下函数名来自压缩后的代码，调用细节仅适用于这一固定版本。

## 代码中可直接确认的路径

| 位置及文件 SHA-256 | 观察到的调用 | 能说明什么 |
| --- | --- | --- |
| `.vite/build/early-bootstrap-632-62c641245a52ef0e.js`；`C16675E64DAE86BDB09F7720F038A8C2F2BEACF0E85BBADD369F407D38662AA4` | 初始化附件管理器时设置 `isLocalHost: "local" === this.hostId`；`uploadLocalFiles` 遇到 `isLocalHost` 立即返回传入的附件描述符。非本地主机分支才使用 `uploadLocalFile` 或 `fs/writeFile` 将文件复制到目标主机。 | **本地主机分支没有在此函数内上传原文件字节**。因此不能把该函数的非本地传输分支当作所有本地附件的网络发送点。 |
| `webview/assets/async/228323.e1ce728ea2.js`；`F7821473BE2910D35745576AC721F5B6FA28B00955FC24C776D35EB5E62F8ADA` | 对已有本地路径，界面调用 `uploadLocalFileAttachments({attachments:[{label, path, fsPath}], ...})`，随后取返回的 `fsPath`。 | 界面存在将**本地路径描述符**交给附件管理器的路径；结合上一行，本地主机分支可能继续传递路径，而非立即发送文件字节。 |
| 同一个 webview bundle 与上述 early-bootstrap bundle | 浏览器 `File` 对象由 `createBrowserFileAttachmentDescriptors` 处理；在 `createAttachmentFromLocalFile` 路径中，以 18,432 字节为一块经界面桥接写入暂存资产，然后调用 `copyLocalFileAttachment`；另一条路径调用 `createFileAttachment`，后者生成 Blob 内容并经 `fs/writeFile` 写入受管附件目录。 | **界面选取或粘贴的文件还有暂存、复制路径**，不能用“本地路径直接返回”概括所有附件来源。暂存资产与受管副本也不能自动等同于模型端收到的字节。 |

## 对 DLP 原型的影响

按上述代码推断，本地 Codex 任务可能先把路径或本地副本交给后端，再由后端决定如何读取及组装模型输入。固定版桌面端因此至少要区分：原始本地文件、界面暂存或复制的文件、后端构造的请求正文，以及模型请求里的文件引用。**原文件字节的检查点应在实际读取或复制它们的地方确定**；只盯着一个推测的 Electron 附件上传网络端点，无法证明覆盖本地任务。检查后的文件快照必须和后续请求引用绑定；文件变化或引用无法关联时，门控应拒绝。

下一步在专用 Windows 账户运行同一固定版的 `idle`、文字、现有路径文件及浏览器选取文件样本，分别记录经身份核对的桌面主进程、NetworkService 和 `codex.exe app-server` 的只读调用事件。需要动态确认：`hostId` 在本地任务中的实值、文件原始字节最先出现的进程和调用栈、后端读取时间、HTTP/WSS 序列化正文与文件引用的关系，以及拒绝能否发生在任何字节到达受控源站之前。当前静态证据**不构成 Hook 覆盖、阻断或零字节外发证明**。本机观察流程见 [desktop-path-host.md](desktop-path-host.md)。
