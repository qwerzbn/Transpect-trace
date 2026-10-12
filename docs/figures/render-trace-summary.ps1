Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 1400,860
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.Clear([System.Drawing.Color]::FromArgb(247,249,252))
$font = New-Object System.Drawing.Font 'Microsoft YaHei',18
$small = New-Object System.Drawing.Font 'Microsoft YaHei',13
$title = [System.Drawing.Font]::new('Microsoft YaHei',[single]28,[System.Drawing.FontStyle]::Bold)
$dark = [System.Drawing.Brushes]::MidnightBlue
function Label($s,$x,$y,$f=$font) { $g.DrawString($s,$f,$dark,[float]$x,[float]$y) }
function Box($x,$y,$w,$h,$s,$sub) {
 $g.FillRectangle([System.Drawing.Brushes]::White,$x,$y,$w,$h)
 $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(125,155,190)),2
 $g.DrawRectangle($pen,$x,$y,$w,$h)
 Label $s ($x+15) ($y+15)
 Label $sub ($x+15) ($y+50) $small
 $pen.Dispose()
}
function Arrow($x1,$y1,$x2,$y2,$dashed=$false) {
 $p=New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(64,104,160)),3
 $p.CustomEndCap=New-Object System.Drawing.Drawing2D.AdjustableArrowCap 5,6
 if($dashed){$p.DashStyle='Dash'}
 $g.DrawLine($p,$x1,$y1,$x2,$y2)
 $p.Dispose()
}
Label 'Agent 信息流追踪：真实 Demo 结果示意' 45 24 $title
Label '2 个 Agent  ·  9 次工具调用  ·  15 次模型请求  |  简化展示，非界面截图' 48 78 $small
Label '① 调用树：谁调用了谁' 45 126
Box 540 177 320 88 '主 Codex Agent' '读取项目资料，组织任务'
Arrow 620 265 300 320
Arrow 780 265 1100 320
Box 120 320 360 88 'delegate_budget' '显式创建独立 Codex 子进程'
Box 920 320 360 88 'submit_report' '接收报告，返回本地回执'
Arrow 300 408 300 454
Box 120 454 360 88 '子 Codex Agent' '读取 budget.csv，完成预算分析'
Label '父子 Agent 有独立 Thread ID；系统进程树另外记录 fork / exec / PID。' 540 462 $small
Label '本地回执表示工具收到数据，不表示互联网外发。' 540 495 $small
Label '② 数据流：读取 → 模型请求 → 改写 → 工具输入' 45 576
Box 40 626 275 95 'budget.csv 等文件' '系统调用证据：成功读取'
Box 385 626 275 95 '模型请求正文' '原文匹配；上游响应证明接收'
Box 730 626 275 95 '分析 / 汇总结果' '改写内容保留可能来源标签'
Box 1075 626 285 95 'submit_report 输入' '本地工具接收证据'
Arrow 315 673 385 673
Arrow 660 673 730 673 $true
Arrow 1005 673 1075 673 $true
Label '实线：采集证据支持的步骤；文件原文出现不等于唯一来源证明。' 45 751 $small
Label '虚线：保守的可能依赖关系，不是逐字节或语义来源证明。完整事件保存在 JSON / JSONL。' 45 783 $small
$bmp.Save((Join-Path (Get-Location) 'docs/figures/trace-demo-summary.png'),[System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
