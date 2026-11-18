param(
    [string]$StatePath = "$env:LOCALAPPDATA\TranspectTrace\guard-hub\state.json",
    [switch]$ValidateOnly
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$created = $false
$monitorMutexName = if ($ValidateOnly) { "Local\ttrace-unified-guard-monitor-validation-$PID" } else { 'Local\ttrace-unified-guard-monitor' }
$singleton = New-Object System.Threading.Mutex($true, $monitorMutexName, [ref]$created)
if (-not $created) { $singleton.Dispose(); exit 0 }
try {
    $stateDirectory = Split-Path -Parent $StatePath
    $stopIntentPath = Join-Path $stateDirectory 'stop-request.json'
    $monitorStatePath = Join-Path $stateDirectory 'monitor-state.json'
    [void][System.IO.Directory]::CreateDirectory($stateDirectory)
    $monitorState = @{ pid = $PID; started_at = [datetime]::Now.ToString('o'); script = $PSCommandPath }
    if (-not $ValidateOnly) {
        [System.IO.File]::WriteAllText($monitorStatePath, ($monitorState | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    }
    $script:nextRecover = [datetime]::MinValue
    function Test-HubRunning {
        try {
            $mutex = [System.Threading.Mutex]::OpenExisting('Local\ttrace-unified-guard-hub')
            $mutex.Dispose()
            return $true
        } catch [System.Threading.WaitHandleCannotBeOpenedException] {
            return $false
        } catch {
            # An access error is not proof that the singleton disappeared.
            return $true
        }
    }
    function Recover-Hub($observed) {
        if ((Test-Path -LiteralPath $stopIntentPath) -or $observed.status -ne 'RUNNING' -or
            -not $observed.pid -or [datetime]::Now -lt $script:nextRecover -or (Test-HubRunning)) { return }
        $script:nextRecover = [datetime]::Now.AddSeconds(5)
        $pythonPath = Join-Path (Split-Path -Parent $PSScriptRoot) '.venv\Scripts\python.exe'
        $launcherPath = Join-Path $PSScriptRoot 'guard_hub.py'
        # The CLI checks this observed generation and stop intent again before launching.
        $arguments = '"' + $launcherPath + '" start --recover-hub-pid ' + [int]$observed.pid
        $attempt = @{ prior_hub_pid = [int]$observed.pid; requested_at = [datetime]::Now.ToString('o'); live_test = [bool]$observed.claude_live_test }
        [System.IO.File]::AppendAllText((Join-Path $stateDirectory 'monitor-recovery.jsonl'),
            (($attempt | ConvertTo-Json -Compress) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
        Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory (Split-Path -Parent $PSScriptRoot) -WindowStyle Hidden | Out-Null
    }
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Transpect Trace | Codex + Claude 监视器'
    $form.ClientSize = New-Object System.Drawing.Size(1050, 680)
    $form.MinimumSize = New-Object System.Drawing.Size(850, 550)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#101827')
    $form.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#E5EAF3')
    $form.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 10)

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.Padding = New-Object System.Windows.Forms.Padding(22)
    $layout.RowCount = 6
    $layout.ColumnCount = 1
    foreach ($height in @(48, 42, 100, 100, 0, 44)) {
        $style = New-Object System.Windows.Forms.RowStyle
        if ($height -eq 0) { $style.SizeType = 'Percent'; $style.Height = 100 }
        else { $style.SizeType = 'Absolute'; $style.Height = $height }
        [void]$layout.RowStyles.Add($style)
    }
    $form.Controls.Add($layout)

    function New-Label([string]$Text, [int]$Size = 10) {
        $control = New-Object System.Windows.Forms.Label
        $control.Text = $Text
        $control.Dock = 'Fill'
        $control.TextAlign = 'MiddleLeft'
        $control.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', $Size)
        return $control
    }
    $title = New-Label 'Transpect Trace   /   双客户端防护监视' 19
    $layout.Controls.Add($title, 0, 0)
    $health = New-Label '正在读取守护状态…'
    $layout.Controls.Add($health, 0, 1)
    $labels = @{}
    foreach ($name in @('codex', 'claude')) {
        $label = New-Label ''
        $label.Padding = New-Object System.Windows.Forms.Padding(12, 4, 8, 4)
        $label.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#1B2639')
        $label.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
        $labels[$name] = $label
        $layout.Controls.Add($label, 0, $(if ($name -eq 'codex') { 2 } else { 3 }))
    }
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.RowHeadersVisible = $false
    $grid.AutoSizeColumnsMode = 'Fill'
    $grid.AutoSizeRowsMode = 'AllCells'
    $grid.BackgroundColor = $form.BackColor
    $grid.BorderStyle = 'None'
    $grid.EnableHeadersVisualStyles = $false
    $grid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#243249')
    $grid.ColumnHeadersDefaultCellStyle.ForeColor = $form.ForeColor
    $grid.ColumnHeadersHeight = 32
    $grid.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#152035')
    $grid.DefaultCellStyle.ForeColor = $form.ForeColor
    $grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.ColorTranslator]::FromHtml('#2B3E5A')
    $grid.DefaultCellStyle.SelectionForeColor = $form.ForeColor
    $grid.DefaultCellStyle.WrapMode = 'True'
    foreach ($column in @(@('client','客户端'), @('pid','PID'), @('state','实际状态'),
                          @('counts','请求 / 放行 / 拒绝'), @('detail','说明'))) {
        [void]$grid.Columns.Add($column[0], $column[1])
    }
    $grid.Columns['client'].FillWeight = 12
    $grid.Columns['pid'].FillWeight = 10
    $grid.Columns['state'].FillWeight = 26
    $grid.Columns['counts'].FillWeight = 22
    $grid.Columns['detail'].FillWeight = 50
    $layout.Controls.Add($grid, 0, 4)
    $footer = New-Label '只读监视窗 · 关闭按钮仅最小化 · 停止守护请运行 ./start.sh stop'
    $footer.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#A3B3CB')
    $layout.Controls.Add($footer, 0, 5)

    $script:allowClose = $false
    $form.Add_FormClosing({
        param($sender, $eventArgs)
        if (-not $script:allowClose -and $eventArgs.CloseReason -eq 'UserClosing') {
            $eventArgs.Cancel = $true
            $sender.WindowState = 'Minimized'
        }
    })
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    $timer.Add_Tick({
        try {
            $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
            $age = ([datetime]::Now - [datetime]::Parse($state.updated_at)).TotalSeconds
            if ($state.status -eq 'STOPPED') {
                $script:allowClose = $true
                $form.Close()
                return
            }
            Recover-Hub $state
            $stale = $age -gt 10 -or $state.status -ne 'RUNNING'
            $health.Text = if ($stale) { '守护心跳中断或正在停止；请检查状态，不能视为正在防护。' }
                           elseif (-not $state.services.codex.running -or -not $state.services.claude.running) {
                               '部分守护正在启动或恢复；下方显示实际状态。'
                           } else { "双守护运行中  ·  更新 $($state.updated_at)  ·  完整保护以逐项验收为准" }
            $health.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($(if ($stale) { '#FF8D8D' } else { '#8ECAF2' }))
            $grid.Rows.Clear()
            foreach ($name in @('codex', 'claude')) {
                $service = $state.services.$name
                $shown = if ($stale) { 'STALE / 状态未确认' } else { [string]$service.status }
                $friendly = if ($name -eq 'codex') { 'Codex 桌面端' } else { 'Claude Code CLI' }
                $mode = if ($name -eq 'claude' -and $state.claude_live_test) { ' · 固定版实验采证' } else { '' }
                $labels[$name].Text = "$friendly    $shown$mode`n模型：$($service.coverage.reason)`n工具出口：$($service.egress.reason)"
                $labels[$name].ForeColor = [System.Drawing.ColorTranslator]::FromHtml($(if ($stale -or $service.status -in @('OFFLINE','ATTENTION','STALE')) { '#FF9C9C' } elseif ($service.status -eq 'PROTECTED') { '#A3E8B6' } else { '#F3D18D' }))
                foreach ($process in $service.processes) {
                    $rowState = if ($stale) { 'STALE' } else { [string]$process.state }
                    $counts = "$($process.requests) / $($process.allowed) / $($process.denied)"
                    [void]$grid.Rows.Add($friendly, [string]$process.pid, $rowState, $counts, [string]$process.detail)
                }
                if ($service.recovery_error) {
                    [void]$grid.Rows.Add($friendly, '-', 'RECOVERY', '-', [string]$service.recovery_error)
                }
            }
            $grid.ClearSelection()
        } catch {
            $health.Text = '尚未读到有效状态；等待守护启动。不会把缺失状态显示为受保护。'
            $health.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#FF9C9C')
            foreach ($label in $labels.Values) { $label.Text = '状态未知 / UNKNOWN' }
            $grid.Rows.Clear()
        }
    })
    if ($ValidateOnly) {
        Write-Output "Monitor controls valid: $($grid.Columns.Count) columns; readonly=$($grid.ReadOnly)"
    } else {
        $timer.Start()
        [System.Windows.Forms.Application]::Run($form)
    }
    $timer.Dispose()
    $form.Dispose()
} finally {
    $singleton.ReleaseMutex()
    $singleton.Dispose()
}
