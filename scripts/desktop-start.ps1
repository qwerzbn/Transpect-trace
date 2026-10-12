$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pythonPath = Join-Path $projectRoot '.venv/Scripts/python.exe'
$outputDirectory = Join-Path $projectRoot 'runs/desktop'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$statePath = Join-Path $outputDirectory 'watcher.json'
if (Test-Path -LiteralPath $statePath) {
    $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $existing = Get-Process -Id $previous.pid -ErrorAction SilentlyContinue
    if ($existing -and $existing.StartTime.ToUniversalTime().ToString('o') -eq $previous.started) {
        Write-Output "Watcher already running: $($previous.pid)"
        exit
    }
}
$watcher = Start-Process -FilePath $pythonPath -ArgumentList '-m transpect_trace.cli desktop-watch' -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $outputDirectory 'watcher.stdout.log') -RedirectStandardError (Join-Path $outputDirectory 'watcher.stderr.log') -PassThru
@{pid=$watcher.Id; started=$watcher.StartTime.ToUniversalTime().ToString('o'); executable=$pythonPath} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
Write-Output "Desktop watcher PID $($watcher.Id), output $outputDirectory"
