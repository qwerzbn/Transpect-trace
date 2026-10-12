$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$statePath = Join-Path $projectRoot 'runs/desktop/watcher.json'
if (!(Test-Path -LiteralPath $statePath)) { Write-Output 'No watcher record'; exit }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$watcher = Get-Process -Id $state.pid -ErrorAction SilentlyContinue
if ($watcher) {
    if ($watcher.StartTime.ToUniversalTime().ToString('o') -ne $state.started -or $watcher.Path -ne $state.executable) {
        throw 'PID identity changed; refusing to stop an unrelated process'
    }
    Stop-Process -Id $watcher.Id
}
Remove-Item -LiteralPath $statePath
Write-Output 'Desktop watcher stopped'
