<#
.SYNOPSIS
Plans or installs a user-level hourly cleanup task for desktop DLP archives.

Default behavior is read-only. -Install is the only mutating switch. The task
runs only with the current user's interactive token so DPAPI can unwrap that
user's archive key. It cannot provide isolation from other same-user code.
#>
param(
    [Parameter(Mandatory = $true)][string]$ExpectedSid,
    [string]$ArchiveRoot,
    [switch]$Install
)

$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne $ExpectedSid) {
    throw "Current account SID does not match ExpectedSid"
}

$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($ArchiveRoot)) {
    $ArchiveRoot = Join-Path $repository 'runs\desktop-current'
}
$archiveRootResolved = (Resolve-Path -LiteralPath $ArchiveRoot -ErrorAction Stop).ProviderPath
$runsResolved = (Resolve-Path -LiteralPath (Join-Path $repository 'runs') -ErrorAction Stop).ProviderPath
$runsPrefix = $runsResolved.TrimEnd('\') + '\'
if (-not $archiveRootResolved.StartsWith($runsPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'ArchiveRoot must be a child of the repository runs directory'
}
$python = Join-Path $repository '.venv\Scripts\python.exe'
$cleaner = Join-Path $PSScriptRoot 'prune_desktop_dlp_archives.py'
if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or
    -not (Test-Path -LiteralPath $cleaner -PathType Leaf)) {
    throw 'Pinned repository Python or archive cleaner is missing'
}

$planJson = & $python $cleaner --root $archiveRootResolved --expected-sid $ExpectedSid
if ($LASTEXITCODE -ne 0) {
    throw 'Archive cleaner preflight failed'
}
$plan = $planJson | ConvertFrom-Json
if ($plan.status -ne 'inspection_only') {
    throw 'Archive cleaner did not return an inspection-only plan'
}

$taskName = 'Transpect-Desktop-DLP-Archive-Prune-' + $ExpectedSid.Split('-')[-1]
$actionArgs = '"' + $cleaner + '" --root "' + $archiveRootResolved + '" --expected-sid ' +
    $ExpectedSid + ' --prune'
$action = New-ScheduledTaskAction -Execute $python -Argument $actionArgs -WorkingDirectory $repository
$hourly = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
    -RepetitionInterval ([TimeSpan]::FromHours(1)) `
    -RepetitionDuration ([TimeSpan]::FromDays(3650))
$logon = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::FromMinutes(10)) -MultipleInstances IgnoreNew `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

function Test-InstalledTask {
    param($Task, [string]$Sid, [string]$PythonPath,
          [string]$Arguments, [string]$WorkingDirectory)
    try {
        $taskSid = ([System.Security.Principal.NTAccount]$Task.Principal.UserId).
            Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $false
    }
    return ($taskSid -eq $Sid -and
        $Task.Principal.LogonType -eq 'Interactive' -and
        $Task.Principal.RunLevel -eq 'Limited' -and
        @($Task.Actions).Count -eq 1 -and
        $Task.Actions[0].Execute -eq $PythonPath -and
        $Task.Actions[0].Arguments -eq $Arguments -and
        $Task.Actions[0].WorkingDirectory -eq $WorkingDirectory -and
        @($Task.Triggers).Count -eq 2)
}

$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    if (-not (Test-InstalledTask $existing $ExpectedSid $python $actionArgs $repository)) {
        throw "Scheduled task name is already in use with different settings: $taskName"
    }
    [pscustomobject]@{
        Schema             = 'transpect.desktop-dlp.archive-prune-task/1.0'
        Status             = 'VerifiedInstalled'
        AccountSid         = $ExpectedSid
        TaskName           = $taskName
        ArchiveDirectories = $plan.archive_directories
        MutationsPerformed = $false
    }
    return
}

if (-not $Install) {
    [pscustomobject]@{
        Schema             = 'transpect.desktop-dlp.archive-prune-task/1.0'
        Status             = 'ReadyToInstall'
        AccountSid         = $ExpectedSid
        TaskName           = $taskName
        ArchiveDirectories = $plan.archive_directories
        ExpiredAtPreflight = $plan.expired_count_at_preflight
        Frequency          = 'hourly while the account has an interactive session; also at logon'
        MutationsPerformed = $false
    }
    return
}

$null = Register-ScheduledTask -TaskName $taskName -Action $action `
    -Trigger @($hourly, $logon) -Principal $principal -Settings $settings `
    -Description 'Prune expired encrypted desktop DLP snapshots' -ErrorAction Stop
$verified = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if (-not (Test-InstalledTask $verified $ExpectedSid $python $actionArgs $repository)) {
    throw 'Scheduled task registration could not be verified'
}
[pscustomobject]@{
    Schema             = 'transpect.desktop-dlp.archive-prune-task/1.0'
    Status             = 'VerifiedInstalled'
    AccountSid         = $ExpectedSid
    TaskName           = $taskName
    ArchiveDirectories = $plan.archive_directories
    MutationsPerformed = $true
}
