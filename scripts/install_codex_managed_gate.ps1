<#
.SYNOPSIS
Install the Codex DLP hook gate as a machine-wide managed layer.

.DESCRIPTION
NOT EFFECTIVE ON codex-cli 0.166.0-alpha.6. Verified on this build: the client
does read %ProgramData%\OpenAI\Codex\requirements.toml -- an unsupported key
there is reported as "requirements (...): `model` is ignored" -- and
hooks.windows_managed_dir is in the client's own requirements schema, yet
pointing it at a hooks directory loaded no hook and produced no diagnostic.
Use scripts/install_codex_hook_gate.py --layer user plus the one-time trust
prompt, which is verified end to end. This script is kept for the day the
managed path works; run it with -WhatIfOnly to inspect what it would write.

Writes %ProgramData%\OpenAI\Codex\requirements.toml pointing at an
administrator-owned managed hooks directory, then sets ACLs so a standard user
can read and execute the gate but cannot modify or delete it. Requires an
administrator; the client reads this location from the ProgramData known folder,
which the PROGRAMDATA environment variable cannot redirect, so the path cannot
be tested without writing to the real location.

Honest limits, stated here because they decide what this install is worth:
  * The client treats a hook that fails to start as non-blocking. ACLs on the
    gate are what stop a standard user from arranging that failure; a local
    administrator can still remove this layer.
  * The gate runs as the signed-in user, so its audit log and encrypted archive
    must stay user-writable and are not protected from that user.
  * `-GatePython` and `-GateEntry` must be paths that user cannot write to,
    or the gate's own code remains editable. The script refuses obviously
    user-writable locations unless -AllowUserWritableGate is passed.

.EXAMPLE
PS> .\install_codex_managed_gate.ps1 -GateDirectory C:\ProgramData\Transpect\codex-gate -WhatIfOnly
#>
[CmdletBinding()]
param(
    [string]$ProgramData = $env:ProgramData,
    [string]$ManagedHooksDirectory = (Join-Path $env:ProgramData 'Transpect\codex-hooks'),
    [Parameter(Mandatory = $true)][string]$GatePython,
    [Parameter(Mandatory = $true)][string]$GateEntry,
    [Parameter(Mandatory = $true)][string]$GateConfig,
    [switch]$AllowUserWritableGate,
    [switch]$WhatIfOnly,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run as an administrator.'
    }
}

function Assert-NoSpaces([string]$Value, [string]$Label) {
    if ($Value -match '\s') {
        throw "Codex cannot quote hook command tokens; $Label has whitespace: $Value"
    }
}

function Set-AdminOwnedAcl([string]$Path) {
    # Administrators and SYSTEM own it; Users may read and execute only.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rules = @(
        @('BUILTIN\Administrators', 'FullControl'),
        @('NT AUTHORITY\SYSTEM', 'FullControl'),
        @('BUILTIN\Users', 'ReadAndExecute')
    )
    foreach ($rule in $rules) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $rule[0], $rule[1],
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)))
    }
    $acl.SetOwner((New-Object System.Security.Principal.NTAccount('BUILTIN\Administrators')))
    Set-Acl -Path $Path -AclObject $acl
}

Assert-Administrator
$codexManaged = Join-Path $ProgramData 'OpenAI\Codex'
$requirements = Join-Path $codexManaged 'requirements.toml'
$managedHooks = Join-Path $ManagedHooksDirectory 'hooks.json'

if ($Remove) {
    foreach ($target in @($requirements, $managedHooks)) {
        if (Test-Path -LiteralPath $target) {
            if ($WhatIfOnly) { Write-Output "would remove $target" }
            else { Remove-Item -LiteralPath $target -Force; Write-Output "removed $target" }
        }
    }
    Write-Output 'Restart Codex so the managed layer is reloaded.'
    return
}

foreach ($pair in @(@($GatePython, 'GatePython'), @($GateEntry, 'GateEntry'),
                    @($GateConfig, 'GateConfig'))) {
    Assert-NoSpaces $pair[0] $pair[1]
    if (-not (Test-Path -LiteralPath $pair[0])) { throw "$($pair[1]) not found: $($pair[0])" }
}
if (-not $AllowUserWritableGate) {
    foreach ($path in @($GatePython, $GateEntry, $GateConfig)) {
        $acl = Get-Acl -LiteralPath $path
        $writable = $acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference -notmatch 'Administrators|SYSTEM|TrustedInstaller' -and
            $_.FileSystemRights -match 'Write|Modify|FullControl'
        }
        if ($writable) {
            throw ("$path is writable by $($writable[0].IdentityReference); the gate code " +
                   'would stay editable by the account it governs. Move it under ProgramData ' +
                   'or pass -AllowUserWritableGate to accept that gap knowingly.')
        }
    }
}

$command = "$GatePython $GateEntry $GateConfig"
$requirementsBody = @"
# Managed Codex requirements written by scripts/install_codex_managed_gate.ps1.
# Hooks loaded through this layer are enforced: the signed-in user is not asked
# to trust them and cannot skip them from CODEX_HOME.

[hooks]
windows_managed_dir = "$($ManagedHooksDirectory -replace '\\','/')"
"@
$hooksBody = @"
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "description": "transpect-codex-dlp-gate",
        "hooks": [ { "type": "command", "command": "$($command -replace '\\','/')" } ]
      }
    ],
    "PreToolUse": [
      {
        "description": "transpect-codex-dlp-gate",
        "hooks": [ { "type": "command", "command": "$($command -replace '\\','/')" } ]
      }
    ],
    "PreModelRequest": [
      {
        "description": "transpect-codex-dlp-gate",
        "hooks": [ { "type": "command", "command": "$($command -replace '\\','/')", "async": true } ]
      }
    ]
  }
}
"@

if (Test-Path -LiteralPath $requirements) {
    throw "$requirements already exists; merge it by hand so no managed setting is lost."
}

if ($WhatIfOnly) {
    Write-Output "would write $requirements"
    Write-Output $requirementsBody
    Write-Output "would write $managedHooks"
    Write-Output $hooksBody
    return
}

New-Item -ItemType Directory -Force -Path $codexManaged | Out-Null
New-Item -ItemType Directory -Force -Path $ManagedHooksDirectory | Out-Null
Set-Content -LiteralPath $managedHooks -Value $hooksBody -Encoding UTF8
Set-Content -LiteralPath $requirements -Value $requirementsBody -Encoding UTF8
Set-AdminOwnedAcl $codexManaged
Set-AdminOwnedAcl $ManagedHooksDirectory

Write-Output "wrote $requirements"
Write-Output "wrote $managedHooks"
Write-Output 'ACLs: Administrators/SYSTEM FullControl, Users ReadAndExecute.'
Write-Output 'Restart Codex. Managed hooks need no trust prompt.'
