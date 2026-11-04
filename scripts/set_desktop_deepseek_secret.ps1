# Run only in the dedicated desktop demo account. The key is protected with
# current-user DPAPI and never written as plaintext to config.toml or a log.
[CmdletBinding()]
param([switch]$VerifyOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedSid = 'S-1-5-21-2341826845-1812322924-2265560838-1005'
$expectedName = 'ttrace-desktop-demo'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -cne $expectedSid -or
        ($identity.Name -split '\\')[-1] -cne $expectedName) {
    throw "Dedicated account required: $expectedName ($expectedSid)"
}
if ([Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from a non-elevated dedicated-account PowerShell'
}

$profilePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
if (-not $profilePath) { throw 'Cannot resolve current user profile' }
$authDir = Join-Path (Join-Path $profilePath '.codex') 'transpect-deepseek-auth'
$secretPath = Join-Path $authDir 'deepseek-key.dpapi'
$helperPath = Join-Path $authDir 'read-secret.ps1'
$helperSource = Join-Path $PSScriptRoot 'read_desktop_deepseek_secret.ps1'
if (-not (Test-Path -LiteralPath $helperSource -PathType Leaf)) {
    throw 'Credential reader script is missing'
}
$expectedReaderHash = '2268E97C9B6E0CC6DB9DDB41D40AB653F5BF50C7753945FCAA70331C1242D2C8'
$readerText = [IO.File]::ReadAllText($helperSource, [Text.Encoding]::UTF8)
$readerBytes = [Text.Encoding]::UTF8.GetBytes($readerText.Replace("`r`n", "`n"))
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $readerHash = [BitConverter]::ToString($sha256.ComputeHash($readerBytes)).Replace('-', '')
} finally {
    $sha256.Dispose()
}
if ($readerHash -cne $expectedReaderHash) {
    throw 'Credential reader source differs from the reviewed version'
}

$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$noPropagation = [Security.AccessControl.PropagationFlags]::None
$allow = [Security.AccessControl.AccessControlType]::Allow
$full = [Security.AccessControl.FileSystemRights]::FullControl
$allowedSids = @($identity.User.Value, 'S-1-5-18')

function Assert-PrivateAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Credential path must not be a reparse point'
    }
    $actual = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $actual.AreAccessRulesProtected) {
        throw 'Credential path still inherits permissions'
    }
    $ownerSid = $actual.Owner
    try {
        $ownerSid = ([Security.Principal.NTAccount]$ownerSid).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch {
        if ($ownerSid -cne $identity.User.Value) { throw 'Credential path owner could not be verified' }
    }
    if ($ownerSid -cne $identity.User.Value) { throw 'Credential path has unexpected owner' }
    $userCanRead = $false
    foreach ($entry in $actual.Access) {
        $sid = $entry.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($entry.AccessControlType -eq $allow -and $sid -notin $allowedSids) {
            throw 'Credential path grants access to another identity'
        }
        if ($entry.AccessControlType -eq $allow -and $sid -ceq $identity.User.Value -and
                ($entry.FileSystemRights -band $full) -eq $full) {
            $userCanRead = $true
        }
    }
    if (-not $userCanRead) {
        throw 'Credential path lacks dedicated-user access'
    }
}

function Assert-StoredSecret {
    Assert-PrivateAcl $authDir
    Assert-PrivateAcl $helperPath
    Assert-PrivateAcl $secretPath
    $helperText = [IO.File]::ReadAllText($helperPath, [Text.Encoding]::UTF8)
    $helperBytes = [Text.Encoding]::UTF8.GetBytes($helperText.Replace("`r`n", "`n"))
    $helperDigest = [Security.Cryptography.SHA256]::Create()
    try {
        $helperHash = [BitConverter]::ToString(
            $helperDigest.ComputeHash($helperBytes)).Replace('-', '')
    } finally {
        $helperDigest.Dispose()
    }
    if ($helperHash -cne $expectedReaderHash) {
        throw 'Protected credential reader differs from the reviewed version'
    }
    $secretFile = Get-Item -LiteralPath $secretPath -ErrorAction Stop
    if ($secretFile.Length -lt 1 -or $secretFile.Length -gt 16384) {
        throw 'Invalid protected secret file size'
    }
    $ciphertext = [IO.File]::ReadAllText($secretPath, [Text.Encoding]::UTF8)
    $storedKey = ConvertTo-SecureString -String $ciphertext -ErrorAction Stop
    try {
        if ($storedKey.Length -lt 10) { throw 'Protected secret is unexpectedly short' }
    } finally {
        $storedKey.Dispose()
    }
}

if ($VerifyOnly) {
    Assert-StoredSecret
    [pscustomobject]@{
        Status = 'SecretVerified'
        AccountSid = $identity.User.Value
        MutationsPerformed = $false
    }
    return
}

if (Test-Path -LiteralPath $authDir) {
    Assert-PrivateAcl $authDir
} else {
    New-Item -ItemType Directory -Path $authDir | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]'S-1-5-18')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, $full, $inherit, $noPropagation, $allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $authDir -AclObject $acl
    Assert-PrivateAcl $authDir
}
foreach ($path in @($secretPath, $helperPath)) {
    if (Test-Path -LiteralPath $path) { Assert-PrivateAcl $path }
}

$secureKey = Read-Host 'DeepSeek API key (input hidden)' -AsSecureString
if ($null -eq $secureKey -or $secureKey.Length -lt 10) {
    throw 'API key is missing or unexpectedly short'
}
try {
    # With no -Key argument, PowerShell uses Windows DPAPI for this user.
    $ciphertext = ConvertFrom-SecureString -SecureString $secureKey
} finally {
    $secureKey.Dispose()
}

function Set-PrivateFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetOwner($identity.User)
    foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]'S-1-5-18')) {
        $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, $full, $allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $fileAcl
    Assert-PrivateAcl $Path
}

$secretTemp = Join-Path $authDir ('.deepseek-key-' + [guid]::NewGuid().ToString('N') + '.tmp')
$helperTemp = Join-Path $authDir ('.read-secret-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    [IO.File]::WriteAllText($secretTemp, $ciphertext, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllBytes($helperTemp, [IO.File]::ReadAllBytes($helperSource))
    Set-PrivateFileAcl $secretTemp
    Set-PrivateFileAcl $helperTemp
    if ([IO.File]::Exists($helperPath)) {
        Assert-PrivateAcl $helperPath
        [IO.File]::Replace($helperTemp, $helperPath, $null)
    } else {
        [IO.File]::Move($helperTemp, $helperPath)
    }
    if ([IO.File]::Exists($secretPath)) {
        Assert-PrivateAcl $secretPath
        [IO.File]::Replace($secretTemp, $secretPath, $null)
    } else {
        [IO.File]::Move($secretTemp, $secretPath)
    }
    Assert-StoredSecret
} finally {
    if ([IO.File]::Exists($secretTemp)) { [IO.File]::Delete($secretTemp) }
    if ([IO.File]::Exists($helperTemp)) { [IO.File]::Delete($helperTemp) }
}

[pscustomobject]@{
    Status = 'SecretStored'
    AccountSid = $identity.User.Value
    SecretFile = $secretPath
    HelperCommand = 'powershell.exe'
    HelperArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                   'RemoteSigned', '-File', $helperPath)
}
