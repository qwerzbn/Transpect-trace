# Configure the fixed desktop package under its dedicated Windows account.
# The default invocation is read-only. -Install writes only that account's
# Codex config and a reviewed model catalog. It never handles the API key.
[CmdletBinding()]
param([switch]$Install)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedSid = 'S-1-5-21-2341826845-1812322924-2265560838-1005'
$expectedAccount = 'ttrace-desktop-demo'
$expectedPackage = 'OpenAI.Codex_26.1029.7803.0_x64__2p2nqsd0c76g0'
$expectedDesktopHash = '74DCBC67421C5D5406EA5E4CC80D9C8D8A05D0DF62F1D7BE5690F090F182E71F'
$expectedBackendHash = '925C7D0665FFA49B0DCF748E034A805A04DA984164AC92301432073B47789B99'
$sourceRoot = Split-Path -Parent $PSScriptRoot
$catalogSource = Join-Path $sourceRoot 'deploy/guard/desktop-deepseek-v4-pro-models.json'
$helper = Join-Path $PSScriptRoot 'read_desktop_deepseek_secret.ps1'

function Assert-Equal {
    param([string]$Actual, [string]$Expected, [string]$Label)
    if ($Actual -cne $Expected) { throw "$Label mismatch: expected '$Expected', got '$Actual'" }
}

function Assert-PlainPath {
    param([string]$Path, [string]$Label)
    if ($Path.Contains("'")) { throw "$Label cannot be represented as a TOML literal path" }
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label must not be a reparse point"
        }
    }
}

function Write-NewFile {
    param([string]$Path, [byte[]]$Bytes)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew,
                                  [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length) }
    finally { $stream.Dispose() }
}

# The identity check must precede all filesystem and package access.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
Assert-Equal $identity.User.Value $expectedSid 'Current account SID'
Assert-Equal (($identity.Name -split '\\')[-1]) $expectedAccount 'Current account name'
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Demo account must be a standard user'
}

$profileRegistry = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$expectedSid"
$profileImage = (Get-ItemProperty -LiteralPath $profileRegistry -Name ProfileImagePath).ProfileImagePath
$profilePath = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$profileImage)).TrimEnd('\')
Assert-Equal $profilePath ([IO.Path]::GetFullPath('C:\Users\ttrace-desktop-demo').TrimEnd('\')) 'Dedicated profile path'
Assert-Equal ([IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')) $profilePath 'Current profile path'
$codexHome = Join-Path $profilePath '.codex'
$configPath = Join-Path $codexHome 'config.toml'
$catalogTarget = Join-Path $codexHome 'desktop-deepseek-v4-pro-models.json'
$authDir = Join-Path $codexHome 'transpect-deepseek-auth'
$protectedHelper = Join-Path $authDir 'read-secret.ps1'
$secretPath = Join-Path $authDir 'deepseek-key.dpapi'
Assert-PlainPath $codexHome 'Codex home'
Assert-PlainPath $configPath 'Codex config'
Assert-PlainPath $catalogTarget 'Model catalog target'
Assert-PlainPath $authDir 'Credential directory'
Assert-PlainPath $protectedHelper 'Protected credential helper'
Assert-PlainPath $secretPath 'Protected secret'

$packages = @(Get-AppxPackage -Name 'OpenAI.Codex')
if ($packages.Count -ne 1) { throw 'Expected exactly one current-user OpenAI.Codex package' }
$package = $packages[0]
Assert-Equal ([string]$package.PackageFullName) $expectedPackage 'Installed package'
Assert-Equal ([string]$package.Version) '26.1029.7803.0' 'Installed version'
$desktopImage = Join-Path $package.InstallLocation 'app/ChatGPT.exe'
$backendImage = Join-Path $package.InstallLocation 'app/resources/codex.exe'
Assert-Equal (Get-FileHash -LiteralPath $desktopImage -Algorithm SHA256).Hash.ToUpperInvariant() `
    $expectedDesktopHash 'Installed desktop SHA-256'
Assert-Equal (Get-FileHash -LiteralPath $backendImage -Algorithm SHA256).Hash.ToUpperInvariant() `
    $expectedBackendHash 'Installed backend SHA-256'

$catalogSource = (Resolve-Path -LiteralPath $catalogSource).ProviderPath
$helper = (Resolve-Path -LiteralPath $helper).ProviderPath
Assert-PlainPath $catalogSource 'Model catalog source'
$expectedCatalogHash = '3388852E294471DA49048D786F51F87439BCE78ADB74D944F2F63BB67BB54C89'
$catalogText = [IO.File]::ReadAllText($catalogSource, [Text.Encoding]::UTF8)
$catalogCanonicalBytes = [Text.Encoding]::UTF8.GetBytes($catalogText.Replace("`r`n", "`n"))
$catalogDigest = [Security.Cryptography.SHA256]::Create()
try {
    $canonicalHash = [BitConverter]::ToString(
        $catalogDigest.ComputeHash($catalogCanonicalBytes)).Replace('-', '')
} finally {
    $catalogDigest.Dispose()
}
Assert-Equal $canonicalHash $expectedCatalogHash 'Reviewed model catalog SHA-256'
if (-not (Test-Path -LiteralPath $protectedHelper -PathType Leaf)) {
    throw 'Run set_desktop_deepseek_secret.ps1 in the dedicated account first'
}
if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) {
    throw 'Protected DeepSeek secret is missing'
}
Assert-Equal (Get-FileHash -LiteralPath $protectedHelper -Algorithm SHA256).Hash.ToUpperInvariant() `
    (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToUpperInvariant() 'Protected credential helper SHA-256'
$catalogBytes = [IO.File]::ReadAllBytes($catalogSource)
$catalog = [Text.Encoding]::UTF8.GetString($catalogBytes) | ConvertFrom-Json
if (@($catalog.models).Count -ne 1 -or $catalog.models[0].slug -cne 'deepseek-v4-pro') {
    throw 'Reviewed model catalog must contain only deepseek-v4-pro'
}
if ($catalog.models[0].PSObject.Properties.Name -contains 'model_messages') {
    throw 'Reviewed model catalog must not contain provider instruction templates'
}
$catalogHash = (Get-FileHash -LiteralPath $catalogSource -Algorithm SHA256).Hash.ToUpperInvariant()

$powershellImage = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$powershellImage = (Resolve-Path -LiteralPath $powershellImage).ProviderPath
Assert-PlainPath $powershellImage 'PowerShell image'
$catalogTomlPath = $catalogTarget.Replace('\', '/')
$helperTomlPath = $protectedHelper.Replace('\', '/')
$powershellTomlPath = $powershellImage.Replace('\', '/')
$configText = @"
model = "deepseek-v4-pro"
model_provider = "ttrace_deepseek"
model_catalog_json = '$catalogTomlPath'
model_reasoning_effort = "low"
web_search = "disabled"

[model_providers.ttrace_deepseek]
name = "DeepSeek V4 Pro demo"
base_url = "https://api.deepseek.com"
wire_api = "responses"
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0

[model_providers.ttrace_deepseek.auth]
command = '$powershellTomlPath'
args = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', '$helperTomlPath']
timeout_ms = 10000
refresh_interval_ms = 0
"@ -replace "`r?`n", "`n"
$configText += "`n"
$configBytes = [Text.UTF8Encoding]::new($false).GetBytes($configText)

$catalogMatches = (Test-Path -LiteralPath $catalogTarget) -and
    ((Get-FileHash -LiteralPath $catalogTarget -Algorithm SHA256).Hash.ToUpperInvariant() -ceq $catalogHash)
$configMatches = (Test-Path -LiteralPath $configPath) -and
    ((Get-Content -LiteralPath $configPath -Raw -Encoding UTF8) -ceq $configText)
if ((Test-Path -LiteralPath $catalogTarget) -and -not $catalogMatches) {
    throw 'Existing model catalog differs; review it before changing configuration'
}
if ((Test-Path -LiteralPath $configPath) -and -not $configMatches) {
    throw 'Existing Codex config differs; review it before changing configuration'
}

if ($catalogMatches -and $configMatches) {
    $status = 'VerifiedConfigured'
} elseif (-not $Install) {
    $status = 'ReadyToConfigure'
} else {
    if (-not (Test-Path -LiteralPath $codexHome)) {
        $null = New-Item -ItemType Directory -Path $codexHome
    }
    if (-not $catalogMatches) { Write-NewFile $catalogTarget $catalogBytes }
    if (-not $configMatches) { Write-NewFile $configPath $configBytes }
    $status = 'VerifiedConfigured'
}

[pscustomobject]@{
    Schema = 'transpect.desktop-deepseek-config/1.0'
    Status = $status
    Account = $identity.Name
    AccountSid = $identity.User.Value
    PackageFullName = $package.PackageFullName
    Model = 'deepseek-v4-pro'
    ProviderBaseUrl = 'https://api.deepseek.com'
    CatalogSha256 = $catalogHash
    ConfigPath = $configPath
    SecretStoredInConfig = $false
    MutationsPerformed = [bool]($Install -and $status -eq 'VerifiedConfigured' -and
        (-not $catalogMatches -or -not $configMatches))
}
