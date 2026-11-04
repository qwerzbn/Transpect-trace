# Per-user fixed MSIX registration, only from the separate demo account.
# The default invocation is read-only. -Install is the sole mutation switch.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$MsixPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSid,
    [Parameter(Mandatory = $true)][string]$ProtectedSid,
    [string]$ExpectedAccountName = 'ttrace-desktop-demo',
    [string]$PinsPath,
    [switch]$Install
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $PinsPath) {
    $PinsPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'deploy/guard/desktop-vm-pins.json'
}

$packageName = 'OpenAI.Codex'
$packageVersion = '26.1029.7803.0'
$packageFullName = 'OpenAI.Codex_26.1029.7803.0_x64__2p2nqsd0c76g0'
$publisher = 'CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B'
$thumbprint = 'B0429F3569607833179400E29D6D641B363CA6A4'
$desktopHash = '74DCBC67421C5D5406EA5E4CC80D9C8D8A05D0DF62F1D7BE5690F090F182E71F'
$backendHash = '925C7D0665FFA49B0DCF748E034A805A04DA984164AC92301432073B47789B99'
$sidPattern = '^S-1-5-21-(?:\d+-){3}\d+$'

function Assert-Equal {
    param([string]$Actual, [string]$Expected, [string]$Label)
    if ($Actual -cne $Expected) {
        throw "$Label mismatch: expected '$Expected', got '$Actual'"
    }
}

function Read-MsixIdentity {
    param([string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entry = $archive.GetEntry('AppxManifest.xml')
        if ($null -eq $entry) { throw 'MSIX lacks AppxManifest.xml' }
        $reader = [System.IO.StreamReader]::new($entry.Open())
        try { [xml]$manifest = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        $node = $manifest.SelectSingleNode("/*[local-name()='Package']/*[local-name()='Identity']")
        if ($null -eq $node) { throw 'MSIX lacks Package/Identity' }
        return [pscustomobject]@{
            Name = $node.GetAttribute('Name')
            Publisher = $node.GetAttribute('Publisher')
            Version = $node.GetAttribute('Version')
            Architecture = $node.GetAttribute('ProcessorArchitecture')
        }
    } finally { $archive.Dispose() }
}

function Assert-RegisteredPackage {
    param($Package)
    Assert-Equal ([string]$Package.PackageFullName) $packageFullName 'Installed package'
    Assert-Equal ([string]$Package.Version) $packageVersion 'Installed version'
    Assert-Equal ([string]$Package.Publisher) $publisher 'Installed publisher'
    $location = [IO.Path]::GetFullPath([string]$Package.InstallLocation).TrimEnd([IO.Path]::DirectorySeparatorChar)
    Assert-Equal ([IO.Path]::GetFileName($location)) $packageFullName 'Installed directory'
    $desktop = Join-Path $location 'app/ChatGPT.exe'
    $backend = Join-Path $location 'app/resources/codex.exe'
    Assert-Equal (Get-FileHash -LiteralPath $desktop -Algorithm SHA256).Hash.ToUpperInvariant() $desktopHash 'Installed desktop SHA-256'
    Assert-Equal (Get-FileHash -LiteralPath $backend -Algorithm SHA256).Hash.ToUpperInvariant() $backendHash 'Installed backend SHA-256'
    return [pscustomobject]@{ DesktopImage = $desktop; BackendImage = $backend }
}

# Confirm the account before touching Appx registration. A SID copied from the
# protected account cannot accidentally turn this into a current-user update.
if ($ExpectedSid -notmatch $sidPattern -or $ProtectedSid -notmatch $sidPattern -or
        $ExpectedSid -ceq $ProtectedSid) {
    throw 'ExpectedSid and ProtectedSid must be distinct local user SIDs'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-Equal $identity.User.Value $ExpectedSid 'Current account SID'
Assert-Equal (($identity.Name -split '\\')[-1]) $ExpectedAccountName 'Current account name'
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Demo account must be a standard user'
}

$archivePath = (Resolve-Path -LiteralPath $MsixPath).ProviderPath
$pins = Get-Content -LiteralPath (Resolve-Path -LiteralPath $PinsPath).ProviderPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($null -eq $pins.chatgpt_msix_sha256) { throw 'Pin manifest lacks chatgpt_msix_sha256' }
Assert-Equal (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToUpperInvariant() `
    ([string]$pins.chatgpt_msix_sha256).ToUpperInvariant() 'Archived MSIX SHA-256'
$signature = Get-AuthenticodeSignature -FilePath $archivePath
Assert-Equal ([string]$signature.Status) 'Valid' 'MSIX signature status'
if ($null -eq $signature.SignerCertificate) { throw 'MSIX signer certificate missing' }
Assert-Equal $signature.SignerCertificate.Subject $publisher 'MSIX signer subject'
Assert-Equal $signature.SignerCertificate.Thumbprint.ToUpperInvariant() $thumbprint 'MSIX signer thumbprint'
$packageIdentity = Read-MsixIdentity $archivePath
Assert-Equal $packageIdentity.Name $packageName 'Archived package name'
Assert-Equal $packageIdentity.Publisher $publisher 'Archived package publisher'
Assert-Equal $packageIdentity.Version $packageVersion 'Archived package version'
Assert-Equal $packageIdentity.Architecture 'x64' 'Archived package architecture'

$existing = @(Get-AppxPackage -Name $packageName)
if ($existing.Count -gt 1) { throw 'Multiple current-user Codex registrations need review' }
if ($existing.Count -eq 1) {
    $images = Assert-RegisteredPackage $existing[0]
    [pscustomobject]@{
        Schema = 'transpect.desktop-host-install/1.0'
        Status = 'VerifiedInstalled'
        Account = $identity.Name
        AccountSid = $identity.User.Value
        PackageFullName = $packageFullName
        DesktopImage = $images.DesktopImage
        BackendImage = $images.BackendImage
        MutationsPerformed = $false
    }
    return
}
if (-not $Install) {
    [pscustomobject]@{
        Schema = 'transpect.desktop-host-install/1.0'
        Status = 'ReadyToInstall'
        Account = $identity.Name
        AccountSid = $identity.User.Value
        PackageFullName = $packageFullName
        ArchiveMsix = $archivePath
        MutationsPerformed = $false
    }
    return
}

Add-AppxPackage -Path $archivePath -ErrorAction Stop
$registered = @(Get-AppxPackage -Name $packageName)
if ($registered.Count -ne 1) { throw 'Fixed package was not registered to the dedicated account' }
$images = Assert-RegisteredPackage $registered[0]
[pscustomobject]@{
    Schema = 'transpect.desktop-host-install/1.0'
    Status = 'VerifiedInstalled'
    Account = $identity.Name
    AccountSid = $identity.User.Value
    PackageFullName = $packageFullName
    DesktopImage = $images.DesktopImage
    BackendImage = $images.BackendImage
    MutationsPerformed = $true
}
