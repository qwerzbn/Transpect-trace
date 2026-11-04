# Read-only preflight for the dedicated-account Windows desktop experiment.
# It deliberately contains no account, package, firewall, or process mutation.
[CmdletBinding()]
param(
    [string]$MsixPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'runs/desktop-vm/guest-media/ChatGPT-x64.msix'),
    [string]$PinsPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'deploy/guard/desktop-vm-pins.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedArchiveVersion = '26.1029.7803.0'
$expectedActiveVersion = '26.1027.6604.0'
$expectedName = 'OpenAI.Codex'
$expectedPublisher = 'CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B'
$expectedFamily = 'OpenAI.Codex_2p2nqsd0c76g0'
$expectedSignerThumbprint = 'B0429F3569607833179400E29D6D641B363CA6A4'

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
        $manifest = $archive.GetEntry('AppxManifest.xml')
        if ($null -eq $manifest) { throw 'MSIX lacks AppxManifest.xml' }
        $reader = [System.IO.StreamReader]::new($manifest.Open())
        try {
            [xml]$xml = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
        $node = $xml.SelectSingleNode("/*[local-name()='Package']/*[local-name()='Identity']")
        if ($null -eq $node) { throw 'MSIX manifest lacks Package/Identity' }
        return [pscustomobject]@{
            Name = $node.GetAttribute('Name')
            Publisher = $node.GetAttribute('Publisher')
            Version = $node.GetAttribute('Version')
            Architecture = $node.GetAttribute('ProcessorArchitecture')
        }
    } finally {
        $archive.Dispose()
    }
}

$msix = (Resolve-Path -LiteralPath $MsixPath).ProviderPath
$pins = (Resolve-Path -LiteralPath $PinsPath).ProviderPath
$pin = Get-Content -LiteralPath $pins -Raw -Encoding UTF8 | ConvertFrom-Json
if ($null -eq $pin.chatgpt_msix_sha256) { throw 'Pin manifest lacks chatgpt_msix_sha256' }

$actualHash = (Get-FileHash -LiteralPath $msix -Algorithm SHA256).Hash.ToUpperInvariant()
Assert-Equal $actualHash ([string]$pin.chatgpt_msix_sha256).ToUpperInvariant() 'Archived MSIX SHA-256'

$signature = Get-AuthenticodeSignature -FilePath $msix
Assert-Equal ([string]$signature.Status) 'Valid' 'MSIX signature status'
if ($null -eq $signature.SignerCertificate) { throw 'MSIX signer certificate missing' }
Assert-Equal $signature.SignerCertificate.Subject $expectedPublisher 'MSIX signer subject'
Assert-Equal $signature.SignerCertificate.Thumbprint.ToUpperInvariant() $expectedSignerThumbprint 'MSIX signer thumbprint'

$archiveIdentity = Read-MsixIdentity $msix
Assert-Equal $archiveIdentity.Name $expectedName 'Archived package name'
Assert-Equal $archiveIdentity.Publisher $expectedPublisher 'Archived package publisher'
Assert-Equal $archiveIdentity.Version $expectedArchiveVersion 'Archived package version'
Assert-Equal $archiveIdentity.Architecture 'x64' 'Archived package architecture'

$installed = @(Get-AppxPackage -Name $expectedName)
if ($installed.Count -ne 1) { throw "Expected one active-user $expectedName registration, found $($installed.Count)" }
$active = $installed[0]
Assert-Equal ([string]$active.Name) $expectedName 'Active package name'
Assert-Equal ([string]$active.Publisher) $expectedPublisher 'Active package publisher'
Assert-Equal ([string]$active.PackageFamilyName) $expectedFamily 'Active package family'
Assert-Equal ([string]$active.Version) $expectedActiveVersion 'Active package version'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$activeProcesses = @(Get-CimInstance Win32_Process -Filter "Name='ChatGPT.exe'" |
    Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith(
        $active.InstallLocation + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase) })

[pscustomobject]@{
    Schema = 'transpect.desktop-host-preflight/1.0'
    ArchiveMsix = $msix
    ArchiveVersion = $archiveIdentity.Version
    ArchiveSha256 = $actualHash
    ArchiveSignature = [string]$signature.Status
    ArchiveSignerThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
    CurrentUser = $identity.Name
    CurrentUserSid = $identity.User.Value
    CurrentUserIsAdministrator = $isAdministrator
    ActivePackageVersion = [string]$active.Version
    ActivePackageFamily = [string]$active.PackageFamilyName
    ActiveDesktopProcessCount = $activeProcesses.Count
    SamePackageFamily = $true
    SafeToInstallInCurrentUser = $false
    RequiredPath = 'Create a separate standard Windows account; run per-user package registration only in that account after admin review.'
    MutationsPerformed = $false
}
