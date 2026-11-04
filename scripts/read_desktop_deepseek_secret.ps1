# The setup script copies this helper into the dedicated account's protected
# profile directory. Codex invokes that copy to obtain a short-lived token.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$expectedSid = 'S-1-5-21-2341826845-1812322924-2265560838-1005'
if ($identity.User.Value -cne $expectedSid) {
    throw 'Dedicated desktop demo account required'
}
$profilePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$authDir = Join-Path (Join-Path $profilePath '.codex') 'transpect-deepseek-auth'
$expectedHelper = Join-Path $authDir 'read-secret.ps1'
if ([IO.Path]::GetFullPath($PSCommandPath) -ne [IO.Path]::GetFullPath($expectedHelper)) {
    throw 'Run the protected credential reader copy'
}
$secretPath = Join-Path $authDir 'deepseek-key.dpapi'
$secretFile = Get-Item -LiteralPath $secretPath -ErrorAction Stop
if ($secretFile.Length -lt 1 -or $secretFile.Length -gt 16384) {
    throw 'Invalid protected secret file size'
}
$ciphertext = [IO.File]::ReadAllText($secretPath, [Text.Encoding]::UTF8)
$secureKey = ConvertTo-SecureString -String $ciphertext
$buffer = [IntPtr]::Zero
try {
    $buffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($buffer)
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'Protected secret is empty' }
    [Console]::Out.Write($token)
} finally {
    if ($buffer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($buffer)
    }
    $secureKey.Dispose()
}
