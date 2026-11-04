param(
    [ValidateSet('Install', 'Run')][string]$Mode = 'Install',
    [ValidateRange(4096, 16384)][int]$MemoryMiB = 4096,
    [ValidateRange(2, 16)][int]$Cpus = 2,
    [switch]$EnableGuestNetwork,
    [switch]$AttachPackageMedia
)

$ErrorActionPreference = 'Stop'
$vm = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'runs\desktop-vm'
$qemu = Join-Path $vm 'qemu-portable\qemu-system-x86_64.exe'
$firmware = Join-Path $vm 'qemu-portable\share\edk2-x86_64-code.fd'
$vars = Join-Path $vm 'desktop-uefi-vars.fd'
$disk = Join-Path $vm 'codex-desktop-win11.qcow2'
$iso = Join-Path $vm 'Win11_EnterpriseEval_26H2_zh-cn.iso'
$media = Join-Path $vm 'guest-media.iso'
$pins = Join-Path $vm 'pins.json'

foreach ($path in @($qemu, $firmware, $vars, $disk, $pins)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "VM file missing: $path" }
}
$pin = Get-Content -LiteralPath $pins -Raw | ConvertFrom-Json
foreach ($item in @(@($qemu, $pin.qemu_exe_sha256), @($firmware, $pin.uefi_code_sha256))) {
    if ((Get-FileHash -LiteralPath $item[0] -Algorithm SHA256).Hash -ne $item[1]) {
        throw "VM executable or firmware hash mismatch: $($item[0])"
    }
}

$arguments = @('-accel', 'whpx', '-M', 'q35', '-cpu', 'max', '-smp', "$Cpus",
    '-m', "$MemoryMiB", '-display', 'sdl', '-device', 'qemu-xhci',
    '-device', 'usb-tablet', '-vga', 'std',
    '-drive', "if=pflash,format=raw,unit=0,file=$firmware,readonly=on",
    '-drive', "if=pflash,format=raw,unit=1,file=$vars",
    '-drive', "file=$disk,format=qcow2,if=ide,index=0,media=disk")

if ($Mode -eq 'Install') {
    if (-not (Test-Path -LiteralPath $iso -PathType Leaf)) { throw "Windows ISO missing: $iso" }
    if ((Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash -ne $pin.windows_iso_sha256) {
        throw 'Windows ISO hash mismatch'
    }
    $arguments += @('-drive', "file=$iso,format=raw,if=ide,index=2,media=cdrom,readonly=on",
        '-boot', 'order=d')
} else {
    $arguments += @('-boot', 'order=c')
}

if ($EnableGuestNetwork) {
    $arguments += @('-nic', 'user,model=e1000e')
} else {
    $arguments += @('-nic', 'none')
}

if ($AttachPackageMedia) {
    if ($Mode -eq 'Install') { throw 'Package media is attached only after Windows installation' }
    if (-not (Test-Path -LiteralPath $media -PathType Leaf) -or
            (Get-FileHash -LiteralPath $media -Algorithm SHA256).Hash -ne $pin.guest_media_iso_sha256) {
        throw 'Guest package media ISO is missing or has a different hash'
    }
    $arguments += @('-drive', "file=$media,format=raw,if=ide,index=2,media=cdrom,readonly=on")
}

Write-Host "Starting isolated Codex demo VM ($Mode; network=$($EnableGuestNetwork.IsPresent); package media=$($AttachPackageMedia.IsPresent))."
& $qemu @arguments
exit $LASTEXITCODE
