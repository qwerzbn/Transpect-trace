#!/usr/bin/env bash
set -euo pipefail

# Run inside the existing Ubuntu-24.04 WSL distribution. WSL's /dev/kvm and
# swtpm give this VM a real virtual TPM 2.0 without changing the Windows host.
# `preflight` never opens the VM disk or starts its guest firmware.

mode=${1:-preflight}
case "$mode" in preflight|install|run) ;; *) echo "usage: $0 preflight|install|run [--network] [--package-media] [--skip-media-pin]" >&2; exit 2 ;; esac
shift || true
network=0
package_media=0
skip_media_pin=0
for option in "$@"; do
    case "$option" in
        --network) network=1 ;;
        --package-media) package_media=1 ;;
        --skip-media-pin) skip_media_pin=1 ;;
        *) echo "unknown option: $option" >&2; exit 2 ;;
    esac
done
if [[ "$skip_media_pin" == 1 && "$mode" != preflight ]]; then
    echo 'media pin can only be skipped in a no-disk preflight' >&2
    exit 2
fi
if [[ "$mode" == install && "$package_media" == 1 ]]; then
    echo "attach package media only after installation" >&2
    exit 2
fi

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
vm="$repo/runs/desktop-vm"
iso="$vm/Win11_EnterpriseEval_26H2_zh-cn.iso"
disk="$vm/codex-desktop-win11.qcow2"
media="$vm/guest-media.iso"
vars="$vm/desktop-uefi-vars-wsl-ms.fd"
code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
vars_template=/usr/share/OVMF/OVMF_VARS_4M.ms.fd

check_package() {
    local found
    found=$(dpkg-query -W -f='${Version}' "$1" 2>/dev/null) || {
        echo "missing WSL package $1" >&2; exit 3;
    }
    if [[ "$found" != "$2" ]]; then
        echo "$1 version differs: expected $2, got $found" >&2
        exit 3
    fi
}

check_hash() {
    local actual
    actual=$(sha256sum -- "$1" | cut -d ' ' -f 1)
    if [[ "$actual" != "$2" ]]; then
        echo "SHA-256 mismatch: $1" >&2
        exit 3
    fi
}

check_package qemu-system-x86 '1:8.2.2+ds-0ubuntu1.18'
check_package swtpm '0.7.3-0ubuntu5.24.04.1'
check_package ovmf '2024.02-2ubuntu0.10'
check_hash /usr/bin/qemu-system-x86_64 8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854
check_hash /usr/bin/swtpm 5e9e073fc569588b9fa87dff6785233a714a27c234d23da940e708f44e25368d
check_hash "$code" 1286f2a3217d09b374d05951355d7a561c8bacecd74845c8a1fbb71a48c0de8d
check_hash "$vars_template" a9b2b13aba3d4629593913471af7545bd8eef1d414f33cab4c86fff7d5bc09b9

python3 - "$vm" "$iso" "$disk" "$media" "$package_media" "$skip_media_pin" "$mode" <<'PY'
import hashlib, json, pathlib, struct, sys
vm, iso, disk, media = map(pathlib.Path, sys.argv[1:5])
media_required = sys.argv[5] == '1'
skip_media_pin = sys.argv[6] == '1'
mode = sys.argv[7]
pins = json.loads((vm / 'pins.json').read_text(encoding='utf-8'))
for path, field in [(iso, 'windows_iso_sha256'), (media, 'guest_media_iso_sha256')]:
    if skip_media_pin:
        continue
    if path == media and not media_required:
        continue
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest.lower() != pins[field].lower():
        raise SystemExit(f'pin mismatch: {path}')
if mode != 'preflight':
    with disk.open('rb') as stream:
        header = stream.read(32)
    if len(header) < 32 or header[:4] != b'QFI\xfb' or struct.unpack('>I', header[4:8])[0] not in (2, 3):
        raise SystemExit('unexpected qcow2 header')
    virtual_bytes = struct.unpack('>Q', header[24:32])[0]
    if virtual_bytes < 64 * 1024**3:
        raise SystemExit(f'VM disk too small: {virtual_bytes}')
    print(f'ISO pin valid; qcow2 virtual size {virtual_bytes // 1024**3} GiB')
else:
    print(f'ISO pin {"skipped" if skip_media_pin else "valid"}; VM disk unopened')
PY

python3 - <<'PY'
import fcntl, os
fd = os.open('/dev/kvm', os.O_RDWR)
try:
    version = fcntl.ioctl(fd, 0xAE00, 0)
finally:
    os.close(fd)
if version != 12:
    raise SystemExit(f'unexpected KVM API version {version}')
print('WSL KVM API version 12 available')
PY

tpm_help=$(qemu-system-x86_64 -tpmdev help 2>&1 || true)
[[ "$tpm_help" == *"emulator"* ]] || { echo 'QEMU lacks the TPM emulator backend' >&2; exit 4; }
device_help=$(qemu-system-x86_64 -device help 2>&1 || true)
[[ "$device_help" == *"tpm-tis"* ]] || { echo 'QEMU lacks the TPM TIS device' >&2; exit 4; }

# Verify the actual swtpm/QEMU/KVM linkage with no VM disk, ISO or OVMF vars.
if [[ "$mode" == preflight ]]; then
    probe_dir=$(mktemp -d /tmp/ttrace-tpm-preflight.XXXXXX)
    swtpm socket --tpmstate "dir=$probe_dir" \
        --ctrl "type=unixio,path=$probe_dir/socket" --tpm2 --flags not-need-init \
        >"$probe_dir/swtpm.out" 2>&1 &
    tpm_pid=$!
    trap 'kill "$tpm_pid" 2>/dev/null || true; wait "$tpm_pid" 2>/dev/null || true' EXIT
    for ((i=0; i<50; i++)); do
        [[ -S "$probe_dir/socket" ]] && break
        sleep 0.1
    done
    [[ -S "$probe_dir/socket" ]] || { cat "$probe_dir/swtpm.out" >&2; exit 4; }
    output=$(printf 'info tpm\nquit\n' | timeout 15 qemu-system-x86_64 \
        -accel kvm -machine q35 -cpu host -nodefaults -S -display none \
        -chardev "socket,id=chrtpm,path=$probe_dir/socket" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0 -monitor stdio)
    if [[ "$output" != *"tpm0"* ]]; then
        echo "QEMU TPM smoke test lacked tpm0: $output" >&2
        exit 4
    fi
    printf 'swtpm/QEMU/KVM smoke test passed (no VM disk attached)\n'
    exit 0
fi

[[ -n "${DISPLAY:-}" ]] || { echo 'WSLg DISPLAY is unavailable' >&2; exit 4; }
display_help=$(qemu-system-x86_64 -display help 2>&1 || true)
[[ "$display_help" == *"gtk"* ]] || { echo 'QEMU GTK display is unavailable' >&2; exit 4; }

if [[ "$mode" == install && ! -e "$vars" ]]; then
    cp -- "$vars_template" "$vars"
fi
[[ -f "$vars" ]] || { echo "UEFI vars missing: $vars" >&2; exit 4; }

state="${XDG_STATE_HOME:-$HOME/.local/state}/transpect-trace/desktop-vm/tpm2"
mkdir -p -- "$state"
chmod 700 "$state"
runtime=$(mktemp -d /tmp/ttrace-tpm-runtime.XXXXXX)
swtpm socket --tpmstate "dir=$state,mode=0600" \
    --ctrl "type=unixio,path=$runtime/socket" --tpm2 --flags not-need-init \
    >"$runtime/swtpm.out" 2>&1 &
tpm_pid=$!
trap 'kill "$tpm_pid" 2>/dev/null || true; wait "$tpm_pid" 2>/dev/null || true' EXIT
for ((i=0; i<50; i++)); do
    [[ -S "$runtime/socket" ]] && break
    sleep 0.1
done
[[ -S "$runtime/socket" ]] || { cat "$runtime/swtpm.out" >&2; exit 4; }

args=(-accel kvm -machine q35,smm=on -cpu host -smp 2 -m 4096
      -display gtk,gl=off -vga std -device qemu-xhci -device usb-tablet
      -drive "if=pflash,format=raw,unit=0,file=$code,readonly=on"
      -drive "if=pflash,format=raw,unit=1,file=$vars"
      -drive "file=$disk,format=qcow2,if=ide,index=0,media=disk"
      -chardev "socket,id=chrtpm,path=$runtime/socket"
      -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0)
if [[ "$mode" == install ]]; then
    args+=(-drive "file=$iso,format=raw,if=ide,index=2,media=cdrom,readonly=on" -boot order=d)
else
    args+=(-boot order=c)
fi
if [[ "$package_media" == 1 ]]; then
    args+=(-drive "file=$media,format=raw,if=ide,index=2,media=cdrom,readonly=on")
fi
if [[ "$network" == 1 ]]; then
    args+=(-nic user,model=e1000e)
else
    args+=(-nic none)
fi
printf 'Starting isolated guest with vTPM 2.0; mode=%s; network=%s\n' "$mode" "$network"
qemu-system-x86_64 "${args[@]}"
