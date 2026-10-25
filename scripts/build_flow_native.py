"""Build the observation-only cross-application I/O components."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT, enter_repository


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/flow')
    parser.add_argument('--observer-only', action='store_true', help='Build only the Native I/O observer')
    args = parser.parse_args()
    output = args.output.resolve()
    enter_repository()
    vendor = ROOT / 'native/guard/third_party/minhook'
    pin = json.loads((vendor / 'source-manifest.json').read_text())
    for name, expected in pin['sha256'].items():
        if digest(vendor / name) != expected:
            raise RuntimeError('MinHook source checksum mismatch')
    output.mkdir(parents=True, exist_ok=True)
    mh = [vendor / 'src' / name for name in ('buffer.c', 'hook.c', 'trampoline.c', 'hde/hde64.c')]
    targets = [('ttrace-flow-io.dll', [ROOT / 'native/flow/io_observer.c', *mh], ['-shared'])]
    if not args.observer_only:
        targets += [('flow_uploader.exe', [ROOT / 'native/flow/uploader.c'], ['-municode', '-lwinhttp', '-lbcrypt']),
                    ('flow_etw.exe', [ROOT / 'native/flow/etw.c'], ['-ladvapi32', '-ltdh', '-lole32'])]
    artifacts = {}
    all_sources = {ROOT / 'native/flow/protocol.h', vendor / 'source-manifest.json', ROOT/'native/guard/etw.c'}
    all_sources.update(vendor/name for name in pin['sha256'])
    if not args.observer_only:
        all_sources.add(ROOT / 'native/guard/etw.c')
    for name, sources, flags in targets:
        for source in sources:
            if not source.is_file():
                raise FileNotFoundError(f'Flow build input missing: {source.relative_to(ROOT)}')
        subprocess.run([sys.executable, '-m', 'ziglang', 'cc', '-target', 'x86_64-windows-gnu', '-O2',
                        *map(str, sources), *flags, '-o', str(output / name)], check=True)
        artifacts[name] = {'sha256': digest(output / name)}
        all_sources.update(sources)
    manifest = {'protocol': 'FIO1', 'audit_transport': 'FIO1-ACK1', 'can_enforce': False,
                'toolchain': {'ziglang': importlib.metadata.version('ziglang')},
                'sources_sha256': {str(path.relative_to(ROOT)).replace('\\', '/'): digest(path) for path in sorted(all_sources)},
                'artifacts': artifacts}
    (output / 'native-build.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(output)


if __name__ == '__main__':
    main()
