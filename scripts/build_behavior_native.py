"""Build isolated behavior components without rebuilding certified Guard artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT, enter_repository


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/behavior')
    args = parser.parse_args(); output = args.output.resolve()
    enter_repository(); output.mkdir(parents=True, exist_ok=True)
    for name, libraries in [('etw', ['-ladvapi32', '-ltdh', '-lole32']),
                            ('egress_client', ['-lws2_32']),
                            ('wfp_lease', ['-lfwpuclnt', '-lbcrypt', '-lrpcrt4', '-lws2_32', '-municode'])]:
        subprocess.run([sys.executable, '-m', 'ziglang', 'cc', '-target', 'x86_64-windows-gnu', '-O2',
                        str(ROOT / 'native/behavior' / (name + '.c')), *libraries, '-o', str(output / (name + '.exe'))], check=True)
    sources = [*ROOT.glob('native/behavior/*.c'), *ROOT.glob('native/behavior/*.h'), ROOT / 'native/guard/etw.c']
    manifest = dict(toolchain='ziglang 0.13.0', artifacts_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.glob('*.exe')},
                    sources_sha256={p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
    (output / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    main()
