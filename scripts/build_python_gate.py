"""Build only the restored, fixed CPython HTTPX Native gate; never overwrite evidence."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig

from _build_support import ROOT

# Preserved from the original deploy/protect/baselines.json. New builds do not
# depend on the original, dirty working copy or any prebuilt DLL from there.
RUNTIME_PINS = {
    'python.exe': '4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a',
    'python312.dll': '9a0e3435aaa680d868150f87ab3e388ad2eebc22f87e036155c7b4eda8cd2120',
    'DLLs/libssl-3.dll': '007142039f04d04e0ed607bda53de095e5bc6a8a10d26ecedde94ea7d2d7eefe',
}
RESTORED_SOURCES = {
    'native/protect/python_gate.c': '0c4fab09b6846cca57f96c0e2d4fd4d98d0a77acfa15b98c1e38cffc8651e379',
    'src/transpect_trace/protect/python_bridge.py': '91d0df64a5bedeb0b7fb95a4ab139d8d5fe61a67bc09bb28b909d83867b24fce',
    'src/transpect_trace/protect/python_runner.py': 'b829c4f1e2711578dfd75ab6745dc52342c7fb75419d6c60c3f0324b714d7d66',
}


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prerequisites() -> tuple[list[Path], list[Path]]:
    if sys.platform != 'win32' or sys.maxsize <= 2**32 or sys.version_info[:3] != (3, 12, 10):
        raise RuntimeError('fixed baseline requires Windows x64 CPython 3.12.10')
    if importlib.metadata.version('ziglang') != '0.13.0':
        raise ValueError('fixed Zig toolchain mismatch')
    if importlib.metadata.version('httpx') != '0.28.1':
        raise ValueError('fixed HTTPX baseline mismatch')
    base = Path(sys.base_prefix).resolve()
    runtime = [base / name for name in RUNTIME_PINS]
    for path, wanted in zip(runtime, RUNTIME_PINS.values()):
        if digest(path) != wanted:
            raise ValueError(f'fixed runtime identity mismatch: {path.name}')
    source = ROOT / 'native/protect/python_gate.c'
    if digest(source) != RESTORED_SOURCES['native/protect/python_gate.c']:
        raise ValueError('restored Native source changed; review ABI before creating a new baseline')
    vendor = ROOT / 'native/guard/third_party/jsmn'
    manifest = json.loads((vendor / 'source-manifest.json').read_text(encoding='utf-8'))
    for name, wanted in manifest['sha256'].items():
        if digest(vendor / name) != wanted:
            raise ValueError('jsmn checksum mismatch')
    import httpx
    package = Path(httpx.__file__).resolve().parent
    runtime += [Path(sys.executable).resolve(), package / '_client.py', package / '_transports/default.py']
    # Record link and compile inputs as well as the sources restored above.
    sources = [ROOT / name for name in RESTORED_SOURCES]
    sources += [vendor / 'jsmn.h', vendor / 'source-manifest.json', Path(__file__).resolve()]
    for path in [base / 'libs/python312.lib', Path(sysconfig.get_paths()['include']) / 'Python.h']:
        if not path.is_file():
            raise FileNotFoundError(path)
        runtime.append(path)
    return list(dict.fromkeys(runtime)), sources


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/python-outbound-20261026')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    runtime, sources = prerequisites()
    if args.check:
        print(json.dumps({'ready': True, 'runtime_files': len(runtime), 'sources': len(sources)}))
        return
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    native = output / '_ttrace_native_gate.pyd'
    command = [sys.executable, '-m', 'ziglang', 'cc', '-target', 'x86_64-windows-gnu', '-O2', '-s',
               '-shared', str(ROOT / 'native/protect/python_gate.c'),
               '-I' + sysconfig.get_paths()['include'], str(Path(sys.base_prefix) / 'libs/python312.lib'),
               '-o', str(native)]
    subprocess.run(command, cwd=ROOT, env={**os.environ, 'SOURCE_DATE_EPOCH': '0'}, check=True)
    manifest = {
        'schema_version': 'transpect.protect.native-build/1.0',
        'python_version': sys.version.split()[0], 'httpx_version': '0.28.1',
        'toolchain': 'ziglang 0.13.0', 'pe_timestamp': 0,
        'sources_sha256': {str(path.relative_to(ROOT)).replace('\\', '/'): digest(path) for path in sources},
        'restored_source_sha256': RESTORED_SOURCES,
        'runtime_files': {str(path): digest(path) for path in runtime},
        'artifacts': {native.name: digest(native)},
    }
    (output / 'native-build.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(output)


if __name__ == '__main__':
    main()
