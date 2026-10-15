"""Build passive observer; preserves the separate enforcement DLL."""
import hashlib,json,subprocess,sys
from pathlib import Path


def main():
    root=Path('native/guard/third_party/minhook')
    manifest=json.loads((root/'source-manifest.json').read_text())
    for name,want in manifest['sha256'].items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=want:raise RuntimeError('Vendor checksum mismatch')
    output=Path('build/observe');output.mkdir(parents=True,exist_ok=True)
    sources=[Path('native/observe/observer.c'),*[root/'src'/p for p in ['buffer.c','hook.c','trampoline.c','hde/hde64.c']]]
    subprocess.run([sys.executable,'-m','ziglang','cc','-target','x86_64-windows-gnu','-O2','-shared',
                    *map(str,sources),'-lsecur32','-o',str(output/'ttrace-observe.dll')],check=True)
    subprocess.run([sys.executable,'-m','ziglang','cc','-target','x86_64-windows-gnu','-O2','-municode',
                    'native/observe/schannel_fixture.c','-lwinhttp','-o',str(output/'schannel_fixture.exe')],check=True)
    result={'sources_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*sources,Path('native/observe/schannel_fixture.c')]},
            'dll_sha256':hashlib.sha256((output/'ttrace-observe.dll').read_bytes()).hexdigest(),
            'fixture_sha256':hashlib.sha256((output/'schannel_fixture.exe').read_bytes()).hexdigest()}
    (output/'native-build.json').write_text(json.dumps(result,indent=2)+'\n')
    print(output.resolve())


if __name__=='__main__':main()
