"""Reproducible, pinned upstream Windows build. Requires a local Go toolchain."""
import argparse,hashlib,json,os,subprocess,sys,shutil,tempfile
from pathlib import Path
from transpect_trace.observe.ecapture import PIN
from _build_support import ROOT, enter_repository


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'.external/ecapture-windows')
    parser.add_argument('--go',type=Path,default=ROOT/'.external/toolchains/go/bin/go.exe')
    parser.add_argument('--variant',choices=['upstream','enhanced'],default='upstream')
    parser.add_argument('--output',type=Path,help='Isolated artifact directory; defaults to the existing build location.')
    args=parser.parse_args();source=args.source.resolve()
    args.go=args.go.resolve()
    output=(args.output or ROOT/('build/observe' if args.variant=='upstream' else 'build/observe/ecapture-enhanced')).resolve()
    enter_repository();output.mkdir(parents=True,exist_ok=True)
    actual=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    if actual!=PIN['commit']:raise RuntimeError('eCapture source pin mismatch')
    if subprocess.check_output(['git','-C',str(source),'status','--porcelain'],text=True).strip():raise RuntimeError('eCapture source must be unmodified')
    patches={};temp=None
    if args.variant=='enhanced':
        patch_root=Path('patches/ecapture-windows').resolve()
        patch_manifest=json.loads((patch_root/'manifest.json').read_text(encoding='utf-8'))
        if patch_manifest.get('base_commit')!=PIN['commit']:raise RuntimeError('Enhanced patch base mismatch')
        patches=patch_manifest['sha256']
        for name,want in patches.items():
            if hashlib.sha256((patch_root/name).read_bytes()).hexdigest()!=want:raise RuntimeError('Enhanced patch checksum mismatch')
        # Only tracked, pinned files enter the derived source tree. The external
        # checkout is never edited, and untracked local binaries cannot leak in.
        temp=tempfile.TemporaryDirectory(prefix='ecapture-derived-');derived=Path(temp.name)
        entries=subprocess.check_output(['git','-C',str(source),'ls-files','--stage','-z']).decode().split('\0')
        for entry in filter(None,entries):
            metadata,name=entry.split('\t',1)
            if metadata.startswith('160000 '):continue  # Linux-only submodule gitlinks
            target=derived/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,target)
        shutil.copyfile(patch_root/'enhanced/enhanced_entry_windows.go',derived/'enhanced_entry_windows.go')
        shutil.copyfile(patch_root/'enhanced/enhanced_elevation_windows.go',derived/'enhanced_elevation_windows.go')
        shutil.copyfile(patch_root/'enhanced/schannel_hook.c',derived/'contrib/schannel_hook/schannel_hook.c')
        source=derived
    env=dict(os.environ,CGO_ENABLED='0',GOTOOLCHAIN='local')
    subprocess.run([str(args.go.resolve()),'build','-trimpath','-buildvcs=false','-tags','windows','-o',str(output/'ecapture.exe'),'.'],cwd=source,env=env,check=True)
    dll=source/'contrib/schannel_hook/schannel_hook.c'
    extra=[]
    if args.variant=='enhanced':
        vendor=Path('native/guard/third_party/minhook').resolve()
        vendor_manifest=json.loads((vendor/'source-manifest.json').read_text())
        for name,want in vendor_manifest['sha256'].items():
            if hashlib.sha256((vendor/name).read_bytes()).hexdigest()!=want:raise RuntimeError('MinHook checksum mismatch')
        extra=['-I',str(vendor/'include'),*[str(vendor/'src'/p) for p in ['buffer.c','hook.c','trampoline.c','hde/hde64.c']]]
    subprocess.run([sys.executable,'-m','ziglang','cc','-target','x86_64-windows-gnu','-shared','-O2',
                    '-s',f'-ffile-prefix-map={source}=/ecapture',
                    str(dll),*extra,'-lsecur32','-lws2_32','-o',str(output/'schannel_hook.dll')],check=True,
                    env=dict(os.environ,SOURCE_DATE_EPOCH='0'))
    artifacts=['ecapture.exe','schannel_hook.dll']
    if patches:
        subprocess.run([sys.executable,'-m','ziglang','cc','-target','x86_64-windows-gnu','-O2','-s','-municode',
            'native/observe/ecapture_fixture.c','-lwinhttp','-o',str(output/'ecapture_fixture.exe')],check=True,
            env=dict(os.environ,SOURCE_DATE_EPOCH='0'))
        artifacts.append('ecapture_fixture.exe')
    manifest={**PIN,'variant':args.variant,'protocol':'ECW2' if patches else 'upstream-preview',
              'patches_sha256':patches,'go_version':subprocess.check_output([str(args.go.resolve()),'version'],text=True).strip(),
              'native_toolchain':subprocess.check_output([sys.executable,'-m','ziglang','version'],text=True).strip(),
              'companion_source_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),
              'artifacts_sha256':{name:hashlib.sha256((output/name).read_bytes()).hexdigest() for name in artifacts}}
    if patches:manifest.update(transport='restricted-local-named-pipe',connection_identity='SSPI-context-generation',text_preview_limit=None)
    (output/'ecapture-build.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))
    if temp:temp.cleanup()


if __name__=='__main__':main()
