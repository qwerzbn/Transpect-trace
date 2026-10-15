"""Reproducible, pinned upstream Windows build. Requires a local Go toolchain."""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
from transpect_trace.observe.ecapture import PIN


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('.external/ecapture-windows'))
    parser.add_argument('--go',type=Path,default=Path('.external/toolchains/go/bin/go.exe'))
    args=parser.parse_args();source=args.source.resolve();output=Path('build/observe').resolve();output.mkdir(parents=True,exist_ok=True)
    actual=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    if actual!=PIN['commit']:raise RuntimeError('eCapture source pin mismatch')
    if subprocess.check_output(['git','-C',str(source),'status','--porcelain'],text=True).strip():raise RuntimeError('eCapture source must be unmodified')
    env=dict(os.environ,CGO_ENABLED='0',GOTOOLCHAIN='local')
    subprocess.run([str(args.go.resolve()),'build','-tags','windows','-o',str(output/'ecapture.exe'),'.'],cwd=source,env=env,check=True)
    dll=source/'contrib/schannel_hook/schannel_hook.c'
    subprocess.run([sys.executable,'-m','ziglang','cc','-target','x86_64-windows-gnu','-shared','-O2',
                    str(dll),'-lsecur32','-lws2_32','-o',str(output/'schannel_hook.dll')],check=True)
    manifest={**PIN,'go_version':subprocess.check_output([str(args.go.resolve()),'version'],text=True).strip(),
              'companion_source_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),
              'artifacts_sha256':{name:hashlib.sha256((output/name).read_bytes()).hexdigest() for name in ['ecapture.exe','schannel_hook.dll']}}
    (output/'ecapture-build.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))


if __name__=='__main__':main()
