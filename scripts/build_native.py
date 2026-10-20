"""Official Native build dispatcher. Existing per-component entry points remain supported."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
import tomllib

from _build_support import ROOT

BUILDERS = {'guard':'build_guard_native.py', 'observe':'build_observe_native.py',
            'ecapture':'build_ecapture_windows.py',
            'behavior':'build_behavior_native.py'}
SOURCES = {
    'behavior':['native/behavior/etw.c','native/behavior/egress_client.c','native/behavior/wfp_lease.c',
                'native/behavior/wfp_ids.h','native/guard/etw.c'],
    'guard':['native/guard/guard.c','native/guard/etw.c','native/guard/policy_fixture.c'],
    'observe':['native/observe/observer.c','native/observe/schannel_fixture.c'],
    'ecapture':[],
}


def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def preflight(components, variant='upstream', source=None, go=None):
    """Read-only checks; do not load a Hook, rebuild, download, or alter a pin."""
    checks=[]
    def record(name,ok): checks.append({'check':name,'passed':bool(ok)})
    record('Windows x64 CPython 3.12',sys.platform=='win32' and sys.maxsize>2**32 and sys.version_info[:2]==(3,12))
    project=tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))
    zig_requirement=next(r for r in project['project']['optional-dependencies']['native-build'] if r.startswith('ziglang=='))
    zig_version=zig_requirement.split('==',1)[1]
    try: record(zig_requirement,importlib.metadata.version('ziglang')==zig_version)
    except importlib.metadata.PackageNotFoundError: record(zig_requirement,False)
    for component in components:
        for rel in SOURCES[component]: record(rel,(ROOT/rel).is_file())
    vendors=set()
    if set(components)&{'guard'}:vendors.update(('minhook','jsmn'))
    if 'observe' in components or ('ecapture' in components and variant=='enhanced'):vendors.add('minhook')
    for vendor in sorted(vendors):
        folder=ROOT/'native/guard/third_party'/vendor
        for name,want in json.loads((folder/'source-manifest.json').read_text(encoding='utf-8'))['sha256'].items():
            p=folder/name;record(f'{vendor}/{name}',p.is_file() and digest(p)==want)
    if 'ecapture' in components:
        from transpect_trace.observe.ecapture import PIN
        source=source or ROOT/'.external/ecapture-windows';go=go or ROOT/'.external/toolchains/go/bin/go.exe'
        record('local Go toolchain',go.is_file())
        try:
            head=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],stderr=subprocess.DEVNULL,text=True).strip()
            clean=not subprocess.check_output(['git','-C',str(source),'status','--porcelain'],stderr=subprocess.DEVNULL,text=True).strip()
            record('eCapture upstream pin and clean checkout',head==PIN['commit'] and clean)
        except (OSError,subprocess.CalledProcessError):record('eCapture upstream pin and clean checkout',False)
        if variant=='enhanced':
            record('native/observe/ecapture_fixture.c',(ROOT/'native/observe/ecapture_fixture.c').is_file())
            folder=ROOT/'patches/ecapture-windows';pin=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
            record('eCapture patch base',pin['base_commit']==PIN['commit'])
            for name,want in pin['sha256'].items():record(name,(folder/name).is_file() and digest(folder/name)==want)
    return {'components':components,'variant':variant,'ready':all(c['passed'] for c in checks),'checks':checks}


def commands(components, output_root, variant, source=None, go=None):
    for component in components:
        destination=output_root/('observe/ecapture-enhanced' if component=='ecapture' and variant=='enhanced'
                                 else 'observe' if component=='ecapture' else component)
        command=[sys.executable,str(ROOT/'scripts'/BUILDERS[component]),'--output',str(destination)]
        if component=='ecapture':
            command+=['--variant',variant]
            if source:command+=['--source',str(source)]
            if go:command+=['--go',str(go)]
        yield command


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component',choices=['all',*BUILDERS],default='all')
    parser.add_argument('--output-root',type=Path,default=ROOT/'build')
    parser.add_argument('--ecapture-variant',choices=['upstream','enhanced'],default='upstream')
    parser.add_argument('--source',type=Path,help='Pinned eCapture checkout override.')
    parser.add_argument('--go',type=Path,help='Local Go executable override.')
    parser.add_argument('--check',action='store_true',help='Verify prerequisites without changing artifacts.')
    args=parser.parse_args();components=list(BUILDERS) if args.component=='all' else [args.component]
    source=args.source.resolve() if args.source else None;go=args.go.resolve() if args.go else None
    result=preflight(components,args.ecapture_variant,source,go)
    print(json.dumps(result,indent=2),flush=True)
    if not result['ready']:raise SystemExit(1)
    if not args.check:
        for command in commands(components,args.output_root.resolve(),args.ecapture_variant,source,go):
            subprocess.run(command,cwd=ROOT,check=True)


if __name__=='__main__':main()
