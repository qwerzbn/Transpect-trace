"""Check source layout, local links, public entry points and optional evidence paths.

No raw run payloads or local environment configuration are read or printed.
This checks engineering integrity, not runtime capture/enforcement certification.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tomllib
import zipfile
from urllib.parse import unquote, urlsplit

from _build_support import ROOT


def local_links(root=ROOT):
    failures=[];checked=0;external_local=[]
    for source in [root/'README.md',*sorted((root/'docs').rglob('*.md'))]:
        for line,text in enumerate(source.read_text(encoding='utf-8').splitlines(),1):
            for match in re.finditer(r'!?\[[^\]\n]*\]\(([^)\n]+)\)',text):
                target=match.group(1).strip().strip('<>')
                if target.startswith('#'):continue
                parts=urlsplit(target)
                if parts.scheme or parts.netloc:
                    if parts.scheme.lower() in {'file','c','d'}:external_local.append({'source':source.relative_to(root).as_posix(),'line':line,'target':target})
                    continue
                path=unquote(parts.path)
                if not path:continue
                if path.startswith('/'):
                    external_local.append({'source':source.relative_to(root).as_posix(),'line':line,'target':path});continue
                resolved=(source.parent/path).resolve();checked+=1
                if not resolved.exists():failures.append({'source':source.relative_to(root).as_posix(),'line':line,'target':path})
    return {'checked':checked,'missing':failures,'external_local_links':external_local}


def evidence_paths(root=ROOT):
    # Public reports carry redacted facts; raw local evidence is intentionally
    # excluded. Check only paths explicitly supplied in this checkout.
    manifest=root/'deploy/validation/local-evidence.json'
    if not manifest.is_file():
        return [{'manifest':str(manifest.relative_to(root)), 'target':'not installed', 'exists':False}]
    value=json.loads(manifest.read_text(encoding='utf-8'))
    return [{'manifest':str(manifest.relative_to(root)), 'target':name, 'exists':(root/name).is_file()}
            for name in value['paths']]


def check(root=ROOT,with_local_evidence=False):
    required=['src/transpect_trace/'+name for name in ('guard','observe','protect','behavior')]
    required+=['native','schemas','tests','scripts','deploy','patches','.github']
    missing=[rel for rel in required if not (root/rel).is_dir()]
    tracked=subprocess.check_output(['git','-C',str(root),'ls-files','-z']).decode('utf-8').split('\0')
    allowed=set(json.loads((root/'release-files.json').read_text(encoding='utf-8'))['files'])
    forbidden=[rel for rel in tracked if rel and (root/rel).is_file() and (rel not in allowed or rel.split('/')[0] in {'.venv','.external','build','runs','dist','.idea'}
               or Path(rel).name=='.env' or (Path(rel).name.startswith('.env.') and Path(rel).name!='.env.example'))]
    ignored={rel:subprocess.run(['git','-C',str(root),'check-ignore','--quiet','--',rel],capture_output=True).returncode==0
             for rel in ['.env','.env.local','.idea/workspace.xml','runs/example/summary.json','build/example.dll']}
    project=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    entrypoints=project['project']['scripts']
    expected={'ttrace':'transpect_trace.cli:main'}
    from typer.main import get_command
    from transpect_trace.cli import app
    registered=sorted(get_command(app).commands)
    links=local_links(root)
    evidence=evidence_paths(root) if with_local_evidence else []
    passed=not missing and not forbidden and all(ignored.values()) and entrypoints==expected and {'guard','observe','protect','behavior'}==set(registered)
    passed=passed and not links['missing'] and all(r['exists'] for r in evidence)
    return {'passed':passed,'missing_directories':missing,'forbidden_tracked_paths':forbidden,
            'ignore_checks':ignored,'entrypoints':entrypoints,'cli_commands':registered,'links':links,
            'evidence_paths':evidence,'local_evidence_checked':with_local_evidence,
            'runtime_capture_certified':False}


def check_wheel(path):
    with zipfile.ZipFile(path) as wheel:
        names=wheel.namelist()
    forbidden=[]
    for name in names:
        parts=PurePosixPath(name).parts
        if (not (name.startswith('transpect_trace/') or parts and parts[0].endswith('.dist-info')) or
            any(p in {'..','__pycache__','.venv','.external','runs','build','dist'} or p.startswith('.env') for p in parts) or
            Path(name).suffix.lower() in {'.exe','.dll','.pyd','.pyc','.pdb','.key'}):
            forbidden.append(name)
    return {'path':str(path),'members':len(names),'forbidden_members':forbidden,'passed':not forbidden}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-local-evidence',action='store_true')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--wheel',type=Path,help='Also inspect a built Python-only wheel.')
    args=parser.parse_args();result=check(with_local_evidence=args.with_local_evidence)
    if args.wheel:
        result['wheel']=check_wheel(args.wheel)
        result['passed']=result['passed'] and result['wheel']['passed']
    rendered=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(rendered,encoding='utf-8')
    print(rendered)
    if not result['passed']:raise SystemExit(1)


if __name__=='__main__':main()
