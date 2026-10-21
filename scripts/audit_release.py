"""Audit the explicit public file list without printing matched secret values."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

from _build_support import ROOT


def audit(root=ROOT,working_tree=False):
    manifest=json.loads((root/"release-files.json").read_text(encoding="utf-8"))
    allowed=set(manifest["files"])
    tracked=set(filter(None,subprocess.check_output(
        ["git","-C",str(root),"ls-files","-z"]).decode("utf-8").split("\0")))
    issues=[]
    patterns={
        "private_key_block":re.compile(r"^-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----$",re.M),
        "github_token":re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b"),
        "provider_token":re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
        "slack_token":re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{24,}\b"),
    }
    total=0
    for name in sorted(tracked|allowed):
        path=root/name
        if name not in allowed:
            issues.append({"path":name,"reason":"not_in_release_allowlist"})
            continue
        if not path.is_file():
            issues.append({"path":name,"reason":"missing_release_file"})
            continue
        resolved=path.resolve()
        if not resolved.is_relative_to(root.resolve()) or path.is_symlink():
            issues.append({"path":name,"reason":"outside_release_root"})
            continue
        if path.suffix.lower() in {".exe",".dll",".pyd",".pdb",".pyc",".key",".pem",".zip",".xz",".docx",".pdf"} or any(
            part in {"runs","reports","build","dist",".external",".venv","__pycache__"} or part.startswith(".env")
            for part in path.relative_to(root).parts):
            issues.append({"path":name,"reason":"private_or_generated_asset"})
            continue
        raw=subprocess.check_output(["git","-C",str(root),"show",":"+name]) if name in tracked and not working_tree else path.read_bytes()
        total+=len(raw)
        if len(raw)>1024*1024:
            issues.append({"path":name,"reason":"unexpected_large_file"})
        try:
            text=raw.decode("utf-8")
        except UnicodeDecodeError:
            issues.append({"path":name,"reason":"non_text_asset"})
            continue
        for rule,pattern in patterns.items():
            if pattern.search(text):
                issues.append({"path":name,"reason":rule})
    return {"passed":not issues,"files":len(allowed),"bytes":total,"issues":issues,
            "scope":"allowlisted current tree only; history is not rewritten; heuristic secret scan"}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    parser.add_argument('--working-tree',action='store_true',help='Inspect pending source changes without staging them.')
    args=parser.parse_args();result=audit(working_tree=args.working_tree)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2))
    if not result["passed"]:raise SystemExit(1)


if __name__=="__main__":main()
