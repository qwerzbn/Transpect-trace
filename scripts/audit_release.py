"""Audit the explicit public file list without printing matched secret values."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import re

from _build_support import ROOT
from _release_files import ReleaseInventory, staged_reader


MAX_FILE_SIZE = 1024 * 1024
PRIVATE_DIRECTORIES = {"runs", "reports", "build", "dist", ".external", ".venv", "__pycache__"}
PRIVATE_SUFFIXES = {".exe", ".dll", ".pyd", ".pdb", ".pyc", ".key", ".pem",
                    ".zip", ".xz", ".docx", ".pdf"}
PATTERNS = {
    "private_key_block": re.compile(r"^-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----$", re.M),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    "provider_token": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{24,}\b"),
    "stripe_live_key": re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b"),
    "google_api_key": re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
}


def audit(root: Path = ROOT, working_tree: bool = False) -> dict:
    root = root.resolve()
    inventory = ReleaseInventory.read(root)
    issues = []
    total = 0
    with ExitStack() as stack:
        indexed = None if working_tree else stack.enter_context(staged_reader(root))
        for name in sorted(inventory.paths.union(inventory.index_blobs)):
            path = root / name
            fixture = inventory.binary_fixtures.get(name)
            if name not in inventory.paths:
                reason = "not_in_release_allowlist"
            elif indexed is not None and name in inventory.non_regular_entries:
                reason = "non_regular_index_entry"
            elif not path.resolve().is_relative_to(root) or path.is_symlink():
                reason = "outside_release_root"
            elif not path.is_file():
                reason = "missing_release_file"
            elif any(part in PRIVATE_DIRECTORIES or part.startswith(".env") for part in Path(name).parts):
                reason = "private_or_generated_asset"
            elif fixture is None and path.suffix.lower() in PRIVATE_SUFFIXES:
                reason = "private_or_generated_asset"
            elif indexed is not None and name not in inventory.index_blobs:
                reason = "release_file_not_staged"
            else:
                reason = None
            if reason:
                issues.append({"path": name, "reason": reason})
                continue

            if indexed is not None:
                size, raw = indexed(inventory.index_blobs[name], MAX_FILE_SIZE)
            else:
                with path.open("rb") as source:
                    raw = source.read(MAX_FILE_SIZE + 1)
                size = path.stat().st_size
            total += size
            if raw is None or size > MAX_FILE_SIZE or len(raw) > MAX_FILE_SIZE:
                issues.append({"path": name, "reason": "unexpected_large_file"})
            elif fixture is not None:
                if hashlib.sha256(raw).hexdigest() != fixture:
                    issues.append({"path": name, "reason": "binary_fixture_digest_mismatch"})
            else:
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    issues.append({"path": name, "reason": "non_text_asset"})
                    continue
                issues.extend({"path": name, "reason": rule}
                              for rule, pattern in PATTERNS.items() if pattern.search(text))
    return {"passed": not issues, "files": len(inventory.paths), "bytes": total, "issues": issues,
            "scope": "allowlisted current tree only; history is not rewritten; heuristic secret scan"}


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
