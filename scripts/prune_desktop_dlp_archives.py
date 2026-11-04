"""Inspect or prune expired desktop DLP snapshots under this repository's runs/.

Inspection is the default. ``--prune`` performs deletion. Only directories
named ``encrypted-archive`` with an existing DPAPI key are considered.
Reports contain counts, not record identifiers, hashes, or request bodies.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard.desktop import current_user_sid  # noqa: E402
from transpect_trace.protect.archive import EncryptedRequestArchive  # noqa: E402


SCHEMA = "transpect.desktop-dlp.archive-prune/1.0"
MAX_ARCHIVES = 1024
MAX_RECORDS = 100_000
ARCHIVE_NAME = "encrypted-archive"
KEY_NAME = "archive-key.dpapi"


def _is_reparse(path: Path) -> bool:
    return path.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(path))


def discover_archives(root: Path, *, allowed_root: Path = ROOT / "runs") -> list[Path]:
    """Resolve every deletion target before invoking the archive pruner."""
    allowed = allowed_root.resolve(strict=True)
    selected = root.resolve(strict=True)
    if (_is_reparse(allowed_root) or _is_reparse(root) or
            not selected.is_relative_to(allowed) or not selected.is_dir()):
        raise ValueError("archive root is outside the repository runs directory")
    archives: list[Path] = []
    for current, dirs, _ in os.walk(selected, topdown=True, followlinks=False):
        directory = Path(current)
        for name in dirs:
            if _is_reparse(directory / name):
                raise ValueError("archive search contains a reparse point")
        if directory.name == ARCHIVE_NAME:
            if not directory.resolve(strict=True).is_relative_to(allowed):
                raise ValueError("archive directory escaped the runs directory")
            key = directory / KEY_NAME
            if not key.is_file() or _is_reparse(key):
                raise ValueError("archive directory has no regular DPAPI key")
            archives.append(directory)
            dirs.clear()
            if len(archives) > MAX_ARCHIVES:
                raise ValueError("archive directory limit exceeded")
    return archives


def inspect_or_prune(root: Path, *, expected_sid: str, prune: bool = False,
                     now: datetime | None = None,
                     allowed_root: Path = ROOT / "runs") -> dict:
    if current_user_sid() != expected_sid:
        raise ValueError("current user SID does not match archive owner")
    if type(prune) is not bool:
        raise ValueError("prune must be boolean")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("time must be timezone-aware")
    archives = discover_archives(root, allowed_root=allowed_root)
    # Finish all read-only validation before the first deletion.
    opened: list[tuple[EncryptedRequestArchive, int]] = []
    total_records = 0
    for directory in archives:
        count = sum(1 for _ in directory.glob("*.enc"))
        total_records += count
        if total_records > MAX_RECORDS:
            raise ValueError("archive record limit exceeded")
        archive = EncryptedRequestArchive(directory)
        expired = archive.prune(now=now, dry_run=True)
        opened.append((archive, expired))
    removed = 0
    if prune:
        for archive, _ in opened:
            if _is_reparse(archive.directory):
                raise ValueError("archive directory changed into a reparse point")
            removed += archive.prune(now=now)
    return {
        "schema": SCHEMA,
        "status": "pruned" if prune else "inspection_only",
        "archive_directories": len(opened),
        "record_count_before": total_records,
        "expired_count_at_preflight": sum(expired for _, expired in opened),
        "removed_count": removed,
        "retention_days": 7,
        "contains_request_bodies": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True,
                        help="Subdirectory of this repository's runs/ to inspect")
    parser.add_argument("--expected-sid", required=True)
    parser.add_argument("--prune", action="store_true",
                        help="Delete expired encrypted records after validation")
    args = parser.parse_args()
    try:
        result = inspect_or_prune(args.root, expected_sid=args.expected_sid,
                                  prune=args.prune)
    except Exception as error:
        print(json.dumps({"schema": SCHEMA, "status": "failed",
                          "error_type": type(error).__name__,
                          "contains_request_bodies": False}))
        raise SystemExit(2) from None
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
