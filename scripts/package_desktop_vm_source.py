"""Package the current working-tree source for the isolated guest transfer ISO.

This deliberately includes uncommitted implementation files. It excludes
build output, Python caches, datasets, credentials, the VM disk, and Git state.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "runs/desktop-vm/guest-media/desktop-demo-source.zip"
DIRECTORIES = ("src", "scripts", "native", "tests", "docs")
ROOT_FILES = ("pyproject.toml", "uv.lock", "README.md", ".gitattributes")


def sources() -> list[Path]:
    paths = [ROOT / name for name in ROOT_FILES if (ROOT / name).is_file()]
    for name in DIRECTORIES:
        for path in (ROOT / name).rglob("*"):
            if (not path.is_file() or "__pycache__" in path.parts
                    or path.suffix in {".pyc", ".pyo"}):
                continue
            if path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError(f"source file too large for guest bundle: {path}")
            paths.append(path)
    return sorted(paths)


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    files = sources()
    manifest = {}
    with ZipFile(OUTPUT, "w", ZIP_DEFLATED, compresslevel=6) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            payload = path.read_bytes()
            archive.writestr(relative, payload)
            manifest[relative] = hashlib.sha256(payload).hexdigest()
        archive.writestr("source-manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
    print(f"{OUTPUT} ({len(files)} files; {OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
