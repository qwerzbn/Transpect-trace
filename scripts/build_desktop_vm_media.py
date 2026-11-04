"""Build a read-only transfer ISO for the isolated Windows desktop demo VM.

Run with ``uv run --no-sync --with pycdlib==1.22.0 python scripts/build_desktop_vm_media.py``.
The guest can install from this ISO before any guest network route is enabled.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pycdlib


ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / "runs" / "desktop-vm"
MEDIA = VM / "guest-media"
OUTPUT = VM / "guest-media.iso"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    pins = json.loads((VM / "pins.json").read_text(encoding="utf-8-sig"))
    package = MEDIA / "ChatGPT-x64.msix"
    if digest(package).upper() != pins["chatgpt_msix_sha256"].upper():
        raise SystemExit("official desktop package hash changed")
    files = sorted(path for path in MEDIA.iterdir() if path.is_file())
    if not files:
        raise SystemExit("guest media is empty")
    manifest = {path.name: {"sha256": digest(path), "bytes": path.stat().st_size}
                for path in files}
    (VM / "guest-media-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                                    encoding="utf-8")
    image = pycdlib.PyCdlib()
    image.new(interchange_level=3, joliet=3, vol_ident="CODEXDLP")
    for number, path in enumerate(files, 1):
        image.add_file(str(path), iso_path=f"/FILE{number:04d}.DAT;1",
                       joliet_path=f"/{path.name}")
    image.write(str(OUTPUT))
    image.close()
    print(f"{OUTPUT} {digest(OUTPUT)}")


if __name__ == "__main__":
    main()
