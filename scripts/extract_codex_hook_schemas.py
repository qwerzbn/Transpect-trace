"""Extract the Codex backend's embedded hook JSON schemas for one pinned binary.

The backend ships generated draft-07 schemas for each command hook event. This
reads them from the verified image so the local adapter is written against the
client's own contract instead of a guess. Read-only; no Codex process is
started and no hook is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024
MAX_SCHEMA_BYTES = 262_144
_SCHEMA_START = re.compile(
    rb'\{\s*"\$schema":\s*"http://json-schema\.org/draft-07/schema#"')


def _decode_schema(data: bytes, start: int) -> tuple[str, dict]:
    """Read one embedded JSON object forward with a string-aware brace counter."""
    depth = 0
    in_string = False
    escaped = False
    for offset in range(start, min(len(data), start + MAX_SCHEMA_BYTES)):
        char = data[offset]
        if in_string:
            if escaped:
                escaped = False
            elif char == 0x5C:
                escaped = True
            elif char == 0x22:
                in_string = False
            continue
        if char == 0x22:
            in_string = True
        elif char == 0x7B:
            depth += 1
        elif char == 0x7D:
            depth -= 1
            if depth == 0:
                document = json.loads(data[start:offset + 1].decode("utf-8"))
                title = document.get("title")
                if not isinstance(title, str):
                    raise ValueError("schema has no title")
                return title, document
    raise ValueError("unterminated embedded schema")


def extract(image: Path) -> dict:
    if image.stat().st_size > MAX_IMAGE_BYTES:
        raise ValueError("image exceeds supported size")
    data = image.read_bytes()
    schemas: dict[str, dict] = {}
    for match in _SCHEMA_START.finditer(data):
        try:
            title, document = _decode_schema(data, match.start())
        except ValueError:
            continue
        if not title.endswith((".command.input", ".command.output")):
            continue
        if title in schemas and schemas[title] != document:
            raise ValueError(f"conflicting embedded schema: {title}")
        schemas[title] = document
    if not schemas:
        raise ValueError("no embedded hook schemas found")
    return {
        "schema": "transpect.codex.hook-schemas/1.0",
        "image_path": str(image),
        "image_sha256": hashlib.sha256(data).hexdigest(),
        "image_bytes": len(data),
        "titles": sorted(schemas),
        "schemas": dict(sorted(schemas.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = extract(args.image.resolve(strict=True))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({"image_sha256": report["image_sha256"],
                      "titles": report["titles"]}, indent=2))


if __name__ == "__main__":
    main()
