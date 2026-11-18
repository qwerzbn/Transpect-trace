"""Read the public file inventory and staged blobs used by release checks."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
from typing import BinaryIO, Callable


@dataclass(frozen=True)
class ReleaseInventory:
    paths: frozenset[str]
    binary_fixtures: dict[str, str]
    index_blobs: dict[str, str]
    non_regular_entries: frozenset[str]

    @classmethod
    def read(cls, root: Path) -> ReleaseInventory:
        manifest = json.loads((root / "release-files.json").read_text(encoding="utf-8"))
        fixtures = manifest.get("binary_fixtures", {})
        staged = subprocess.check_output(["git", "-C", str(root), "ls-files", "--stage", "-z"])
        blobs = {}
        non_regular = set()
        for record in staged.split(b"\0"):
            if record:
                metadata, path = record.split(b"\t", 1)
                mode, oid, stage = metadata.split()
                name = path.decode("utf-8")
                if stage != b"0":
                    raise ValueError(f"unmerged index entry: {name}")
                if mode not in (b"100644", b"100755"):
                    non_regular.add(name)
                blobs[name] = oid.decode("ascii")
        return cls(frozenset(manifest["files"]).union(fixtures), fixtures, blobs,
                   frozenset(non_regular))


@contextmanager
def staged_reader(root: Path) -> Iterator[Callable[[str, int], tuple[int, bytes | None]]]:
    """Read exactly the indexed bytes through one Git process, bounding memory per blob."""
    with subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as git:
        assert git.stdin is not None and git.stdout is not None
        stdin: BinaryIO = git.stdin
        stdout: BinaryIO = git.stdout

        def read(oid: str, limit: int) -> tuple[int, bytes | None]:
            stdin.write(oid.encode("ascii") + b"\n")
            stdin.flush()
            header = stdout.readline().split()
            if len(header) != 3 or header[:2] != [oid.encode("ascii"), b"blob"]:
                raise ValueError(f"expected a staged Git blob: {oid}")
            size = int(header[2])
            content = None
            if size <= limit:
                content = stdout.read(size)
                if len(content) != size:
                    raise EOFError("truncated Git blob")
            else:
                remaining = size
                while remaining:
                    block = stdout.read(min(remaining, 65536))
                    if not block:
                        raise EOFError("truncated Git blob")
                    remaining -= len(block)
            if stdout.read(1) != b"\n":
                raise ValueError("missing Git blob delimiter")
            return size, content

        try:
            yield read
        finally:
            stdin.close()
