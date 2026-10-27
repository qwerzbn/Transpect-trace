"""Private bounded pre-receive rendezvous for the fake-only Git origin.

No object content or remote messages are written here. The parent inspects the
live quarantine using Git before allowing this fixture hook to finish.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time


def main():
    destination = Path(os.environ['TTRACE_GIT_CAPTURE_DIR'])
    if not destination.is_dir() or destination.is_symlink():
        return 1
    # Consume the fixed one-branch fixture's input without exporting ref names.
    lines = sys.stdin.buffer.read(4097)
    if len(lines) > 4096 or len(lines.splitlines()) != 1:
        return 1
    fields = lines.split()
    if len(fields) != 3 or fields[2] != b'refs/heads/fixture':
        return 1
    value = {'object_directory': os.environ.get('GIT_OBJECT_DIRECTORY'),
             'alternate_object_directories': os.environ.get('GIT_ALTERNATE_OBJECT_DIRECTORIES', '')}
    pending = destination / 'ready.pending'
    pending.write_text(json.dumps(value), encoding='utf-8')
    pending.replace(destination / 'ready.json')
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = destination / 'release'
        if result.is_file():
            try:
                decision = result.read_bytes()
            except OSError:
                time.sleep(.01)
                continue
            if decision in (b'allow', b'reject'):
                (destination / 'decision.json').write_text(json.dumps({'decision': decision.decode('ascii')}), encoding='utf-8')
                return 0 if decision == b'allow' else 1
        time.sleep(.01)
    return 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, KeyError, ValueError):
        raise SystemExit(1)
