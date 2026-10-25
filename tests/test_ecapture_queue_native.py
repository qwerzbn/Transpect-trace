"""Compile and exercise the real companion queue logic with deterministic locks."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows critical-section native fixture')
def test_native_queue_isolation_and_honest_loss(tmp_path):
    vendor = ROOT / 'native/guard/third_party/minhook'
    pin = json.loads((vendor / 'source-manifest.json').read_text())
    for name, expected in pin['sha256'].items():
        assert hashlib.sha256((vendor / name).read_bytes()).hexdigest() == expected
    sources = [vendor / 'src' / name for name in ('buffer.c', 'hook.c', 'trampoline.c', 'hde/hde64.c')]
    executable = tmp_path / 'ecapture_queue_fixture.exe'
    subprocess.run([sys.executable, '-m', 'ziglang', 'cc', '-target', 'x86_64-windows-gnu', '-O2',
                    str(ROOT / 'tests/native/ecapture_queue_fixture.c'), *map(str, sources),
                    '-I', str(vendor / 'include'), '-lsecur32', '-o', str(executable)], check=True,
                   capture_output=True, timeout=60)
    result = subprocess.run([str(executable)], check=True, capture_output=True, text=True, timeout=15)
    assert json.loads(result.stdout) == {
        'queue_contention_preserves_begin': True,
        'publisher_does_not_hold_context_while_waiting_queue': True,
        'context_contention_counted': True,
        'capacity_loss_counted': True,
        'fifo_preserved': True,
        'uncertainty_preserved': True,
    }
