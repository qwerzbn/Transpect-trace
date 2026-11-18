"""The launcher must end its Claude child if the proxy goes away."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import claude_model_proxy as launcher  # noqa: E402


def test_proxy_exit_ends_child_process():
    sleeper = [sys.executable, "-c", "import time;time.sleep(30)"]
    proxy = subprocess.Popen(sleeper, stdout=subprocess.DEVNULL)
    child = subprocess.Popen(sleeper, stdout=subprocess.DEVNULL)
    try:
        proxy.terminate()
        proxy.wait(timeout=5)
        assert launcher._supervise_child(child, proxy) == 1
        assert child.poll() is not None
    finally:
        for process in (child, proxy):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
