"""Repository location shared by build entry points, not runtime policy code."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def enter_repository():
    """Keep compiler-relative source names stable regardless of caller CWD."""
    os.chdir(ROOT)
