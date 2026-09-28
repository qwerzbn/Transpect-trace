from __future__ import annotations

from pathlib import Path


FRIDA_VERSION = "17.18.0"
GADGET_LIBRARY = "/opt/transpect-frida/libgadget.so"
GADGET_LOG_DIR = "/evidence/raw/frida"


def gadget_environment(base: dict[str, str], *, log_dir: str | Path = GADGET_LOG_DIR) -> dict[str, str]:
    """Return the child environment that loads Gadget beside strace.

    Gadget enters through LD_PRELOAD and does not take the ptrace slot that
    strace needs. Processes that drop the variable, or that are statically
    linked, remain visible to strace only.
    """

    environment = dict(base)
    environment["LD_PRELOAD"] = GADGET_LIBRARY
    environment["TTRACE_FRIDA_LOG_DIR"] = str(log_dir).replace("\\", "/")
    return environment
