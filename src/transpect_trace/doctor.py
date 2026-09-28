from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .config import load_project_env
from .supervisor import AGENT_IMAGE, CLAUDE_IMAGE, GATEWAY_IMAGE, OTEL_IMAGE


def doctor() -> dict[str, Any]:
    load_project_env()
    checks: dict[str, Any] = {}
    docker = shutil.which("docker")
    checks["docker_cli"] = {"ok": bool(docker), "path": docker}
    daemon_ok = False
    daemon_error = None
    if docker:
        result = subprocess.run([docker, "info"], capture_output=True, text=True, timeout=30, check=False)
        daemon_ok = result.returncode == 0
        daemon_error = None if daemon_ok else (result.stderr or result.stdout).strip()[-1000:]
    checks["docker_daemon"] = {"ok": daemon_ok, "error": daemon_error}
    checks["api_key"] = {
        "ok": bool(os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("TRANSPECT_MODEL_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("API_KEY")),
        "accepted_variables": ["DEEPSEEK_API_KEY", "TRANSPECT_MODEL_API_KEY", "ANTHROPIC_API_KEY", "API_KEY"],
    }
    image_availability: dict[str, bool] = {}
    if daemon_ok and docker:
        for image in (AGENT_IMAGE, CLAUDE_IMAGE, GATEWAY_IMAGE, OTEL_IMAGE):
            result = subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True, timeout=30, check=False)
            image_availability[image] = result.returncode == 0
    checks["images"] = {
        "ok": len(image_availability) == 4 and all(image_availability.values()),
        "available": image_availability,
    }
    usage = shutil.disk_usage(Path.cwd())
    checks["disk"] = {"ok": usage.free >= 5 * 1024**3, "free_bytes": usage.free, "required_bytes": 5 * 1024**3}
    return {"ok": all(value.get("ok", False) for value in checks.values()), "checks": checks}
