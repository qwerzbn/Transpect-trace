from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


def project_root() -> Path:
    """Return the source checkout root used by Docker build resources."""
    configured = os.environ.get("TTRACE_PROJECT_ROOT")
    candidates = [Path(configured).resolve()] if configured else []
    candidates.extend([Path.cwd().resolve(), Path(__file__).resolve().parents[2]])
    for candidate in candidates:
        if (candidate / "pyproject.toml").is_file() and (candidate / "deploy").is_dir():
            return candidate
    return Path(__file__).resolve().parents[2]


def load_project_env() -> Path | None:
    """Load checkout-local settings without overriding explicit environment values."""
    candidates = [Path.cwd() / ".env", project_root() / ".env"]
    for candidate in candidates:
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return candidate.resolve()
    return None


def provider_api_key(provider: str) -> str | None:
    names = (
        ("ANTHROPIC_API_KEY", "API_KEY")
        if provider == "anthropic"
        else ("DEEPSEEK_API_KEY", "TRANSPECT_MODEL_API_KEY", "API_KEY")
    )
    return next((value for name in names if (value := os.environ.get(name))), None)


def provider_key_names(provider: str) -> tuple[str, ...]:
    return (
        ("ANTHROPIC_API_KEY", "API_KEY")
        if provider == "anthropic"
        else ("DEEPSEEK_API_KEY", "TRANSPECT_MODEL_API_KEY", "API_KEY")
    )
