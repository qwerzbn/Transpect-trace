"""Point the user's Codex configuration at a local Gateway, and put it back.

The edit touches only two top-level keys and appends one provider table, so the
rest of the user's settings (MCP servers, plugins, projects) stay as they are.
A backup is written first; restore copies it back and checks the SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tomllib
from datetime import datetime
from pathlib import Path

PROVIDER_ID = "transpect"
BACKUP_PREFIX = "config.toml.ttrace-backup-"


def default_config_path() -> Path:
    return Path.home() / ".codex" / "config.toml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _backups(config: Path) -> list[Path]:
    return sorted(config.parent.glob(BACKUP_PREFIX + "*"))


def use_gateway(config: Path, *, port: int, model: str, agent: str = "desktop") -> dict[str, str]:
    text = config.read_text(encoding="utf-8") if config.is_file() else ""
    lines = text.splitlines()
    first_table = next((index for index, line in enumerate(lines) if line.lstrip().startswith("[")), len(lines))
    top = lines[:first_table]
    if any(re.match(r"\s*model_provider\s*=", line) for line in top):
        raise ValueError("model_provider is already set; restore the original configuration first")

    backup = config.parent / f"{BACKUP_PREFIX}{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    if config.is_file():
        shutil.copy2(config, backup)
    else:
        config.parent.mkdir(parents=True, exist_ok=True)
        backup.write_text("", encoding="utf-8")

    model_line = f"model = {json.dumps(model)}"
    model_index = next((index for index, line in enumerate(top) if re.match(r"\s*model\s*=", line)), None)
    if model_index is None:
        top.insert(0, model_line)
        model_index = 0
    else:
        top[model_index] = model_line
    top.insert(model_index + 1, f"model_provider = {json.dumps(PROVIDER_ID)}")
    updated_lines = top + lines[first_table:] + [
        "",
        f"[model_providers.{PROVIDER_ID}]",
        'name = "Transpect Gateway"',
        f'base_url = "http://127.0.0.1:{port}/agents/{agent}"',
        'wire_api = "responses"',
        "requires_openai_auth = false",
        "",
    ]
    updated = "\n".join(updated_lines)
    parsed = tomllib.loads(updated)
    if parsed.get("model_provider") != PROVIDER_ID:
        raise ValueError("generated configuration does not select the Gateway provider")
    config.write_text(updated, encoding="utf-8", newline="\n")
    return {"config": str(config), "backup": str(backup), "backup_sha256": _sha256(backup)}


def restore(config: Path, backup: Path | None = None) -> dict[str, str]:
    candidates = _backups(config)
    source = backup or (candidates[-1] if candidates else None)
    if source is None or not source.is_file():
        raise FileNotFoundError(f"no {BACKUP_PREFIX}* backup next to {config}")
    expected = _sha256(source)
    shutil.copy2(source, config)
    actual = _sha256(config)
    if actual != expected:
        raise RuntimeError("restored configuration does not match the backup")
    return {"config": str(config), "backup": str(source), "sha256": actual}
