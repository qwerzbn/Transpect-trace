"""Security checks for the dedicated-account desktop provider setup."""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "configure_desktop_deepseek.ps1"
DEMO_SID = "S-1-5-21-2341826845-1812322924-2265560838-1005"


def test_rendered_provider_config_is_valid_and_has_no_inline_secret() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    template = re.search(r'\$configText = @"\n(.*?)\n"@ -replace', source, re.DOTALL)
    assert template is not None
    rendered = (
        template.group(1)
        .replace("$catalogTomlPath", "C:/Users/ttrace-desktop-demo/.codex/models.json")
        .replace("$powershellTomlPath", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
        .replace(
            "$helperTomlPath",
            "C:/Users/ttrace-desktop-demo/.codex/transpect-deepseek-auth/read-secret.ps1",
        )
    )
    config = tomllib.loads(rendered)
    provider = config["model_providers"]["ttrace_deepseek"]
    assert config["model"] == "deepseek-v4-pro"
    assert config["model_provider"] == "ttrace_deepseek"
    assert config["model_catalog_json"].endswith("models.json")
    assert provider["base_url"] == "https://api.deepseek.com"
    assert provider["wire_api"] == "responses"
    assert provider["auth"]["args"][-2:] == [
        "-File",
        "C:/Users/ttrace-desktop-demo/.codex/transpect-deepseek-auth/read-secret.ps1",
    ]
    assert "experimental_bearer_token" not in provider
    assert "env_key" not in provider


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell and SID required")
def test_windows_powershell_51_parses_setup_script() -> None:
    command = (
        "$tokens = $null; $errors = $null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{SCRIPT}', [ref]$tokens, [ref]$errors) > $null; "
        "if ($errors.Count) { $errors | ForEach-Object Message; exit 1 }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell and SID required")
def test_other_account_cannot_install_provider_config() -> None:
    identity = subprocess.run(
        ["whoami", "/user"], capture_output=True, text=True, timeout=10, check=True
    )
    if DEMO_SID in identity.stdout:
        pytest.skip("Do not run an install probe in the dedicated demo account")

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-File",
            str(SCRIPT),
            "-Install",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode != 0
    assert "Current account SID mismatch" in result.stdout + result.stderr
