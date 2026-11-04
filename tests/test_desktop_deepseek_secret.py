"""Account isolation for the Windows DeepSeek credential helper."""

import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SID = "S-1-5-21-2341826845-1812322924-2265560838-1005"


def test_reader_hash_pin_matches_reviewed_helper():
    setup = (ROOT / "scripts" / "set_desktop_deepseek_secret.ps1").read_text(
        encoding="utf-8"
    )
    reader = (ROOT / "scripts" / "read_desktop_deepseek_secret.ps1").read_bytes()
    match = re.search(r"\$expectedReaderHash = '([A-F0-9]{64})'", setup)
    assert match is not None
    normalized = reader.replace(b"\r\n", b"\n")
    assert hashlib.sha256(normalized).hexdigest().upper() == match.group(1)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI helper")
@pytest.mark.parametrize(
    ("script", "expected_error"),
    [
        ("set_desktop_deepseek_secret.ps1", "Dedicated account required"),
        ("read_desktop_deepseek_secret.ps1", "Dedicated desktop demo account required"),
    ],
)
def test_secret_helpers_refuse_other_windows_account(script, expected_error):
    if not shutil.which("powershell.exe"):
        pytest.skip("Windows PowerShell is unavailable")
    identity = subprocess.run(
        ["whoami", "/user"], capture_output=True, text=True, timeout=10, check=True
    )
    if EXPECTED_SID in identity.stdout:
        pytest.skip("this test must not prompt or emit a real key from the demo account")

    result = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
            "RemoteSigned", "-File", str(ROOT / "scripts" / script),
        ],
        input="", capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert expected_error in result.stderr + result.stdout
    assert "DeepSeek API key (input hidden)" not in result.stdout
