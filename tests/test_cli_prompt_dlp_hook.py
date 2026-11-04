"""Prompt-only hook contract and local persistence checks."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import ctypes
from ctypes import wintypes
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts" / "cli_prompt_dlp_hook.py"


def run_hook(tmp_path: Path, event: bytes) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "TTRACE_CLI_PROMPT_DEMO_DIR": str(tmp_path / "archive")}
    return subprocess.run([sys.executable, str(HOOK)], input=event,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=env, timeout=10, check=False)


def event_bytes(prompt: str) -> bytes:
    return json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": prompt},
                      ensure_ascii=False).encode("utf-8")


def decrypt_dpapi(ciphertext: bytes) -> bytes:
    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    data = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
    source = DataBlob(len(ciphertext), ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte)))
    clear = DataBlob()
    crypt32 = ctypes.WinDLL("Crypt32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(DataBlob), ctypes.c_void_p,
                                          ctypes.POINTER(DataBlob), ctypes.c_void_p,
                                          ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(DataBlob)]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    if not crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None,
                                      None, 0x1, ctypes.byref(clear)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(clear.pbData, clear.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(clear.pbData, ctypes.c_void_p))


def test_malformed_and_duplicate_events_block_without_creating_archive(tmp_path: Path):
    for event in (b"not-json", b'{"hook_event_name":"UserPromptSubmit","prompt":"a","prompt":"b"}'):
        run = run_hook(tmp_path, event)
        assert run.returncode == 0
        assert json.loads(run.stdout)["decision"] == "block"
        assert run.stderr == b""
    assert not (tmp_path / "archive").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="The demo archives with Windows DPAPI")
def test_sensitive_prompt_is_encrypted_audited_and_blocked(tmp_path: Path):
    prompt = "aws_access_key_id=AKIAABCDEFGHIJKLMNOP"
    run = run_hook(tmp_path, event_bytes(prompt))
    assert run.returncode == 0
    assert json.loads(run.stdout)["decision"] == "block"
    assert prompt.encode() not in run.stdout + run.stderr

    archive = tmp_path / "archive"
    rows = [json.loads(line) for line in (archive / "audit.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    row = rows[0]
    assert row["action"] == "BLOCK"
    assert row["prompt_sha256"] == hashlib.sha256(prompt.encode()).hexdigest()
    assert row["prompt_bytes"] == len(prompt.encode())
    assert any(rule.startswith("SECRET:") for rule in row["rules"])
    cipher = (archive / f"{row['archive_id']}.dpapi").read_bytes()
    prefix = b"TTRACE_CLI_PROMPT_DPAPI_V1\n"
    assert cipher.startswith(prefix)
    assert prompt.encode() not in cipher
    assert decrypt_dpapi(cipher[len(prefix):]) == prompt.encode()
    assert prompt not in (archive / "audit.jsonl").read_text()


@pytest.mark.skipif(sys.platform != "win32", reason="The demo archives with Windows DPAPI")
def test_benign_prompt_is_archived_before_allow(tmp_path: Path):
    prompt = "请总结这段公开资料的要点。"
    run = run_hook(tmp_path, event_bytes(prompt))
    assert run.returncode == 0
    assert run.stdout == b""
    assert run.stderr == b""
    audit = [json.loads(line) for line in (tmp_path / "archive" / "audit.jsonl").read_text().splitlines()]
    assert len(audit) == 1
    assert audit[0]["action"] == "ALLOW"
    assert (tmp_path / "archive" / f"{audit[0]['archive_id']}.dpapi").is_file()


@pytest.mark.skipif(sys.platform != "win32", reason="The demo archives with Windows DPAPI")
@pytest.mark.parametrize("prompt", [
    "员工 Zhang Wei (E10293), SSN 123-45-6789, 需要报销。",
    "phase beta adds the capability minting service, phase gamma delivers "
    "the information flow control plane for all internal agents.",
    "def rotate_signing_key(tenant_id, kms_client):\n"
    "    current = kms_client.get_active_key(tenant_id)\n"
    "    new_key = kms_client.create_key(tenant_id, algorithm='ed25519')\n"
    "    kms_client.promote(new_key); kms_client.retire(current)\n"
    "    return new_key.fingerprint",
])
def test_registered_pii_document_and_code_are_blocked(tmp_path: Path, prompt: str):
    run = run_hook(tmp_path, event_bytes(prompt))
    assert run.returncode == 0
    assert json.loads(run.stdout)["decision"] == "block"
    assert prompt.encode() not in run.stdout + run.stderr


@pytest.mark.skipif(sys.platform != "win32", reason="The demo archives with Windows DPAPI")
def test_review_is_also_held_before_submission(tmp_path: Path):
    prompt = "deploytok_xqeF7P2mZk9Lw3Rt8Vb1Nc6Hy4Jd0Gs5Pa2"
    run = run_hook(tmp_path, event_bytes(prompt))
    assert run.returncode == 0
    assert "review" in json.loads(run.stdout)["reason"].lower()
    audit = json.loads((tmp_path / "archive" / "audit.jsonl").read_text().splitlines()[0])
    assert audit["action"] == "REVIEW"


@pytest.mark.skipif(sys.platform != "win32", reason="The demo archives with Windows DPAPI")
def test_archive_failure_blocks_an_otherwise_benign_prompt(tmp_path: Path):
    blocked_path = tmp_path / "archive"
    blocked_path.write_text("cannot create directory here", encoding="utf-8")
    run = run_hook(tmp_path, event_bytes("公开资料摘要"))
    assert run.returncode == 0
    assert json.loads(run.stdout)["decision"] == "block"
    assert run.stderr == b""
