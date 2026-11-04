"""The scheduled-pruner entry point must be inert without --prune."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import prune_desktop_dlp_archives as cleaner  # noqa: E402
from transpect_trace.protect.archive import EncryptedRequestArchive  # noqa: E402


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI archive")


def test_inspect_then_prune_only_expired_records(tmp_path, monkeypatch):
    allowed = tmp_path / "runs"
    selected = allowed / "desktop-current"
    directory = selected / "synthetic-case" / "encrypted-archive"
    archive = EncryptedRequestArchive(directory)
    old = datetime.now(timezone.utc) - timedelta(days=8)
    expired = archive.save("model_request", b"old synthetic body", now=old)
    recent = archive.save("model_request", b"new synthetic body")
    monkeypatch.setattr(cleaner, "current_user_sid", lambda: "S-1-5-21-test")

    plan = cleaner.inspect_or_prune(selected, expected_sid="S-1-5-21-test",
                                    allowed_root=allowed)
    assert plan["status"] == "inspection_only"
    assert plan["archive_directories"] == 1
    assert plan["record_count_before"] == 2
    assert plan["expired_count_at_preflight"] == 1
    assert plan["removed_count"] == 0
    assert (directory / f"{expired.record_id}.enc").exists()

    result = cleaner.inspect_or_prune(selected, expected_sid="S-1-5-21-test",
                                      allowed_root=allowed, prune=True)
    assert result["status"] == "pruned" and result["removed_count"] == 1
    assert not (directory / f"{expired.record_id}.enc").exists()
    assert archive.read(recent.record_id)[1] == b"new synthetic body"


def test_root_and_owner_must_be_verified_before_deletion(tmp_path, monkeypatch):
    allowed = tmp_path / "runs"
    selected = allowed / "desktop-current"
    directory = selected / "encrypted-archive"
    archive = EncryptedRequestArchive(directory)
    old = datetime.now(timezone.utc) - timedelta(days=8)
    expired = archive.save("attachment", b"old synthetic file", now=old)
    monkeypatch.setattr(cleaner, "current_user_sid", lambda: "S-1-5-21-test")

    with pytest.raises(ValueError, match="SID"):
        cleaner.inspect_or_prune(selected, expected_sid="different",
                                 allowed_root=allowed, prune=True)
    with pytest.raises(ValueError, match="outside"):
        cleaner.inspect_or_prune(tmp_path, expected_sid="S-1-5-21-test",
                                 allowed_root=allowed, prune=True)
    assert (directory / f"{expired.record_id}.enc").exists()


def test_missing_key_fails_preflight_without_deleting_other_archives(tmp_path,
                                                                    monkeypatch):
    allowed = tmp_path / "runs"
    selected = allowed / "desktop-current"
    good = selected / "a" / "encrypted-archive"
    archive = EncryptedRequestArchive(good)
    old = datetime.now(timezone.utc) - timedelta(days=8)
    expired = archive.save("model_request", b"old synthetic body", now=old)
    (selected / "z" / "encrypted-archive").mkdir(parents=True)
    monkeypatch.setattr(cleaner, "current_user_sid", lambda: "S-1-5-21-test")

    with pytest.raises(ValueError, match="DPAPI key"):
        cleaner.inspect_or_prune(selected, expected_sid="S-1-5-21-test",
                                 allowed_root=allowed, prune=True)
    assert (good / f"{expired.record_id}.enc").exists()
