from datetime import datetime, timedelta, timezone
import os

import pytest

from transpect_trace.protect.archive import EncryptedRequestArchive


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI archive")


def test_archive_encrypts_and_persists_before_receipt(tmp_path):
    payload = b"FAKE_SECRET_SENTINEL_9a1b2c3d"
    archive = EncryptedRequestArchive(tmp_path / "private")
    receipt = archive.save("model_request", payload)
    ciphertext = (archive.directory / f"{receipt.record_id}.enc").read_bytes()
    assert payload not in ciphertext
    assert receipt.body_sha256.encode("ascii") not in ciphertext
    assert receipt.saved_at.encode("ascii") not in ciphertext
    assert receipt.body_bytes == len(payload)
    reopened = EncryptedRequestArchive(archive.directory)
    restored_receipt, restored_payload = reopened.read(receipt.record_id)
    assert restored_receipt == receipt
    assert restored_payload == payload


def test_archive_tamper_and_expiration(tmp_path):
    archive = EncryptedRequestArchive(tmp_path / "private")
    receipt = archive.save("attachment", b"fake document")
    path = archive.directory / f"{receipt.record_id}.enc"
    frame = bytearray(path.read_bytes())
    frame[-1] ^= 1
    path.write_bytes(frame)
    with pytest.raises(Exception):
        archive.read(receipt.record_id)
    old = datetime.now(timezone.utc) - timedelta(days=8)
    os.utime(path, (old.timestamp(), old.timestamp()))
    assert archive.prune() == 1
    assert not path.exists()


def test_archive_rejects_invalid_or_empty_snapshot(tmp_path):
    archive = EncryptedRequestArchive(tmp_path / "private")
    with pytest.raises(ValueError):
        archive.save("model_request", b"")
    with pytest.raises(ValueError):
        archive.save("other", b"content")


def test_expired_encrypted_record_cannot_authorize_a_reference(tmp_path):
    archive = EncryptedRequestArchive(tmp_path / "private")
    old = datetime.now(timezone.utc) - timedelta(days=8)
    receipt = archive.save("attachment", b"old synthetic file", now=old)
    with pytest.raises(ValueError, match="expired"):
        archive.read(receipt.record_id)
    # The encrypted record's authenticated timestamp governs retention even
    # when filesystem mtime was refreshed after creation.
    assert archive.prune() == 1
    assert not (archive.directory / f"{receipt.record_id}.enc").exists()
