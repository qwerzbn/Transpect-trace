"""Load private, fixed local reference data for all four desktop DLP layers.

The controller owns this directory. Only HMAC digests and document shingles
remain in the engine after load; source bytes are never written to audit rows.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import re

from .archive import EncryptedRequestArchive, MAX_SNAPSHOT_BYTES
from .content_dlp import ContentDLPEngine, EDMIndex, FingerprintIndex
from .file_extract import extract_text


SCHEMA = "transpect.desktop-dlp-registration/1.0"
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def _no_duplicate_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError("duplicate registration field")
        fields[key] = value
    return fields


def _private_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("registration path must be relative")
    target = (root / relative).resolve(strict=True)
    if not target.is_relative_to(root):
        raise ValueError("registration path escapes private directory")
    if not target.is_file() or target.stat().st_size > MAX_SNAPSHOT_BYTES:
        raise ValueError("registration file is missing or oversized")
    return target


def load_desktop_registration(directory: Path, archive: EncryptedRequestArchive
                              ) -> tuple[ContentDLPEngine, str, dict[str, str]]:
    """Build a deterministic DLP snapshot; abort if EDM or either document class is absent."""
    root = Path(directory).resolve(strict=True)
    manifest_file = _private_file(root, "registration.json")
    manifest_bytes = manifest_file.read_bytes()
    if len(manifest_bytes) > 1024 * 1024:
        raise ValueError("registration manifest exceeds limit")
    manifest = json.loads(manifest_bytes, object_pairs_hook=_no_duplicate_fields)
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "records", "documents"}
            or manifest.get("schema") != SCHEMA):
        raise ValueError("invalid desktop DLP registration manifest")
    records_file = _private_file(root, manifest["records"])
    records_bytes = records_file.read_bytes()
    records = json.loads(records_bytes, object_pairs_hook=_no_duplicate_fields)
    if not isinstance(records, dict) or not records:
        raise ValueError("desktop EDM records are empty")
    documents = manifest["documents"]
    if not isinstance(documents, list) or not 2 <= len(documents) <= 4096:
        raise ValueError("desktop fingerprint documents are missing")

    registered: dict[str, tuple[str, str]] = {}
    used_sources = {manifest_file, records_file}
    source_hashes = {"registration.json": hashlib.sha256(manifest_bytes).hexdigest(),
                     manifest["records"]: hashlib.sha256(records_bytes).hexdigest()}
    for item in documents:
        if (not isinstance(item, dict) or set(item) != {"id", "category", "path"}
                or not isinstance(item["id"], str) or not _ID.fullmatch(item["id"])
                or item["id"] in registered
                or item["category"] not in {"INTERNAL_DOC", "SOURCE_CODE"}):
            raise ValueError("invalid fingerprint registration entry")
        source = _private_file(root, item["path"])
        if source in used_sources:
            raise ValueError("duplicate or overlapping registration source")
        used_sources.add(source)
        data = source.read_bytes()
        registered[item["id"]] = (item["category"], extract_text(source.name, data))
        source_hashes[item["path"]] = hashlib.sha256(data).hexdigest()
    if {category for category, _ in registered.values()} != {"INTERNAL_DOC", "SOURCE_CODE"}:
        raise ValueError("both internal document and source code registrations are required")

    edm_key = hmac.new(archive.key, b"transpect.desktop-dlp.edm/1\0", hashlib.sha256).digest()
    edm = EDMIndex.from_records(records, edm_key)
    fingerprint = FingerprintIndex.from_documents(registered)
    version_digest = hashlib.sha256(json.dumps(source_hashes, sort_keys=True,
                                               separators=(",", ":")).encode("utf-8")).hexdigest()
    return ContentDLPEngine(fingerprint, edm), f"desktop-dlp/1:{version_digest[:24]}", source_hashes
