import json

import pytest

from transpect_trace.protect.archive import EncryptedRequestArchive
from transpect_trace.protect.desktop_bridge import DesktopDLPBridge
from transpect_trace.protect.desktop_registration import load_desktop_registration


def _registration(root):
    root.mkdir()
    (root / "employees.json").write_text(json.dumps({
        "synthetic-1": {"name": "Ada Sample", "email": "ada@example.test", "id": "ZX98765432"}
    }), encoding="utf-8")
    (root / "internal.md").write_text(
        "Internal Apollo schedule is restricted to the review team. "
        "The launch window opens after final approval.", encoding="utf-8")
    (root / "module.py").write_text(
        "def calculate_private_score(values):\n"
        "    total = sum(values)\n"
        "    return total / len(values)\n", encoding="utf-8")
    (root / "registration.json").write_text(json.dumps({
        "schema": "transpect.desktop-dlp-registration/1.0",
        "records": "employees.json",
        "documents": [
            {"id": "apollo", "category": "INTERNAL_DOC", "path": "internal.md"},
            {"id": "module", "category": "SOURCE_CODE", "path": "module.py"},
        ],
    }), encoding="utf-8")


def test_registration_enables_edm_and_both_fingerprint_categories(tmp_path):
    source = tmp_path / "references"
    _registration(source)
    archive = EncryptedRequestArchive(tmp_path / "archive")
    bridge = DesktopDLPBridge.from_registration({"pid": 123}, archive, source)
    assert bridge.policy.version.startswith("desktop-dlp/1:")
    assert bridge.dlp.inspect_text("Ada Sample and ada@example.test").decision == "BLOCK"
    assert bridge.dlp.inspect_text((source / "internal.md").read_text()).decision == "BLOCK"
    assert bridge.dlp.inspect_text((source / "module.py").read_text()).decision == "BLOCK"
    assert bridge.dlp.inspect_text("A harmless public update.").decision == "ALLOW"


def test_registration_rejects_missing_layer_and_escaping_path(tmp_path):
    source = tmp_path / "references"
    _registration(source)
    archive = EncryptedRequestArchive(tmp_path / "archive")
    manifest = json.loads((source / "registration.json").read_text())
    manifest["documents"].pop()
    (source / "registration.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="fingerprint documents are missing"):
        load_desktop_registration(source, archive)
    manifest["documents"].append({"id": "escape", "category": "SOURCE_CODE", "path": "../outside.py"})
    (tmp_path / "outside.py").write_text("def leaked(): return 1")
    (source / "registration.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="escapes private directory"):
        load_desktop_registration(source, archive)


def test_registration_rejects_same_source_registered_twice(tmp_path):
    source = tmp_path / "references"
    _registration(source)
    archive = EncryptedRequestArchive(tmp_path / "archive")
    manifest = json.loads((source / "registration.json").read_text())
    manifest["documents"][1]["path"] = "internal.md"
    (source / "registration.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="overlapping registration source"):
        load_desktop_registration(source, archive)


def test_registration_rejects_duplicate_manifest_and_record_fields(tmp_path):
    source = tmp_path / "references"
    _registration(source)
    archive = EncryptedRequestArchive(tmp_path / "archive")
    manifest_path = source / "registration.json"
    original = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(original.replace('"records": "employees.json",',
                                              '"records": "employees.json", "records": "employees.json",'),
                             encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate registration field"):
        load_desktop_registration(source, archive)
    manifest_path.write_text(original, encoding="utf-8")
    (source / "employees.json").write_text(
        '{"synthetic-1":{"name":"Ada Sample","name":"Ben Sample","email":"ada@example.test"}}',
        encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate registration field"):
        load_desktop_registration(source, archive)
