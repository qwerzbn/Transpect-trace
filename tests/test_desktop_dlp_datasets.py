"""The offline evaluation keeps policy labels separate from corpus entity labels."""
import json
import hashlib
from io import BytesIO
from zipfile import ZipFile

import pytest

from scripts import evaluate_desktop_dlp_datasets as evaluation


def test_gretel_annotation_formats_and_rejection():
    python_repr = "[{'entity': '123-45-6789', 'types': ['ssn']}]"
    actual_json = '[{"entity":"123-45-6789","types":["ssn"]}]'
    assert evaluation._gretel_labels(python_repr) == {"ssn"}
    assert evaluation._gretel_labels(actual_json) == {"ssn"}
    with pytest.raises((ValueError, SyntaxError)):
        evaluation._gretel_labels("not a list")
    assert evaluation._redact_entities("Zhang Wei E10293", ["Zhang Wei", "E10293"]) == "REDACTED REDACTED"


def test_synthetic_fixture_matrix_and_no_raw_content_in_report():
    report = evaluation.evaluate_fixtures("2026-11-04")
    assert report["matrix"]["ALLOW"] == {"ALLOW": 9}
    assert report["matrix"]["BLOCK"] == {"BLOCK": 12, "ALLOW": 1}
    rows = {row["case"]: row for row in report["rows"]}
    assert rows["text_paraphrase"]["actual"] == "ALLOW"
    assert rows["file_unsupported"]["actual"] == "BLOCK"
    assert rows["file_image_only_pdf"]["actual"] == "BLOCK"
    assert all("policy_would_deny" in row and "gate_denied" not in row
               for row in rows.values())
    for extension in ("docx", "xlsx", "pptx"):
        assert rows[f"file_{extension}_public"]["actual"] == "ALLOW"
        assert rows[f"file_{extension}_secret"]["actual"] == "BLOCK"
    assert evaluation._FAKE_SECRET not in json.dumps(report)
    assert all(len(row["payload_sha256"]) == 64 for row in rows.values())


def test_fixture_hashes_are_repeatable():
    first = {row["case"]: row["payload_sha256"] for row in evaluation.evaluate_fixtures("fixed")["rows"]}
    second = {row["case"]: row["payload_sha256"] for row in evaluation.evaluate_fixtures("fixed")["rows"]}
    assert first == second


@pytest.mark.parametrize("extension", ["docx", "xlsx", "pptx"])
def test_office_fixture_uses_fixed_zip_metadata(extension):
    with ZipFile(BytesIO(evaluation._office(extension, "synthetic"))) as archive:
        assert all(entry.date_time == (1980, 1, 1, 0, 0, 0)
                   for entry in archive.infolist())


@pytest.mark.parametrize("extension", ["docx", "xlsx", "pptx"])
def test_office_fixture_round_trips_through_document_library(extension):
    text = "Public conference notes"
    payload = BytesIO(evaluation._office(extension, text))
    if extension == "docx":
        library = pytest.importorskip("docx")
        assert library.Document(payload).paragraphs[0].text == text
    elif extension == "xlsx":
        library = pytest.importorskip("openpyxl")
        assert library.load_workbook(payload, read_only=True).active["A1"].value == text
    else:
        library = pytest.importorskip("pptx")
        presentation = library.Presentation(payload)
        assert any(shape.text == text for shape in presentation.slides[0].shapes
                   if shape.has_text_frame)


def test_download_is_verified_before_publishing_to_cache(monkeypatch, tmp_path):
    descriptor = {"id": "fake/synthetic", "revision": "fixed", "source_path": "data.bin",
                  "file": "data.bin", "size": 4,
                  "sha256": hashlib.sha256(b"good").hexdigest()}
    monkeypatch.setattr(evaluation, "urlopen", lambda *_args, **_kwargs: BytesIO(b"too large"))
    with pytest.raises(ValueError, match="exceeds pinned value"):
        evaluation._local_file(tmp_path, descriptor)
    assert not (tmp_path / "data.bin").exists()
    monkeypatch.setattr(evaluation, "urlopen", lambda *_args, **_kwargs: BytesIO(b"bad!"))
    with pytest.raises(ValueError, match="digest or size mismatch"):
        evaluation._local_file(tmp_path, descriptor)
    assert not (tmp_path / "data.bin").exists()
    monkeypatch.setattr(evaluation, "urlopen", lambda *_args, **_kwargs: BytesIO(b"good"))
    assert evaluation._local_file(tmp_path, descriptor).read_bytes() == b"good"
    (tmp_path / "data.bin").write_bytes(b"goad")
    with pytest.raises(ValueError, match="digest mismatch"):
        evaluation._local_file(tmp_path, descriptor)


def test_sampling_rejects_duplicate_ids_and_negative_limits():
    rows = [("gretel_en", "duplicate", "public", set(), "public") for _ in range(2)]
    with pytest.raises(ValueError, match="duplicate dataset row ID"):
        list(evaluation._select(rows, 0, "fixed"))
    with pytest.raises(ValueError, match="nonnegative"):
        list(evaluation._select(rows, -1, "fixed"))


def test_default_evaluation_is_full_and_marks_policy_truth_unavailable(monkeypatch):
    rows = [("gretel_en", "one", "Public note one", set(), "Public note one"),
            ("gretel_en", "two", "Public note two", set(), "Public note two")]
    monkeypatch.setattr(evaluation, "_rows", lambda _paths: rows)
    report = evaluation.evaluate({})
    assert report["schema"] == "transpect.desktop-dlp.dataset-evaluation/1.1"
    assert report["selection_mode"] == "full"
    assert report["datasets"]["gretel_en"]["decisions"]["rows"] == 2
    assert not report["blind_holdout"]
    assert not report["policy_truth_available_for_public_corpora"]
    assert not report["live_enforcement_verified"]
    assert "redacted_proxy_decisions" in report["datasets"]["gretel_en"]
