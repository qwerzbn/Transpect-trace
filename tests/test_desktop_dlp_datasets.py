"""The offline evaluation keeps policy labels separate from corpus entity labels."""
import json

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
    assert evaluation._FAKE_SECRET not in json.dumps(report)
    assert all(len(row["payload_sha256"]) == 64 for row in rows.values())


def test_fixture_hashes_are_repeatable():
    first = {row["case"]: row["payload_sha256"] for row in evaluation.evaluate_fixtures("fixed")["rows"]}
    second = {row["case"]: row["payload_sha256"] for row in evaluation.evaluate_fixtures("fixed")["rows"]}
    assert first == second
