"""Deterministic core of the delivery demo: detector matrix + latency budget."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import demo_io_audit as demo  # noqa: E402


def test_detector_matrix_blocks_sensitive_allows_benign():
    matrix = demo.detection_matrix()
    assert matrix["sensitive_blocked"] == matrix["sensitive_total"]
    assert matrix["benign_allowed"] == matrix["benign_total"]


def test_latency_within_pilot_budget():
    bench = demo.latency_benchmark(200, 64)
    assert bench["p95_ms"] <= demo.BUDGET_P95_MS
    assert bench["within_budget"] is True


def test_evasion_matrix_catches_encoding_dodges_and_honestly_reports_semantic_misses():
    matrix = demo.evasion_matrix()
    assert matrix["matrix_as_expected"] is True
    by = {row["case"]: row for row in matrix["rows"]}
    # Encoding/verbatim dodges are caught beyond plain regex.
    assert by["base64_encoded"]["caught"] and by["base64_encoded"]["caught_by"] == "canonicalize+rules"
    assert by["registered_content_wrapped"]["caught"] and "registration" in by["registered_content_wrapped"]["caught_by"]
    # Semantic transforms are honestly reported as misses (not hidden).
    assert not by["paraphrase_semantic"]["caught"] and not by["rot13_transform"]["caught"]
    assert set(matrix["misses"]) == {"paraphrase_semantic", "rot13_transform"}


def test_canonicalize_decodes_base64_but_not_substitution_cipher():
    plain = demo.RULE_SECRET
    encoded = f"blob: {__import__('base64').b64encode(plain.encode()).decode()}"
    assert any(plain in candidate for candidate in demo.canonicalize(encoded))
    rot13 = plain.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    assert all(plain not in candidate for candidate in demo.canonicalize(rot13))
