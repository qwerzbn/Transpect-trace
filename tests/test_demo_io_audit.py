"""The four-dimension report runs on the production content DLP engine."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import demo_io_audit as demo  # noqa: E402


def test_report_uses_the_production_engine():
    assert demo.build_engine().__class__.__module__ == (
        "transpect_trace.protect.content_dlp")


def test_detection_matrix_blocks_sensitive_and_allows_benign():
    matrix = demo.detection_matrix()
    assert matrix["all_sensitive_caught"] is True
    assert matrix["benign_allowed"] == matrix["benign_total"]
    assert matrix["sensitive_blocked"] == matrix["sensitive_total"]


def test_evasion_matrix_matches_declared_expectations():
    matrix = demo.evasion_matrix()
    assert matrix["matrix_as_expected"] is True
    assert matrix["misses"] == ["paraphrased_internal_doc"]


def test_file_upload_sample_is_denied(tmp_path):
    assert demo.file_upload_sample(tmp_path)["decision"] == "BLOCK"


def test_performance_within_measured_budget_for_each_payload_size():
    for payload_kib, budget in demo.PAYLOAD_BUDGETS_MS.items():
        result = demo.latency(200, payload_kib)
        assert result["budget_p95_ms"] == budget
        assert result["within_budget"] is True, result
