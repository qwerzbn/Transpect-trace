"""The delivery demo presents the content-recognition engine across the four dimensions."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import demo_io_audit as demo  # noqa: E402
import demo_content_dlp as dlp  # noqa: E402


def test_detection_matrix_blocks_sensitive_allows_benign():
    matrix = dlp.detection_matrix()
    assert matrix["all_sensitive_caught"] is True
    assert matrix["benign_allowed"] == matrix["benign_total"]


def test_performance_within_pilot_budget():
    perf = dlp.latency(200, 64)
    assert perf["p95_ms"] <= demo.BUDGET_P95_MS
