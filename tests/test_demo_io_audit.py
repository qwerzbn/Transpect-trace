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
