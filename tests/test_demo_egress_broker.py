"""The egress-boundary prototype: structural controls hold on a real loopback
broker, and the semantic-miss case is demonstrated honestly."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import demo_egress_broker as broker  # noqa: E402


def test_broker_structural_controls_hold_and_semantic_miss_is_honest():
    report = broker.run_scenarios()
    by = {row["case"]: row for row in report["rows"]}
    # Every structural deny lets zero bytes reach the real loopback upstream.
    assert by["direct_to_upstream"]["upstream_bytes"] == 0
    assert by["broker_sensitive"]["upstream_bytes"] == 0
    assert by["broker_arbitrary_url"]["upstream_bytes"] == 0
    assert by["broker_policy_down"]["upstream_bytes"] == 0
    # A benign request really is forwarded through the broker.
    assert by["broker_benign"]["upstream_bytes"] > 0
    assert report["structural_controls_pass"] is True
    # Honest limit: a semantic transform passes the content check and reaches upstream.
    assert by["broker_semantic_miss"]["upstream_bytes"] > 0
    assert report["semantic_miss_demonstrated"] is True
