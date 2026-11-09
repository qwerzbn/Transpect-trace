"""Current-backend lab comparison and collection evidence invariants."""
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import probe_desktop_capture_current_lab as lab  # noqa: E402


def test_compact_trace_preserves_string_bytes_and_escapes():
    pretty = (b'{\n  "model": "x", \n  "input": ["space  tab\\t", '
              b'"brace { and \\\" quote", "slash \\\\ tail"]\n}')
    compact = lab.compact_trace_json(pretty)
    assert compact == (b'{"model":"x","input":["space  tab\\t",'
                       b'"brace { and \\\" quote","slash \\\\ tail"]}')
    assert json.loads(compact) == json.loads(pretty)


def test_full_body_mode_needs_native_capture(tmp_path):
    with pytest.raises(ValueError, match="requires Frida"):
        lab.probe(tmp_path / "does-not-exist", collect_full_body=True,
                  evidence_dir=tmp_path / "evidence")


@pytest.mark.skipif(os.name != "nt", reason="encrypted archive uses Windows DPAPI")
def test_observed_body_archives_exact_bytes_without_enforcement_claim(tmp_path):
    body = (ROOT / "tests" / "fixtures" / "codex_collection" /
            "http_turn1.json").read_bytes()
    evidence = tmp_path / "evidence"
    result = lab._collect_full_body(body, protocol="http", pid=1234,
                                    evidence_dir=evidence)
    assert result["observation_only"] is True
    assert result["body_bytes"] == len(body)
    assert result["readback_exact"] is True
    assert result["recorded_decision_point"] == "none"
    assert result["recorded_route_decision"] == "not_enforceable"
    assert result["recorded_released_by_route"] is None
    assert body not in (evidence / "archive" /
                        f'{result["archive_record_id"]}.enc').read_bytes()
