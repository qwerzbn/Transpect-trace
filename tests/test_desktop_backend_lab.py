"""Interpret the local synthetic source record without inflating hook coverage."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from probe_desktop_backend_lab import compare_http_candidate_body  # noqa: E402


BODY = b'{"input":"FAKE_DESKTOP_PROMPT_fixture"}'
DIGEST = hashlib.sha256(BODY).hexdigest()


def origin() -> dict:
    return {"requests": 1, "body_bytes": len(BODY),
            "body_sha256": [DIGEST], "marker_in_body": True,
            "paths": ["responses"]}


def candidate(*, size: int = len(BODY), digest: str = DIGEST) -> dict:
    return {"kind": "marker_buffer", "hook": "model.http",
            "stage": "hypothesized-http-body", "bytes": size, "sha256": digest}


def test_exact_candidate_bytes_match_one_synthetic_origin_body():
    rows = [candidate(), {**candidate(), "hook": "ReadFile"}, candidate()]
    result = compare_http_candidate_body(rows, origin())
    assert result["status"] == "exact_byte_match"
    assert result["candidate_body_count"] == 2
    assert result["exact_match_count"] == 2
    assert result["candidate_bodies"] == [
        {"bytes": len(BODY), "sha256": DIGEST},
        {"bytes": len(BODY), "sha256": DIGEST},
    ]


def test_mismatch_or_missing_candidate_is_not_promoted_to_exact_evidence():
    assert compare_http_candidate_body([], origin())["status"] == "candidate_body_not_observed"
    incomplete = {**candidate(), "sha256": "bad"}
    assert compare_http_candidate_body([candidate(), incomplete], origin())[
        "status"] == "candidate_metadata_incomplete"
    changed = candidate(digest="0" * 64)
    assert compare_http_candidate_body([changed], origin())["status"] == "candidate_body_mismatch"
    mixed = compare_http_candidate_body([candidate(), changed], origin())
    assert mixed["status"] == "mixed_match_and_mismatch"
    assert mixed["exact_match_count"] == 1


def test_multiple_or_unmarked_origin_requests_are_not_comparable():
    many = {**origin(), "requests": 2}
    assert compare_http_candidate_body([candidate()], many)["status"] == "origin_not_comparable"
    unmarked = {**origin(), "marker_in_body": False}
    assert compare_http_candidate_body([candidate()], unmarked)["status"] == "origin_not_comparable"
