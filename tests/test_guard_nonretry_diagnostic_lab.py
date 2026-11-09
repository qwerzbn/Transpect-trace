"""The diagnostic DLL is generated separately from the frozen Guard source."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

from transpect_trace.guard.policy import GuardRequest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_guard_nonretry_diagnostic_lab import (  # noqa: E402
    PINNED_SOURCE_SHA256, diagnostic_source,
)


def _frame(kind: str, stage: str) -> dict:
    return {"schema": "transpect.guard.request/1.0", "request_id": "1-2",
            "guard_session_id": "1-42", "pid": 1, "tid": 2,
            "kind": kind, "protocol": "control" if kind != "model.request" else "http",
            "completeness": "complete", "payload_utf8": "", "diagnostic_stage": stage}


def test_diagnostic_transform_preserves_frozen_source_and_adds_allow_outcomes():
    source = (ROOT / "native/guard/guard.c").read_text(encoding="utf-8")
    before = hashlib.sha256((ROOT / "native/guard/guard.c").read_bytes()).hexdigest()
    assert before == PINNED_SOURCE_SHA256
    transformed = diagnostic_source(source)
    assert transformed.count("report_outcome(action); return original_http") == 1
    assert transformed.count("report_outcome(action); return returned") == 1
    assert 'last_policy_stage="parsed_allow"' in transformed
    assert 'last_policy_stage="reply_shape_invalid"' in transformed
    assert hashlib.sha256((ROOT / "native/guard/guard.c").read_bytes()).hexdigest() == before


def test_diagnostic_transform_rejects_unpinned_anchors():
    source = (ROOT / "native/guard/guard.c").read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="anchor count differs"):
        diagnostic_source(source.replace("static _Thread_local long long outcome_qpc;", ""))


def test_diagnostic_stage_is_bounded_to_native_outcome():
    frame = _frame("native.outcome", "parsed_allow")
    assert GuardRequest.model_validate(frame).diagnostic_stage == "parsed_allow"
    with pytest.raises(ValidationError):
        GuardRequest.model_validate(_frame("native.outcome", "prompt text"))
    with pytest.raises(ValidationError):
        GuardRequest.model_validate(_frame("model.request", "parsed_allow"))
