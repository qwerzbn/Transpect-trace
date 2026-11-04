"""The desktop permission audit must inspect only the pinned test rollout metadata."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_desktop_local_permissions as audit  # noqa: E402


def _record(kind: str, payload: dict, timestamp: str = "2026-11-04T12:00:00Z") -> bytes:
    return (json.dumps({"timestamp": timestamp, "ordinal": 1, "type": kind,
                        "payload": payload}, separators=(",", ":")) + "\n").encode()


def _rollout(root: Path, records: list[bytes], thread_id: str = audit.TEST_THREAD_ID) -> Path:
    path = root / "2026" / "11" / "04" / f"rollout-test-{thread_id}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(records))
    return path


def test_reads_only_pinned_chat_and_latest_context_without_prompt_body(tmp_path):
    secret_prompt = "SECRET_USER_PROMPT_DO_NOT_REPORT"
    _rollout(tmp_path, [_record("response_item", {"content": secret_prompt})],
             "11111111-1111-1111-1111-111111111111")
    _rollout(tmp_path, [
        _record("event_msg", {"content": secret_prompt}),
        b'{"type":"response_item","payload":{"content":"' + b'\xff' * 1024 + b'"}}\n',
        _record("turn_context", {
            "turn_id": "old", "sandbox_policy": {"type": "workspace-write",
                                                     "network_access": False},
            "permission_profile": {"type": "enabled"},
            "active_permission_profile": {"id": ":workspace"},
            "approval_policy": "on-request",
        }),
        _record("response_item", {"content": secret_prompt}),
        _record("turn_context", {
            "turn_id": "new", "sandbox_policy": {"type": "danger-full-access"},
            "permission_profile": {"type": "disabled"},
            "active_permission_profile": {"id": ":danger-full-access"},
            "approval_policy": "never",
        }, timestamp="2026-11-04T12:02:00Z"),
    ])
    result = audit.audit(tmp_path)
    assert result["status"] == "unrestricted"
    assert result["context_count"] == 2
    assert result["latest"]["turn_id"] == "new"
    assert result["desktop_tool_offline_attested"] is False
    assert result["desktop_tool_mxc_attested"] is False
    assert secret_prompt not in json.dumps(result)


def test_restricted_context_does_not_claim_mxc_or_offline(tmp_path):
    _rollout(tmp_path, [_record("turn_context", {
        "turn_id": "one", "sandbox_policy": {"type": "workspace-write",
                                                 "network_access": False},
        "permission_profile": {"type": "enabled"},
        "active_permission_profile": {"id": ":workspace"},
    })])
    result = audit.audit(tmp_path)
    assert result["status"] == "restricted_policy_observed"
    assert result["latest"]["network_access"] is False
    assert not result["desktop_tool_offline_attested"]
    assert not result["desktop_tool_mxc_attested"]


@pytest.mark.parametrize("records,error", [
    ([], "turn_context_missing"),
    ([_record("turn_context", {"sandbox_policy": {"type": "danger-full-access"},
                                "active_permission_profile": {"id": ":workspace"}})], None),
    ([b'{"timestamp":"x","type":"turn_context","payload":not-json}\n'],
     "invalid_turn_context_json"),
])
def test_missing_conflicting_or_invalid_context_never_claims_protection(tmp_path, records, error):
    _rollout(tmp_path, records)
    if error:
        with pytest.raises(ValueError, match=error):
            audit.audit(tmp_path)
    else:
        result = audit.audit(tmp_path)
        assert result["status"] == ("unvalidated_conflicting_metadata"
                                    if records else "unvalidated_metadata")
        assert not result["desktop_tool_offline_attested"]


def test_missing_or_multiple_test_rollouts_are_unvalidated(tmp_path):
    with pytest.raises(ValueError, match="test_rollout_missing"):
        audit.audit(tmp_path)
    records = [_record("turn_context", {"sandbox_policy": {"type": "danger-full-access"},
                                         "active_permission_profile": {"id": ":danger-full-access"}})]
    _rollout(tmp_path / "a", records)
    _rollout(tmp_path / "b", records)
    with pytest.raises(ValueError, match="multiple_test_rollouts"):
        audit.audit(tmp_path)
