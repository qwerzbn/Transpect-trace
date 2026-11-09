"""The desktop permission audit must inspect only selected rollout metadata."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_desktop_local_permissions as audit  # noqa: E402


ALTERNATE_THREAD_ID = "c8b02f8a-318c-4f5c-9a91-d941ea531b72"


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
    assert result["thread_id"] == audit.TEST_THREAD_ID
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


def test_selected_thread_id_is_normalized_and_only_its_rollout_is_read(tmp_path):
    _rollout(tmp_path, [_record("turn_context", {
        "turn_id": "default", "sandbox_policy": {"type": "danger-full-access"},
        "active_permission_profile": {"id": ":danger-full-access"},
    })])
    selected = _rollout(tmp_path, [_record("turn_context", {
        "turn_id": "selected", "sandbox_policy": {"type": "workspace-write", "network_access": False},
        "active_permission_profile": {"id": ":workspace"},
    })], ALTERNATE_THREAD_ID)

    result = audit.audit(tmp_path, ALTERNATE_THREAD_ID.upper())

    assert result["thread_id"] == ALTERNATE_THREAD_ID
    assert result["rollout_file"] == selected.name
    assert result["latest"]["turn_id"] == "selected"
    assert result["status"] == "restricted_policy_observed"
    assert result["desktop_tool_mxc_attested"] is False
    assert result["desktop_tool_offline_attested"] is False


@pytest.mark.parametrize("invalid", ["", "not-a-uuid", "*", "../../sessions/*", "c8b02f8a-318c-4f5c-9a91-d941ea531b7z"])
def test_invalid_thread_id_is_rejected_before_filesystem_lookup(tmp_path, monkeypatch, invalid):
    def unexpected_glob(_self, _pattern):
        raise AssertionError("rollout lookup must not run for invalid UUID")

    monkeypatch.setattr(Path, "glob", unexpected_glob)
    with pytest.raises(ValueError, match="thread_id_must_be_uuid"):
        audit.audit(tmp_path, invalid)


def test_selected_thread_missing_or_duplicate_is_unvalidated(tmp_path):
    with pytest.raises(ValueError, match="test_rollout_missing"):
        audit.audit(tmp_path, ALTERNATE_THREAD_ID)
    records = [_record("turn_context", {
        "sandbox_policy": {"type": "danger-full-access"},
        "active_permission_profile": {"id": ":danger-full-access"},
    })]
    _rollout(tmp_path / "a", records, ALTERNATE_THREAD_ID)
    _rollout(tmp_path / "b", records, ALTERNATE_THREAD_ID)
    with pytest.raises(ValueError, match="multiple_test_rollouts"):
        audit.audit(tmp_path, ALTERNATE_THREAD_ID)


def test_cli_read_error_reports_normalized_selected_thread_id(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["audit_desktop_local_permissions.py", "--sessions-root",
                                  str(tmp_path), "--thread-id", ALTERNATE_THREAD_ID.upper()])

    assert audit.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["thread_id"] == ALTERNATE_THREAD_ID
    assert result["status"] == "unvalidated"
    assert result["error"] == "test_rollout_missing"
    assert result["desktop_tool_mxc_attested"] is False
    assert result["desktop_tool_offline_attested"] is False


def test_cli_invalid_uuid_fails_before_rollout_lookup(tmp_path, monkeypatch, capsys):
    def unexpected_glob(_self, _pattern):
        raise AssertionError("rollout lookup must not run for invalid UUID")

    monkeypatch.setattr(Path, "glob", unexpected_glob)
    monkeypatch.setattr(sys, "argv", ["audit_desktop_local_permissions.py", "--sessions-root",
                                  str(tmp_path), "--thread-id", "*"])
    with pytest.raises(SystemExit) as error:
        audit.main()
    assert error.value.code == 2
    assert "thread_id_must_be_uuid" in capsys.readouterr().err
