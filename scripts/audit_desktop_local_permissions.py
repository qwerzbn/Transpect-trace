"""Read only the effective permission metadata of the dedicated Local test chat.

This tool is deliberately pinned to one synthetic desktop chat. It never parses
user messages, tool outputs, or model content from the rollout JSONL file.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


SCHEMA = "transpect.desktop-local-permission-audit/1.0"
TEST_THREAD_ID = "01a1a5ad-14de-7861-afe8-7670bfb99d3b"
_TYPE_IN_PREFIX = re.compile(rb'"type":"([a-z_]+)"')
_MAX_CONTEXT_BYTES = 8 * 1024 * 1024


def _context_records(path: Path):
    """Skip non-context lines without decoding or parsing their contents."""
    with path.open("rb") as stream:
        while True:
            prefix = stream.readline(256)
            if not prefix:
                return
            found = _TYPE_IN_PREFIX.search(prefix)
            if found is None:
                raise ValueError("unexpected_rollout_record_prefix")
            if found.group(1) != b"turn_context":
                while prefix and not prefix.endswith(b"\n"):
                    prefix = stream.readline(65536)
                continue
            if prefix.endswith(b"\n"):
                line = prefix
            else:
                line = prefix + stream.readline(_MAX_CONTEXT_BYTES + 1 - len(prefix))
            if len(line) > _MAX_CONTEXT_BYTES or not line.endswith(b"\n"):
                raise ValueError("turn_context_too_large_or_incomplete")
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("invalid_turn_context_json") from error
            if record.get("type") != "turn_context" or not isinstance(record.get("payload"), dict):
                raise ValueError("invalid_turn_context_shape")
            yield record


def _string_field(value: object, key: str) -> str | None:
    return value.get(key) if isinstance(value, dict) and isinstance(value.get(key), str) else None


def audit(sessions_root: Path) -> dict:
    candidates = list(sessions_root.glob(f"**/rollout-*-{TEST_THREAD_ID}.jsonl"))
    if len(candidates) != 1:
        raise ValueError("test_rollout_missing" if not candidates else "multiple_test_rollouts")
    path = candidates[0]
    contexts = list(_context_records(path))
    if not contexts:
        raise ValueError("turn_context_missing")
    rows = []
    for record in contexts:
        payload = record["payload"]
        policy = payload.get("sandbox_policy")
        permission = payload.get("permission_profile")
        active = payload.get("active_permission_profile")
        rows.append({
            "timestamp": record.get("timestamp"),
            "turn_id": payload.get("turn_id"),
            "sandbox_policy": _string_field(policy, "type"),
            "network_access": policy.get("network_access") if isinstance(policy, dict) else None,
            "permission_profile": _string_field(permission, "type"),
            "active_permission_profile": _string_field(active, "id"),
            "approval_policy": payload.get("approval_policy"),
        })
    latest = rows[-1]
    sandbox = latest["sandbox_policy"]
    active = latest["active_permission_profile"]
    if sandbox == "danger-full-access" and active == ":danger-full-access":
        status = "unrestricted"
    elif sandbox is None or active is None:
        status = "unvalidated_metadata"
    elif sandbox == "danger-full-access" or active == ":danger-full-access":
        status = "unvalidated_conflicting_metadata"
    else:
        status = "restricted_policy_observed"
    return {
        "schema": SCHEMA,
        "thread_id": TEST_THREAD_ID,
        "rollout_file": path.name,
        "read_only": True,
        "context_count": len(rows),
        "latest": latest,
        "status": status,
        "desktop_tool_offline_attested": False,
        "desktop_tool_mxc_attested": False,
        "interpretation": (
            "The Local test chat has unrestricted command permissions."
            if status == "unrestricted" else
            "The recorded policy alone does not prove Windows MXC isolation or zero-byte tool egress."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions-root", type=Path,
                        default=Path.home() / ".codex" / "sessions")
    args = parser.parse_args()
    try:
        result = audit(args.sessions_root)
    except (OSError, ValueError) as error:
        result = {"schema": SCHEMA, "thread_id": TEST_THREAD_ID,
                  "read_only": True, "status": "unvalidated",
                  "error": str(error), "desktop_tool_offline_attested": False,
                  "desktop_tool_mxc_attested": False}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
