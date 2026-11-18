"""Correlate one interactive no-forward TUI run with Native and archive evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.protect.archive import EncryptedRequestArchive  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin-receipt", required=True, type=Path)
    parser.add_argument("--native-audit", required=True, type=Path)
    parser.add_argument("--marker", action="append", required=True)
    args = parser.parse_args()
    receipt_bytes = args.origin_receipt.read_bytes()
    audit_bytes = args.native_audit.read_bytes()
    receipt = json.loads(receipt_bytes)
    assert receipt["schema"] == "transpect.claude.local-origin-receipt/1.0"
    assert receipt["mode"] == "no_forward"
    markers = [value.encode() for value in args.marker]
    assert receipt["markers_sha256"] == [sha(value) for value in markers]
    origin = [row for row in receipt["records"] if row["starts_post"]]
    native = [json.loads(line) for line in audit_bytes.splitlines()]
    native = [row for row in native if row.get("route_event") == "model.request"
              and row.get("category") == "request_envelope"]
    assert len(origin) == len(native) == 4, (len(origin), len(native))
    assert all(row["complete"] and row["auth_matches"] and row["app_bytes"] > 0
               and row["request_line"].startswith("POST /v1/messages") for row in origin)
    archive = EncryptedRequestArchive(args.native_audit.parent / "archive")
    evidence = []
    for index, (seen, row) in enumerate(zip(origin, native)):
        _, source = archive.read(row["archive_record_id"])
        assert row["request_sha256"] == sha(source)
        assert row["content_bytes"] == seen["body_bytes"] == len(source)
        assert row["decision"] == "allow"
        offsets = [seen["marker_offset"], *seen["secondary_marker_offsets"]]
        assert offsets == [-1] * len(markers), (index, offsets)
        source_offsets = [source.find(marker) for marker in markers]
        if index == 0:
            assert row["actionable_decision"] == "ALLOW"
            assert source_offsets == [-1] * len(markers)
            assert seen["body_sha256"] == sha(source)
        else:
            assert row["actionable_decision"] == "BLOCK"
            assert source_offsets[0] >= 0
            if index >= 2:
                assert source_offsets[1] >= 0
            assert seen["body_sha256"] != sha(source)
        evidence.append({"turn": index + 1, "request_id": row["request_id"],
                         "native_decision": row["decision"],
                         "actionable_decision": row["actionable_decision"],
                         "archive_sha256": sha(source),
                         "origin_sha256": seen["body_sha256"],
                         "body_bytes": len(source), "origin_app_bytes": seen["app_bytes"],
                         "source_marker_offsets": source_offsets,
                         "origin_marker_offsets": offsets})
    report = {"schema": "transpect.claude.tui-local-verification/1.0",
              "result": "PASS", "cases": 4,
              "native_audit_file": str(args.native_audit.resolve()),
              "native_audit_sha256": sha(audit_bytes),
              "origin_receipt_file": str(args.origin_receipt.resolve()),
              "origin_receipt_sha256": sha(receipt_bytes),
              "turns": evidence}
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
