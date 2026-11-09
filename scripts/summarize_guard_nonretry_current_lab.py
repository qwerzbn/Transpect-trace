"""Verify and pin the separate disposable nonretry lab reports.

This checks saved evidence only. It never injects or starts a desktop process.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import sys

from _build_support import ROOT
from desktop_demo import _ControllerLease
from probe_desktop_guard_graceful_current_lab import controller_source_hashes


SCHEMA = "transpect.guard.nonretry-current-lab-validation/1.0"
OUT = ROOT / "runs/scratch/adapt-26.1103/nonretry-validation-summary-v3.json"
DLL = ROOT / "build/guard-nonretry-current-lab-v2/ttrace-guard-nonretry-current-lab.dll"
MANIFEST = DLL.parent / "build-manifest.json"
EXPECTED_OUTPUT_TAG = str(0x8000000000000012)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def main() -> None:
    manifest = read(MANIFEST)
    check(manifest.get("schema") == "transpect.guard.nonretry-current-lab-build/1.0",
          "wrong build schema")
    check(manifest.get("lab_only") is True, "build is not lab-only")
    check(manifest.get("artifact", {}).get("sha256") == sha(DLL), "DLL SHA differs")
    check(manifest.get("backend", {}).get("sha256") ==
          "40ecc3d8b6899afd8f935a8cccb7d53ba41ffd7c199f679e186d30ddd0d0bf39",
          "backend SHA differs")
    source_hashes = manifest.get("sources_sha256", {})
    for name, expected in source_hashes.items():
        check(sha(ROOT / name) == expected, f"build source changed: {name}")

    evidence: dict[str, dict] = {}
    for transport in ("http", "wss"):
        for loss in ("release", "abandon"):
            name = f"{transport}-{loss}"
            path = ROOT / "runs/scratch/adapt-26.1103/nonretry-lease-smoke-3" / f"{name}.json"
            row = read(path)
            check(row.get("validated") is True and row.get("lab_only") is True,
                  f"{name} lease report failed")
            check(row.get("backend_sha256") == manifest["backend"]["sha256"]
                  and row.get("dll_sha256") == sha(DLL), f"{name} binary differs")
            check(row.get("protected_denied") is True
                  and row.get("disabled_ack") is True
                  and row.get("post_lease_origin_match") is True
                  and row.get("no_post_lease_pipe_request") is True
                  and row.get("same_pid_after_lease") is True
                  and row.get("denied_origin_requests_after_lease") == 0,
                  f"{name} lease semantics failed")
            evidence[f"lease_{name}"] = {"path": str(path), "sha256": sha(path)}

    for transport, size in (("http", "small"), ("wss", "small"),
                            ("http", "large")):
        name = f"{transport}-{size}"
        path = ROOT / "runs/scratch/adapt-26.1103/nonretry-deep-lab-v2" / f"{name}.json"
        row = read(path)
        denied = [item for item in row.get("pipe_requests", [])
                  if item.get("denied_marker")]
        check(row.get("validated") is True and row.get("lease_disabled_ack") is True,
              f"{name} deep report failed")
        check(row.get("backend_sha256") == manifest["backend"]["sha256"]
              and row.get("dll_sha256") == sha(DLL), f"{name} binary differs")
        check(len(denied) == 2 and all(item.get("protocol") == transport for item in denied),
              f"{name} repeated a denied request or changed transport")
        check(row.get("deny_non_warmup_wire_body_bytes_received") == 0
              and row.get("deny_origin_requests") == 0
              and row.get("same_pid_for_followup") is True
              and row.get("backend_alive_after_repeat") is True
              and row.get("followup_origin_match") is True
              and row.get("repeat_followup_origin_match") is True,
              f"{name} origin or follow-up check failed")
        check(row.get("denied_turn_completion", {}).get("status") == "failed"
              and row.get("repeat_denied_turn_completion", {}).get("status") == "failed",
              f"{name} denied turn did not fail")
        if size == "large":
            check(row.get("denied_input_items") == 536
                  and all(item.get("bytes", 0) >= 900000 for item in denied),
                  "large case did not reach expected size")
        evidence[f"deep_{name}"] = {"path": str(path), "sha256": sha(path),
                                   "denied_requests_for_two_turns": len(denied),
                                   "denied_body_bytes": [item["bytes"] for item in denied]}

    for transport, folder, entry_tag in (
        ("http", "nonretry-map-out-lab-1", "10"),
        ("wss", "nonretry-map-out-wss-lab-1", "25"),
    ):
        path = ROOT / "runs/scratch/adapt-26.1103" / folder / "report.json"
        row = read(path)
        events = row.get("events", [])
        lease_result = row.get("lease_result", {})
        check(lease_result.get("validated") is True
              and lease_result.get("dll_sha256") == sha(DLL)
              and lease_result.get("backend_sha256") == manifest["backend"]["sha256"],
              f"{transport} dynamic mapper lease failed")
        check(any(item.get("where") == "api_error_map_entry"
                  and item.get("tag") == entry_tag for item in events),
              f"{transport} mapper input tag absent")
        check(any(item.get("where") == "api_error_map_return"
                  and item.get("output_tag") == EXPECTED_OUTPUT_TAG for item in events),
              f"{transport} InvalidPrompt output tag absent")
        evidence[f"mapper_{transport}"] = {"path": str(path), "sha256": sha(path),
                                           "input_tag": int(entry_tag),
                                           "output_tag": EXPECTED_OUTPUT_TAG}

    success_path = (ROOT / "runs/scratch/adapt-26.1103"
                    / "nonretry-success-http-lab-2/report.json")
    success = read(success_path)
    success_report = success.get("report", {})
    success_denied = [item for item in success_report.get("pipe_requests", [])
                      if item.get("denied_marker")]
    check(success.get("schema") == "transpect.guard.nonretry-success-http-lab/1.0"
          and success.get("validated") is True
          and success.get("source_sha256_before") == success.get("source_sha256_after")
          and success.get("source_sha256_before", {}).get("guard.c")
          == next(value for name, value in source_hashes.items()
                  if name.endswith("guard.c"))
          and success_report.get("validated") is True
          and success_report.get("dll_sha256") == sha(DLL)
          and success_report.get("backend_sha256") == manifest["backend"]["sha256"]
          and len(success_denied) == 2
          and all(item.get("protocol") == "http" for item in success_denied)
          and success_report.get("deny_non_warmup_wire_body_bytes_received") == 0
          and success_report.get("followup_turn_completion", {}).get("status") == "completed"
          and success_report.get("repeat_followup_turn_completion", {}).get("status")
          == "completed" and success_report.get("lease_disabled_ack") is True,
          "synthetic HTTP success-origin check failed")
    evidence["successful_http_followup"] = {
        "path": str(success_path), "sha256": sha(success_path),
        "denied_requests_for_two_turns": len(success_denied),
        "completed_benign_turns": 2,
    }

    report = {
        "schema": SCHEMA,
        "validated": True,
        "scope": "disposable app-server children and non-forwarding local origin only",
        "production_desktop_coverage_validated": False,
        "live_desktop_injected": False,
        "backend": manifest["backend"],
        "dll": {"path": str(DLL), "sha256": sha(DLL)},
        "build_manifest": {"path": str(MANIFEST), "sha256": sha(MANIFEST)},
        "source_sha256_at_build_and_summary": source_hashes,
        "controller_lease_class_sha256_at_summary": hashlib.sha256(
            inspect.getsource(_ControllerLease).encode("utf-8")).hexdigest(),
        "controller_implementation_sha256_at_summary": {
            "scripts/desktop_demo.py": sha(ROOT / "scripts/desktop_demo.py"),
            **controller_source_hashes(),
        },
        "retry_config": {"request_max_retries": 2, "stream_max_retries": 2},
        "denied_turns_per_deep_case": 2,
        "mapper_output": "CodexErr::InvalidPrompt (0x8000000000000012)",
        "evidence": evidence,
        "limitation": "App-server turn errors and synthetic HTTP completions were observed; desktop frontend rendering was not validated.",
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(OUT)
    print(sha(OUT))


if __name__ == "__main__":
    main()
