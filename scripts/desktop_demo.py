"""Current-build desktop model capture without Codex command hooks.

`status` is read-only. `run` is an explicit-PID foreground experiment using a
pinned lab artifact and a local NativeCollectionEngine. A fail-stop DLL may
terminate the backend; the lease variants disable their hooks on controller
exit and then leave model egress uncovered. Real desktop route coverage is not
established merely by injection or a ready event.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import inspect
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))

from transpect_trace.behavior.desktop_identity import (
    BACKEND_IMAGE_SHA256, BACKEND_VERSION, PACKAGE_FULL_NAME,
    collect_desktop_observation_identity, same_desktop_observation_subject,
)
from transpect_trace.guard.native import api, inject, wait_ready
from transpect_trace.guard.pipe import PipeServer
from transpect_trace.observe.windows import identity as image_identity, modules
from transpect_trace.protect.codex_hook_gate import GateConfig
from transpect_trace.protect.native_collection import NativeCollectionEngine


SCHEMA = "transpect.desktop-native-demo/1.0"
MODEL_NOT_COVERED = "MODEL_EGRESS_NOT_COVERED"
BUILD_SCHEMA = "transpect.guard.failstop-current-lab-build/1.0"
LAB_SCHEMA = "transpect.desktop-guard-failstop-current-lab/1.0"
DEFAULT_DLL = ROOT / "build/guard-failstop-current-lab/ttrace-guard-failstop-current-lab.dll"
DEFAULT_LAB_REPORT = ROOT / "runs/scratch/adapt-26.1103/current-integrated-guard-lab-quiescent-1/summary.json"
GRACEFUL_BUILD_SCHEMA = "transpect.guard.graceful-current-lab-build/1.0"
GRACEFUL_LAB_SCHEMA = "transpect.desktop-guard-graceful-current-lab/1.0"
DEFAULT_GRACEFUL_DLL = ROOT / "build/guard-graceful-current-lab/ttrace-guard-graceful-current-lab.dll"
DEFAULT_GRACEFUL_LAB_REPORT = ROOT / "runs/scratch/adapt-26.1103/graceful-shared-repeat-1/summary.json"
DEFAULT_GRACEFUL_REPEAT_REPORT = ROOT / "runs/scratch/adapt-26.1103/graceful-shared-large-http-1/summary.json"
GRACEFUL_DLL_SHA256 = "365d61b01fd6e6c289f0a2b1d5b86014e7a979bfae26faa77294f62e8d5a43c1"
GRACEFUL_MANIFEST_SHA256 = "cb2c22e4c6d5d3372206d8e8354ac7e8d91e03a730ed97d01280f78642ce20af"
GRACEFUL_LAB_REPORT_SHA256 = "29cde631a65e2b7e125d0c00378d2da0d0d01672918c0ec8943755b0b3011976"
GRACEFUL_REPEAT_REPORT_SHA256 = "e0ebc3f2a2b62f4f7d72f3fc9877d9f65ad3e4180b897f8a430098cb9054961f"
LEASE_BUILD_SCHEMA = "transpect.guard.graceful-lease-current-lab-build/1.0"
LEASE_LAB_SCHEMA = "transpect.desktop-guard-graceful-lease-current-lab/1.0"
LEASE_CONTENT_LAB_SCHEMA = "transpect.desktop-guard-graceful-lease-content-lab/1.0"
DEFAULT_LEASE_DLL = ROOT / "build/guard-graceful-lease-current-lab/ttrace-guard-graceful-lease-current-lab.dll"
DEFAULT_LEASE_LAB_REPORT = ROOT / "runs/scratch/adapt-26.1103/graceful-lease-2/summary.json"
DEFAULT_LEASE_REPEAT_REPORT = ROOT / "runs/scratch/adapt-26.1103/graceful-lease-content-repeat-1/summary.json"
DEFAULT_LEASE_LARGE_REPORT = ROOT / "runs/scratch/adapt-26.1103/graceful-lease-content-large-http-1/summary.json"
LEASE_DLL_SHA256 = "768c07f709d83fbb8cd5d808e89b254cd96813a56c6ea6f2763f4dac9123de2d"
LEASE_MANIFEST_SHA256 = "6f837feeaa9c1dde5488560749b7ddac6788222ae3c8b1f935111e7f89ff2950"
# Updated after the isolated lab pins the exact _ControllerLease class source.
LEASE_LAB_REPORT_SHA256 = "8357538bc8a249b2d62d5e3d264f4406b24b5b3c4fa7e30c3254ca91df359dfc"
LEASE_REPEAT_REPORT_SHA256 = "e1c21163aa9d14087e69206491c90bd5bf045dcba30518e8b3b03cbfacb835ce"
LEASE_LARGE_REPORT_SHA256 = "9f2f6c0e1b65924a4c661c86215b51c255d0e1b955dd1ae4e0fc74ecafc2072d"
NONRETRY_BUILD_SCHEMA = "transpect.guard.nonretry-current-lab-build/1.0"
NONRETRY_VALIDATION_SCHEMA = "transpect.guard.nonretry-current-lab-validation/1.0"
DEFAULT_NONRETRY_DLL = ROOT / "build/guard-nonretry-current-lab-v2/ttrace-guard-nonretry-current-lab.dll"
DEFAULT_NONRETRY_REPORT = ROOT / "runs/scratch/adapt-26.1103/nonretry-validation-summary-v3.json"
NONRETRY_DLL_SHA256 = "36dd35096ff05b8cfbd5e714aa8700ff26abd04471b7340132e3bb99d0a976ba"
NONRETRY_MANIFEST_SHA256 = "c37a12e67e0a0bc6ec068294dc0106d3fda4944193bf3c8dfdb2f1634b2b37b1"
NONRETRY_REPORT_SHA256 = "fde28d6066d55a589e599a030dd7ab019f288e49325904b1c2fa477710595284"
NONRETRY_PINS = {
    "http": {"rva": "0xab2d670", "prefix_hex": "5541574156415541545657534881ec28"},
    "wss": {"rva": "0x400c4d0", "prefix_hex": "5541574156415541545657534881ecd8"},
    "drop_headers": {"rva": "0xa6410", "prefix_hex": "555657534883ec58"},
    "api_error_map": {"rva": "0x3fff370", "prefix_hex": "554157415641554154565753"},
}
NONRETRY_ABI = {"http_denied_tag": 3, "api_error_build_tag": 10,
                "api_error_invalid_prompt_tag": 25, "wss_denied_tag": 25,
                "api_error_string_offsets": [8, 16, 24]}
NONRETRY_EVIDENCE = {
    "lease_http-release": "nonretry-lease-smoke-3/http-release.json",
    "lease_http-abandon": "nonretry-lease-smoke-3/http-abandon.json",
    "lease_wss-release": "nonretry-lease-smoke-3/wss-release.json",
    "lease_wss-abandon": "nonretry-lease-smoke-3/wss-abandon.json",
    "deep_http-small": "nonretry-deep-lab-v2/http-small.json",
    "deep_wss-small": "nonretry-deep-lab-v2/wss-small.json",
    "deep_http-large": "nonretry-deep-lab-v2/http-large.json",
    "mapper_http": "nonretry-map-out-lab-1/report.json",
    "mapper_wss": "nonretry-map-out-wss-lab-1/report.json",
    "successful_http_followup": "nonretry-success-http-lab-2/report.json",
}
NONRETRY_EVIDENCE_ROOT = ROOT / "runs/scratch/adapt-26.1103"
GRACEFUL_CONTROLLER_SOURCES = {
    "src/transpect_trace/protect/content_dlp.py":
        "a9e5383381077aeaa83d427051d432b3e596ed79f6bcdbbc8c56119f0634dccc",
    "src/transpect_trace/protect/native_collection.py":
        "ece050ea388f10c69e96331f93e353cbd310725a3c65decb55db79c3aa03d75e",
    "src/transpect_trace/protect/collection_eval.py":
        "66853c588cea5d6275610ebc07dcf8d7ab78ba711a97c863b31ca47f51f2ebe0",
}
MAX_SECONDS = 3600
LIVE_TRIALS_PAUSED = True
FAIL_STOP_EXIT_CODE = 76
EXPECTED_PINS = {"http_rva": "0xab2d670",
                 "http_entry_prefix_hex": "5541574156415541545657534881ec28",
                 "wss_rva": "0x400c4d0",
                 "wss_entry_prefix_hex": "5541574156415541545657534881ecd8",
                 "wss_success_tag": "0x20"}
GRACEFUL_PINS = {
    "http": {"rva": EXPECTED_PINS["http_rva"],
             "prefix_hex": EXPECTED_PINS["http_entry_prefix_hex"]},
    "wss": {"rva": EXPECTED_PINS["wss_rva"],
            "prefix_hex": EXPECTED_PINS["wss_entry_prefix_hex"]},
    "drop_headers": {"rva": "0xa6410", "prefix_hex": "555657534883ec58"},
}
GRACEFUL_ABI = {"http_denied_tag": 3, "http_empty_string_words": [0, 1, 0],
                "wss_success_tag": 32, "wss_denied_tag": 13,
                "wss_owned_buffer_reused": True}
EXPECTED_SOURCES = {
    "native/guard/guard.c",
    "native/guard/third_party/minhook/src/buffer.c",
    "native/guard/third_party/minhook/src/hook.c",
    "native/guard/third_party/minhook/src/trampoline.c",
    "native/guard/third_party/minhook/src/hde/hde64.c",
}


def _hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _same_path(left: str | Path, right: str | Path) -> bool:
    return ntpath.normcase(ntpath.normpath(str(left))) == ntpath.normcase(ntpath.normpath(str(right)))


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid JSON object: {path.name}")
    return value


def _lab_artifacts(backend: Path, dll: Path, report_path: Path) -> dict:
    """Admit only the exact synthetic DLL and all four integrated lab cases."""
    if not dll.is_file() or not report_path.is_file():
        raise ValueError("pinned DLL or integrated lab report is unavailable")
    manifest_path = dll.parent / "build-manifest.json"
    manifest = _json(manifest_path)
    dll_sha = _hash(dll)
    expected = manifest.get("backend", {})
    artifact = manifest.get("artifact", {})
    sources = manifest.get("sources_sha256", {})
    pins = manifest.get("pins")
    captures = manifest.get("capture_evidence")
    if (not isinstance(expected, dict) or not isinstance(artifact, dict)
            or not isinstance(pins, dict) or not isinstance(captures, dict)):
        raise ValueError("malformed fail-stop DLL manifest")
    if (manifest.get("schema") != BUILD_SCHEMA
            or manifest.get("lab_only") is not True
            or manifest.get("status") != "synthetic_collection_only_not_desktop_validated"
            or manifest.get("deny_behavior") != "terminate_process_exit_76"
            or expected.get("sha256") != BACKEND_IMAGE_SHA256
            or expected.get("version") != BACKEND_VERSION
            or not _same_path(expected.get("path", ""), backend)
            or artifact.get("sha256") != dll_sha
            or not _same_path(artifact.get("path", ""), dll)
            or pins != EXPECTED_PINS
            or set(captures) != {"http", "wss"}):
        raise ValueError("fail-stop DLL manifest does not match the pinned live backend")
    if _hash(backend) != BACKEND_IMAGE_SHA256:
        raise ValueError("live backend image differs from the lab pin")
    if any(not isinstance(capture, dict)
           or capture.get("full_body_readback_exact") is not True
           or capture.get("observation_only") is not True
           or capture.get("decrypted_archive_verified") is not True
           or capture.get("collection_envelope_verified") is not True
           for capture in captures.values()):
        raise ValueError("DLL capture evidence is incomplete")
    normalized_sources = ({name.replace("\\", "/"): digest
                           for name, digest in sources.items()}
                          if isinstance(sources, dict)
                          and all(isinstance(name, str) for name in sources) else {})
    if (set(normalized_sources) != EXPECTED_SOURCES
            or any(not isinstance(digest, str)
                   or Path(name).is_absolute() or ".." in Path(name).parts
                   or not (ROOT / name).is_file() or _hash(ROOT / name) != digest
                   for name, digest in normalized_sources.items())):
        raise ValueError("DLL source tree differs from its build manifest")
    report = _json(report_path)
    results = report.get("results")
    report_build = report.get("build")
    if (not isinstance(report_build, dict) or not isinstance(results, list)
            or len(results) != 4 or not all(isinstance(row, dict) for row in results)):
        raise ValueError("malformed integrated four-case lab report")
    if (report.get("schema") != LAB_SCHEMA
            or report.get("backend_sha256") != BACKEND_IMAGE_SHA256
            or report.get("validated") is not True
            or report.get("synthetic_only") is not True
            or report.get("production_desktop_coverage_validated") is not False
            or report_build.get("sha256") != dll_sha
            or {(row.get("transport"), row.get("case")) for row in results} != {(transport, case)
                                             for transport in ("http", "wss")
                                             for case in ("allow", "dlp_block")}):
        raise ValueError("integrated four-case lab evidence does not match the DLL")
    for row in results:
        status = row.get("status", {})
        requests = row.get("pipe_requests")
        if not isinstance(status, dict):
            raise ValueError("malformed integrated lab case status")
        if (row.get("validated") is not True or row.get("dll_sha256") != dll_sha
                or row.get("backend_sha256") != BACKEND_IMAGE_SHA256
                or row.get("synthetic_only") is not True
                or row.get("local_origin_only") is not True
                or row.get("codex_command_hooks_present") is not False
                or row.get("target_trace_exact") is not True
                or row.get("all_origin_seen_by_native_pipe") is not True
                or row.get("all_allowed_pipe_requests_sent") is not True
                or status.get("injected_before_thread_start") is not True
                or status.get("hook_ready") is not True
                or status.get("pipe_ready") is not True
                or not isinstance(requests, list) or not requests
                or not all(isinstance(item, dict)
                           and item.get("archive_readback_exact") is True
                           for item in requests)
                or row.get("pipe_errors") != [] or row.get("errors") != []):
            raise ValueError("integrated lab case lacks exact native capture and readback")
        if row["case"] == "dlp_block":
            if (row.get("target_origin_requests") != 0
                    or row.get("target_origin_body_bytes") != 0
                    or row.get("non_warmup_wire_body_bytes_received") != 0
                    or row.get("non_warmup_body_counter_verified") is not True
                    or row.get("process_exit_code") != 76
                    or not any(item.get("target") is True and item.get("decision") == "deny"
                               and item.get("archive_readback_exact") is True
                               for item in requests)):
                raise ValueError("integrated lab deny case did not stop the target body")
        elif row.get("target_origin_requests") != 1 or row.get("target_origin_body_bytes", 0) <= 0:
            raise ValueError("integrated lab allow case did not reach the local origin")
    return {"dll": str(dll), "dll_sha256": dll_sha,
            "build_manifest_sha256": _hash(manifest_path),
            "lab_report": str(report_path), "lab_report_sha256": _hash(report_path),
            "synthetic_cases_validated": 4, "lab_only": True}


def _graceful_lab_artifacts(backend: Path, dll: Path, report_path: Path,
                            repeat_path: Path = DEFAULT_GRACEFUL_REPEAT_REPORT) -> dict:
    """Admit only the pinned same-PID HTTP/WSS graceful-denial lab result."""
    if (not dll.is_file() or not report_path.is_file() or not repeat_path.is_file()
            or _same_path(report_path, repeat_path)):
        raise ValueError("pinned graceful DLL or independent same-PID labs are unavailable")
    manifest_path = dll.parent / "build-manifest.json"
    manifest = _json(manifest_path)
    dll_sha = _hash(dll)
    manifest_sha = _hash(manifest_path)
    if (dll_sha != GRACEFUL_DLL_SHA256
            or manifest_sha != GRACEFUL_MANIFEST_SHA256
            or _hash(report_path) != GRACEFUL_LAB_REPORT_SHA256
            or _hash(repeat_path) != GRACEFUL_REPEAT_REPORT_SHA256):
        raise ValueError("graceful DLL or lab evidence differs from exact SHA pins")
    expected = manifest.get("backend")
    artifact = manifest.get("artifact")
    captures = manifest.get("capture_evidence")
    sources = manifest.get("sources_sha256")
    if (not isinstance(expected, dict) or not isinstance(artifact, dict)
            or not isinstance(captures, dict) or not isinstance(sources, dict)):
        raise ValueError("malformed graceful DLL manifest")
    if (manifest.get("schema") != GRACEFUL_BUILD_SCHEMA
            or manifest.get("lab_only") is not True
            or manifest.get("status") != "unvalidated_graceful_candidate_not_desktop_adapter"
            or manifest.get("deny_behavior") != "return_rust_error_candidate"
            or manifest.get("desktop_adapter_created") is not False
            or expected.get("sha256") != BACKEND_IMAGE_SHA256
            or expected.get("version") != BACKEND_VERSION
            or not _same_path(expected.get("path", ""), backend)
            or artifact.get("sha256") != dll_sha
            or not _same_path(artifact.get("path", ""), dll)
            or manifest.get("pins") != GRACEFUL_PINS
            or manifest.get("abi") != GRACEFUL_ABI
            or set(captures) != {"http", "wss"}):
        raise ValueError("graceful DLL manifest does not match the pinned backend")
    if _hash(backend) != BACKEND_IMAGE_SHA256:
        raise ValueError("live backend image differs from the graceful lab pin")
    if any(not isinstance(capture, dict)
           or capture.get("full_body_readback_exact") is not True
           or capture.get("observation_only") is not True
           or capture.get("decrypted_archive_verified") is not True
           or capture.get("collection_envelope_verified") is not True
           for capture in captures.values()):
        raise ValueError("graceful DLL capture evidence is incomplete")
    normalized_sources = ({name.replace("\\", "/"): digest
                           for name, digest in sources.items()}
                          if all(isinstance(name, str) for name in sources) else {})
    if (set(normalized_sources) != EXPECTED_SOURCES
            or any(not isinstance(digest, str)
                   or Path(name).is_absolute() or ".." in Path(name).parts
                   or not (ROOT / name).is_file() or _hash(ROOT / name) != digest
                   for name, digest in normalized_sources.items())):
        raise ValueError("graceful DLL source tree differs from its build manifest")
    if any(not (ROOT / name).is_file() or _hash(ROOT / name) != digest
           for name, digest in GRACEFUL_CONTROLLER_SOURCES.items()):
        raise ValueError("Python collection sources differ from graceful lab pins")

    report = _json(report_path)
    build = report.get("build")
    results = report.get("results")
    if (not isinstance(build, dict) or not isinstance(results, list)
            or len(results) != 2 or not all(isinstance(row, dict) for row in results)):
        raise ValueError("malformed graceful same-PID lab report")
    if (report.get("schema") != GRACEFUL_LAB_SCHEMA
            or report.get("backend_sha256") != BACKEND_IMAGE_SHA256
            or report.get("validated") is not True
            or report.get("synthetic_only") is not True
            or report.get("production_desktop_coverage_validated") is not False
            or report.get("collection_mode") != "shared_request_archive"
            or report.get("controller_sources_unchanged_during_lab") is not True
            or report.get("controller_sources_sha256") != GRACEFUL_CONTROLLER_SOURCES
            or build.get("sha256") != dll_sha
            or build.get("manifest_sha256") != manifest_sha
            or build.get("lab_only") is not True
            or build.get("deny_behavior") != "return_rust_error_candidate"
            or {row.get("transport") for row in results} != {"http", "wss"}):
        raise ValueError("graceful same-PID lab evidence does not match the DLL")
    for row in results:
        identity = row.get("identity")
        denied_turn = row.get("denied_turn_completion")
        requests = row.get("pipe_requests")
        if (not isinstance(identity, dict) or not isinstance(denied_turn, dict)
                or not isinstance(requests, list)
                or not all(isinstance(item, dict) for item in requests)):
            raise ValueError("malformed graceful lab transport evidence")
        denied = [item for item in requests if item.get("denied_marker") is True]
        followup = [item for item in requests if item.get("allowed_marker") is True]
        if (row.get("schema") != GRACEFUL_LAB_SCHEMA
                or row.get("dll_sha256") != dll_sha
                or row.get("backend_sha256") != BACKEND_IMAGE_SHA256
                or row.get("validated") is not True
                or row.get("synthetic_only") is not True
                or row.get("local_origin_only") is not True
                or row.get("codex_command_hooks_present") is not False
                or row.get("collection_mode") != "shared_request_archive"
                or row.get("target_trace_exact") is not True
                or row.get("shared_archive_layout_verified") is not True
                or row.get("all_request_archive_readback_exact") is not True
                or row.get("deny_origin_requests") != 0
                or row.get("deny_origin_body_bytes") != 0
                or row.get("deny_non_warmup_wire_body_bytes_received") != 0
                or row.get("denied_origin_requests_after_followup") != 0
                or denied_turn.get("status") != "failed"
                or row.get("post_deny_alive") is not True
                or row.get("post_deny_identity_stable") is not True
                or row.get("same_pid_for_followup") is not True
                or row.get("followup_origin_match") is not True
                or row.get("backend_alive_after_followup") is not True
                or not isinstance(row.get("repeat_denied_turn_completion"), dict)
                or row["repeat_denied_turn_completion"].get("status") != "failed"
                or row.get("repeat_deny_body_bytes_delta") != 0
                or row.get("repeat_same_pid") is not True
                or row.get("repeat_followup_origin_match") is not True
                or row.get("backend_alive_after_repeat") is not True
                or identity.get("mode") != "app-server"
                or identity.get("image_sha256") != BACKEND_IMAGE_SHA256
                or not isinstance(identity.get("pid"), int) or identity["pid"] < 1
                or not isinstance(identity.get("creation_filetime"), int)
                or identity["creation_filetime"] < 1
                or not denied or not followup
                or any(item.get("decision") != "deny" or item.get("action") != "BLOCK"
                       for item in denied)
                or any(item.get("decision") != "allow" for item in followup)
                or row.get("pipe_errors") != [] or row.get("errors") != []):
            raise ValueError("graceful lab lacks zero-egress and same-PID recovery proof")
    repeat = _json(repeat_path)
    repeat_build = repeat.get("build")
    repeat_results = repeat.get("results")
    if (not isinstance(repeat_build, dict) or not isinstance(repeat_results, list)
            or len(repeat_results) != 1
            or not all(isinstance(row, dict) for row in repeat_results)):
        raise ValueError("malformed independent graceful large-HTTP lab report")
    if (repeat.get("schema") != GRACEFUL_LAB_SCHEMA
            or repeat.get("backend_sha256") != BACKEND_IMAGE_SHA256
            or repeat.get("validated") is not True
            or repeat.get("synthetic_only") is not True
            or repeat.get("production_desktop_coverage_validated") is not False
            or repeat.get("collection_mode") != "shared_request_archive"
            or repeat.get("controller_sources_unchanged_during_lab") is not True
            or repeat.get("controller_sources_sha256") != GRACEFUL_CONTROLLER_SOURCES
            or repeat_build.get("sha256") != dll_sha
            or repeat_build.get("manifest_sha256") != manifest_sha
            or repeat_build.get("lab_only") is not True
            or repeat_build.get("deny_behavior") != "return_rust_error_candidate"
            or {row.get("transport") for row in repeat_results} != {"http"}):
        raise ValueError("independent graceful large-HTTP lab differs from pinned DLL")
    first_by_transport = {row["transport"]: row for row in results}
    for row in repeat_results:
        denied_turn = row.get("repeat_denied_turn_completion")
        identity = row.get("identity")
        requests = row.get("pipe_requests")
        first_identity = first_by_transport[row["transport"]]["identity"]
        if (not isinstance(denied_turn, dict) or not isinstance(identity, dict)
                or not isinstance(requests, list)
                or not all(isinstance(item, dict) for item in requests)
                or row.get("schema") != GRACEFUL_LAB_SCHEMA
                or row.get("dll_sha256") != dll_sha
                or row.get("backend_sha256") != BACKEND_IMAGE_SHA256
                or row.get("validated") is not True
                or row.get("synthetic_only") is not True
                or row.get("local_origin_only") is not True
                or row.get("codex_command_hooks_present") is not False
                or row.get("collection_mode") != "shared_request_archive"
                or row.get("target_trace_exact") is not True
                or row.get("all_request_archive_readback_exact") is not True
                or row.get("shared_archive_layout_verified") is not True
                or row.get("large_multi_item") is not True
                or not isinstance(row.get("denied_input_items"), int)
                or row["denied_input_items"] < 500
                or not any(item.get("denied_marker") is True
                           and isinstance(item.get("bytes"), int)
                           and item["bytes"] >= 900_000
                           and item.get("decision") == "deny"
                           for item in requests)
                or row.get("deny_origin_requests") != 0
                or row.get("deny_origin_body_bytes") != 0
                or row.get("deny_non_warmup_wire_body_bytes_received") != 0
                or row.get("denied_origin_requests_after_followup") != 0
                or row.get("post_deny_alive") is not True
                or row.get("post_deny_identity_stable") is not True
                or row.get("same_pid_for_followup") is not True
                or row.get("followup_origin_match") is not True
                or row.get("backend_alive_after_followup") is not True
                or denied_turn.get("status") != "failed"
                or row.get("repeat_deny_body_bytes_delta") != 0
                or row.get("repeat_same_pid") is not True
                or row.get("repeat_followup_origin_match") is not True
                or row.get("backend_alive_after_repeat") is not True
                or identity.get("mode") != "app-server"
                or identity.get("image_sha256") != BACKEND_IMAGE_SHA256
                or not isinstance(identity.get("pid"), int) or identity["pid"] < 1
                or not isinstance(identity.get("creation_filetime"), int)
                or identity["creation_filetime"] < 1
                or (identity["pid"], identity["creation_filetime"])
                   == (first_identity["pid"], first_identity["creation_filetime"])
                or row.get("pipe_errors") != [] or row.get("errors") != []):
            raise ValueError("graceful large-HTTP lab lacks zero-egress and same-PID recovery proof")
    return {"dll": str(dll), "dll_sha256": dll_sha,
            "build_manifest_sha256": manifest_sha,
            "lab_report": str(report_path), "lab_report_sha256": _hash(report_path),
            "repeat_lab_report": str(repeat_path),
            "repeat_lab_report_sha256": _hash(repeat_path),
            "synthetic_cases_validated": 3, "lab_only": True,
            "deny_behavior": "return_rust_error_candidate",
            "post_deny_same_pid_followup_verified": True,
            "shared_request_archive_verified": True,
            "large_http_request_verified": True,
            "controller_sources_sha256": dict(GRACEFUL_CONTROLLER_SOURCES)}


def _lease_lab_artifacts(backend: Path, dll: Path, report_path: Path,
                         repeat_path: Path = DEFAULT_LEASE_REPEAT_REPORT,
                         large_path: Path = DEFAULT_LEASE_LARGE_REPORT) -> dict:
    """Admit only one exact lease DLL and its lifecycle/content lab reports."""
    if (not dll.is_file() or not report_path.is_file()
            or not repeat_path.is_file() or not large_path.is_file()
            or len({report_path, repeat_path, large_path}) != 3):
        raise ValueError("pinned lease DLL or independent lab reports are unavailable")
    manifest_path = dll.parent / "build-manifest.json"
    if (_hash(dll) != LEASE_DLL_SHA256
            or _hash(manifest_path) != LEASE_MANIFEST_SHA256
            or _hash(report_path) != LEASE_LAB_REPORT_SHA256
            or _hash(repeat_path) != LEASE_REPEAT_REPORT_SHA256
            or _hash(large_path) != LEASE_LARGE_REPORT_SHA256):
        raise ValueError("lease DLL or lab evidence differs from exact SHA pins")
    manifest = _json(manifest_path)
    expected = manifest.get("backend")
    artifact = manifest.get("artifact")
    captures = manifest.get("capture_evidence")
    sources = manifest.get("sources_sha256")
    if (not isinstance(expected, dict) or not isinstance(artifact, dict)
            or not isinstance(captures, dict) or not isinstance(sources, dict)):
        raise ValueError("malformed lease DLL manifest")
    if (manifest.get("schema") != LEASE_BUILD_SCHEMA
            or manifest.get("lab_only") is not True
            or manifest.get("status") != "unvalidated_test_only_graceful_lease_candidate"
            or manifest.get("deny_behavior") != "return_rust_error_candidate"
            or manifest.get("controller_loss_behavior") != "bypass_and_disable_hooks"
            or manifest.get("desktop_adapter_created") is not False
            or expected.get("sha256") != BACKEND_IMAGE_SHA256
            or expected.get("version") != BACKEND_VERSION
            or not _same_path(expected.get("path", ""), backend)
            or artifact.get("sha256") != LEASE_DLL_SHA256
            or not _same_path(artifact.get("path", ""), dll)
            or manifest.get("pins") != GRACEFUL_PINS
            or manifest.get("abi") != GRACEFUL_ABI
            or manifest.get("lease") != {
                "mutex": "Local\\ttrace-guard-lease-<pid>-<creation_filetime>",
                "disabled_event": "Local\\ttrace-guard-disabled-<pid>-<creation_filetime>",
                "owner": "controller_main_thread", "dll_stays_mapped": True}
            or set(captures) != {"http", "wss"}
            or _hash(backend) != BACKEND_IMAGE_SHA256):
        raise ValueError("lease DLL manifest does not match the pinned backend")
    if any(not isinstance(item, dict)
           or item.get("full_body_readback_exact") is not True
           or item.get("observation_only") is not True
           or item.get("decrypted_archive_verified") is not True
           or item.get("collection_envelope_verified") is not True
           for item in captures.values()):
        raise ValueError("lease DLL capture evidence is incomplete")
    normalized_sources = ({name.replace("\\", "/"): digest
                           for name, digest in sources.items()}
                          if all(isinstance(name, str) for name in sources) else {})
    if (set(normalized_sources) != EXPECTED_SOURCES
            or any(not isinstance(digest, str)
                   or Path(name).is_absolute() or ".." in Path(name).parts
                   or not (ROOT / name).is_file() or _hash(ROOT / name) != digest
                   for name, digest in normalized_sources.items())):
        raise ValueError("lease DLL source tree differs from its build manifest")
    report = _json(report_path)
    build = report.get("build")
    results = report.get("results")
    lease_source = hashlib.sha256(
        inspect.getsource(_ControllerLease).encode("utf-8")).hexdigest()
    if (not isinstance(build, dict) or not isinstance(results, list)
            or len(results) != 4 or not all(isinstance(row, dict) for row in results)):
        raise ValueError("malformed lease lifecycle lab report")
    if (report.get("schema") != LEASE_LAB_SCHEMA
            or report.get("backend_sha256") != BACKEND_IMAGE_SHA256
            or report.get("validated") is not True
            or report.get("synthetic_only") is not True
            or report.get("production_desktop_coverage_validated") is not False
            or report.get("controller_sources_unchanged_during_lab") is not True
            or report.get("controller_sources_sha256") != GRACEFUL_CONTROLLER_SOURCES
            or report.get("controller_lease_class_sha256") != lease_source
            or build.get("dll_sha256") != LEASE_DLL_SHA256
            or build.get("manifest_sha256") != LEASE_MANIFEST_SHA256
            or build.get("controller_loss_behavior") != "bypass_and_disable_hooks"
            or build.get("lab_only") is not True
            or {(row.get("transport"), row.get("loss")) for row in results} != {
                ("http", "release"), ("http", "abandon"),
                ("wss", "release"), ("wss", "abandon")}):
        raise ValueError("lease lifecycle report differs from pinned build or controller")
    if any(_hash(ROOT / name) != digest
           for name, digest in GRACEFUL_CONTROLLER_SOURCES.items()):
        raise ValueError("Python collection sources differ from lease lab")
    identities = []
    for row in results:
        identity = row.get("identity")
        if not isinstance(identity, dict):
            raise ValueError("malformed lease lab process identity")
        identities.append((identity.get("pid"), identity.get("creation_filetime")))
        if (row.get("schema") != LEASE_LAB_SCHEMA
                or row.get("backend_sha256") != BACKEND_IMAGE_SHA256
                or row.get("dll_sha256") != LEASE_DLL_SHA256
                or row.get("validated") is not True
                or row.get("synthetic_only") is not True
                or row.get("local_origin_only") is not True
                or row.get("lab_only") is not True
                or row.get("production_desktop_coverage_validated") is not False
                or row.get("protected_denied") is not True
                or row.get("denied_archive_readback_exact") is not True
                or row.get("denied_turn_status") != "failed"
                or row.get("disabled_ack") is not True
                or row.get("post_lease_origin_match") is not True
                or row.get("no_post_lease_pipe_request") is not True
                or row.get("same_pid_after_lease") is not True
                or row.get("denied_origin_requests_after_lease") != 0
                or row.get("pipe_errors") != [] or row.get("errors") != []
                or identity.get("mode") != "app-server"
                or not isinstance(identity.get("pid"), int) or identity["pid"] < 1
                or not isinstance(identity.get("creation_filetime"), int)
                or identity["creation_filetime"] < 1):
            raise ValueError("lease lifecycle lab lacks zero-egress and safe teardown proof")
    if len(set(identities)) != 4:
        raise ValueError("lease lifecycle lab cases must use independent backend instances")
    for content_path, expected_transports, large_required in (
            (repeat_path, {"http", "wss"}, False),
            (large_path, {"http"}, True)):
        content = _json(content_path)
        build = content.get("build")
        cases = content.get("results")
        if (not isinstance(build, dict) or not isinstance(cases, list)
                or len(cases) != len(expected_transports)
                or not all(isinstance(case, dict) for case in cases)):
            raise ValueError("malformed lease content lab report")
        if (content.get("schema") != LEASE_CONTENT_LAB_SCHEMA
                or content.get("backend_sha256") != BACKEND_IMAGE_SHA256
                or content.get("validated") is not True
                or content.get("synthetic_only") is not True
                or content.get("production_desktop_coverage_validated") is not False
                or content.get("lease_mode") is not True
                or content.get("collection_mode") != "shared_request_archive"
                or content.get("controller_sources_unchanged_during_lab") is not True
                or content.get("controller_sources_sha256") != GRACEFUL_CONTROLLER_SOURCES
                or content.get("controller_lease_class_sha256") != lease_source
                or build.get("sha256") != LEASE_DLL_SHA256
                or build.get("manifest_sha256") != LEASE_MANIFEST_SHA256
                or build.get("lab_only") is not True
                or build.get("deny_behavior") != "return_rust_error_candidate"
                or build.get("lease_mode") is not True
                or {case.get("transport") for case in cases} != expected_transports):
            raise ValueError("lease content report differs from pinned build or controller")
        for case in cases:
            identity = case.get("identity")
            denied_turn = case.get("denied_turn_completion")
            repeat_turn = case.get("repeat_denied_turn_completion")
            requests = case.get("pipe_requests")
            if (not isinstance(identity, dict) or not isinstance(denied_turn, dict)
                    or not isinstance(repeat_turn, dict) or not isinstance(requests, list)
                    or not all(isinstance(item, dict) for item in requests)):
                raise ValueError("malformed lease content transport proof")
            denied = [item for item in requests if item.get("denied_marker") is True]
            allowed = [item for item in requests if item.get("allowed_marker") is True]
            if (case.get("schema") != LEASE_CONTENT_LAB_SCHEMA
                    or case.get("backend_sha256") != BACKEND_IMAGE_SHA256
                    or case.get("dll_sha256") != LEASE_DLL_SHA256
                    or case.get("validated") is not True
                    or case.get("synthetic_only") is not True
                    or case.get("local_origin_only") is not True
                    or case.get("lab_only") is not True
                    or case.get("production_desktop_coverage_validated") is not False
                    or case.get("codex_command_hooks_present") is not False
                    or case.get("lease_mode") is not True
                    or case.get("lease_released") is not True
                    or case.get("lease_disabled_ack") is not True
                    or case.get("lease_cleanup_error") is not None
                    or case.get("collection_mode") != "shared_request_archive"
                    or case.get("large_multi_item") is not large_required
                    or case.get("target_trace_exact") is not True
                    or case.get("all_request_archive_readback_exact") is not True
                    or case.get("shared_archive_layout_verified") is not True
                    or case.get("deny_origin_requests") != 0
                    or case.get("deny_origin_body_bytes") != 0
                    or case.get("deny_non_warmup_wire_body_bytes_received") != 0
                    or case.get("denied_origin_requests_after_followup") != 0
                    or denied_turn.get("status") != "failed"
                    or repeat_turn.get("status") != "failed"
                    or case.get("post_deny_alive") is not True
                    or case.get("post_deny_identity_stable") is not True
                    or case.get("same_pid_for_followup") is not True
                    or case.get("followup_origin_match") is not True
                    or case.get("backend_alive_after_followup") is not True
                    or case.get("repeat_deny_body_bytes_delta") != 0
                    or case.get("repeat_same_pid") is not True
                    or case.get("repeat_followup_origin_match") is not True
                    or case.get("backend_alive_after_repeat") is not True
                    or case.get("pipe_errors") != [] or case.get("errors") != []
                    or identity.get("mode") != "app-server"
                    or identity.get("image_sha256") != BACKEND_IMAGE_SHA256
                    or not isinstance(identity.get("pid"), int) or identity["pid"] < 1
                    or not isinstance(identity.get("creation_filetime"), int)
                    or identity["creation_filetime"] < 1
                    or not denied or not allowed
                    or any(item.get("decision") != "deny" or item.get("action") != "BLOCK"
                           for item in denied)
                    or any(item.get("decision") != "allow" for item in allowed)):
                raise ValueError("lease content lab lacks zero-egress and recovery proof")
            if large_required and (case.get("denied_input_items", 0) < 500
                                   or not any(item.get("bytes") == 950001 for item in denied)):
                raise ValueError("lease large-request proof is incomplete")
            identities.append((identity["pid"], identity["creation_filetime"]))
    if len(set(identities)) != 7:
        raise ValueError("lease lab cases must use independent backend instances")
    return {"dll": str(dll), "dll_sha256": LEASE_DLL_SHA256,
            "build_manifest_sha256": LEASE_MANIFEST_SHA256,
            "lab_report": str(report_path),
            "lab_report_sha256": LEASE_LAB_REPORT_SHA256,
            "repeat_lab_report": str(repeat_path),
            "repeat_lab_report_sha256": LEASE_REPEAT_REPORT_SHA256,
            "large_lab_report": str(large_path),
            "large_lab_report_sha256": LEASE_LARGE_REPORT_SHA256,
            "lab_only": True, "synthetic_cases_validated": 7,
            "safe_teardown_attested_in_lab": True,
            "integrated_model_guard_validated": True,
            "controller_loss_behavior": "bypass_and_disable_hooks"}


def _nonretry_lease_lab_artifacts(backend: Path, dll: Path, report_path: Path) -> dict:
    """Pin the distinct nonretry lease DLL and every isolated lab receipt."""
    manifest_path = dll.parent / "build-manifest.json"
    if (not dll.is_file() or not manifest_path.is_file() or not report_path.is_file()
            or _hash(dll) != NONRETRY_DLL_SHA256
            or _hash(manifest_path) != NONRETRY_MANIFEST_SHA256
            or _hash(report_path) != NONRETRY_REPORT_SHA256):
        raise ValueError("nonretry DLL, manifest or summary differs from exact SHA pins")
    manifest = _json(manifest_path)
    summary = _json(report_path)
    expected = manifest.get("backend")
    artifact = manifest.get("artifact")
    captures = manifest.get("capture_evidence")
    sources = manifest.get("sources_sha256")
    if (not isinstance(expected, dict) or not isinstance(artifact, dict)
            or not isinstance(captures, dict) or not isinstance(sources, dict)):
        raise ValueError("malformed nonretry build manifest")
    normalized_sources = ({name.replace("\\", "/"): digest
                           for name, digest in sources.items()}
                          if all(isinstance(name, str) for name in sources) else {})
    if (manifest.get("schema") != NONRETRY_BUILD_SCHEMA
            or manifest.get("lab_only") is not True
            or manifest.get("status") != "unvalidated_nonretry_candidate_not_desktop_adapter"
            or manifest.get("desktop_adapter_created") is not False
            or expected.get("version") != BACKEND_VERSION
            or expected.get("sha256") != BACKEND_IMAGE_SHA256
            or not _same_path(expected.get("path", ""), backend)
            or artifact.get("sha256") != NONRETRY_DLL_SHA256
            or not _same_path(artifact.get("path", ""), dll)
            or manifest.get("pins") != NONRETRY_PINS
            or manifest.get("abi") != NONRETRY_ABI
            or set(captures) != {"http", "wss"}
            or any(not isinstance(item, dict)
                   or item.get("full_body_readback_exact") is not True
                   or item.get("observation_only") is not True
                   or item.get("decrypted_archive_verified") is not True
                   or item.get("collection_envelope_verified") is not True
                   for item in captures.values())
            or _hash(backend) != BACKEND_IMAGE_SHA256):
        raise ValueError("nonretry build does not match the pinned backend and ABI")
    if (set(normalized_sources) != EXPECTED_SOURCES
            or any(not isinstance(digest, str) or Path(name).is_absolute()
                   or ".." in Path(name).parts or not (ROOT / name).is_file()
                   or _hash(ROOT / name) != digest
                   for name, digest in normalized_sources.items())):
        raise ValueError("nonretry Native source tree differs from its build manifest")
    summary_sources = summary.get("source_sha256_at_build_and_summary")
    controller_sources = summary.get("controller_implementation_sha256_at_summary")
    lease_source = hashlib.sha256(
        inspect.getsource(_ControllerLease).encode("utf-8")).hexdigest()
    if (summary.get("schema") != NONRETRY_VALIDATION_SCHEMA
            or summary.get("validated") is not True
            or summary.get("production_desktop_coverage_validated") is not False
            or summary.get("live_desktop_injected") is not False
            or not isinstance(summary.get("backend"), dict)
            or summary["backend"].get("sha256") != BACKEND_IMAGE_SHA256
            or not _same_path(summary["backend"].get("path", ""), backend)
            or not isinstance(summary.get("dll"), dict)
            or summary["dll"].get("sha256") != NONRETRY_DLL_SHA256
            or not _same_path(summary["dll"].get("path", ""), dll)
            or not isinstance(summary.get("build_manifest"), dict)
            or summary["build_manifest"].get("sha256") != NONRETRY_MANIFEST_SHA256
            or not _same_path(summary["build_manifest"].get("path", ""), manifest_path)
            or summary_sources != sources
            or summary.get("controller_lease_class_sha256_at_summary") != lease_source
            or not isinstance(controller_sources, dict)
            or any(controller_sources.get(name) != digest
                   or _hash(ROOT / name) != digest
                   for name, digest in GRACEFUL_CONTROLLER_SOURCES.items())
            or summary.get("retry_config") != {"request_max_retries": 2,
                                                "stream_max_retries": 2}
            or summary.get("denied_turns_per_deep_case") != 2
            or summary.get("mapper_output") !=
            "CodexErr::InvalidPrompt (0x8000000000000012)"):
        raise ValueError("nonretry validation summary differs from pinned build or controller")
    # The summary records the whole controller file at lab time. This gate
    # itself changes that file, so the stable attested unit is the lease class.
    evidence = summary.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != set(NONRETRY_EVIDENCE):
        raise ValueError("nonretry validation evidence is incomplete")
    rows = {}
    for name, relative in NONRETRY_EVIDENCE.items():
        item = evidence[name]
        path = NONRETRY_EVIDENCE_ROOT / relative
        if (not isinstance(item, dict) or not _same_path(item.get("path", ""), path)
                or not isinstance(item.get("sha256"), str)
                or not path.is_file() or _hash(path) != item["sha256"]):
            raise ValueError(f"nonretry evidence hash or path drift: {name}")
        rows[name] = _json(path)
    identities = set()
    for transport in ("http", "wss"):
        for loss in ("release", "abandon"):
            row = rows[f"lease_{transport}-{loss}"]
            identity = row.get("identity")
            if (row.get("schema") != LEASE_LAB_SCHEMA
                    or row.get("transport") != transport or row.get("loss") != loss
                    or row.get("backend_sha256") != BACKEND_IMAGE_SHA256
                    or row.get("dll_sha256") != NONRETRY_DLL_SHA256
                    or row.get("validated") is not True
                    or row.get("synthetic_only") is not True
                    or row.get("local_origin_only") is not True
                    or row.get("lab_only") is not True
                    or row.get("production_desktop_coverage_validated") is not False
                    or row.get("protected_denied") is not True
                    or row.get("denied_archive_readback_exact") is not True
                    or row.get("denied_turn_status") != "failed"
                    or row.get("disabled_ack") is not True
                    or row.get("post_lease_origin_match") is not True
                    or row.get("no_post_lease_pipe_request") is not True
                    or row.get("same_pid_after_lease") is not True
                    or row.get("denied_origin_requests_after_lease") != 0
                    or row.get("pipe_errors") != [] or row.get("errors") != []
                    or not isinstance(identity, dict)
                    or identity.get("mode") != "app-server"
                    or not isinstance(identity.get("pid"), int)
                    or not isinstance(identity.get("creation_filetime"), int)):
                raise ValueError("nonretry lease lifecycle proof is incomplete")
            identities.add((identity["pid"], identity["creation_filetime"]))
    for case, transport, large in (("http-small", "http", False),
                                   ("wss-small", "wss", False),
                                   ("http-large", "http", True)):
        row = rows[f"deep_{case}"]
        identity = row.get("identity")
        requests = row.get("pipe_requests")
        trace = row.get("target_trace")
        if (not isinstance(identity, dict) or not isinstance(requests, list)
                or not isinstance(trace, list) or len(trace) != 2
                or not all(isinstance(item, dict) for item in requests + trace)):
            raise ValueError("malformed nonretry deep content proof")
        denied = [item for item in requests if item.get("denied_marker") is True]
        allowed = [item for item in requests if item.get("allowed_marker") is True]
        denied_bytes = [item.get("bytes") for item in denied]
        if (row.get("schema") != LEASE_CONTENT_LAB_SCHEMA
                or row.get("transport") != transport
                or row.get("backend_sha256") != BACKEND_IMAGE_SHA256
                or row.get("dll_sha256") != NONRETRY_DLL_SHA256
                or row.get("validated") is not True
                or row.get("synthetic_only") is not True
                or row.get("local_origin_only") is not True
                or row.get("lab_only") is not True
                or row.get("production_desktop_coverage_validated") is not False
                or row.get("codex_command_hooks_present") is not False
                or row.get("lease_mode") is not True
                or row.get("lease_released") is not True
                or row.get("lease_disabled_ack") is not True
                or row.get("lease_cleanup_error") is not None
                or row.get("collection_mode") != "shared_request_archive"
                or row.get("large_multi_item") is not large
                or row.get("target_trace_exact") is not True
                or row.get("all_request_archive_readback_exact") is not True
                or row.get("shared_archive_layout_verified") is not True
                or row.get("deny_origin_requests") != 0
                or row.get("deny_origin_body_bytes") != 0
                or row.get("deny_non_warmup_wire_body_bytes_received") != 0
                or row.get("denied_origin_requests_after_followup") != 0
                or row.get("denied_turn_completion", {}).get("status") != "failed"
                or row.get("repeat_denied_turn_completion", {}).get("status") != "failed"
                or row.get("post_deny_alive") is not True
                or row.get("post_deny_identity_stable") is not True
                or row.get("same_pid_for_followup") is not True
                or row.get("followup_origin_match") is not True
                or row.get("backend_alive_after_followup") is not True
                or row.get("repeat_deny_body_bytes_delta") != 0
                or row.get("repeat_same_pid") is not True
                or row.get("repeat_followup_origin_match") is not True
                or row.get("backend_alive_after_repeat") is not True
                or row.get("pipe_errors") != [] or row.get("errors") != []
                or identity.get("mode") != "app-server"
                or identity.get("image_sha256") != BACKEND_IMAGE_SHA256
                or not isinstance(identity.get("pid"), int)
                or not isinstance(identity.get("creation_filetime"), int)
                or len(denied) != 2 or not allowed
                or [item.get("bytes") for item in trace] != denied_bytes
                or [item.get("sha256") for item in trace] !=
                [item.get("sha256") for item in denied]
                or any(item.get("decision") != "deny" or item.get("action") != "BLOCK"
                       or item.get("archive_readback_exact") is not True
                       or item.get("protocol") != transport for item in denied)
                or any(item.get("decision") != "allow"
                       or item.get("archive_readback_exact") is not True
                       for item in allowed)
                or evidence[f"deep_{case}"].get("denied_requests_for_two_turns") != 2
                or evidence[f"deep_{case}"].get("denied_body_bytes") != denied_bytes):
            raise ValueError("nonretry content or no-retry proof is incomplete")
        if large and (row.get("denied_input_items", 0) < 500
                      or denied_bytes != [950001, 950001]):
            raise ValueError("nonretry 950 KB request proof is incomplete")
        identities.add((identity["pid"], identity["creation_filetime"]))
    for transport, input_tag in (("http", 10), ("wss", 25)):
        row = rows[f"mapper_{transport}"]
        events = row.get("events")
        completions = row.get("completions")
        lease_result = row.get("lease_result")
        if (row.get("synthetic_only") is not True
                or row.get("local_origin_only") is not True
                or row.get("candidate_map_rva") != "0x3fff370"
                or not isinstance(events, list) or not isinstance(completions, list)
                or not isinstance(lease_result, dict)
                or not any(item.get("where") == "api_error_map_entry"
                           and item.get("tag") == str(input_tag)
                           for item in events if isinstance(item, dict))
                or not any(item.get("where") == "api_error_map_return"
                           and item.get("output_tag") == "9223372036854775826"
                           for item in events if isinstance(item, dict))
                or len(completions) != 2
                or any(not isinstance(item, dict) or item.get("status") != "failed"
                       for item in completions)
                or lease_result.get("dll_sha256") != NONRETRY_DLL_SHA256
                or lease_result.get("disabled_ack") is not True
                or lease_result.get("protected_denied") is not True
                or evidence[f"mapper_{transport}"].get("input_tag") != input_tag
                or evidence[f"mapper_{transport}"].get("output_tag") !=
                "9223372036854775826"):
            raise ValueError("nonretry invalid-prompt mapper proof is incomplete")
        identity = lease_result.get("identity", {})
        if (not isinstance(identity, dict) or not isinstance(identity.get("pid"), int)
                or not isinstance(identity.get("creation_filetime"), int)):
            raise ValueError("nonretry mapper process identity is incomplete")
        identities.add((identity["pid"], identity["creation_filetime"]))
    success = rows["successful_http_followup"]
    success_case = success.get("report")
    before = success.get("source_sha256_before")
    after = success.get("source_sha256_after")
    if (success.get("schema") != "transpect.guard.nonretry-success-http-lab/1.0"
            or success.get("validated") is not True
            or success.get("synthetic_only") is not True
            or success.get("local_origin_only") is not True
            or success.get("live_desktop_injected") is not False
            or success.get("retry_config") != {"request_max_retries": 2,
                                               "stream_max_retries": 2}
            or not isinstance(before, dict) or before != after
            or before.get("guard.c") != normalized_sources["native/guard/guard.c"]
            or before.get("controller_lease_class") != lease_source
            or any(before.get(name) != digest
                   for name, digest in GRACEFUL_CONTROLLER_SOURCES.items())
            or not isinstance(success_case, dict)
            or success_case.get("schema") != LEASE_CONTENT_LAB_SCHEMA
            or success_case.get("transport") != "http"
            or success_case.get("backend_sha256") != BACKEND_IMAGE_SHA256
            or success_case.get("dll_sha256") != NONRETRY_DLL_SHA256
            or success_case.get("validated") is not True
            or success_case.get("synthetic_only") is not True
            or success_case.get("local_origin_only") is not True
            or success_case.get("lab_only") is not True
            or success_case.get("production_desktop_coverage_validated") is not False
            or success_case.get("lease_mode") is not True
            or success_case.get("lease_released") is not True
            or success_case.get("lease_disabled_ack") is not True
            or success_case.get("lease_cleanup_error") is not None
            or success_case.get("collection_mode") != "shared_request_archive"
            or success_case.get("target_trace_exact") is not True
            or success_case.get("all_request_archive_readback_exact") is not True
            or success_case.get("shared_archive_layout_verified") is not True
            or success_case.get("deny_origin_requests") != 0
            or success_case.get("deny_origin_body_bytes") != 0
            or success_case.get("deny_non_warmup_wire_body_bytes_received") != 0
            or success_case.get("denied_origin_requests_after_followup") != 0
            or success_case.get("post_deny_alive") is not True
            or success_case.get("post_deny_identity_stable") is not True
            or success_case.get("same_pid_for_followup") is not True
            or success_case.get("followup_origin_match") is not True
            or success_case.get("backend_alive_after_followup") is not True
            or success_case.get("repeat_deny_body_bytes_delta") != 0
            or success_case.get("repeat_same_pid") is not True
            or success_case.get("repeat_followup_origin_match") is not True
            or success_case.get("backend_alive_after_repeat") is not True
            or success_case.get("pipe_errors") != [] or success_case.get("errors") != []
            or success_case.get("denied_turn_completion", {}).get("status") != "failed"
            or success_case.get("repeat_denied_turn_completion", {}).get("status") != "failed"
            or success_case.get("followup_turn_completion", {}).get("status") != "completed"
            or success_case.get("repeat_followup_turn_completion", {}).get("status") != "completed"
            or evidence["successful_http_followup"].get("denied_requests_for_two_turns") != 2
            or evidence["successful_http_followup"].get("completed_benign_turns") != 2):
        raise ValueError("nonretry successful benign HTTP follow-up proof is incomplete")
    requests = success_case.get("pipe_requests")
    origin = success_case.get("origin")
    identity = success_case.get("identity")
    if (not isinstance(requests, list) or not isinstance(origin, list)
            or not isinstance(identity, dict)
            or not all(isinstance(item, dict) for item in requests + origin)
            or identity.get("mode") != "app-server"
            or identity.get("image_sha256") != BACKEND_IMAGE_SHA256
            or not isinstance(identity.get("pid"), int)
            or not isinstance(identity.get("creation_filetime"), int)):
        raise ValueError("malformed nonretry successful HTTP proof")
    denied = [item for item in requests if item.get("denied_marker") is True]
    allowed = [item for item in requests if item.get("allowed_marker") is True]
    if (len(denied) != 2 or len(allowed) < 2 or len(origin) != 2
            or any(item.get("decision") != "deny" or item.get("action") != "BLOCK"
                   or item.get("archive_readback_exact") is not True for item in denied)
            or any(item.get("decision") != "allow"
                   or item.get("archive_readback_exact") is not True for item in allowed)
            or any(item.get("complete") is not True or item.get("target") is not False
                   or item.get("http_body_bytes_received", 0) <= 0 for item in origin)
            or {item.get("sha256") for item in origin} -
            {item.get("sha256") for item in allowed}):
        raise ValueError("nonretry successful HTTP origin proof is incomplete")
    identities.add((identity["pid"], identity["creation_filetime"]))
    if len(identities) != 10:
        raise ValueError("nonretry lab cases must use ten independent backend instances")
    return {"dll": str(dll), "dll_sha256": NONRETRY_DLL_SHA256,
            "build_manifest_sha256": NONRETRY_MANIFEST_SHA256,
            "lab_report": str(report_path), "lab_report_sha256": NONRETRY_REPORT_SHA256,
            "synthetic_cases_validated": 10, "lab_only": True,
            "safe_teardown_attested_in_lab": True,
            "no_retry_attested_in_lab": True,
            "benign_http_completion_attested_in_lab": True,
            "integrated_model_guard_validated": True,
            "desktop_frontend_rendering_validated": False,
            "controller_loss_behavior": "bypass_and_disable_hooks"}


def _candidate_pids() -> list[int]:
    command = ("$rows=@(Get-CimInstance Win32_Process -Filter \"Name='codex.exe'\" | "
               "Select-Object -ExpandProperty ProcessId); "
               "ConvertTo-Json -InputObject $rows -Compress")
    response = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=15, check=False)
    if response.returncode:
        raise ValueError("cannot enumerate Codex backend PIDs")
    value = json.loads(response.stdout or "[]")
    if isinstance(value, int):
        value = [value]
    if not isinstance(value, list) or len(value) > 32 or any(
            not isinstance(item, int) or item < 1 for item in value):
        raise ValueError("ambiguous Codex backend process inventory")
    return sorted(set(value))


def _subject(pid: int | None) -> dict:
    if pid is not None:
        return collect_desktop_observation_identity(pid)
    candidates = []
    for candidate in _candidate_pids():
        try:
            candidates.append(collect_desktop_observation_identity(candidate))
        except (OSError, RuntimeError, ValueError):
            continue
    if len(candidates) != 1:
        raise ValueError(f"expected one pinned desktop app-server; found {len(candidates)}")
    return candidates[0]


def _resident_guard(pid: int) -> bool:
    return any(ntpath.basename(row["path"]).lower().startswith("ttrace-guard")
               and ntpath.basename(row["path"]).lower().endswith(".dll")
               for row in modules(pid))


def _lease_disabled_event_signaled(pid: int, creation_filetime: int) -> bool:
    """Read-only proof that this exact backend's lease hooks were disabled."""
    kernel = api()
    name = f"Local\\ttrace-guard-disabled-{pid}-{creation_filetime}"
    event = kernel.OpenEventW(0x100000, False, name)
    if not event:
        return False
    try:
        outcome = kernel.WaitForSingleObject(event, 0)
        if outcome == 0:
            return True
        if outcome == 258:
            return False
        raise c.WinError(c.get_last_error())
    finally:
        kernel.CloseHandle(event)


def _command_hooks_present() -> bool:
    # This Demo must not be confounded by command hooks in the default home.
    return (Path.home() / ".codex" / "hooks.json").is_file()


def _guard_config(guard: str, dll: Path | None,
                  lab_report: Path | None) -> tuple[Path, Path, object]:
    if guard == "failstop":
        return (dll or DEFAULT_DLL, lab_report or DEFAULT_LAB_REPORT,
                _lab_artifacts)
    if guard == "graceful":
        return (dll or DEFAULT_GRACEFUL_DLL,
                lab_report or DEFAULT_GRACEFUL_LAB_REPORT,
                _graceful_lab_artifacts)
    if guard == "graceful_lease":
        return (dll or DEFAULT_LEASE_DLL,
                lab_report or DEFAULT_LEASE_LAB_REPORT,
                _lease_lab_artifacts)
    if guard == "nonretry_lease":
        return (dll or DEFAULT_NONRETRY_DLL,
                lab_report or DEFAULT_NONRETRY_REPORT,
                _nonretry_lease_lab_artifacts)
    raise ValueError("unknown desktop guard kind")


def _scope_thread_id(value: str | None, guard: str) -> str | None:
    if value is None:
        return None
    if guard not in ("graceful", "graceful_lease", "nonretry_lease"):
        raise ValueError("thread scope requires the graceful guard candidate")
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("protect-thread-id must be a UUID") from error


def _scope_description(thread_id: str | None) -> dict:
    return ({"kind": "thread", "thread_id": thread_id,
             "coverage": "partial_test_only"} if thread_id else
            {"kind": "shared_backend", "coverage": "unverified"})


def _collection_engine(config: GateConfig, guard: str) -> NativeCollectionEngine:
    # The graceful experiment durably archives the full serialized request
    # once and inspects all its items against that receipt. Hundreds of
    # per-item fsyncs exceeded the Native two-second decision deadline live.
    engine = NativeCollectionEngine(config, archive_full_body=True,
                                    shared_request_archive=(guard in (
                                        "graceful", "graceful_lease", "nonretry_lease")))
    # This current-version candidate alone opts in to parallel content checks.
    # The engine source is pinned by earlier isolated reports; keep it intact.
    engine.concurrent_safe = guard == "nonretry_lease"
    return engine


def status(pid: int | None = None, *, dll: Path | None = None,
           lab_report: Path | None = None, repeat_report: Path | None = None,
           large_report: Path | None = None, guard: str = "failstop",
           protect_thread_id: str | None = None) -> dict:
    """Read-only status; synthetic lab evidence is never live coverage proof."""
    scoped_thread = _scope_thread_id(protect_thread_id, guard)
    dll, lab_report, admit = _guard_config(guard, dll, lab_report)
    if guard not in ("graceful", "graceful_lease") and repeat_report is not None:
        raise ValueError("repeat report is only valid for graceful guards")
    if guard != "graceful_lease" and large_report is not None:
        raise ValueError("large report is only valid for the lease guard")
    result = {"schema": SCHEMA, "model_egress_status": MODEL_NOT_COVERED,
              "tool_egress_status": "NOT_ATTESTED", "live_guard_resident": None,
              "native_hooks_disabled_attested": None,
              "foreground_controller_active": False,
              "guard_kind": guard,
              "scope": _scope_description(scoped_thread),
              "target_request_observed": False if scoped_thread else None,
              "pinned_desktop_identity_verified": False,
              "synthetic_native_lab_validated": False,
              "codex_command_hooks_present": _command_hooks_present(),
              "ready_for_live_trial": False, "backend": None, "lab_gate": None,
              "gaps": []}
    try:
        subject = _subject(pid)
        result["pinned_desktop_identity_verified"] = True
        result["backend"] = {"pid": subject["pid"],
                             "creation_filetime": subject["creation_filetime"],
                             "image_sha256": subject["baseline"]["sha256"],
                             "version": subject["baseline"]["version"],
                             "desktop_pid": subject["desktop_pid"],
                             "package_full_name": subject["package_full_name"]}
        result["live_guard_resident"] = _resident_guard(subject["pid"])
        if guard in ("graceful_lease", "nonretry_lease") and result["live_guard_resident"]:
            result["native_hooks_disabled_attested"] = (
                _lease_disabled_event_signaled(
                    subject["pid"], subject["creation_filetime"]))
        backend = Path(subject["baseline"]["path"]).resolve(strict=True)
        if guard == "graceful":
            result["lab_gate"] = admit(
                backend, dll.resolve(), lab_report.resolve(),
                (repeat_report or DEFAULT_GRACEFUL_REPEAT_REPORT).resolve())
        elif guard == "graceful_lease":
            result["lab_gate"] = admit(
                backend, dll.resolve(), lab_report.resolve(),
                (repeat_report or DEFAULT_LEASE_REPEAT_REPORT).resolve(),
                (large_report or DEFAULT_LEASE_LARGE_REPORT).resolve())
        elif guard == "nonretry_lease":
            result["lab_gate"] = admit(backend, dll.resolve(), lab_report.resolve())
        else:
            result["lab_gate"] = admit(backend, dll.resolve(), lab_report.resolve())
        result["synthetic_native_lab_validated"] = (
            guard not in ("graceful_lease", "nonretry_lease")
            or result["lab_gate"].get("integrated_model_guard_validated") is True)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        result["gaps"].append(f"preflight_{type(error).__name__}: {error}")
    if result["codex_command_hooks_present"]:
        result["gaps"].append("codex_command_hooks_present")
    if result["live_guard_resident"] is True:
        result["gaps"].append("native_guard_already_resident_controller_unknown")
    if (guard in ("graceful_lease", "nonretry_lease") and result["lab_gate"] is not None
            and not result["synthetic_native_lab_validated"]):
        result["gaps"].append("lease_model_guard_lab_pending")
    result["trial_prerequisites_met"] = (
        result["pinned_desktop_identity_verified"]
        and result["synthetic_native_lab_validated"]
        and result["live_guard_resident"] is False
        and not result["codex_command_hooks_present"])
    if guard == "failstop":
        # This build intentionally exits the shared backend on a deny. The
        # live trial reproduced a user-visible GPT error.
        result["gaps"].append("fail_stop_build_exits_backend_on_deny")
        result["operational_note"] = (
            "The current fail-stop build terminates the backend on a deny and can "
            "cause a user-visible GPT error. Live trials are paused. After a desktop "
            "restart, the new backend has no active Native controller; model egress "
            "is not covered.")
    elif guard == "graceful_lease":
        result["operational_note"] = (
            "The pinned lease DLL passed seven isolated lifecycle, repeated denial, "
            "and large-request cases. It stays mapped but disables its Native hooks "
            "when the controller "
            "lease ends, leaving model egress uncovered. This test-only fail-open "
            "behavior has not been validated on the real desktop; live activation "
            "remains paused.")
    elif guard == "nonretry_lease":
        result["operational_note"] = (
            "The pinned nonretry lease DLL passed ten isolated lifecycle, content, "
            "large-request, error-mapper, and benign HTTP completion cases. Each of "
            "two denied turns produced one denied Native request in the synthetic labs. "
            "Desktop frontend rendering "
            "and real desktop coverage remain unverified. The DLL stays mapped, and "
            "model egress becomes uncovered when the controller lease ends. Live "
            "activation remains paused.")
    else:
        result["operational_note"] = (
            "Two synthetic local-origin labs verified HTTP and WSS denial with zero "
            "target egress and same-PID benign follow-ups. The DLL is lab-only; live "
            "desktop coverage is not attested. The live trial showed an app-level "
            "error, so activation is paused pending investigation.")
    if scoped_thread:
        result["operational_note"] += (
            " A scoped trial would inspect only the selected thread ID; all other "
            "or unidentifiable requests would pass through without content collection. "
            "This is partial test coverage, not a global protection claim.")
    if LIVE_TRIALS_PAUSED:
        result["gaps"].append("live_activation_paused_after_desktop_error")
    # Ready only when every prerequisite holds and no gap remains; the pause
    # itself is a gap, so a paused build can never report ready.
    result["ready_for_live_trial"] = bool(
        result["trial_prerequisites_met"] and not result["gaps"])
    return result


def _terminate_same_instance(pid: int, creation_filetime: int) -> bool:
    """Terminate only the exact generation after failed live activation."""
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.GetProcessTimes.argtypes = [w.HANDLE, c.POINTER(w.FILETIME), c.POINTER(w.FILETIME),
                                       c.POINTER(w.FILETIME), c.POINTER(w.FILETIME)]
    kernel.GetProcessTimes.restype = w.BOOL
    kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    kernel.TerminateProcess.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    handle = kernel.OpenProcess(0x1 | 0x400, False, pid)
    if not handle:
        return False
    try:
        times = [w.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *(c.byref(item) for item in times)):
            return False
        birth = times[0].dwLowDateTime + (times[0].dwHighDateTime << 32)
        return birth == creation_filetime and bool(kernel.TerminateProcess(handle, 76))
    finally:
        kernel.CloseHandle(handle)


class _BackendProcess:
    """Keep a handle to the exact backend generation through the trial."""

    def __init__(self, pid: int, creation_filetime: int):
        self.kernel = api()
        self.kernel.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
        self.kernel.GetExitCodeProcess.restype = w.BOOL
        self.handle = self.kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not self.handle:
            raise c.WinError(c.get_last_error())
        try:
            times = [w.FILETIME() for _ in range(4)]
            if not self.kernel.GetProcessTimes(
                    self.handle, *(c.byref(item) for item in times)):
                raise c.WinError(c.get_last_error())
            birth = times[0].dwLowDateTime + (times[0].dwHighDateTime << 32)
            if birth != creation_filetime or self.poll() is not None:
                raise ValueError("desktop backend generation changed before trial")
        except BaseException:
            self.close()
            raise

    def poll(self) -> int | None:
        outcome = self.kernel.WaitForSingleObject(self.handle, 0)
        if outcome == 258:
            return None
        if outcome != 0:
            raise c.WinError(c.get_last_error())
        code = w.DWORD()
        if not self.kernel.GetExitCodeProcess(self.handle, c.byref(code)):
            raise c.WinError(c.get_last_error())
        return code.value

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class _ControllerLease:
    """Own the exact backend generation's graceful test lease on this thread.

    The Native lease build checks this mutex before each policy call. Releasing
    it requests pass-through and hook disable; the disabled event is the only
    evidence that MinHook actually stopped intercepting the shared backend.
    """

    def __init__(self, pid: int, creation_filetime: int):
        if pid < 1 or creation_filetime < 1:
            raise ValueError("invalid backend generation for Native lease")
        self.kernel = api()
        self.kernel.CreateMutexW.argtypes = [c.c_void_p, w.BOOL, w.LPCWSTR]
        self.kernel.CreateMutexW.restype = w.HANDLE
        self.kernel.ReleaseMutex.argtypes = [w.HANDLE]
        self.kernel.ReleaseMutex.restype = w.BOOL
        self.lease_name = f"Local\\ttrace-guard-lease-{pid}-{creation_filetime}"
        self.disabled_name = f"Local\\ttrace-guard-disabled-{pid}-{creation_filetime}"
        self.owner_thread = threading.get_ident()
        self.released = False
        self.handle = self.kernel.CreateMutexW(None, True, self.lease_name)
        if not self.handle:
            raise c.WinError(c.get_last_error())
        if c.get_last_error() == 183:  # ERROR_ALREADY_EXISTS: initial owner ignored.
            self.kernel.CloseHandle(self.handle)
            self.handle = None
            raise ValueError("Native lease already exists for this backend generation")

    def release(self) -> None:
        if threading.get_ident() != self.owner_thread:
            raise RuntimeError("Native lease must be released by its owner thread")
        if self.handle and not self.released:
            if not self.kernel.ReleaseMutex(self.handle):
                raise c.WinError(c.get_last_error())
            self.released = True

    def wait_disabled(self, timeout_ms: int = 5000) -> bool:
        """Attest native hook disable after release, without unloading the DLL."""
        if not self.released or not 0 <= timeout_ms <= 30000:
            raise ValueError("release the Native lease before waiting for disable")
        deadline = time.monotonic() + timeout_ms / 1000
        event = None
        while event is None:
            event = self.kernel.OpenEventW(0x100000, False, self.disabled_name)
            if event or time.monotonic() >= deadline:
                break
            time.sleep(0.025)
        if not event:
            return False
        try:
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            outcome = self.kernel.WaitForSingleObject(event, remaining)
            if outcome == 0:
                return True
            if outcome == 258:  # WAIT_TIMEOUT
                return False
            raise c.WinError(c.get_last_error())
        finally:
            self.kernel.CloseHandle(event)

    def close(self) -> None:
        if self.handle:
            try:
                self.release()
            finally:
                self.kernel.CloseHandle(self.handle)
                self.handle = None


def _record_backend_exit(state: dict, pipe: PipeServer,
                         process: _BackendProcess) -> bool:
    """Classify only an observed exit, tied to a recorded model denial."""
    code = process.poll()
    if code is None:
        return False
    with pipe.lock:
        denied = sum(row.get("route_event") == "model.request"
                     and row.get("decision") == "deny"
                     for row in pipe.records)
    state["backend_exit_code"] = code
    state["recorded_model_denials"] = denied
    state["foreground_controller_active"] = False
    if (state.get("guard_kind", "failstop") == "failstop"
            and code == FAIL_STOP_EXIT_CODE and denied):
        state["state"] = "blocked_backend_exit"
        state["expected_backend_exit"] = True
        state["warning"] = (
            "The blocked backend exited. A restarted backend has no active Native "
            "controller; model egress remains uncovered.")
        state["operational_note"] = (
            "A recorded model request was denied and the fail-stop DLL exited this "
            "backend. The desktop may show a GPT error. This process is no longer "
            "protected; a restarted backend has no active Native controller.")
    else:
        state["state"] = "failed"
        state["warning"] = "The backend exited; there is no active Native controller."
        state["failure"] = (
            f"backend exited with code {code} without an attested fail-stop denial")
    return True


def _write_status(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    # A reader (status poller, indexer, antivirus) holding the target open
    # makes the Windows rename fail with access denied. That is transient and
    # must not end a running guard, so retry briefly before giving up.
    for attempt in range(40):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 39:
                raise
            time.sleep(0.05)


def run(pid: int, output: Path, *, dll: Path | None = None,
        lab_report: Path | None = None, repeat_report: Path | None = None,
        large_report: Path | None = None,
        guard: str = "failstop", seconds: int | None = 300,
        protect_thread_id: str | None = None) -> dict:
    """Run a pinned controller for a bounded trial or until STOP is requested.

    ``seconds=None`` is for a separately supervised controller. A finite
    duration remains the default for direct experiments. Neither mode bypasses
    the live activation gate or establishes complete desktop coverage.
    """
    if LIVE_TRIALS_PAUSED:
        raise ValueError("live desktop activation is paused after a user-visible app error")
    scoped_thread = _scope_thread_id(protect_thread_id, guard)
    if pid < 1 or (seconds is not None and not 1 <= seconds <= MAX_SECONDS):
        raise ValueError("invalid PID or duration")
    dll, lab_report, admit = _guard_config(guard, dll, lab_report)
    preflight = status(pid, dll=dll, lab_report=lab_report,
                       repeat_report=repeat_report, large_report=large_report,
                       guard=guard,
                       protect_thread_id=scoped_thread)
    if not preflight["ready_for_live_trial"]:
        raise ValueError("live desktop preflight failed: " + "; ".join(preflight["gaps"]))
    baseline = collect_desktop_observation_identity(pid)
    if (baseline["creation_filetime"] != preflight["backend"]["creation_filetime"]
            or baseline["desktop_pid"] != preflight["backend"]["desktop_pid"]):
        raise ValueError("desktop process instance changed after preflight")
    backend = Path(baseline["baseline"]["path"]).resolve(strict=True)
    dll = dll.resolve(strict=True)
    lab_report = lab_report.resolve(strict=True)
    if guard == "graceful":
        repeat_report = (repeat_report or DEFAULT_GRACEFUL_REPEAT_REPORT).resolve(strict=True)
    elif guard == "graceful_lease":
        repeat_report = (repeat_report or DEFAULT_LEASE_REPEAT_REPORT).resolve(strict=True)
        large_report = (large_report or DEFAULT_LEASE_LARGE_REPORT).resolve(strict=True)

    def recheck_artifacts() -> None:
        if guard == "graceful":
            admit(backend, dll, lab_report, repeat_report)
        elif guard == "graceful_lease":
            admit(backend, dll, lab_report, repeat_report, large_report)
        elif guard == "nonretry_lease":
            admit(backend, dll, lab_report)
        else:
            admit(backend, dll, lab_report)

    recheck_artifacts()
    if _resident_guard(pid) or _command_hooks_present():
        raise ValueError("a resident native guard or Codex command hooks confound this trial")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    config = GateConfig(mode="enforce", archive_directory=output / "archive",
                        audit_file=output / "audit.jsonl", registration_directory=None,
                        review_override_ttl_seconds=0,
                        collection_file=output / "collection.jsonl")
    engine = _collection_engine(config, guard)
    counts = {"http": 0, "wss": 0}
    counts_lock = threading.Lock()

    def request_tap(request) -> None:
        if request.kind == "model.request":
            with counts_lock:
                counts[request.protocol] = counts.get(request.protocol, 0) + 1

    pipe = PipeServer(pid, engine, output / "native-audit.jsonl",
                      request_tap=request_tap, client_sid=baseline["user_sid"],
                      target_thread_id=scoped_thread)
    controller = image_identity(os.getpid())
    state = {"schema": SCHEMA, "state": "starting", "guard_kind": guard,
             "scope": _scope_description(scoped_thread),
             "target_request_observed": False if scoped_thread else None,
             "model_egress_status": MODEL_NOT_COVERED,
             "pid": pid, "creation_filetime": baseline["creation_filetime"],
             "controller_pid": controller["pid"],
             "controller_creation_filetime": controller["creation_filetime"],
             "controller_image_sha256": controller["image_sha256"],
             "package_full_name": PACKAGE_FULL_NAME,
             "dll_sha256": _hash(dll), "native_ready": False,
             "pipe_ready": False, "live_model_requests_observed": 0,
             "foreground_controller_active": False,
             "dll_resident_after_stop": False,
             "warning": (
                 "A deny exits the backend and may cause a GPT error. "
                 "If the backend survives controller shutdown, the DLL stays resident; "
                 "restart Codex desktop before further use."
                 if guard == "failstop" else
                 "A controller-owned lease requests Native hook disable before the "
                 "policy pipe closes. The final status must attest the disabled event; "
                 "until then, desktop coverage remains unverified."
                 if guard in ("graceful_lease", "nonretry_lease") else
                 "The graceful DLL remains resident after controller shutdown. "
                 "Restart Codex desktop before further use; a lost controller can "
                 "make later model requests fail.")}

    def update_scope_state() -> None:
        snapshot = (pipe.scope_snapshot() if hasattr(pipe, "scope_snapshot") else
                    dict(getattr(pipe, "scope_counts", {})))
        state["scope_counts"] = snapshot
        if scoped_thread:
            state["target_request_observed"] = snapshot.get("target", 0) > 0

    def update_pipe_validation_state() -> None:
        state["pipe_validation"] = (pipe.validation_snapshot()
                                    if hasattr(pipe, "validation_snapshot") else
                                    {"count": 0, "recent": []})

    def update_decision_delivery_state() -> None:
        state["server_decision_delivery"] = (
            pipe.decision_delivery_snapshot()
            if hasattr(pipe, "decision_delivery_snapshot") else [])

    status_path = output / "status.json"
    _write_status(status_path, state)
    resolver_succeeded = False
    terminated_on_failure = False
    failure = None
    process = None
    lease = None
    began = time.monotonic()
    try:
        process = _BackendProcess(pid, baseline["creation_filetime"])
        pipe.start()
        # Re-read the DLL, manifest, both lab reports and source hashes
        # immediately before the native loader is allowed to run.
        recheck_artifacts()
        if guard in ("graceful_lease", "nonretry_lease"):
            # The DLL only enables its detours while this exact generation's
            # main-thread-owned mutex exists and is held. Never create it in
            # a helper thread: Windows mutex ownership is per thread.
            lease = _ControllerLease(pid, baseline["creation_filetime"])
        # The resolver runs inside inject just before opening the target. It
        # rechecks parent, SID, image hash, package and both creation times.
        def resolve(current_pid: int) -> dict:
            nonlocal resolver_succeeded
            actual = collect_desktop_observation_identity(current_pid)
            if not same_desktop_observation_subject(baseline, actual):
                raise ValueError("desktop process instance changed before injection")
            if not _same_path(actual["baseline"]["path"], backend):
                raise ValueError("desktop backend path changed before injection")
            resolver_succeeded = True
            return actual

        inject(pid, dll, baseline, identity_resolver=resolve)
        state["native_ready"] = wait_ready(baseline, timeout=15)
        state["pipe_ready"] = pipe.ready.wait(3)
        if not state["native_ready"] or not state["pipe_ready"]:
            raise RuntimeError("native guard failed to attest readiness after injection")
        state["state"] = "ready"
        state["foreground_controller_active"] = True
        _write_status(status_path, state)
        deadline = None if seconds is None else time.monotonic() + seconds
        next_identity_check = 0.0
        while (deadline is None or time.monotonic() < deadline) and not (output / "STOP").exists():
            if _record_backend_exit(state, pipe, process):
                break
            if pipe.errors:
                raise RuntimeError("native policy pipe reported an error")
            if time.monotonic() >= next_identity_check:
                try:
                    actual = collect_desktop_observation_identity(pid)
                except (OSError, RuntimeError, ValueError):
                    if _record_backend_exit(state, pipe, process):
                        break
                    raise
                if not same_desktop_observation_subject(baseline, actual):
                    raise RuntimeError("desktop backend identity changed during live trial")
                next_identity_check = time.monotonic() + 5
            with counts_lock:
                state["live_model_requests_observed"] = sum(counts.values())
            update_scope_state()
            update_pipe_validation_state()
            update_decision_delivery_state()
            _write_status(status_path, state)
            time.sleep(0.5)
        if state["state"] == "ready":
            state["state"] = "stopped"
    except KeyboardInterrupt:
        state["state"] = "stopped_by_operator"
        if (guard not in ("graceful_lease", "nonretry_lease") and resolver_succeeded
                and not (state["native_ready"] and state["pipe_ready"])):
            terminated_on_failure = _terminate_same_instance(
                pid, baseline["creation_filetime"])
    except Exception as error:
        if process is not None and _record_backend_exit(state, pipe, process):
            pass
        else:
            failure = f"{type(error).__name__}: {error}"
            state["state"] = "failed"
            state["failure"] = failure
        if (guard not in ("graceful_lease", "nonretry_lease") and resolver_succeeded
                and state["state"] == "failed"):
            # The resolver rejected case is non-destructive. Once accepted,
            # a remote LoadLibrary thread could be in flight even if module
            # enumeration has not observed it yet. Any activation or runtime
            # failure stops this exact generation before our pipe is closed.
            terminated_on_failure = _terminate_same_instance(
                pid, baseline["creation_filetime"])
    finally:
        state["foreground_controller_active"] = False
        update_scope_state()
        with counts_lock:
            state["live_model_requests_observed"] = sum(counts.values())
            state["native_requests_by_protocol"] = dict(counts)
        state["pipe_errors"] = list(pipe.errors)
        update_pipe_validation_state()
        update_decision_delivery_state()
        state["duration_seconds"] = round(time.monotonic() - began, 1)
        if lease is not None:
            # Release before closing the pipe. A lease-aware DLL switches to
            # pass-through and then acknowledges MinHook disable. Even when
            # the acknowledgement is unavailable, do not claim protection.
            try:
                lease.release()
                state["lease_released"] = True
                state["native_hooks_disabled_attested"] = lease.wait_disabled()
                state["warning"] = (
                    "Native hooks were disabled for this exact backend generation; "
                    "the DLL remains mapped and model egress is not covered."
                    if state["native_hooks_disabled_attested"] else
                    "Native lease was released, but hook disable was not attested. "
                    "Restart Codex desktop before further use.")
            except Exception as error:
                state["lease_cleanup_error"] = f"{type(error).__name__}: {error}"
                state["native_hooks_disabled_attested"] = False
                state["warning"] = (
                    "Native lease cleanup failed; restart Codex desktop before further use.")
            finally:
                try:
                    lease.close()
                except Exception as error:
                    state["lease_close_error"] = f"{type(error).__name__}: {error}"
        pipe.close()
        try:
            image = image_identity(pid)
            same = (image["creation_filetime"] == baseline["creation_filetime"]
                    and image["image_sha256"] == BACKEND_IMAGE_SHA256)
            state["dll_resident_after_stop"] = same and _resident_guard(pid)
        except (OSError, RuntimeError, ValueError):
            state["dll_resident_after_stop"] = False
        state["terminated_on_activation_failure"] = terminated_on_failure
        state["model_egress_status"] = MODEL_NOT_COVERED
        state["live_capture_coverage_attested"] = False
        _write_status(status_path, state)
        if process is not None:
            process.close()
    return state


def stop(output: Path) -> dict:
    """Request the matching foreground controller to stop; never unload DLL."""
    output = output.resolve(strict=True)
    current = _json(output / "status.json")
    controller_pid = current.get("controller_pid")
    controller_birth = current.get("controller_creation_filetime")
    controller_hash = current.get("controller_image_sha256")
    if (current.get("schema") != SCHEMA or current.get("state") != "ready"
            or not isinstance(controller_pid, int) or controller_pid < 1
            or not isinstance(controller_birth, int) or controller_birth < 1
            or not isinstance(controller_hash, str)):
        raise ValueError("no ready foreground desktop controller at this output")
    actual = image_identity(controller_pid)
    if (actual["creation_filetime"] != controller_birth
            or actual["image_sha256"] != controller_hash):
        raise ValueError("foreground controller process identity changed")
    signal = output / "STOP"
    already_requested = False
    try:
        with signal.open("x", encoding="ascii") as stream:
            stream.write("stop requested\n")
    except FileExistsError:
        already_requested = True
    except OSError as error:
        raise ValueError("cannot signal foreground controller") from error
    return {"schema": SCHEMA, "stop_requested": True,
            "already_requested": already_requested,
            "controller_pid": controller_pid, "backend_pid": current.get("pid"),
            "dll_unloaded": False, "model_egress_status": MODEL_NOT_COVERED,
            "warning": (
                "Lease release and Native hook disable are pending in the foreground "
                "controller; read its final status before using this backend."
                if current.get("guard_kind") in ("graceful_lease", "nonretry_lease") else
                "The DLL remains resident. Restart Codex desktop before using the backend again.")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("status", help="Read-only pinned desktop and lab evidence check")
    s.add_argument("--pid", type=int)
    s.add_argument("--guard", choices=("failstop", "graceful", "graceful_lease", "nonretry_lease"), default="failstop")
    s.add_argument("--dll", type=Path)
    s.add_argument("--lab-report", type=Path)
    s.add_argument("--repeat-report", type=Path)
    s.add_argument("--large-report", type=Path)
    s.add_argument("--protect-thread-id", help="Test-only UUID scope; graceful guards only")
    r = sub.add_parser("run", help="Explicit-PID foreground Native capture trial")
    r.add_argument("--pid", type=int, required=True)
    r.add_argument("--output", type=Path, required=True)
    duration = r.add_mutually_exclusive_group()
    duration.add_argument("--seconds", type=int)
    duration.add_argument("--until-stopped", action="store_true",
                          help="Keep the controller alive until STOP or backend exit")
    r.add_argument("--guard", choices=("failstop", "graceful", "graceful_lease", "nonretry_lease"), default="failstop")
    r.add_argument("--dll", type=Path)
    r.add_argument("--lab-report", type=Path)
    r.add_argument("--repeat-report", type=Path)
    r.add_argument("--large-report", type=Path)
    r.add_argument("--protect-thread-id", help="Test-only UUID scope; graceful guards only")
    x = sub.add_parser("stop", help="Signal a verified foreground controller")
    x.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "status":
        result = status(args.pid, dll=args.dll, lab_report=args.lab_report,
                        repeat_report=args.repeat_report, large_report=args.large_report,
                        guard=args.guard,
                        protect_thread_id=args.protect_thread_id)
        print(json.dumps(result, indent=2))
        return 0 if result["ready_for_live_trial"] else 2
    if args.command == "stop":
        print(json.dumps(stop(args.output), indent=2))
        return 0
    result = run(args.pid, args.output, dll=args.dll, lab_report=args.lab_report,
                 repeat_report=args.repeat_report, large_report=args.large_report,
                 guard=args.guard,
                 seconds=(None if args.until_stopped else
                          300 if args.seconds is None else args.seconds),
                 protect_thread_id=args.protect_thread_id)
    print(json.dumps(result, indent=2))
    return 0 if result["state"] in {"stopped", "stopped_by_operator",
                                   "blocked_backend_exit"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
