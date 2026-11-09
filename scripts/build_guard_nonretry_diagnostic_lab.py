"""Build a disposable, stage-telemetry variant of the pinned 0.167 Guard.

The frozen Native source and production candidate DLL are not modified. This
script copies that exact source, applies checked lab-only substitutions, and
compiles into a new output directory. Diagnostic outcome frames contain only
an enum describing the Native decision path, never prompt content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from _build_support import ROOT
from build_guard_nonretry_current_lab import (
    API_ERROR_MAP_PREFIX, API_ERROR_MAP_RVA, BACKEND_SHA256,
    DROP_HEADERS_PREFIX, DROP_HEADERS_RVA, HTTP_PREFIX, HTTP_RVA,
    WSS_PREFIX, WSS_RVA, _check_backend, _default_backend,
    _prefix_define,
)
from desktop_demo import DEFAULT_NONRETRY_DLL, NONRETRY_DLL_SHA256


SCHEMA = "transpect.guard.nonretry-diagnostic-lab-build/1.0"
PINNED_SOURCE_SHA256 = "319ca930377b72204c183467cfe376acf5fc2e3e06b0cea6c370e3a4c8b02f85"
STAGES = ("io_failed", "deadline_expired", "reply_shape_invalid",
          "reply_fields_invalid", "parsed_allow", "parsed_deny")


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def diagnostic_source(source: str) -> str:
    """Apply exact, single-occurrence substitutions to the frozen C source."""
    replacements = [
        (
            "static _Thread_local long long outcome_qpc;",
            "static _Thread_local long long outcome_qpc;\n"
            "static _Thread_local const char *last_policy_stage;\n"
            "static _Thread_local const char *outcome_stage;",
        ),
        (
            '        strcpy(last_request_id,request_id);outcome_parent[0]=0;outcome_action=NULL;',
            '        strcpy(last_request_id,request_id);outcome_parent[0]=0;outcome_action=NULL;\n'
            '        last_policy_stage="io_failed";',
        ),
        (
            r'\"outcome_captured_qpc\":%lld,\"payload_utf8\":',
            r'\"outcome_captured_qpc\":%lld,\"diagnostic_stage\":\"%s\",\"payload_utf8\":',
        ),
        (
            'frequency.QuadPart,outcome_parent,outcome_action?outcome_action:"none",outcome_qpc);',
            'frequency.QuadPart,outcome_parent,outcome_action?outcome_action:"none",outcome_qpc,\n'
            '        outcome_stage?outcome_stage:"");',
        ),
        (
            '            if (GetTickCount64() < deadline && decision_shape(reply, reply_length, tokens, count) &&',
            '            int deadline_ok = GetTickCount64() < deadline;\n'
            '            int shape_ok = decision_shape(reply, reply_length, tokens, count);\n'
            '            if (!deadline_ok) last_policy_stage="deadline_expired";\n'
            '            else if (!shape_ok) last_policy_stage="reply_shape_invalid";\n'
            '            else last_policy_stage="reply_fields_invalid";\n'
            '            if (deadline_ok && shape_ok &&',
        ),
        (
            'if (!strcmp(decision, "allow") && !strcmp(requested_action, "none")) action = 0;',
            'if (!strcmp(decision, "allow") && !strcmp(requested_action, "none")) '\
            '{ action = 0; last_policy_stage="parsed_allow"; }',
        ),
        (
            'else if (!strcmp(decision, "deny")) {',
            'else if (!strcmp(decision, "deny")) {\n'
            '                    last_policy_stage="parsed_deny";',
        ),
        (
            'typedef struct { char parent[64]; int action; long long qpc; } Outcome;',
            'typedef struct { char parent[64]; int action; long long qpc; char stage[48]; } Outcome;',
        ),
        (
            '    outcome_action=result->action==2?"block_session":"block_request";',
            '    outcome_action=result->action==0?"none":result->action==2?"block_session":"block_request";\n'
            '    outcome_stage=result->stage;',
        ),
        (
            '    outcome_parent[0]=0;outcome_action=NULL;outcome_qpc=0;',
            '    outcome_parent[0]=0;outcome_action=NULL;outcome_qpc=0;outcome_stage=NULL;',
        ),
        (
            '    result->qpc=last_request_qpc;',
            '    result->qpc=last_request_qpc;\n'
            '    snprintf(result->stage,sizeof(result->stage),"%s",\n'
            '             last_policy_stage?last_policy_stage:"io_failed");',
        ),
        (
            '    if (!action) return original_http(result, request, headers, body);',
            '    if (!action) { report_outcome(action); return original_http(result, request, headers, body); }',
        ),
        (
            '    if (!action) return returned;',
            '    if (!action) { report_outcome(action); return returned; }',
        ),
    ]
    for old, new in replacements:
        if source.count(old) != 1:
            raise ValueError(f"diagnostic source anchor count differs: {old[:64]!r}")
        source = source.replace(old, new, 1)
    return source


def build(backend: Path, output: Path) -> dict:
    backend = backend.resolve(strict=True)
    output = output.resolve()
    _check_backend(backend)
    original = ROOT / "native/guard/guard.c"
    if _sha(original) != PINNED_SOURCE_SHA256:
        raise ValueError("frozen Native source differs from diagnostic base pin")
    if _sha(DEFAULT_NONRETRY_DLL) != NONRETRY_DLL_SHA256:
        raise ValueError("frozen nonretry DLL differs from diagnostic base pin")
    rendered = diagnostic_source(original.read_text(encoding="utf-8"))
    output.mkdir(parents=True, exist_ok=False)
    transformed = output / "guard_diagnostic.c"
    transformed.write_text(rendered, encoding="utf-8")
    source_root = ROOT / "native/guard"
    sources = [transformed, *(source_root / "third_party/minhook/src" / name
                for name in ("buffer.c", "hook.c", "trampoline.c", "hde/hde64.c"))]
    dll = output / "ttrace-guard-nonretry-diagnostic-lab.dll"
    defines = ["-DJSMN_PARENT_LINKS", "-DTTRACE_FAIL_STOP_DENY=0",
               "-DTTRACE_GRACEFUL_LEASE=1", "-DTTRACE_NONRETRY_DENY_LAB=1",
               "-DHTTP_EMPTY_ERROR_STRING=0", "-DHTTP_DENIED_TAG=3",
               "-DWSS_SUCCESS_TAG=0x20", "-DWSS_DENIED_TAG=25",
               f"-DHTTP_RVA=0x{HTTP_RVA:x}", f"-DWSS_RVA=0x{WSS_RVA:x}",
               f"-DDROP_HEADERS_RVA=0x{DROP_HEADERS_RVA:x}",
               f"-DAPI_ERROR_MAP_RVA=0x{API_ERROR_MAP_RVA:x}",
               _prefix_define("HTTP_ENTRY_PREFIX_BYTES", HTTP_PREFIX),
               _prefix_define("WSS_ENTRY_PREFIX_BYTES", WSS_PREFIX),
               _prefix_define("DROP_HEADERS_PREFIX_BYTES", DROP_HEADERS_PREFIX),
               _prefix_define("API_ERROR_MAP_PREFIX_BYTES", API_ERROR_MAP_PREFIX),
               f'-DTTRACE_EXPECTED_HASH="{BACKEND_SHA256}"']
    command = [sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-windows-gnu",
               "-O2", "-shared", "-I", str(source_root), *defines,
               *map(str, sources), "-lbcrypt", "-o", str(dll)]
    subprocess.run(command, check=True, cwd=ROOT)
    result = {"schema": SCHEMA, "lab_only": True,
              "desktop_demo_admitted": False,
              "backend_sha256": _sha(backend),
              "frozen_nonretry_dll_sha256": NONRETRY_DLL_SHA256,
              "base_source_sha256": PINNED_SOURCE_SHA256,
              "diagnostic_source_sha256": _sha(transformed),
              "diagnostic_dll_sha256": _sha(dll),
              "diagnostic_dll": str(dll), "stages": list(STAGES)}
    (output / "build-manifest.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, default=_default_backend())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.backend, args.output)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
