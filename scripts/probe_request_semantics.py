"""Real fixed Native/eCapture paths -> four semantic groups, fake local data only.

No new blocking capability is installed or certified. Full semantic values are
only exported with --synthetic-content; default evidence remains metadata-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from _build_support import ROOT, enter_repository
from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.policy import GuardPolicy, PolicyEngine
from transpect_trace.observe.semantics import GROUPS, extract_request


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write("\n")


class Sink:
    def __init__(self, directory, plaintext):
        self.directory, self.plaintext, self.rows = directory, plaintext, []

    def __call__(self, result):
        self.rows.append(result)
        self.directory.mkdir(parents=True, exist_ok=True)
        with (self.directory / "request-semantics.jsonl").open("a", encoding="utf-8") as out:
            out.write(result.model_dump_json() + "\n")
        if self.plaintext:
            write(self.directory / f"synthetic-{len(self.rows):03d}.json", result.synthetic_export())

    def summary(self):
        return dict(observations=len(self.rows),
            groups={g:sum(len(getattr(r, g)) for r in self.rows) for g in GROUPS},
            statuses=[r.status for r in self.rows],
            body_hashes=[r.raw_body_sha256 for r in self.rows],
            can_enforce=False, synthetic_content_exported=self.plaintext)


def schannel(args, root):
    from probe_ecapture_windows import experiment
    sink = Sink(root / "extraction", args.synthetic_content)
    payload = {"model": "fixture", "instructions": "FAKE_CONTEXT 中文上下文",
        "input": [{"role": "user", "content": "FAKE_ECAPTURE_PROBE 请分析假数据"},
                  {"type": "function_call", "call_id": "fixture-call", "name": "read_fixture",
                   "arguments": '{"path":"FAKE_FILE"}'},
                  {"type": "function_call_output", "call_id": "fixture-call", "output": "FAKE_RESULT"}],
        "tools": [{"type": "function", "name": "read_fixture", "parameters": {"type": "object"}}]}
    result = experiment(root / "capture", ROOT / "build/observe/ecapture-enhanced/ecapture.exe",
                        elevate=args.elevate, semantic_payload=payload, semantic_sink=sink)
    exact = len(sink.rows) == 4 and all(
        [p.value for p in r.prompt] == ["FAKE_ECAPTURE_PROBE 请分析假数据"] and
        [p.value for p in r.context] == ["FAKE_CONTEXT 中文上下文"] and
        len(r.tool_calls) == 1 and r.tool_calls[0].value == {"path": "FAKE_FILE"} and
        r.tool_calls[0].tool_name == "read_fixture" and
        [p.value for p in r.tool_results] == ["FAKE_RESULT"] and len(r.tool_links) == 1 and
        r.status == "extracted" for r in sink.rows)
    return dict(channel="controlled-schannel", passed=bool(result["plaintext_validation_passed"] and exact),
        extraction=sink.summary(), exact_fixture_fields_match=exact,
        source_body_hashes_match=result["plaintext_validation_passed"],
        terminal_health=result["terminal_health_confirmed"],
        limitations=["Controlled Schannel fixture only; not browser or general AI certification"])


def codex(args, root, protocol):
    from probe_guard_native import experiment
    sink = Sink(root / "extraction", args.synthetic_content)

    class Observer(PolicyEngine):
        def evaluate(self, request):
            decision, audit = super().evaluate(request)
            if request.kind == "model.request":
                sink(extract_request(request.payload_utf8.encode(), observation_id=request.request_id,
                    capture_source="native-guard-fixture", completeness=request.completeness,
                    capture_point="request-before-send", protocol=request.protocol))
            return decision, audit

    def fixture(workspace):
        policy = GuardPolicy(credential_rules=False)
        return dict(marker="FAKE_SEMANTIC_TOOL_RESULT", policy=policy, engine=Observer(policy),
            command="Write-Output 'FAKE_SEMANTIC_TOOL_RESULT'",
            prompt="FAKE_SEMANTIC_PROMPT: Run the supplied synthetic tool and explain its output.")

    result = experiment(args.codex, ROOT / "build/guard/ttrace-guard.dll", root / "capture",
        protocol, "observe", scenario="tool_network", fixture_factory=fixture)
    last = [r for r in sink.rows if any("FAKE_SEMANTIC_TOOL_RESULT" in str(p.value) for p in r.tool_results)]
    matched = bool(last and all(
        any("FAKE_SEMANTIC_PROMPT" in str(p.value) for p in r.prompt) and
        bool(r.context) and
        any(p.tool_name == "exec_command" and isinstance(p.value, dict) and
            p.value.get("cmd") == "Write-Output 'FAKE_SEMANTIC_TOOL_RESULT'" for p in r.tool_calls) and
        bool(r.tool_links) for r in last))
    arrived = any(c.get("marker_in_origin_payload") for c in result["origin_connections"])
    passed = bool(matched and arrived and result["native_ready"] and result["disk_unchanged"]
                  and result["returncode"] == 0 and not result["fixture_cleanup_terminated_child"])
    return dict(channel="codex-" + protocol, passed=passed, extraction=sink.summary(),
        expected_prompt_command_and_result_match=matched, marker_reached_origin=arrived,
        native_ready=result["native_ready"], disk_unchanged=result["disk_unchanged"],
        client_exit_code=result["returncode"],
        source_records=len(result["origin_connections"]),
        limitations=["Real fixed CLI, synthetic model source and real tool execution",
                     "Context is request-carried system/developer/history, not all server-side history",
                     "Tool records observed in outgoing request, not response-stream interception",
                     "Extraction observations may repeat; counts are not unique network request counts"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--only", choices=["schannel", "codex"], action="append")
    parser.add_argument("--elevate", action="store_true", help="UAC for Schannel eCapture only.")
    parser.add_argument("--synthetic-content", action="store_true")
    parser.add_argument("--codex", type=Path,
        default=ROOT / "runs/guard-native/aslr-copy-reject-16/official-copy/codex.exe")
    args = parser.parse_args()
    enter_repository()
    args.codex = args.codex.resolve()
    selected = args.only or ["schannel", "codex"]
    if "codex" in selected and hashlib.sha256(args.codex.read_bytes()).hexdigest() != BINARY_SHA256:
        parser.error("fixed official Codex baseline mismatch")
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    rows = []
    jobs = []
    if "schannel" in selected:
        jobs.append(("schannel", lambda p: schannel(args, p)))
    if "codex" in selected:
        jobs.extend([(f"codex-{protocol}", lambda p, t=protocol: codex(args, p, t)) for protocol in ("http", "wss")])
    for name, job in jobs:
        directory = root / name
        try:
            row = job(directory)
        except (OSError, RuntimeError, ValueError, TimeoutError) as error:
            row = dict(channel=name, passed=False, status="unavailable", error_type=type(error).__name__)
        write(directory / "semantic-validation.json", row)
        rows.append(row)
        print(json.dumps({k:row[k] for k in ("channel", "passed")}), flush=True)
    summary = dict(cases=rows, passed=bool(rows) and all(r["passed"] for r in rows),
        can_enforce=False, external_AI_services_tested=False,
        scope="request-side semantic extraction using existing verified capture adapters")
    write(root / "summary.json", summary)
    if not summary["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
