"""Controlled file/paste allow-block validation for the pinned Chrome SDK.

This proves the local SDK protocol and policy path only.  It does not certify
that a normal Chrome installation has received the cloud-only connector
policies which activate those events.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

from _build_support import ROOT, enter_repository
from transpect_trace.protect.content_analysis import (
    ContentAnalysisEngine,
    ContentAnalysisPolicy,
)
from transpect_trace.protect.content_analysis.runtime import ContentAnalysisRuntime


CASES = (
    ("paste_clean", "bulk", b"ordinary controlled paste text", 0, "ALLOW"),
    (
        "paste_sensitive",
        "bulk",
        b"password=ControlledFakeSecret12345",
        10,
        "BLOCK",
    ),
    ("file_clean", "attach", b"ordinary controlled upload text", 0, "ALLOW"),
    (
        "file_sensitive",
        "attach",
        b"api_key=ControlledFakeKey_1234567890",
        10,
        "BLOCK",
    ),
)


def _client_result(
    client: Path, mode: str, content: bytes, fixture: Path
) -> tuple[int, dict]:
    command = [
        str(client),
        f"--mode={mode}",
        "--url=https://chatgpt.com/",
    ]
    request_input = None
    if mode == "bulk":
        command.append("--stdin")
        request_input = content
    else:
        fixture.write_bytes(content)
        command.append("@" + str(fixture))
    completed = subprocess.run(
        command,
        input=request_input,
        stdin=subprocess.DEVNULL if request_input is None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    try:
        value = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("controlled SDK client returned invalid output") from error
    if not isinstance(value, dict):
        raise RuntimeError("controlled SDK client returned a non-object")
    return completed.returncode, value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--agent",
        type=Path,
        default=ROOT / "build/content-analysis-agent/ttrace-content-agent.exe",
    )
    parser.add_argument(
        "--client",
        type=Path,
        default=ROOT / "build/content-analysis-agent/ttrace-content-sdk-client.exe",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    enter_repository()
    agent = args.agent.resolve()
    client = args.client.resolve()
    if not agent.is_file() or not client.is_file():
        raise SystemExit("build the pinned content-analysis agent and test client first")
    run_dir = args.output.resolve()
    engine = ContentAnalysisEngine(
        ContentAnalysisPolicy(allowed_hosts=["chatgpt.com"])
    )
    results = []
    with tempfile.TemporaryDirectory(prefix="ttrace-content-sdk-") as temporary:
        fixture_root = Path(temporary)
        runtime = ContentAnalysisRuntime(
            agent=agent,
            chrome=client,
            engine=engine,
            run_dir=run_dir,
            allow_sdk_test_client=True,
        )
        try:
            runtime.start()
            for index, (name, mode, body, expected_code, expected_decision) in enumerate(
                CASES
            ):
                code, event = _client_result(
                    client, mode, body, fixture_root / f"fixture-{index}.txt"
                )
                passed = (
                    code == expected_code
                    and event.get("event") == "result"
                    and event.get("decision") == expected_decision
                )
                results.append(
                    {
                        "case": name,
                        "connector": (
                            "BULK_DATA_ENTRY" if mode == "bulk" else "FILE_ATTACHED"
                        ),
                        "expected": expected_decision,
                        "observed": event.get("decision", "UNKNOWN"),
                        "client_exit_code": code,
                        "passed": passed,
                    }
                )
                if not passed:
                    raise RuntimeError(f"controlled SDK case failed: {name}")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                acknowledgements = [
                    event
                    for event in runtime.native_events
                    if event.get("event") == "response_acknowledged"
                ]
                if len(acknowledgements) >= len(CASES):
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("native acknowledgement evidence incomplete")
            runtime.attest_controlled_protocol(len(CASES))
        finally:
            runtime.close()
    summary = {
        "schema_version": "transpect.chrome.content.sdk-probe/1.0",
        "passed": all(case["passed"] for case in results),
        "scope": "controlled_sdk_protocol_only",
        "normal_chrome_policy_activation": "not_tested",
        "normal_chrome_can_enforce": False,
        "cases": results,
        "policy_audit_records": len(runtime.server.records),
        "native_acknowledgements": len(
            [
                event
                for event in runtime.native_events
                if event.get("event") == "response_acknowledged"
            ]
        ),
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
