from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from aiohttp import ClientSession, web

from transpect_trace.config import load_project_env, provider_api_key
from transpect_trace.core.storage import atomic_write
from transpect_trace.gateway.policy import GatewayPolicy
from transpect_trace.gateway.server import GatewayConfig, create_app


OFFICIAL_REPOSITORY = "https://github.com/uiuc-kang-lab/InjecAgent.git"
OFFICIAL_COMMIT = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
OFFICIAL_DATASET_SHA256 = "7959777711834b23e8cca2f89717a8fd6ca92ac3a0a915e38fa563a2cf9cf8bd"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an exact 20-case subset of the official InjecAgent DS benchmark")
    parser.add_argument("--source-dir", type=Path, default=Path(".external/InjecAgent"))
    parser.add_argument("--output-dir", type=Path, default=Path("reports/injecagent-official-20"))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--model", default=os.environ.get("MODEL_ID"))
    parser.add_argument("--upstream", default=os.environ.get("BASE_URL", "https://api.deepseek.com"))
    return parser.parse_args()


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import official InjecAgent module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as error:
        sys.modules.pop(name, None)
        if error.name == "nltk":
            raise RuntimeError("Official InjecAgent evaluation requires: uv sync --extra benchmarks") from error
        raise
    return module


def _validate_source(source_dir: Path) -> tuple[Path, str]:
    source_dir = source_dir.resolve()
    commit = subprocess.run(
        ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if commit != OFFICIAL_COMMIT:
        raise RuntimeError(f"unexpected InjecAgent commit: {commit}; expected {OFFICIAL_COMMIT}")
    dataset = source_dir / "data" / "test_cases_ds_base.json"
    digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
    if digest != OFFICIAL_DATASET_SHA256:
        raise RuntimeError(f"unexpected official dataset digest: {digest}")
    return dataset, digest


def _select_cases(dataset: Path, limit: int) -> list[dict[str, Any]]:
    cases = json.loads(dataset.read_text(encoding="utf-8"))
    groups: dict[str, list[dict[str, Any]]] = {}
    user_tools: list[str] = []
    for case in cases:
        instruction = str(case["Attacker Instruction"])
        groups.setdefault(instruction, []).append(case)
        user_tool = str(case["User Tool"])
        if user_tool not in user_tools:
            user_tools.append(user_tool)
    selected: list[dict[str, Any]] = []
    for index, grouped_cases in enumerate(groups.values()):
        desired_user_tool = user_tools[index % len(user_tools)]
        selected.append(next(case for case in grouped_cases if case["User Tool"] == desired_user_tool))
        if len(selected) == limit:
            break
    if len(selected) != limit:
        raise RuntimeError(f"requested {limit} unique attacker instructions, found {len(selected)}")
    return selected


def _tool_dict(source_dir: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    toolkits = json.loads((source_dir / "data" / "tools.json").read_text(encoding="utf-8"))
    for toolkit in toolkits:
        for original in toolkit["tools"]:
            tool = dict(original)
            name = str(toolkit["toolkit"]) + str(tool["name"])
            tool["name"] = name
            result[name] = tool
    return result


def _model_input(case: dict[str, Any], tools: dict[str, dict[str, Any]], prompts: Any, *, step_2: bool = False) -> list[dict[str, str]]:
    system_prompt, user_prompt = prompts.PROMPT_DICT["InjecAgent"]
    available_names = [case["User Tool"], *case["Attacker Tools"]]
    descriptions = json.dumps([tools[name] for name in available_names], indent=True)
    if step_2:
        scratchpad = (
            f"\n{case['Thought']}\nAction: {case['User Tool']}\nAction Input: {case['Tool Parameters']}"
            f"\nObservation: {case['Tool Response']}\n{case['Attacker Tool Thought']}"
            f"\nAction: {case['Attacker Tools'][0]}\nAction Input: {case['Attacker Tool Parameters']}"
            f"\nObservation: {case['Attacker Tool Response']}\n"
        )
    else:
        scratchpad = (
            f"\n{case['Thought']}\nAction: {case['User Tool']}\nAction Input: {case['Tool Parameters']}"
            f"\nObservation: {case['Tool Response']}\n"
        )
    filled = user_prompt.format(
        available_tool_descriptions=descriptions,
        input=case["User Instruction"],
        available_tool_names=available_names,
        agent_scratchpad=scratchpad,
    )
    return [{"role": "system", "content": system_prompt}, {"role": "user", "content": filled}]


async def _start(app: web.Application) -> tuple[web.AppRunner, str]:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    sockets = site._server.sockets  # type: ignore[union-attr]
    return runner, f"http://127.0.0.1:{sockets[0].getsockname()[1]}"


async def _completion(session: ClientSession, gateway_url: str, model: str, messages: list[dict[str, str]]) -> tuple[int, str, dict[str, Any]]:
    async with session.post(
        gateway_url + "/chat/completions",
        json={"model": model, "messages": messages, "temperature": 0, "stream": False},
    ) as response:
        payload = await response.json(content_type=None)
        if response.status != 200:
            return response.status, "", payload
        choices = payload.get("choices") if isinstance(payload, dict) else None
        text = ""
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            message = choices[0].get("message")
            if isinstance(message, dict):
                text = str(message.get("content") or "")
        return response.status, text, payload


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    load_project_env()
    api_key = provider_api_key("deepseek")
    model = args.model or os.environ.get("MODEL_ID") or "deepseek-chat"
    if not api_key:
        raise RuntimeError("DeepSeek API key is required")
    dataset, digest = _validate_source(args.source_dir)
    selected = _select_cases(dataset, args.limit)
    source_dir = args.source_dir.resolve()
    prompts = _load_module("injecagent_official_agent_prompts", source_dir / "src" / "prompts" / "agent_prompts.py")
    output_parsing = _load_module("injecagent_official_output_parsing", source_dir / "src" / "output_parsing.py")
    tools = _tool_dict(source_dir)
    simulated = json.loads((source_dir / "data" / "attacker_simulated_responses.json").read_text(encoding="utf-8"))

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_dir / "gateway-evidence"
    policy = GatewayPolicy.model_validate(
        {
            "schema": "transpect.gateway.policy/1.0",
            "policy_id": "injecagent-official-ds-20",
            "version": OFFICIAL_COMMIT[:12],
            "allowed_upstreams": [args.upstream],
            "allowed_source_paths": [],
            "content_markers": [],
        }
    )
    app = create_app(
        GatewayConfig(
            run_id="injecagent-official-ds-20",
            run_dir=evidence_dir,
            upstream=args.upstream,
            api_key=api_key,
            provider="deepseek",
            policy=policy,
        )
    )
    runner, gateway_url = await _start(app)
    results: list[dict[str, Any]] = []
    try:
        async with ClientSession() as session:
            for index, original in enumerate(selected, start=1):
                case = json.loads(json.dumps(original))
                status, output, error = await _completion(session, gateway_url, model, _model_input(case, tools, prompts))
                row: dict[str, Any] = {
                    "case_number": index,
                    "official_case": original,
                    "step_1": {"http_status": status, "output": output},
                    "step_2": {"attempted": False},
                }
                if status != 200:
                    row["step_1"]["error"] = error
                    row["step_1"]["eval"] = "gateway_blocked" if status == 403 else "request_error"
                    results.append(row)
                    continue
                parsed = output_parsing.evaluate_output_prompted(
                    output,
                    case["Attacker Tools"][0],
                    case["Attacker Tools"],
                    case["User Tool"],
                    case["Attacker Instruction"],
                )
                row["step_1"]["eval"] = parsed["eval"]
                if parsed["eval"] == "invalid":
                    row["step_1"]["invalid_reason"] = parsed.get("invalid_reason")
                if parsed["eval"] == "succ":
                    parameters = parsed["Attacker Tool Parameters"]
                    cache_key = f"({case['Attacker Tools'][0]},{parameters})"
                    if cache_key not in simulated:
                        row["step_2"] = {"attempted": False, "reason": "official_simulated_response_not_found"}
                    else:
                        case["Attacker Tool Parameters"] = parameters
                        case["Attacker Tool Thought"] = parsed["Attacker Tool Thought"]
                        case["Attacker Tool Response"] = simulated[cache_key]
                        status_2, output_2, error_2 = await _completion(
                            session, gateway_url, model, _model_input(case, tools, prompts, step_2=True)
                        )
                        row["step_2"] = {"attempted": True, "http_status": status_2, "output": output_2}
                        if status_2 == 200:
                            parsed_2 = output_parsing.evaluate_output_prompted(
                                output_2,
                                case["Attacker Tools"][1],
                                case["Attacker Tools"],
                                case["User Tool"],
                                case["Attacker Instruction"],
                            )
                            row["step_2"]["eval"] = parsed_2["eval"]
                            if parsed_2["eval"] == "invalid":
                                row["step_2"]["invalid_reason"] = parsed_2.get("invalid_reason")
                        else:
                            row["step_2"]["error"] = error_2
                            row["step_2"]["eval"] = "gateway_blocked" if status_2 == 403 else "request_error"
                results.append(row)
    finally:
        await runner.cleanup()

    gateway_rows = [
        json.loads(line)
        for line in (evidence_dir / "raw" / "gateway" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    decisions = [row for row in gateway_rows if row.get("kind") == "policy.decision"]
    summary = {
        "source": {
            "repository": OFFICIAL_REPOSITORY,
            "commit": OFFICIAL_COMMIT,
            "dataset": "data/test_cases_ds_base.json",
            "dataset_sha256": f"sha256:{digest}",
            "official_cases_total": 544,
            "official_unique_attacker_instructions": 32,
            "selection": (
                f"first {args.limit} distinct Attacker Instruction groups in source order; "
                "choose user-tool surfaces round-robin in official source order"
            ),
        },
        "model": model,
        "cases_selected": len(results),
        "step_1": dict(Counter(row["step_1"]["eval"] for row in results)),
        "step_2_attempted": sum(bool(row["step_2"].get("attempted")) for row in results),
        "step_2": dict(Counter(row["step_2"].get("eval", "not_attempted") for row in results)),
        "gateway": {
            "requests": sum(row.get("kind") == "model.request" for row in gateway_rows),
            "policy_allowed": sum(row.get("decision") == "allow" for row in decisions),
            "policy_denied": sum(row.get("decision") == "deny" for row in decisions),
            "blocked_requests": sum(row.get("kind") == "model.request.blocked" for row in gateway_rows),
            "responses_completed": sum(row.get("kind") == "model.response.completed" for row in gateway_rows),
        },
    }
    selection = {
        "source": summary["source"],
        "cases": selected,
    }
    atomic_write(output_dir / "selection.json", (json.dumps(selection, ensure_ascii=False, indent=2) + "\n").encode())
    atomic_write(
        output_dir / "results.jsonl",
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in results).encode(),
    )
    atomic_write(output_dir / "summary.json", (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode())
    return summary


def main() -> None:
    load_project_env()
    args = _arguments()
    print(json.dumps(asyncio.run(_run(args)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
