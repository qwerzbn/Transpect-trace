"""Run both collection routes over the same synthetic cases and compare them.

Route H is the client's own command hooks (scripts/codex_hook_gate.py); Route N
is guard.c injected into the pinned desktop backend with
`native_collection.NativeCollectionEngine` as its policy service. Each case runs
`codex exec` once per route in a private CODEX_HOME against the scripted,
non-forwarding local origin of probe_codex_hook_coverage.py. Ground truth is
the bytes that origin received; both routes write `transpect.codex-collection/1.0`
rows (digests only) and archive plaintext in their own encrypted archive.

Output (runs/scratch/compare-<label>/report.json): the case x category x route
`matrix`, `fidelity`, `false_positives`, `latency`, `dedupe`, `tool_executed`,
`portability` and a per-build `recommendation`. Only synthetic markers and fake
keys are used; no real model endpoint is contacted.

Usage:
  uv run --no-sync python scripts/compare_collection_routes.py --backend <0.166 codex.exe> \
      --label live-01 [--routes hook,native] [--cases benign,...] [--timeout 180] \
      [--portability runs/scratch/compare-portability/portability.json] \
      [--hook-only-backend <npm 0.163 codex.exe>]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import probe_native_guard_backend as probe  # noqa: E402
from probe_codex_hook_coverage import FAKE_KEY, MARKER, PINNED_BACKEND_SHA256, origin  # noqa: E402
from transpect_trace.protect import collection_eval as ev  # noqa: E402
from transpect_trace.protect.archive import EncryptedRequestArchive  # noqa: E402
from transpect_trace.protect.codex_hook_gate import GateConfig, audit_files  # noqa: E402

SCHEMA = "transpect.collection-route-comparison/1.0"
DEFAULT_PORTABILITY = ROOT / "runs" / "scratch" / "compare-portability" / "portability.json"
_SESSION = re.compile(r"session ID (\d+)", re.I)


def _poll_session(request: dict) -> tuple[str, dict]:
    """Step 2 of long_running_output: read the still-running command's session
    id from the last tool result and wait for the rest of its output."""
    outputs = [item.get("output") for item in request.get("input", [])
               if isinstance(item, dict) and item.get("type") == "function_call_output"]
    match = _SESSION.search(json.dumps(outputs[-1]) if outputs else "")
    return "write_stdin", {"session_id": int(match.group(1)) if match else 0, "chars": "",
                           "yield_time_ms": 30000}


# `login: false` runs PowerShell with -NoProfile: a slow user profile otherwise
# outlasts the default 10 s yield and the output never reaches the turn.
_SHELL = {"login": False, "yield_time_ms": 30000}


def _shell(cmd: str) -> list:
    return ["exec_command", {"cmd": cmd, **_SHELL}]


Case = ev.Case
CASES = (
    Case("benign", "read notes.txt", (_shell("Get-Content notes.txt"),),
         {"tool_output": MARKER}, sensitive=False),
    Case("secret_prompt", f"deploy with {FAKE_KEY}", (), {"user_prompt": FAKE_KEY}),
    Case("secret_file_output", "read the build log", (_shell("Get-Content build_log.txt"),),
         {"tool_output": FAKE_KEY}),
    # The flag file shows whether the call ran: H can deny before execution, N cannot.
    Case("sensitive_path_call", "read the env",
         (_shell("New-Item executed.flag | Out-Null; Get-Content .env"),), {"tool_output": MARKER}),
    Case("image_tool_output", "look at the image", (["view_image", {"path": "marker.png"}],),
         {"tool_output_image": MARKER}),
    Case("agents_md_secret", "summarize the project", (), {"client_instructions": FAKE_KEY}),
    # `--image=` form, so the `-` (prompt on stdin) is not read as a second image.
    Case("user_image_attachment", "describe the image", (), {"user_attachment": MARKER},
         exec_args=("--image=marker.png",)),
    Case("long_running_output", "watch the job",
         # The marker is joined at run time: written literally it would reach the
         # origin in the echoed call arguments and prove nothing about the output.
         (["exec_command", {"cmd": f"Write-Output ('{MARKER[:14]}' + '{MARKER[14:]}'); "
                                   "Start-Sleep 20",
                            "login": False, "yield_time_ms": 500}], _poll_session),
         {"tool_output": MARKER}, sensitive=False),
    Case("benign_multi_step", "check the notes",
         (_shell("Get-Content notes.txt"), _shell("(Get-Content notes.txt).Length"),
          _shell("Get-ChildItem -Name")), {"tool_output": MARKER}, sensitive=False),
    Case("agents_md_benign", "summarize the project", (), {"client_instructions": MARKER},
         sensitive=False,
         agents_md=f"# Project\nUse PowerShell. Notes live in notes.txt ({MARKER}).\n"),
)


def _native_engine(config):
    from transpect_trace.protect.native_collection import NativeCollectionEngine
    return NativeCollectionEngine(config)


def _setup(case: Case):
    if case.agents_md is None:
        return None
    return lambda work: (work / "AGENTS.md").write_text(case.agents_md, encoding="utf-8")


def run(route: str, case: Case, backend: Path, dll: Path | None, out: Path, server,
        timeout: int) -> tuple[dict, Path]:
    """Codex runs outside this checkout, so the requests carry no metadata of
    the real repository; its home is moved under the output afterwards."""
    triple = (case.name, case.prompt, list(case.steps))
    scratch = Path(tempfile.mkdtemp(prefix="ttrace-compare-"))
    options = {"exec_args": case.exec_args, "setup": _setup(case), "scratch": scratch}
    base = out / route / case.name
    try:
        if route == "hook":
            result = probe.run_hook(backend, out, server, triple, timeout, **options)
        else:
            result = probe.run_native(backend, dll, out, server, triple, timeout,
                                      engine=_native_engine, **options)
        result["tool_executed"] = (scratch / "work" / "executed.flag").exists()
        # Kept for inspection only. Codex's background plugin clone may still be
        # writing under .tmp after `exec` exits, so a copy failure is noted,
        # never turned into a route failure.
        try:
            shutil.copytree(scratch / "codex-home", base / "codex-home",
                            ignore=shutil.ignore_patterns(".tmp"), dirs_exist_ok=True)
        except OSError as error:
            result["codex_home_copy_error"] = type(error).__name__
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return result, base


_SEPARATORS = re.compile(rb"[\\/]+")


def _repo_needles() -> list[bytes]:
    """The real checkout's path and remote, in `_SEPARATORS`-folded form."""
    remote = subprocess.run(["git", "-C", str(ROOT), "config", "--get", "remote.origin.url"],
                            capture_output=True, text=True).stdout.strip()
    return [_SEPARATORS.sub(b"/", item.lower().encode("utf-8"))
            for item in (ROOT.as_posix(), remote) if item]


def check_synthetic(bodies: list[bytes], needles: list[bytes]) -> None:
    """Fail the run if a body names the real repository, however escaped."""
    for body in bodies:
        folded = _SEPARATORS.sub(b"/", body.lower())
        if any(needle in folded for needle in needles):
            raise RuntimeError("an origin body carries the real repository's metadata")


def pmr_lost(base: Path, requests: int) -> int:
    """Requests without a PreModelRequest audit row. The hook runs async, and
    `codex exec` exits right after the last response, before that hook writes."""
    rows = [json.loads(line) for part in audit_files(base / "gate" / "audit.jsonl")
            for line in part.read_text(encoding="utf-8").splitlines() if line.strip()]
    return max(0, requests - sum(row.get("hook_event_name") == "PreModelRequest"
                                 for row in rows))


def gather(base: Path) -> dict:
    """Origin bodies, collection rows and the route's own archive for one run."""
    config = GateConfig.load(base / "gate" / "gate-config.json")
    path = getattr(config, "collection_file", None) or config.audit_file.parent / "collection.jsonl"
    bodies = sorted(base.glob("origin-*.json"), key=lambda p: int(p.stem.split("-")[1]))
    return {"origin_bodies": [p.read_bytes() for p in bodies],
            "records": ev.load_route_records(path),
            "archive": EncryptedRequestArchive(config.archive_directory), "error": None}


def summarize(route: str, case: Case, result: dict, data: dict, base: Path) -> dict:
    records, bodies = data["records"], data["origin_bodies"]
    row = {"case": case.name, "route": route,
           "outcome": ev.judge(case, len(bodies), ev.origin_bytes(bodies)),
           "requests": len(bodies), "records": len(records),
           "tool_executed": result.get("tool_executed"),
           "latency": ev.latency(records, route),
           **{key: result.get(key) for key in ("exit_code", "client_hook_lines",
                                                "client_error_lines", "native", "pipe_errors")}}
    if not case.sensitive:
        row["false_positives"] = ev.false_positives(records)
    if route == "hook":
        row["pmr_lost"] = pmr_lost(base, len(bodies))
    if route == "native":
        row["allowed_bytes_equal_origin"] = ev.allowed_bytes_equal_origin(
            records, result["origin_body_sha256"])
        row["dedupe"] = [{key: r["extra"].get(key) for key in
                          ("items_total", "items_new", "items_cached", "duplicate_invocation")}
                         for r in records if r["category"] == "request_envelope"]
    return row


def native_quality(rows: list[dict], cases: dict[str, Case], digest: str) -> dict | None:
    """Route N's live evidence for `recommend`, valid only for the build it ran on."""
    native = [row for row in rows if row["route"] == "native"]
    if not native:
        return None
    benign = [row for row in native if not cases[row["case"]].sensitive]
    # Every benign control must have run, or benign quality is not measured.
    measured = {case.name for case in CASES if not case.sensitive} <= {
        row["case"] for row in benign}
    equal = [row.get("allowed_bytes_equal_origin") for row in native]
    elapsed = [r for row in native for r in row.get("_elapsed", [])]
    return {"backend_sha256": digest,
            "broken_benign": sum(row["outcome"] in ("BROKEN", "PROBE_ERROR")
                                 for row in benign) if measured else None,
            "benign_non_allow": sum(row.get("false_positives", {}).get("actionable_non_allow", 1)
                                    for row in benign) if measured else None,
            "latency_p95_ms": ev.percentile(elapsed, 0.95),
            "allowed_bytes_equal_origin": (False not in equal and True in equal)}


def hook_only_backend(backend: Path, out: Path, server, timeout: int) -> dict:
    """Does a client without PreModelRequest still run the installer's hooks.json?"""
    case = CASES[0]
    try:
        result, base = run("hook", case, backend, None, out, server, timeout)
    except Exception as error:
        return {"backend": str(backend), "error": f"{type(error).__name__}: {error}"}
    audit = [json.loads(line) for part in audit_files(base / "gate" / "audit.jsonl")
             for line in part.read_text(encoding="utf-8").splitlines() if line.strip()]
    data = gather(base)
    return {"backend": str(backend),
            "backend_sha256": hashlib.sha256(backend.read_bytes()).hexdigest(),
            "outcome": ev.judge(case, len(data["origin_bodies"]),
                                ev.origin_bytes(data["origin_bodies"])),
            "requests": len(data["origin_bodies"]),
            "audit_events": sorted({row.get("hook_event_name") for row in audit} - {None}),
            "user_prompt_rows": sum(row.get("hook_event_name") == "UserPromptSubmit"
                                    for row in audit),
            "collection_records": len(data["records"]),
            "client_error_lines": result.get("client_error_lines")}


def load_portability(path: Path | None, backend: Path) -> dict:
    if path is not None and path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    import check_collection_portability as port
    row = port.check_build(backend, port.load_adapters())
    return {"schema": port.SCHEMA, "builds": {row["version"] or str(backend): row}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--routes", default="hook,native")
    parser.add_argument("--cases", default=",".join(case.name for case in CASES))
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--portability", type=Path, default=DEFAULT_PORTABILITY)
    parser.add_argument("--hook-only-backend", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", args.label):
        raise SystemExit("label must be a short identifier")
    routes = args.routes.split(",")
    if set(routes) - {"hook", "native"}:
        raise SystemExit("routes are hook and/or native")
    importlib.import_module("transpect_trace.protect.wire_items")  # ground truth parser
    if "native" in routes:
        importlib.import_module("transpect_trace.protect.native_collection")
    backend = args.backend.resolve(strict=True)
    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    if "native" in routes and digest != PINNED_BACKEND_SHA256:
        raise SystemExit(f"native route needs the pinned backend, got {digest}")
    out = ROOT / "runs" / "scratch" / f"compare-{args.label}"
    out.mkdir(parents=True, exist_ok=False)
    wanted = set(args.cases.split(","))
    cases = {case.name: case for case in CASES if case.name in wanted}
    dll = probe.build_dll(out / "build") if "native" in routes else None
    rows, matrix_input = [], []
    needles = _repo_needles()
    with origin() as server:
        for case in cases.values():
            runs = {}
            for route in routes:
                try:
                    result, base = run(route, case, backend, dll, out, server, args.timeout)
                    runs[route] = gather(base)
                    check_synthetic(runs[route]["origin_bodies"], needles)
                    row = summarize(route, case, result, runs[route], base)
                    if row.get("pmr_lost"):
                        runs[route]["unmeasured"] = ["request_metadata", "user_attachment"]
                    row["_elapsed"] = [r["elapsed_ms"] for r in
                                       ev.decision_rows(runs[route]["records"], route)]
                except Exception as error:
                    runs[route] = {"error": f"{type(error).__name__}: {error}"}
                    row = {"case": case.name, "route": route, "outcome": "PROBE_ERROR",
                           "error": runs[route]["error"]}
                rows.append(row)
                print(json.dumps({k: v for k, v in row.items() if k != "_elapsed"},
                                 ensure_ascii=False), flush=True)
            matrix_input.append({"case": case.name, "planted": ev.planted_categories(case),
                                 "sensitive": case.sensitive, "runs": runs})
        only = (hook_only_backend(args.hook_only_backend.resolve(strict=True),
                                  out / "hook-only-backend", server, args.timeout)
                if args.hook_only_backend else None)
    matrix = ev.coverage_matrix(matrix_input)
    portability = load_portability(args.portability, backend)
    quality = native_quality(rows, cases, digest)
    by_route = {route: [row for row in rows if row["route"] == route] for route in routes}
    elapsed = {route: [e for row in items for e in row.pop("_elapsed", [])]
               for route, items in by_route.items()}
    quality_counts = {route: {} for route in routes}
    for categories in matrix["cells"].values():
        for routes_cells in categories.values():
            for route, value in routes_cells.items():
                key = value["match_quality"] or "none"
                quality_counts[route][key] = quality_counts[route].get(key, 0) + 1
    report = {
        "schema": SCHEMA, "label": args.label, "backend_sha256": digest, "routes": routes,
        "scope": "codex exec in a private CODEX_HOME against a scripted local origin over "
                 "HTTP; not the desktop UI, not WSS",
        "runs": rows, "matrix": matrix,
        "fidelity": {"match_quality": quality_counts, "allowed_bytes_equal_origin": {
            row["case"]: row.get("allowed_bytes_equal_origin")
            for row in by_route.get("native", [])}},
        "false_positives": {route: {row["case"]: row["false_positives"] for row in items
                                    if "false_positives" in row}
                            for route, items in by_route.items()},
        "latency": {route: {"decisions": len(values), "p50_ms": ev.percentile(values, 0.5),
                            "p95_ms": ev.percentile(values, 0.95)}
                    for route, values in elapsed.items()},
        "latency_scope": {
            "hook": "gate time inside decide() per event; excludes starting python.exe "
                    "for each hook event",
            "native": "collector time per request body; excludes the pipe transport and "
                      "the guard's second call on the same body, which reuses the decision"},
        "pmr_lost": {row["case"]: row.get("pmr_lost") for row in by_route.get("hook", [])},
        "dedupe": {row["case"]: row.get("dedupe") for row in by_route.get("native", [])},
        "tool_executed": {route: {row["case"]: row.get("tool_executed") for row in items}
                          for route, items in by_route.items()},
        "hook_only_backend": only, "native_quality": quality, "portability": portability,
        "recommendation": ev.recommend(matrix, portability, quality=quality),
    }
    (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                     encoding="utf-8")
    print(json.dumps(report["recommendation"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
