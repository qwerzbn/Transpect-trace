"""Judge both collection routes against the bytes the origin actually received.

Pure functions only: the live harness (scripts/compare_collection_routes.py)
runs the cases and passes in origin bodies, collection rows and each route's own
archive. Ground truth is the origin bodies split by the same wire parser Route N
uses, so a cell compares like with like. Rows are joined to ground truth by keyed
digest under the route's own archive key, by a planted synthetic token found in
the route's archived payload, or by `call_id`/`turn_id` -- never by comparing
hook text with wire text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from pathlib import Path

from .collection import (CATEGORIES, CollectedItem, data_url_payloads, normalize_match_text,
                         validate_record)

CELL = ("COLLECTED_BLOCKED", "COLLECTED_RELEASED", "COLLECTED_LEAKED", "METADATA_ONLY",
        "NOT_COLLECTED", "NOT_APPLICABLE", "PROBE_ERROR")
IMAGE_CATEGORIES = frozenset(("tool_output_image", "user_attachment"))
# Content only Route N can add over Route H; one of these must be gained for N
# to be worth running next to H.
MUST_HAVE = ("client_instructions", "user_attachment", "tool_output")
MAX_NATIVE_P95_MS = 1500.0
HEALTH_SESSION = "transpect-health-check"


@dataclass(frozen=True)
class Case:
    """One synthetic scenario. `planted` maps a category to the synthetic token
    placed in it; `sensitive=False` marks a benign control whose tokens are
    expected upstream (they then prove collection, never leakage)."""
    name: str
    prompt: str
    steps: tuple = ()
    planted: dict = field(default_factory=dict)
    sensitive: bool = True
    exec_args: tuple[str, ...] = ()
    agents_md: str | None = None


def planted_categories(case: Case) -> dict[str, bytes]:
    return {category: token.encode("utf-8") for category, token in case.planted.items()}


def ground_truth(origin_bodies: list[bytes]) -> list[CollectedItem]:
    """Every distinct item the origin received, split by Route N's parser."""
    from .wire_items import parse_wire_request  # WP1 module; imported lazily
    seen: dict[tuple, CollectedItem] = {}
    for body in origin_bodies:
        for item in parse_wire_request(body, protocol="http").items:
            seen.setdefault((item.category, item.call_id, item.payload), item)
    return list(seen.values())


def origin_turns(origin_bodies: list[bytes]) -> frozenset[str]:
    from .wire_items import parse_wire_request
    turns = (parse_wire_request(body, protocol="http").correlation.get("turn_id")
             for body in origin_bodies)
    return frozenset(turn for turn in turns if turn)


def origin_bytes(origin_bodies: list[bytes]) -> bytes:
    """Origin bytes plus decoded inline data URLs, so a token planted in an image
    counts as reaching the origin even though it travels base64-encoded."""
    decoded = []
    for body in origin_bodies:
        try:
            decoded += data_url_payloads(json.loads(body))
        except ValueError:
            pass
    return b"\n".join([*origin_bodies, *decoded])


def load_route_records(path: Path, *, exclude_session: str = HEALTH_SESSION) -> list[dict]:
    """Validated rows from a collection file and its rotations, oldest first."""
    from .codex_hook_gate import audit_files
    rows = []
    for part in audit_files(Path(path)):
        for line in part.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            validate_record(record)
            if record["session_id"] != exclude_session:
                rows.append(record)
    return rows


def _item_digests(archive, item: CollectedItem) -> set[str]:
    digests = {archive.keyed_digest(item.payload)}
    if item.match_text is not None:
        digests.add(archive.keyed_digest(item.match_text.encode("utf-8")))
        digests.add(archive.keyed_digest(
            normalize_match_text(item.category, item.match_text).encode("utf-8")))
    return digests


def _archived_contains(archive, record: dict, token: bytes) -> bool:
    if record["archive_record_id"] is None:
        return False
    try:
        if (record["category"] != "request_envelope"
                and record["extra"].get("shared_request_archive") is True):
            from .native_collection import read_shared_request_item
            payload = read_shared_request_item(archive, record)
        else:
            payload = archive.read(record["archive_record_id"])[1]
        return token in payload
    except (OSError, ValueError):
        return False


def _joined(record: dict, items: list[CollectedItem], turns: frozenset[str]) -> bool:
    if record["call_id"]:
        return any(item.call_id == record["call_id"] for item in items)
    return bool(items) and record["turn_id"] in turns


def _evidence(rows: list[dict], items: list[CollectedItem], token: bytes | None,
              archive, turns: frozenset[str]) -> str | None:
    if archive is not None and items:
        digests = set().union(*(_item_digests(archive, item) for item in items))
        hits = [row for row in rows if {row["match_hmac"], row["content_hmac"]} & digests]
        if hits:
            return "id_and_digest" if any(_joined(row, items, turns) for row in hits) else "digest"
    if token is not None and archive is not None and any(
            _archived_contains(archive, row, token) for row in rows):
        return "planted"
    return "id_only" if any(_joined(row, items, turns) for row in rows) else None


def assess(category: str, route_records: list[dict], gt_items: list[CollectedItem],
           planted: dict[str, bytes], archive, origin_blob: bytes, *,
           sensitive: bool = True, turns: frozenset[str] = frozenset()) -> dict:
    """One matrix cell with its evidence: `match_quality` says how a row was tied
    to ground truth (`unverified` when nothing reached the origin to compare)."""
    rows = [row for row in route_records if row["category"] == category]
    items = [item for item in gt_items if item.category == category]
    token = planted.get(category)
    present = bool(items) or token is not None
    leaked = sensitive and token is not None and token in origin_blob
    result = {"cell": None, "match_quality": None, "leaked": leaked, "records": len(rows)}
    content = [row for row in rows if row["collection"] == "content"]
    if not rows:
        return {**result, "cell": "NOT_COLLECTED" if present else "NOT_APPLICABLE"}
    if not content:
        return {**result, "cell": "METADATA_ONLY"}
    quality = _evidence(content, items, token, archive, turns)
    if quality is None and present:
        return {**result, "cell": "NOT_COLLECTED", "match_quality": "unmatched"}
    cell = ("COLLECTED_LEAKED" if leaked else
            "COLLECTED_BLOCKED" if any(row["route_decision"] == "deny" for row in content) else
            "COLLECTED_RELEASED")
    return {**result, "cell": cell, "match_quality": quality or "unverified"}


def cell(category: str, route_records: list[dict], gt_items: list[CollectedItem],
         planted: dict[str, bytes], archive, origin_blob: bytes, **options) -> str:
    return assess(category, route_records, gt_items, planted, archive, origin_blob,
                  **options)["cell"]


def _prevented(found: dict, planted: dict[str, bytes], blob: bytes) -> bool:
    """The route denied the tool call, so the output it would have collected never existed."""
    token = planted.get("tool_output")
    return (found["tool_call_args"]["cell"] == "COLLECTED_BLOCKED"
            and found["tool_output"]["cell"] == "NOT_COLLECTED"
            and (token is None or token not in blob))


def coverage_matrix(cases: list[dict]) -> dict:
    """`cases`: [{"case", "planted", "sensitive", "runs": {route: {"records",
    "origin_bodies", "archive", "error", "unmeasured"}}}] -> case x category x
    route cells. `unmeasured` lists categories whose rows the harness lost, so
    an absent row there is a PROBE_ERROR, not NOT_COLLECTED."""
    cells: dict = {}
    summary: dict = {}
    for case in cases:
        rows = cells.setdefault(case["case"], {})
        for route, run in case["runs"].items():
            if run.get("error"):
                found = {category: {"cell": "PROBE_ERROR", "match_quality": None,
                                    "leaked": None, "records": 0}
                         for category in sorted(CATEGORIES)}
            else:
                bodies = run["origin_bodies"]
                items, blob = ground_truth(bodies), origin_bytes(bodies)
                turns = origin_turns(bodies)
                found = {category: assess(category, run["records"], items, case["planted"],
                                          run["archive"], blob, sensitive=case["sensitive"],
                                          turns=turns) for category in sorted(CATEGORIES)}
                if _prevented(found, case["planted"], blob):
                    found["tool_output"] = {**found["tool_output"], "cell": "NOT_APPLICABLE",
                                            "match_quality": "prevented_by_route"}
                for category in run.get("unmeasured", ()):
                    if found[category]["cell"] == "NOT_COLLECTED":
                        found[category] = {**found[category], "cell": "PROBE_ERROR",
                                           "match_quality": "async_hook_lost"}
            for category, value in found.items():
                rows.setdefault(category, {})[route] = value
                counts = summary.setdefault(route, {}).setdefault(category, {})
                counts[value["cell"]] = counts.get(value["cell"], 0) + 1
    return {"categories": sorted(CATEGORIES), "cells": cells, "summary": summary}


def judge(case: Case, requests: int, blob: bytes) -> str:
    """Case outcome from origin bytes alone, as the earlier probes judged it."""
    tokens = planted_categories(case)
    if not case.sensitive:  # a control must finish its steps and deliver its tokens
        delivered = all(token in blob for token in tokens.values())
        return "ALLOWED" if requests >= len(case.steps) + 1 and delivered else "BROKEN"
    if not any(token in blob for token in tokens.values()):
        return "STOPPED"
    return "SENT_UNINSPECTED" if set(tokens) <= IMAGE_CATEGORIES else "LEAKED"


def false_positives(records: list[dict]) -> dict:
    """On benign runs: rows a deployment would act on, and protocol-id noise."""
    return {"actionable_non_allow": sum(row["actionable_decision"] in ("REVIEW", "BLOCK")
                                        for row in records),
            "entropy_token_rows": sum("ENTROPY_TOKEN" in row["matched_rule_ids"]
                                      for row in records)}


def decision_rows(records: list[dict], route: str) -> list[dict]:
    """One row per decision: the request envelope (N) or the hook event (H).
    The guard's second call on a body only reuses the first call's decision,
    and a superseding row repeats one, so neither is a decision."""
    records = [row for row in records if not row["extra"].get("superseded_reason")]
    if route == "native":
        return [row for row in records if row["category"] == "request_envelope"
                and not row["extra"].get("duplicate_invocation")]
    return [row for row in records
            if row["decision_point"] != "none" and row["category"] != "tool_output_image"]


def percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile; None without samples."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def latency(records: list[dict], route: str) -> dict:
    values = [row["elapsed_ms"] for row in decision_rows(records, route)]
    return {"decisions": len(values), "p50_ms": percentile(values, 0.50),
            "p95_ms": percentile(values, 0.95)}


def allowed_bytes_equal_origin(records: list[dict], origin_sha256: list[str]) -> bool | None:
    """Every request body Route N released must be byte-identical to one the
    origin received; None when it released nothing."""
    envelopes = [row for row in records if row["category"] == "request_envelope"]
    denied = {row["request_id"] for row in envelopes if not row["released_by_route"]}
    released = [row["request_sha256"] for row in envelopes if row["released_by_route"]
                and row["request_id"] not in denied and row["request_sha256"]]
    return all(digest in set(origin_sha256) for digest in released) if released else None


def _native_gains(matrix: dict) -> list[str]:
    """Must-have categories Route N collected in some case where Route H did not."""
    gains = set()
    for categories in matrix.get("cells", {}).values():
        # A hook that denied the call kept the tool from producing output at all.
        hook_stopped_call = (categories.get("tool_call_args", {}).get("hook", {}).get("cell")
                             == "COLLECTED_BLOCKED")
        for category in MUST_HAVE:
            if category == "tool_output" and hook_stopped_call:
                continue
            routes = categories.get(category, {})
            native = routes.get("native", {}).get("cell", "")
            hook = routes.get("hook", {}).get("cell", "")
            # A lost PreModelRequest row could only ever have been metadata.
            lost = routes.get("hook", {}).get("match_quality") == "async_hook_lost"
            if native.startswith("COLLECTED") and (
                    hook in ("NOT_COLLECTED", "METADATA_ONLY") or lost):
                gains.add(category)
    return sorted(gains)


def _native_only_categories(matrix: dict) -> list[str]:
    found = set()
    for categories in matrix.get("cells", {}).values():
        for category, routes in categories.items():
            if (routes.get("native", {}).get("cell", "").startswith("COLLECTED")
                    and not routes.get("hook", {}).get("cell", "").startswith("COLLECTED")):
                found.add(category)
    return sorted(found)


def recommend(matrix: dict, portability: dict, *, quality: dict | None = None) -> dict:
    """Per build: hook_only | hook_plus_native | native_only | uncollected.

    `quality` is Route N's live evidence on the build under test:
    {"broken_benign", "benign_non_allow", "latency_p95_ms", "allowed_bytes_equal_origin"}.
    Without it Route N cannot earn a place next to Route H."""
    gains = _native_gains(matrix)
    gap = _native_only_categories(matrix)
    quality = quality or {}
    failed = []
    if not gains:
        failed.append("no must-have category gained over hook")
    if quality.get("broken_benign") != 0:
        failed.append("benign runs broken or not measured")
    if quality.get("benign_non_allow") != 0:
        failed.append("benign false positives or not measured")
    p95 = quality.get("latency_p95_ms")
    if p95 is None or p95 >= MAX_NATIVE_P95_MS:
        failed.append("p95 latency over limit or not measured")
    if quality.get("allowed_bytes_equal_origin") is not True:
        failed.append("released bytes not proven equal to origin")
    measured_on = quality.get("backend_sha256")  # live evidence holds for that build only
    verdicts = {}
    for build, facts in portability.get("builds", {}).items():
        hook = facts.get("hook_route") == "available"
        native = facts.get("native_route") == "validated"
        unmeasured = measured_on is not None and facts.get("sha256") != measured_on
        build_failed = (["native live quality not measured on this build",
                         *(f for f in failed if f.startswith("no must-have"))]
                        if unmeasured else failed)
        if hook and native and not build_failed:
            verdict, reasons = "hook_plus_native", [f"native gains {', '.join(gains)}"]
        elif hook:
            verdict = "hook_only"
            missing = ", ".join(gap) or "none measured"
            reasons = (build_failed if native else
                       [f"native route {facts.get('native_route')}; known gap: {missing}"])
        elif native:
            verdict, reasons = "native_only", [f"hook route {facts.get('hook_route')}"]
        else:
            verdict, reasons = "uncollected", [
                f"hook route {facts.get('hook_route')}; native route {facts.get('native_route')}"]
        verdicts[build] = {"verdict": verdict, "reasons": reasons,
                           "hook_route": facts.get("hook_route"),
                           "native_route": facts.get("native_route")}
    return {"native_gains": gains, "native_only_categories": gap,
            "native_conditions_failed": failed, "builds": verdicts}
