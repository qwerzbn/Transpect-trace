"""Synthetic local receiver for one current-desktop Agent tool egress attempt.

This does not change Codex permissions or firewall rules. The receiver binds
only addresses already assigned to this host, excluding loopback, and checks
an independent positive control before an Agent tool client is requested.
Reports contain counts, hashes, and error types, never received payload bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

import probe_codex_mxc_egress as mxc


SCHEMA = "transpect.desktop-current-tool-egress/1.0"
PHASE = "desktop_tool"
POST_CLIENT_OBSERVATION_SECONDS = 2.0


def _write_exclusive(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def validate_local_manifest(path: Path) -> dict:
    """The client must never send to an address not assigned to this host."""
    manifest = mxc._read_manifest(path)
    if not manifest["endpoints"]:
        raise ValueError("no local receiver endpoints")
    local = mxc._local_candidates()
    for route, endpoint in manifest["endpoints"].items():
        version = 4 if route.endswith("4") else 6
        if endpoint["host"] not in local[version]:
            raise ValueError("receiver address is not assigned to this host")
    return manifest


def _read_client_report(path: Path, manifest: dict) -> dict | None:
    try:
        if path.stat().st_size > 64 * 1024:
            return None
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if (not isinstance(report, dict) or report.get("schema") != SCHEMA
            or report.get("phase") != PHASE
            or report.get("nonce_sha256") != hashlib.sha256(
                manifest["nonce"].encode("ascii")).hexdigest()
            or not isinstance(report.get("attempts"), dict)
            or set(report["attempts"]) != set(manifest["endpoints"])):
        return None
    return report


def classify_routes(manifest: dict, baseline_positive: dict[str, bool],
                    client_report: dict | None,
                    new_records: dict[str, list[dict]]) -> dict[str, dict]:
    """Zero received bytes count only when baseline and client attempt exist."""
    routes = {}
    for route in mxc.ROUTES:
        if route not in manifest["endpoints"]:
            routes[route] = {"status": "unvalidated_baseline"}
            continue
        records = new_records.get(route, [])
        if not isinstance(records, list):
            raise ValueError("invalid receiver records")
        marker = mxc._marker(manifest["nonce"], PHASE, route)
        attempt = ((client_report or {}).get("attempts") or {}).get(route)
        run = {"exit_code": 0 if client_report is not None else None,
               "result": {"attempts": {route: attempt}} if attempt is not None else None}
        status = mxc.classify_route(bool(baseline_positive.get(route)), run,
                                    route, records, marker)
        routes[route] = {
            "status": status,
            "received_bytes": sum(int(row["bytes"]) for row in records),
            "receiver_connections_or_datagrams": len(records),
            "client_attempted": isinstance(attempt, dict) and attempt.get("attempted") is True,
            "client_error_type": attempt.get("error_type") if isinstance(attempt, dict) else None,
        }
    return routes


def run_client(manifest_path: Path) -> dict:
    manifest = validate_local_manifest(manifest_path)
    report_path = manifest_path.parent / "client-report.json"
    if report_path.exists():
        raise ValueError("this local egress fixture was already used")
    attempted = mxc._attempts(manifest, PHASE, tuple(manifest["endpoints"]))
    report = {
        "schema": SCHEMA,
        "phase": PHASE,
        "nonce_sha256": hashlib.sha256(manifest["nonce"].encode("ascii")).hexdigest(),
        "client_pid": os.getpid(),
        "attempts": attempted["attempts"],
    }
    _write_exclusive(report_path, report)
    return {"schema": SCHEMA, "client_report_written": True,
            "client_pid": report["client_pid"], "routes_attempted": sorted(report["attempts"])}


def run_server(output: Path, seconds: int) -> dict:
    if sys.platform != "win32":
        raise RuntimeError("current desktop egress test requires Windows")
    if not 10 <= seconds <= 120:
        raise ValueError("receiver duration must be 10..120 seconds")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    nonce = uuid4().hex
    sinks: dict[str, mxc.Sink] = {}
    baseline: dict[str, bool] = {}
    failures: dict[str, list[dict]] = {}
    try:
        candidates = mxc._local_candidates()
        for version in (4, 6):
            selected, _, failed = mxc._select_family(candidates[version], version, nonce)
            sinks.update(selected)
            failures[f"ipv{version}"] = failed
            for route in selected:
                baseline[route] = True
        manifest = {
            "schema": mxc.SCHEMA,
            "nonce": nonce,
            "endpoints": {route: {"host": sink.host, "port": sink.port}
                          for route, sink in sinks.items()},
        }
        manifest_path = output / "manifest.json"
        _write_exclusive(manifest_path, manifest)
        before = {route: len(sink.snapshot()) for route, sink in sinks.items()}
        if sinks:
            print(f"Desktop tool egress receiver ready for {seconds}s: {manifest_path}",
                  flush=True)
            until = time.monotonic() + seconds
            while time.monotonic() < until and not (output / "client-report.json").exists():
                time.sleep(0.05)
            if (output / "client-report.json").exists():
                time.sleep(POST_CLIENT_OBSERVATION_SECONDS)
        report_path = output / "client-report.json"
        client = _read_client_report(report_path, manifest) if report_path.exists() else None
        new_records = {route: sink.snapshot()[before[route]:] for route, sink in sinks.items()}
        routes = classify_routes(manifest, baseline, client, new_records)
        result = {
            "schema": SCHEMA,
            "scope": "current_desktop_local_tool_synthetic_receiver_only",
            "client_report_present_and_valid": client is not None,
            "client_invocation_from_desktop_attested_by_report_alone": False,
            "baseline_positive": {route: baseline.get(route, False) for route in mxc.ROUTES},
            "baseline_candidate_failures": failures,
            "routes": routes,
            "all_four_reached_receiver": all(
                routes[route]["status"] == "egress_reached_receiver" for route in mxc.ROUTES),
            "all_four_blocked_at_receiver": all(
                routes[route]["status"] == "blocked_at_receiver" for route in mxc.ROUTES),
            "desktop_tool_network_boundary_attested": False,
            "interpretation": (
                "Correlate the client PID and invocation with the Local chat tool record. "
                "Four route results are limited to this host's non-loopback receivers. "
                "A positive reach result disproves default-deny for the tested tool; "
                "a zero-byte result does not prove all egress is blocked."
            ),
        }
        _write_exclusive(output / "report.json", result)
        return result
    finally:
        for sink in sinks.values():
            sink.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Run local non-loopback receivers and positive controls")
    serve.add_argument("--output", type=Path, required=True)
    serve.add_argument("--seconds", type=int, default=90)
    client = sub.add_parser("client", help="Attempt only the local manifest endpoints")
    client.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "serve":
        result = run_server(args.output, args.seconds)
        print(json.dumps({"routes": result["routes"],
                          "all_four_reached_receiver": result["all_four_reached_receiver"],
                          "all_four_blocked_at_receiver": result["all_four_blocked_at_receiver"]},
                         indent=2))
    else:
        print(json.dumps(run_client(args.manifest), indent=2))


if __name__ == "__main__":
    main()
