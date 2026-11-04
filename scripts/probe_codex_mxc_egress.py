"""Probe fixed Codex MXC offline egress against local non-loopback receivers.

No filter or global Codex setting is changed. All payloads are fresh synthetic
markers sent only to addresses enumerated on this host. A positive unsandboxed
control is required for each TCP/UDP, IPv4/IPv6 result. This probes a separate
fixed CLI command, not the active desktop Local task's effective permissions.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "transpect.codex-mxc-egress/1.0"
ROUTES = ("tcp4", "udp4", "tcp6", "udp6")
POST_CLIENT_OBSERVATION_SECONDS = 2.0


def _address_parts(host: str) -> tuple[int, str, int]:
    address = ipaddress.ip_address(host)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("receiver must use a non-loopback unicast address")
    if address.version == 4:
        return socket.AF_INET, str(address), 0
    scope = address.scope_id
    if address.is_link_local and not scope:
        raise ValueError("link-local IPv6 receiver requires an interface scope")
    if scope and not scope.isdigit():
        raise ValueError("IPv6 interface scope must be a numeric index")
    return socket.AF_INET6, str(address).split("%", 1)[0], int(scope or 0)


def _socket_address(host: str, port: int) -> tuple:
    family, unscoped, scope = _address_parts(host)
    return (unscoped, port) if family == socket.AF_INET else (unscoped, port, 0, scope)


def _local_candidates() -> dict[int, list[str]]:
    command = ("Get-NetIPAddress -ErrorAction Stop | "
               "Where-Object {$_.AddressState -eq 'Preferred' -and "
               "$_.InterfaceAlias -notlike 'Loopback*'} | "
               "Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress")
    result = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=15, check=True)
    rows = json.loads(result.stdout)
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise ValueError("local interface inventory is unavailable")
    candidates: dict[int, list[tuple[bool, str]]] = {4: [], 6: []}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("IPAddress"), str):
            continue
        host = row["IPAddress"]
        try:
            family, _, _ = _address_parts(host)
        except ValueError:
            continue
        version = 4 if family == socket.AF_INET else 6
        prefer_virtual = str(row.get("InterfaceAlias", "")).lower().startswith("vethernet")
        candidates[version].append((not prefer_virtual, host))
    return {version: [host for _, host in sorted(values)]
            for version, values in candidates.items()}


class Sink:
    def __init__(self, host: str, protocol: str):
        family, _, _ = _address_parts(host)
        self.host, self.protocol, self.family = host, protocol, family
        self.sock = socket.socket(family, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.sock.bind(_socket_address(host, 0))
        self.port = self.sock.getsockname()[1]
        if protocol == "tcp":
            self.sock.listen(8)
        self.sock.settimeout(0.1)
        self.records: list[dict] = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _record(self, data: bytes) -> None:
        with self.lock:
            self.records.append({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                if self.protocol == "udp":
                    data, _ = self.sock.recvfrom(4096)
                    self._record(data)
                else:
                    connection, _ = self.sock.accept()
                    with connection:
                        connection.settimeout(0.1)
                        body = bytearray()
                        until = time.monotonic() + 2
                        while not self.stop.is_set() and time.monotonic() < until:
                            try:
                                chunk = connection.recv(4096)
                            except socket.timeout:
                                continue
                            if not chunk:
                                break
                            body.extend(chunk)
                            if len(body) > 4096:
                                break
                        self._record(bytes(body))
            except socket.timeout:
                continue
            except OSError:
                break

    def snapshot(self) -> list[dict]:
        with self.lock:
            return [dict(item) for item in self.records]

    def close(self) -> None:
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=3)


def _marker(nonce: str, phase: str, route: str) -> bytes:
    return f"FAKE_MXC_EGRESS_{nonce}_{phase}_{route}".encode("ascii")


def _attempts(manifest: dict, phase: str, routes: tuple[str, ...]) -> dict:
    result = {}
    for route in routes:
        item = manifest["endpoints"][route]
        host, port = item["host"], item["port"]
        data = _marker(manifest["nonce"], phase, route)
        family, _, _ = _address_parts(host)
        protocol = socket.SOCK_STREAM if route.startswith("tcp") else socket.SOCK_DGRAM
        row = {"attempted": True, "sent_bytes": 0, "error_type": None, "error_code": None}
        try:
            with socket.socket(family, protocol) as client:
                client.settimeout(2)
                client.connect(_socket_address(host, port))
                if protocol == socket.SOCK_STREAM:
                    client.sendall(data)
                    row["sent_bytes"] = len(data)
                else:
                    row["sent_bytes"] = client.send(data)
        except OSError as error:
            row["error_type"] = type(error).__name__
            row["error_code"] = error.winerror if hasattr(error, "winerror") else error.errno
        result[route] = row
    return {"schema": SCHEMA, "phase": phase, "attempts": result}


def _read_manifest(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or value.get("schema") != SCHEMA
            or not isinstance(value.get("nonce"), str) or len(value["nonce"]) != 32
            or not isinstance(value.get("endpoints"), dict)):
        raise ValueError("invalid synthetic MXC manifest")
    for route, item in value["endpoints"].items():
        if (route not in ROUTES or not isinstance(item, dict)
                or not isinstance(item.get("host"), str)
                or not isinstance(item.get("port"), int)
                or not 1 <= item["port"] <= 65535):
            raise ValueError("invalid synthetic MXC endpoint")
        family, _, _ = _address_parts(item["host"])
        if (route.endswith("4") and family != socket.AF_INET
                or route.endswith("6") and family != socket.AF_INET6):
            raise ValueError("MXC endpoint family mismatch")
    return value


def _parse_result(output: str, phase: str) -> dict | None:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("schema") == SCHEMA and value.get("phase") == phase:
            return value
    return None


def _run_client(codex: Path, manifest: Path, phase: str, *, nested: bool = False) -> dict:
    command = [str(codex), "-c", "windows.sandbox=mxc", "sandbox",
               "--include-managed-config", "--permission-profile", ":workspace", "--",
               sys.executable, str(Path(__file__).resolve()),
               "_nested" if nested else "_client", "--manifest", str(manifest),
               "--phase", phase]
    try:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=45, check=False)
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "timed_out": True, "result": None}
    return {"exit_code": completed.returncode, "timed_out": False,
            "result": _parse_result(completed.stdout, phase),
            "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest()}


def classify_route(baseline_ok: bool, run: dict, route: str,
                   new_records: list[dict], marker: bytes) -> str:
    if not baseline_ok:
        return "unvalidated_baseline"
    result = run.get("result")
    if (run.get("exit_code") != 0 or not isinstance(result, dict)
            or not isinstance(result.get("attempts"), dict)
            or result["attempts"].get(route, {}).get("attempted") is not True):
        return "unvalidated_client"
    expected = {"bytes": len(marker), "sha256": hashlib.sha256(marker).hexdigest()}
    if expected in new_records:
        return "egress_reached_receiver"
    if new_records:
        return "unvalidated_other_traffic_or_connection"
    return "blocked_at_receiver"


def _wait_for(sink: Sink, marker: bytes, seconds: float = 2.5) -> bool:
    expected = {"bytes": len(marker), "sha256": hashlib.sha256(marker).hexdigest()}
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if expected in sink.snapshot():
            return True
        time.sleep(0.02)
    return expected in sink.snapshot()


def _select_family(candidates: list[str], version: int, nonce: str) -> tuple[dict[str, Sink], dict, list[dict]]:
    names = (f"tcp{version}", f"udp{version}")
    failures = []
    for host in candidates:
        sinks: dict[str, Sink] = {}
        selected = False
        try:
            for name in names:
                sinks[name] = Sink(host, name[:3])
            manifest = {"schema": SCHEMA, "nonce": nonce,
                        "endpoints": {name: {"host": host, "port": sink.port}
                                      for name, sink in sinks.items()}}
            attempt = _attempts(manifest, "baseline", names)
            passed = all(attempt["attempts"][name]["sent_bytes"] ==
                         len(_marker(nonce, "baseline", name))
                         and _wait_for(sinks[name], _marker(nonce, "baseline", name))
                         for name in names)
            if passed:
                selected = True
                return sinks, attempt, failures
            failures.append({"address": host, "reason": "positive_control_not_received"})
        except OSError as error:
            failures.append({"address": host, "reason": type(error).__name__})
        finally:
            if not selected:
                for sink in sinks.values():
                    sink.close()
    return {}, {"schema": SCHEMA, "phase": "baseline", "attempts": {}}, failures


def run_probe(codex: Path, output: Path, ipv4: str | None, ipv6: str | None) -> dict:
    if sys.platform != "win32":
        raise RuntimeError("MXC probe requires Windows")
    sys.path.insert(0, str(ROOT / "src"))
    from transpect_trace.guard.desktop import PINNED_BACKEND_SHA256

    codex = codex.resolve(strict=True)
    with codex.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != PINNED_BACKEND_SHA256:
            raise ValueError("Codex CLI differs from the pinned desktop build")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inventory_error = None
    try:
        discovered = _local_candidates()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        discovered = {4: [], 6: []}
        inventory_error = type(error).__name__
    nonce = uuid4().hex
    sinks: dict[str, Sink] = {}
    baseline: dict[str, dict] = {}
    failures: dict[str, list[dict]] = {}
    try:
        for version, requested in ((4, ipv4), (6, ipv6)):
            assigned = requested is None or requested in discovered[version]
            choices = ([requested] if requested else discovered[version]) if assigned else []
            selected, result, failed = _select_family(choices, version, nonce)
            sinks.update(selected)
            baseline.update(result["attempts"])
            failures[f"ipv{version}"] = failed + (
                [{"address": requested, "reason": "not_assigned_to_host"}]
                if not assigned else [])
        manifest = {"schema": SCHEMA, "nonce": nonce,
                    "endpoints": {name: {"host": sink.host, "port": sink.port}
                                  for name, sink in sinks.items()}}
        manifest_path = output / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        before = {name: len(sink.snapshot()) for name, sink in sinks.items()}
        sandbox = _run_client(codex, manifest_path, "sandbox") if sinks else {"result": None}
        time.sleep(POST_CLIENT_OBSERVATION_SECONDS)
        routes = {}
        for name in ROUTES:
            sink = sinks.get(name)
            if sink is None:
                routes[name] = {"status": "unvalidated_baseline"}
                continue
            records = sink.snapshot()[before[name]:]
            marker = _marker(nonce, "sandbox", name)
            routes[name] = {"status": classify_route(True, sandbox, name, records, marker),
                            "received_bytes": sum(row["bytes"] for row in records),
                            "receiver_connections_or_datagrams": len(records),
                            "child_outcome": (sandbox.get("result") or {}).get("attempts", {}).get(name)}
        nested = {"status": "unvalidated_baseline"}
        if "tcp4" in sinks:
            previous = len(sinks["tcp4"].snapshot())
            nested_run = _run_client(codex, manifest_path, "nested", nested=True)
            time.sleep(POST_CLIENT_OBSERVATION_SECONDS)
            records = sinks["tcp4"].snapshot()[previous:]
            child = (nested_run.get("result") or {}).get("child")
            nested_for_classification = {
                "exit_code": nested_run.get("exit_code") if isinstance(child, dict) else None,
                "result": child,
            }
            nested = {"status": classify_route(True, nested_for_classification, "tcp4", records,
                                               _marker(nonce, "nested", "tcp4")),
                      "received_bytes": sum(row["bytes"] for row in records),
                      "child_started": isinstance(child, dict),
                      "child_exit_code": (nested_run.get("result") or {}).get("child_exit_code"),
                      "child_outcome": (child or {}).get("attempts", {}).get("tcp4")}
            if nested["child_exit_code"] != 0:
                nested["status"] = "unvalidated_client"
        report = {"schema": SCHEMA, "fixed_codex_sha256": PINNED_BACKEND_SHA256,
                  "scope": "separate_fixed_cli_mxc_offline_not_active_desktop",
                  "baseline_positive": {name: name in sinks for name in ROUTES},
                  "baseline_attempts": baseline, "candidate_failures": failures,
                  "inventory_error_type": inventory_error,
                  "baseline_receipts": {
                      name: [row for row in sink.snapshot()
                             if row["sha256"] == hashlib.sha256(
                                 _marker(nonce, "baseline", name)).hexdigest()]
                      for name, sink in sinks.items()},
                  "sandbox_exit_code": sandbox.get("exit_code"),
                  "sandbox_stdout_parsed": isinstance(sandbox.get("result"), dict),
                  "routes": routes, "nested_tcp4": nested,
                  "post_client_observation_ms": int(POST_CLIENT_OBSERVATION_SECONDS * 1000),
                  "desktop_local_task_mxc_attested": False,
                  "interpretation": "Only a separate fixed CLI MXC offline process was tested; the active desktop Local task must independently attest MXC and effective no-network permissions before this can support its tool-egress claim.",
                  "all_four_blocked": all(row["status"] == "blocked_at_receiver"
                                          for row in routes.values())}
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report
    finally:
        for sink in sinks.values():
            sink.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    runner = sub.add_parser("run")
    runner.add_argument("--codex", type=Path, required=True)
    runner.add_argument("--output", type=Path, required=True)
    runner.add_argument("--ipv4")
    runner.add_argument("--ipv6")
    for name in ("_client", "_nested"):
        hidden = sub.add_parser(name)
        hidden.add_argument("--manifest", type=Path, required=True)
        hidden.add_argument("--phase", required=True)
    args = parser.parse_args()
    if args.command == "run":
        report = run_probe(args.codex, args.output, args.ipv4, args.ipv6)
        print(json.dumps({"routes": report["routes"], "nested_tcp4": report["nested_tcp4"],
                          "all_four_blocked": report["all_four_blocked"]}, indent=2))
    elif args.command == "_client":
        manifest = _read_manifest(args.manifest)
        names = tuple(manifest["endpoints"]) if args.phase == "sandbox" else ("tcp4",)
        print(json.dumps(_attempts(manifest, args.phase, names), separators=(",", ":")))
    else:
        manifest = _read_manifest(args.manifest)
        if "tcp4" not in manifest["endpoints"]:
            raise ValueError("nested probe requires TCP IPv4 positive control")
        command = [sys.executable, str(Path(__file__).resolve()), "_client",
                   "--manifest", str(args.manifest), "--phase", args.phase]
        child = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=15, check=False)
        print(json.dumps({"schema": SCHEMA, "phase": args.phase,
                          "child_exit_code": child.returncode,
                          "child": _parse_result(child.stdout, args.phase)}, separators=(",", ":")))


if __name__ == "__main__":
    main()
