"""VM-only raw-socket receiver and client for dedicated-user WFP validation.

Run `serve` under the VM administrator and `client` under the dedicated Codex
user. The receiver never forwards data and stores counts/hashes, not payloads.
Its zero-byte receipts, rather than client-side send errors, are authoritative.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import threading
import time
from uuid import uuid4


CASES = (("tcp4", socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1"),
         ("udp4", socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1"),
         ("tcp6", socket.AF_INET6, socket.SOCK_STREAM, "::1"),
         ("udp6", socket.AF_INET6, socket.SOCK_DGRAM, "::1"))


class Sink:
    def __init__(self, name: str, family: int, kind: int, host: str):
        self.name, self.family, self.kind, self.host = name, family, kind, host
        self.socket = socket.socket(family, kind)
        if family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.socket.bind((host, 0))
        if kind == socket.SOCK_STREAM:
            self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.received_bytes = 0
        self.received_chunks = 0
        self.sha256 = hashlib.sha256()
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _record(self, data: bytes) -> None:
        with self.lock:
            self.received_bytes += len(data)
            self.received_chunks += 1
            self.sha256.update(data)

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                if self.kind == socket.SOCK_DGRAM:
                    data, _ = self.socket.recvfrom(65536)
                    self._record(data)
                else:
                    conn, _ = self.socket.accept()
                    with conn:
                        conn.settimeout(0.2)
                        while not self.stop.is_set():
                            try:
                                data = conn.recv(65536)
                            except socket.timeout:
                                continue
                            if not data:
                                break
                            self._record(data)
            except socket.timeout:
                continue
            except OSError:
                break

    def snapshot(self) -> dict:
        with self.lock:
            return {"name": self.name, "received_bytes": self.received_bytes,
                    "received_chunks": self.received_chunks,
                    "received_sha256": self.sha256.hexdigest() if self.received_bytes else None}

    def close(self) -> None:
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=2)


class Receiver:
    def __init__(self):
        self.sinks = []
        try:
            for case in CASES:
                self.sinks.append(Sink(*case))
        except OSError:
            for sink in self.sinks:
                sink.socket.close()
            raise
        for sink in self.sinks:
            sink.start()

    def manifest(self) -> dict:
        return {"schema": "transpect.desktop-wfp-probe/1.0", "forwarding": False,
                "endpoints": {sink.name: {"host": sink.host, "port": sink.port}
                              for sink in self.sinks}}

    def snapshot(self) -> dict:
        rows = {sink.name: sink.snapshot() for sink in self.sinks}
        return {"schema": "transpect.desktop-wfp-receipts/1.0", "forwarding": False,
                "endpoints": rows, "all_received_zero": all(row["received_bytes"] == 0 for row in rows.values())}

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()


def send_probes(manifest: dict, *, marker: bytes | None = None) -> dict:
    if manifest.get("schema") != "transpect.desktop-wfp-probe/1.0":
        raise ValueError("invalid probe manifest")
    payload = marker if marker is not None else f"FAKE_WFP_PROBE_{uuid4().hex}".encode()
    if not payload.startswith(b"FAKE_WFP_PROBE_") or len(payload) > 1024:
        raise ValueError("only bounded synthetic markers are allowed")
    attempts = {}
    for name, family, kind, host in CASES:
        endpoint = manifest["endpoints"][name]
        if endpoint["host"] != host or not 1 <= endpoint["port"] <= 65535:
            raise ValueError("probe destination must be loopback")
        row = {"local_send_succeeded": False, "local_error": None}
        with socket.socket(family, kind) as client:
            client.settimeout(1)
            try:
                if kind == socket.SOCK_STREAM:
                    client.connect((host, endpoint["port"]))
                    client.sendall(payload)
                else:
                    client.sendto(payload, (host, endpoint["port"]))
                row["local_send_succeeded"] = True
            except OSError as error:
                row["local_error"] = type(error).__name__
        attempts[name] = row
    return {"schema": "transpect.desktop-wfp-attempts/1.0", "synthetic_marker_sha256": hashlib.sha256(payload).hexdigest(),
            "synthetic_marker_bytes": len(payload), "attempts": attempts,
            "interpretation": "only receiver-side byte counts prove denial"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("serve", "client"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, default=20)
    parser.add_argument("--attempts-output", type=Path)
    parser.add_argument("--isolated-vm", action="store_true")
    args = parser.parse_args()
    if not args.isolated_vm:
        parser.error("this probe is for an isolated Windows VM only")
    directory = args.directory.resolve()
    if args.mode == "serve":
        if not 1 <= args.duration_seconds <= 300:
            parser.error("duration must be 1–300 seconds")
        directory.mkdir(parents=True, exist_ok=False)
        receiver = Receiver()
        manifest = receiver.manifest()
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"ready": True, "manifest": str(directory / "manifest.json")}), flush=True)
        try:
            time.sleep(args.duration_seconds)
        except KeyboardInterrupt:
            pass
        finally:
            receiver.close()
            (directory / "receipts.json").write_text(json.dumps(receiver.snapshot(), indent=2) + "\n", encoding="utf-8")
    else:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        attempts = send_probes(manifest)
        if args.attempts_output:
            args.attempts_output.write_text(json.dumps(attempts, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(attempts), flush=True)


if __name__ == "__main__":
    main()
