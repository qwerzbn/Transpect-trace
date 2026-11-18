"""Isolated HTTPS acceptance probe for the pinned Claude Code native guard.

The child gets a temporary home, temporary Claude config, synthetic credentials,
and a local HTTPS origin that never forwards traffic. Only summaries are printed.
The local origin replies 403 after a permitted model request reaches it.

Requires the lab DLL build dependencies and an ``openssl`` executable on PATH.
Run ``python scripts/probe_claude_inprocess_lab.py`` on Windows.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import claude_service as lab  # noqa: E402
from transpect_trace.protect.archive import EncryptedRequestArchive  # noqa: E402


FAKE_KEY = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SAFE_TAIL = "The weather is mild today."
PADDING = "benign isolated test context\n" * 1800
MAX_WIRE_BYTES = 2 * 1024 * 1024
CERT_CONFIG = """[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_req
[dn]
CN = localhost
[v3_req]
subjectAltName = IP:127.0.0.1,DNS:localhost
basicConstraints = CA:TRUE
keyUsage = digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage = serverAuth
"""


@dataclass(frozen=True)
class Case:
    name: str
    auth: str
    system: str
    marker: str
    denied: bool
    long_body: bool


CASES = (
    Case("short_bearer_allow", "bearer", "You are concise.",
         "sunny day", False, False),
    Case("long_bearer_allow", "bearer", PADDING + SAFE_TAIL,
         SAFE_TAIL, False, True),
    Case("long_bearer_deny", "bearer", PADDING + FAKE_KEY,
         FAKE_KEY, True, True),
    Case("short_key_allow", "api_key", "You are concise.",
         "sunny day", False, False),
    Case("long_key_allow", "api_key", PADDING + SAFE_TAIL,
         SAFE_TAIL, False, True),
    Case("long_key_deny", "api_key", PADDING + FAKE_KEY,
         FAKE_KEY, True, True),
)


class LocalTlsOrigin:
    """Record decrypted bytes, including a partial request, without forwarding."""

    def __init__(self, directory: Path, openssl: str, auth: str, marker: str):
        config = directory / "openssl.cnf"
        cert = directory / "cert.pem"
        key = directory / "key.pem"
        config.write_text(CERT_CONFIG, encoding="ascii")
        command = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                   "-keyout", str(key), "-out", str(cert), "-days", "1",
                   "-config", str(config)]
        openssl_env = {name: value for name, value in os.environ.items()
                       if name.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}}
        openssl_env["OPENSSL_CONF"] = str(config)
        result = subprocess.run(command, capture_output=True, text=True,
                                env=openssl_env)
        if result.returncode:
            raise RuntimeError(f"openssl certificate generation failed: {result.stderr[-400:]}")
        self.cert = cert
        self.auth = auth
        self.marker = marker.encode("utf-8")
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.records: list[dict] = []
        self.workers: list[threading.Thread] = []
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self._handle, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _handle(self, connection: socket.socket) -> None:
        data = bytearray()
        complete = False
        body = b""
        auth_matches = False
        try:
            with self.context.wrap_socket(connection, server_side=True) as secure:
                secure.settimeout(3)
                while len(data) <= MAX_WIRE_BYTES:
                    try:
                        part = secure.recv(65536)
                    except (socket.timeout, OSError):
                        break
                    if not part:
                        break
                    data.extend(part)
                    end = data.find(b"\r\n\r\n")
                    if end < 0:
                        continue
                    header = bytes(data[:end]).split(b"\r\n")
                    first_line = header[0]
                    if first_line.startswith(b"HEAD "):
                        complete = True
                        secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        break
                    if first_line.startswith(b"GET /inference-profiles"):
                        complete = True
                        response = b'{"inferenceProfileSummaries":[]}'
                        secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                       + f"Content-Length: {len(response)}\r\nConnection: close\r\n\r\n".encode()
                                       + response)
                        break
                    if not first_line.startswith(b"POST "):
                        break
                    fields = {}
                    for line in header[1:]:
                        name, sep, value = line.partition(b":")
                        if sep:
                            fields[name.lower()] = value.strip()
                    try:
                        length = int(fields[b"content-length"])
                    except (KeyError, ValueError):
                        break
                    if length < 0 or length > MAX_WIRE_BYTES:
                        break
                    if len(data) < end + 4 + length:
                        continue
                    body = bytes(data[end + 4:end + 4 + length])
                    expected = (b"Bearer synthetic-lab-token" if self.auth == "bearer"
                                else b"synthetic-lab-api-key")
                    credential = (fields.get(b"authorization") if self.auth == "bearer"
                                  else fields.get(b"x-api-key"))
                    auth_matches = credential == expected
                    complete = True
                    response = (b'{"type":"error","error":{"type":"permission_error",'
                                b'"message":"isolated lab upstream"}}')
                    secure.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                                   + f"Content-Length: {len(response)}\r\nConnection: close\r\n\r\n".encode()
                                   + response)
                    break
        except (OSError, ssl.SSLError):
            pass
        finally:
            # Record even an incomplete POST. Counting only complete requests
            # would miss a sensitive prefix sent before a later fail-stop.
            raw = bytes(data)
            first = raw.split(b"\r\n", 1)[0]
            record = {"app_bytes": len(raw), "starts_post": first.startswith(b"POST "),
                      "request_line": first[:256].decode("ascii", "replace"),
                      "complete": complete, "body_bytes": len(body),
                      "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
                      "marker_offset": body.find(self.marker) if body else -1,
                      "auth_matches": auth_matches}
            with self.lock:
                self.records.append(record)
            connection.close()

    def snapshot(self) -> list[dict]:
        with self.lock:
            return [dict(record) for record in self.records]

    def close(self) -> None:
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=4)


def isolated_env(directory: Path, origin: LocalTlsOrigin, auth: str) -> dict[str, str]:
    """Allowlist inherited variables so no saved or shell credential can leak."""
    keep = {"SYSTEMROOT", "WINDIR", "PATH", "COMSPEC", "PATHEXT",
            "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS"}
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    for name in ("USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME",
                 "TEMP", "TMP", "CLAUDE_CONFIG_DIR"):
        env[name] = str(directory)
    env.update({"ANTHROPIC_BASE_URL": f"https://127.0.0.1:{origin.port}",
                "NODE_EXTRA_CA_CERTS": str(origin.cert), "DISABLE_TELEMETRY": "1",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_GZIP_REQUEST_BODIES": "0",
                "CLAUDE_CODE_MAX_RETRIES": "0"})
    env["ANTHROPIC_AUTH_TOKEN" if auth == "bearer" else "ANTHROPIC_API_KEY"] = (
        "synthetic-lab-token" if auth == "bearer" else "synthetic-lab-api-key")
    # Claude Code reads the isolated file even if a future build changes its
    # environment-precedence behavior. It contains only synthetic values.
    (directory / "settings.json").write_text(
        json.dumps({"env": {key: env[key] for key in (
            "ANTHROPIC_BASE_URL", "NODE_EXTRA_CA_CERTS",
            "ANTHROPIC_AUTH_TOKEN" if auth == "bearer" else "ANTHROPIC_API_KEY")}}),
        encoding="utf-8")
    return env


def run_case(case: Case, binary: Path, openssl: str) -> dict:
    # Claude includes its current directory in a system message. Do not put
    # auth words such as "bearer" in the random directory name: the production
    # entropy rule would correctly treat that path as suspicious context.
    with tempfile.TemporaryDirectory(prefix="ttrace-cc-lab-") as temp:
        directory = Path(temp)
        system = directory / "system.txt"
        system.write_text(case.system, encoding="utf-8")
        origin = LocalTlsOrigin(directory, openssl, case.auth, case.marker)
        try:
            env = isolated_env(directory, origin, case.auth)
            prompt = f"Reply briefly. {case.marker if not case.long_body else 'OK'}".encode()
            state = directory / "state"
            exit_code = lab.run_print(
                prompt, binary=binary, state_dir=state, child_env=env,
                child_cwd=directory,
                child_args=("--tools", "", "--system-prompt-file", str(system)))
            origin.close()  # join workers so a partial POST is recorded too
            records = origin.snapshot()
            run_dirs = list((state / "runs").iterdir())
            if len(run_dirs) != 1:
                raise AssertionError(f"expected one native run directory, found {len(run_dirs)}")
            run_dir = run_dirs[0]
            audit = run_dir / "native-audit.jsonl"
            rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            envelopes = [row for row in rows if row.get("route_event") == "model.request"
                         and row.get("category") == "request_envelope"]
            if len(envelopes) != 1:
                raise AssertionError(f"expected one DLP envelope, found {len(envelopes)}")
            row = envelopes[0]
            receipt, archived = EncryptedRequestArchive(run_dir / "archive").read(
                row["archive_record_id"])
            digest = hashlib.sha256(archived).hexdigest()
            marker_offset = archived.find(case.marker.encode())
            expected_decision = "deny" if case.denied else "allow"
            if row["decision"] != expected_decision:
                collection = run_dir / "collection.jsonl"
                blocked = []
                if collection.exists():
                    for line in collection.read_text(encoding="utf-8").splitlines():
                        item = json.loads(line)
                        if item.get("actionable_decision") == "BLOCK":
                            blocked.append({"category": item.get("category"),
                                            "location": item.get("location"),
                                            "rules": item.get("matched_rule_ids")})
                raise AssertionError(f"DLP decision was {row['decision']} "
                                     f"({row.get('reason')}), expected {expected_decision}; "
                                     f"blocked={blocked[:4]}")
            if digest != row["request_sha256"] or digest != receipt.body_sha256:
                raise AssertionError("DLP audit and encrypted archive hashes differ")
            if len(archived) != row["content_bytes"]:
                raise AssertionError("DLP body length differs from encrypted archive")
            if case.long_body != (len(archived) > 32768):
                raise AssertionError("request body missed the intended TLS chunk size")
            if marker_offset < 0 or (case.long_body and marker_offset <= 32768):
                raise AssertionError("synthetic marker is absent or not in a later chunk")
            post_records = [record for record in records if record["starts_post"]]
            if case.denied:
                if any(record["app_bytes"] for record in records):
                    raise AssertionError("denied request sent TLS application bytes upstream")
            else:
                if len(post_records) != 1 or not post_records[0]["complete"]:
                    raise AssertionError("allowed request did not reach the local HTTPS origin")
                upstream = post_records[0]
                if (upstream["body_sha256"] != digest or upstream["body_bytes"] != len(archived)
                        or upstream["marker_offset"] != marker_offset
                        or not upstream["auth_matches"]):
                    raise AssertionError("upstream, DLP, or archive summaries differ")
            return {"case": case.name, "exit": exit_code, "decision": row["decision"],
                    "body_bytes": len(archived), "marker_offset": marker_offset,
                    "audit_sha256": row["request_sha256"], "archive_sha256": digest,
                    "upstream_sha256": post_records[0]["body_sha256"] if post_records else None,
                    "upstream_app_bytes": sum(record["app_bytes"] for record in records)}
        finally:
            origin.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=None,
                        help="byte-identical pinned Claude Code 2.1.317 executable")
    parser.add_argument("--case", action="append", choices=[case.name for case in CASES],
                        help="run selected case; repeat to select more")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("the native guard and encrypted archive require Windows")
    openssl = shutil.which("openssl")
    if not openssl:
        parser.error("openssl is required for the isolated HTTPS certificate")
    binary = (args.binary or lab.installed_claude()).resolve(strict=True)
    lab.check_binary(lab.load_pin(), binary)
    selected = [case for case in CASES if not args.case or case.name in args.case]
    failed = False
    for case in selected:
        try:
            result = run_case(case, binary, openssl)
            print(json.dumps({"result": "PASS", **result}, sort_keys=True), flush=True)
        except Exception as error:
            failed = True
            print(json.dumps({"result": "FAIL", "case": case.name,
                              "error": f"{type(error).__name__}: {error}"}),
                  file=sys.stderr, flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
