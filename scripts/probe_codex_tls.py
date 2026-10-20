"""Probe the installed Codex's TLS key export against an isolated TLS origin.

No proxy, real account, model service, OS certificate install, or DLL injection.
The origin captures wire bytes before TLS and logs its own synthetic-session
keys as an independent offline-decryption control. Those server keys are NOT
available to a passive observer of an actual model connection.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import threading
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import NameOID


def certificate(root: Path) -> tuple[Path, Path, Path]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Transpect probe CA")])
    now = dt.datetime.now(dt.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=1))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256()))
    cert_path, key_path = root / "origin-cert.pem", root / "origin-key.pem"
    ca_path = root / "origin-ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return cert_path, key_path, ca_path


def events() -> list[dict]:
    item = {"id": "msg_probe", "type": "message", "role": "assistant",
            "status": "completed", "content": [{"type": "output_text",
            "text": "TLS probe received.", "annotations": []}]}
    response = {"id": "resp_probe", "object": "response", "model": "gpt-probe",
                "status": "completed", "output": [item],
                "usage": {"input_tokens": 1, "output_tokens": 1,
                          "total_tokens": 2}}
    return [{"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
            {"type": "response.completed", "response": response}]


class Origin:
    def __init__(self, root: Path, cert: Path, key: Path, marker: bytes, event_factory=None):
        self.root, self.marker = root, marker
        self.event_factory = event_factory or (lambda payload: events())
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(cert, key)
        self.context.keylog_filename = str(root / "origin-session.keys")
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.records: list[dict] = []
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(12)
                row = {"connection": len(self.records) + 1}
                self.records.append(row)
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                tls = self.context.wrap_bio(incoming, outgoing, server_side=True)
                wire = bytearray()

                def flush():
                    data = outgoing.read()
                    if data:
                        conn.sendall(data)

                def feed():
                    data = conn.recv(65536)
                    if not data:
                        raise EOFError("client closed")
                    wire.extend(data)
                    incoming.write(data)

                def read():
                    while True:
                        try:
                            return tls.read(65536)
                        except ssl.SSLWantReadError:
                            flush()
                            feed()

                def write(data):
                    tls.write(data)
                    flush()

                try:
                    while True:
                        try:
                            tls.do_handshake()
                            flush()
                            break
                        except ssl.SSLWantReadError:
                            flush()
                            feed()
                    row.update(tls_version=tls.version(), cipher=tls.cipher()[0])
                    plain = bytearray()
                    while b"\r\n\r\n" not in plain:
                        plain.extend(read())
                    header, payload = bytes(plain).split(b"\r\n\r\n", 1)
                    lines = header.decode().split("\r\n")
                    headers = {name.lower(): value for name, value in
                               (line.split(":", 1) for line in lines[1:])}
                    if headers.get("upgrade", "").strip() == "websocket":
                        row["protocol"] = "websocket"
                        row["wss_wire_body_bytes_received"] = len(payload)
                        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"].strip()
                                    + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                        write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
                        buffered = bytearray(payload)
                        message = bytearray()
                        def take(n):
                            while len(buffered) < n:
                                chunk=read();row["wss_wire_body_bytes_received"]+=len(chunk);buffered.extend(chunk)
                            data = bytes(buffered[:n]); del buffered[:n]
                            return data
                        while True:
                            first, second = take(2)
                            length = second & 127
                            if length == 126:
                                length = struct.unpack("!H", take(2))[0]
                            elif length == 127:
                                length = struct.unpack("!Q", take(8))[0]
                            mask = take(4) if second & 128 else b""
                            frame = take(length)
                            if mask:
                                frame = bytes(x ^ mask[i % 4] for i, x in enumerate(frame))
                            if first & 15 in (0, 1, 2):
                                message.extend(frame)
                                if first & 128:
                                    break
                        payload = bytes(message)
                        for event in self.event_factory(payload):
                            data = json.dumps(event).encode()
                            prefix = bytes([0x81, len(data)]) if len(data) < 126 else b"\x81\x7e" + struct.pack("!H", len(data))
                            write(prefix + data)
                    else:
                        row["protocol"] = "http"
                        row["http_body_bytes_received"] = len(payload)
                        length = int(headers.get("content-length", 0))
                        while len(payload) < length:
                            chunk=read();row["http_body_bytes_received"]+=len(chunk);payload += chunk
                        body = b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in self.event_factory(payload))
                        write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                    row.update(request_line=lines[0], payload_bytes=len(payload),
                               payload_sha256=hashlib.sha256(payload).hexdigest(),
                               marker_in_origin_payload=self.marker in payload)
                except Exception as exc:
                    row["error"] = f"{type(exc).__name__}: {exc}"
                finally:
                    path = self.root / f"client-wire-{row['connection']}.bin"
                    path.write_bytes(wire)
                    row.update(wire_file=path.name, wire_bytes=len(wire), marker_in_wire=self.marker in wire)


def decrypt_control(wire: bytes, keylog: Path, cipher: str, marker: bytes) -> dict:
    """Decrypt captured client TLS 1.3 records using the origin's control keys."""
    lines = [x.split() for x in keylog.read_text().splitlines() if x and not x.startswith("#")]
    secrets = [bytes.fromhex(x[2]) for x in lines if x[0] == "CLIENT_TRAFFIC_SECRET_0"]
    algorithm = hashes.SHA384() if "AES_256" in cipher else hashes.SHA256()
    key_size = 32 if "AES_256" in cipher or "CHACHA20" in cipher else 16
    def expand(secret, label, size):
        label = b"tls13 " + label
        info = struct.pack("!H", size) + bytes([len(label)]) + label + b"\0"
        return HKDFExpand(algorithm=algorithm, length=size, info=info).derive(secret)
    for secret in secrets:
        key, iv = expand(secret, b"key", key_size), expand(secret, b"iv", 12)
        aead = ChaCha20Poly1305(key) if "CHACHA20" in cipher else AESGCM(key)
        offset, sequence, successes = 0, 0, 0
        application = bytearray()
        while offset + 5 <= len(wire):
            header = wire[offset:offset + 5]
            length = int.from_bytes(header[3:5], "big")
            record = wire[offset + 5:offset + 5 + length]
            offset += 5 + length
            if len(record) != length or header[0] != 23:
                continue
            nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
            try:
                inner = aead.decrypt(nonce, record, header).rstrip(b"\0")
            except Exception:
                continue
            sequence += 1
            successes += 1
            if inner and inner[-1] == 23:
                application.extend(inner[:-1])
        if successes:
            payload = bytes(application)
            unparsed_payload_bytes = 0
            if payload.startswith(b"GET ") and b"\r\n\r\n" in payload:
                frames = payload.split(b"\r\n\r\n", 1)[1]
                decoded = bytearray()
                while len(frames) >= 2:
                    first, second = frames[:2]
                    length, start = second & 127, 2
                    if length == 126:
                        if len(frames) < 4: break
                        length, start = struct.unpack("!H", frames[2:4])[0], 4
                    elif length == 127:
                        if len(frames) < 10: break
                        length, start = struct.unpack("!Q", frames[2:10])[0], 10
                    mask = frames[start:start + 4] if second & 128 else b""
                    start += len(mask)
                    if len(frames) < start + length: break
                    frame = frames[start:start + length]
                    if mask:
                        frame = bytes(x ^ mask[i % 4] for i, x in enumerate(frame))
                    if first & 15 in (0, 1, 2): decoded.extend(frame)
                    frames = frames[start + length:]
                payload = bytes(decoded)
                unparsed_payload_bytes = len(frames)
            return {"authenticated_records": successes,
                    "application_bytes": len(application),
                    "application_sha256": hashlib.sha256(application).hexdigest(),
                    "decoded_payload_bytes": len(payload),
                    "unparsed_payload_bytes": unparsed_payload_bytes,
                    "marker_recovered_offline": marker in payload}
    return {"authenticated_records": 0, "application_bytes": 0}


def probe(executable: str, output: Path, websocket: bool) -> dict:
    root = output / ("websocket" if websocket else "http")
    root.mkdir(parents=True, exist_ok=False)
    home, workspace = root / "codex-home", root / "workspace"
    home.mkdir(); workspace.mkdir()
    marker = f"TRANSPECT_TLS_PROBE_{uuid4().hex}"
    cert, key, ca = certificate(root)
    origin = Origin(root, cert, key, marker.encode())
    origin.thread.start()
    config = ('model_provider = "tls_probe"\napproval_policy = "never"\nsandbox_mode = "read-only"\n'
              '[features]\nplugins = false\napps = false\n'
              '[model_providers.tls_probe]\nname = "Local TLS test origin"\n'
              f'base_url = "https://localhost:{origin.port}"\nwire_api = "responses"\n'
              'requires_openai_auth = false\nrequest_max_retries = 0\nstream_max_retries = 0\n'
              f'supports_websockets = {str(websocket).lower()}\n')
    (home / "config.toml").write_text(config)
    excluded = {"CODEX_HOME", "CODEX_CA_CERTIFICATE", "SSL_CERT_FILE", "SSLKEYLOGFILE", "RUST_LOG",
                "OPENAI_API_KEY", "API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY",
                "OPENAI_BASE_URL", "CODEX_API_KEY", "CHATGPT_BASE_URL", "TRANSPECT_MODEL_API_KEY"}
    env = {k: v for k, v in os.environ.items() if k.upper() not in excluded and "PROXY" not in k.upper()}
    client_keys = root / "client-session.keys"
    env.update(CODEX_HOME=str(home), CODEX_CA_CERTIFICATE=str(ca), SSLKEYLOGFILE=str(client_keys),
               NO_PROXY="*", HTTP_PROXY="", HTTPS_PROXY="", ALL_PROXY="", RUST_LOG="warn")
    command = [executable, "exec", "--json", "--ephemeral", "--skip-git-repo-check", "--model", "gpt-probe",
               "--cd", str(workspace), f"Do not run any tools. Reply OK. Synthetic test marker: {marker}"]
    try:
        result = subprocess.run(command, env=env, cwd=workspace, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=40)
        (root / "client.stdout.jsonl").write_bytes(result.stdout)
        (root / "client.stderr.log").write_bytes(result.stderr)
        returncode = result.returncode
    except subprocess.TimeoutExpired as exc:
        (root / "client.stdout.jsonl").write_bytes(exc.stdout or b"")
        (root / "client.stderr.log").write_bytes(exc.stderr or b"")
        returncode = "timeout"
    finally:
        origin.stop.set()
        origin.thread.join(timeout=15)
        origin.listener.close()
    rows = origin.records
    for row in rows:
        if "cipher" in row:
            row["origin_key_offline_decryption_control"] = decrypt_control(
                (root / row["wire_file"]).read_bytes(), root / "origin-session.keys", row["cipher"], marker.encode())
    key_lines = [x for x in client_keys.read_text().splitlines() if x and not x.startswith("#")] if client_keys.exists() else []
    expected_protocol = "websocket" if websocket else "http"
    validated = returncode == 0 and any(
        row.get("protocol") == expected_protocol and row.get("marker_in_origin_payload")
        and row.get("origin_key_offline_decryption_control", {}).get("marker_recovered_offline")
        for row in rows)
    summary = {"requested_transport": expected_protocol, "returncode": returncode,
               "probe_validated": validated,
               "synthetic_marker": marker, "origin": f"https://localhost:{origin.port}",
               "proxy_used": False, "real_account_used": False, "client_keylog_exists": client_keys.exists(),
               "client_keylog_entries": len(key_lines), "connections": rows,
               "scope": "custom local HTTPS origin, process-scoped custom CA; not production account traffic"}
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", default=shutil.which("codex"))
    parser.add_argument("--output", type=Path, default=Path("runs/codex-tls-feasibility") / uuid4().hex)
    args = parser.parse_args()
    if not args.codex:
        parser.error("Codex executable not found")
    root = args.output.resolve(); root.mkdir(parents=True, exist_ok=False)
    version = subprocess.run([args.codex, "--version"], capture_output=True, text=True, check=True).stdout.strip()
    summary = {"version": version, "binary": args.codex,
               "binary_sha256": hashlib.sha256(Path(args.codex).read_bytes()).hexdigest(),
               "probes": [probe(args.codex, root, False), probe(args.codex, root, True)]}
    summary["all_probes_validated"] = all(p["probe_validated"] for p in summary["probes"])
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"output": str(root), **summary}, indent=2))
    if not summary["all_probes_validated"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
