"""Non-forwarding loopback TLS origin for fixed desktop Guard validation.

It records application-body byte counts and hashes for HTTP and WebSocket
requests, including multipart/chunked HTTP uploads. No request plaintext is
saved and no request is forwarded to OpenAI or any other network endpoint.
Use only synthetic fixture content in the isolated demo VM.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import ssl
import struct
import threading
import time
from uuid import uuid4

from probe_codex_tls import certificate, events


LIMIT = 16 * 1024 * 1024
HEADER_LIMIT = 64 * 1024


class ControlledOrigin:
    def __init__(self, cert: Path, key: Path, *, marker: bytes):
        if not marker.startswith(b"FAKE_DESKTOP_ORIGIN_"):
            raise ValueError("origin marker must be synthetic")
        self.marker = marker
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.records: list[dict] = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.workers: list[threading.Thread] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    @staticmethod
    def _receive(stream: ssl.SSLSocket, buffer: bytearray, size: int) -> bytes:
        while len(buffer) < size:
            data = stream.recv(min(65536, max(1, size - len(buffer))))
            if not data:
                raise EOFError("request ended before declared body")
            buffer.extend(data)
        result = bytes(buffer[:size])
        del buffer[:size]
        return result

    @classmethod
    def _line(cls, stream: ssl.SSLSocket, buffer: bytearray, *, limit: int = HEADER_LIMIT) -> bytes:
        while b"\r\n" not in buffer:
            if len(buffer) >= limit:
                raise ValueError("line limit exceeded")
            data = stream.recv(65536)
            if not data:
                raise EOFError("line ended early")
            buffer.extend(data)
        offset = buffer.index(b"\r\n")
        if offset > limit:
            raise ValueError("line limit exceeded")
        return cls._receive(stream, buffer, offset + 2)[:-2]

    @classmethod
    def _http_body(cls, stream: ssl.SSLSocket, buffer: bytearray, headers: dict) -> bytes:
        encoding = headers.get("transfer-encoding", "").lower()
        if encoding:
            if encoding != "chunked" or "content-length" in headers:
                raise ValueError("unsupported or ambiguous HTTP framing")
            body = bytearray()
            while True:
                size_text = cls._line(stream, buffer).split(b";", 1)[0]
                size = int(size_text, 16)
                if size < 0 or size > LIMIT - len(body):
                    raise ValueError("HTTP body limit exceeded")
                if size == 0:
                    while cls._line(stream, buffer):
                        pass
                    break
                body.extend(cls._receive(stream, buffer, size))
                if cls._receive(stream, buffer, 2) != b"\r\n":
                    raise ValueError("invalid chunk terminator")
            return bytes(body)
        if "content-length" not in headers:
            raise ValueError("HTTP request body length unavailable")
        size = int(headers["content-length"])
        if size < 0 or size > LIMIT:
            raise ValueError("HTTP body limit exceeded")
        return cls._receive(stream, buffer, size)

    @classmethod
    def _ws_message(cls, stream: ssl.SSLSocket, buffer: bytearray) -> bytes:
        body = bytearray()
        while True:
            first, second = cls._receive(stream, buffer, 2)
            opcode = first & 0x0f
            if opcode in (8, 9, 10):
                length = second & 127
                if length > 125:
                    raise ValueError("invalid control frame")
                mask = cls._receive(stream, buffer, 4) if second & 128 else None
                data = cls._receive(stream, buffer, length)
                if opcode == 9:
                    cls._ws_send(stream, data, opcode=10)
                if opcode == 8:
                    raise EOFError("websocket closed before request")
                continue
            if opcode not in (0, 1, 2) or not second & 128:
                raise ValueError("unsupported websocket frame")
            size = second & 127
            if size == 126:
                size = struct.unpack("!H", cls._receive(stream, buffer, 2))[0]
            elif size == 127:
                size = struct.unpack("!Q", cls._receive(stream, buffer, 8))[0]
            if size > LIMIT - len(body):
                raise ValueError("websocket body limit exceeded")
            mask = cls._receive(stream, buffer, 4)
            data = cls._receive(stream, buffer, size)
            body.extend(b ^ mask[i % 4] for i, b in enumerate(data))
            if first & 0x80:
                return bytes(body)

    @staticmethod
    def _ws_send(stream: ssl.SSLSocket, data: bytes, *, opcode: int = 1) -> None:
        prefix = bytes([0x80 | opcode])
        if len(data) < 126:
            prefix += bytes([len(data)])
        elif len(data) < 65536:
            prefix += b"\x7e" + struct.pack("!H", len(data))
        else:
            prefix += b"\x7f" + struct.pack("!Q", len(data))
        stream.sendall(prefix + data)

    def _record(self, row: dict) -> None:
        with self.lock:
            self.records.append(row)

    def _handle(self, raw: socket.socket) -> None:
        row = {"transport": None, "method": None, "target_sha256": None, "body_bytes": 0,
               "body_sha256": None, "synthetic_marker_present": False,
               "complete": False, "error": None}
        try:
            with raw, self.context.wrap_socket(raw, server_side=True) as stream:
                stream.settimeout(8)
                buffer = bytearray()
                while b"\r\n\r\n" not in buffer:
                    if len(buffer) >= HEADER_LIMIT:
                        raise ValueError("HTTP header limit exceeded")
                    data = stream.recv(65536)
                    if not data:
                        raise EOFError("HTTP headers ended early")
                    buffer.extend(data)
                offset = buffer.index(b"\r\n\r\n")
                header = self._receive(stream, buffer, offset + 4)[:-4]
                lines = header.decode("iso-8859-1").split("\r\n")
                request_parts = lines[0].split(" ")
                if len(request_parts) != 3 or request_parts[0] not in ("GET", "POST", "PUT"):
                    raise ValueError("unsupported request line")
                row["method"] = request_parts[0]
                row["target_sha256"] = hashlib.sha256(request_parts[1].encode()).hexdigest()
                headers = {}
                for line in lines[1:]:
                    name, sep, value = line.partition(":")
                    if not sep or name.lower() in headers:
                        raise ValueError("invalid or duplicate HTTP header")
                    headers[name.lower()] = value.strip()
                if headers.get("upgrade", "").lower() == "websocket":
                    row["transport"] = "wss"
                    key = headers.get("sec-websocket-key")
                    if not key:
                        raise ValueError("missing websocket key")
                    accept = base64.b64encode(hashlib.sha1((key +
                        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                    stream.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                   b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
                    body = self._ws_message(stream, buffer)
                    row.update(body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest(),
                               synthetic_marker_present=self.marker in body, complete=True)
                    for event in events():
                        self._ws_send(stream, json.dumps(event).encode())
                else:
                    row["transport"] = "https"
                    body = self._http_body(stream, buffer, headers)
                    row.update(body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest(),
                               synthetic_marker_present=self.marker in body, complete=True)
                    if "/files" in lines[0]:
                        reply = b'{"id":"file_synthetic","object":"file","purpose":"user_data"}'
                        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                                       str(len(reply)).encode() + b"\r\nConnection: close\r\n\r\n" + reply)
                    else:
                        reply = b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events())
                        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " +
                                       str(len(reply)).encode() + b"\r\nConnection: close\r\n\r\n" + reply)
        except (OSError, ValueError, EOFError) as error:
            row["error"] = type(error).__name__
        finally:
            self._record(row)

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def snapshot(self) -> dict:
        with self.lock:
            records = [dict(row) for row in self.records]
        return {"schema": "transpect.desktop-controlled-origin/1.0", "forwarding": False,
                "connections": records,
                "complete_body_bytes": sum(row["body_bytes"] for row in records if row["complete"]),
                "unverified_connections": sum(not row["complete"] for row in records),
                "synthetic_marker_received": any(row["synthetic_marker_present"] for row in records)}

    def close(self) -> None:
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=9)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, default=60)
    parser.add_argument("--isolated-vm", action="store_true")
    args = parser.parse_args()
    if not args.isolated_vm:
        parser.error("this origin is for an isolated Windows VM only")
    if not 1 <= args.duration_seconds <= 300:
        parser.error("duration must be 1–300 seconds")
    root = args.directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    cert, key, ca = certificate(root)
    marker = f"FAKE_DESKTOP_ORIGIN_{uuid4().hex}".encode()
    origin = ControlledOrigin(cert, key, marker=marker)
    origin.start()
    print(json.dumps({"ready": True, "base_url": f"https://localhost:{origin.port}",
                      "ca_certificate": str(ca), "synthetic_marker": marker.decode()}), flush=True)
    try:
        time.sleep(args.duration_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        origin.close()
        (root / "receipts.json").write_text(json.dumps(origin.snapshot(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
