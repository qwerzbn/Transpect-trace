"""Research the pinned app-server backend without starting the desktop app.

This probe starts an archived official codex.exe in a temporary CODEX_HOME,
sends one synthetic app-server turn, and points its model provider at a local
HTTP receiver that never forwards. Optional Frida hooks observe only bounded
metadata at static HTTP/WSS candidates. Nothing here validates the desktop UI,
implements a denial, or opens a network permit.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import multiprocessing
import os
from pathlib import Path
from queue import Empty, Queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from probe_desktop_paths_vm import MAX_EVENTS, agent_source, safe_event
from transpect_trace.guard.desktop import load_desktop_adapter
from transpect_trace.observe.windows import identity as process_identity


BACKEND = ROOT / "runs/desktop-vm/pinned-package/app/resources/codex.exe"
ADAPTER = ROOT / "deploy/guard/desktop-candidate-26.1029.7803.0.json"
EXPECTED_BACKEND_SHA256 = "925c7d0665ffa49b0dcf748e034a805a04da984164ac92301432073b47789b99"
EXPECTED_BACKEND_VERSION = "codex-cli 0.166.0-alpha.6"
MAX_BODY = 16 * 1024 * 1024
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def isolated_env(home: Path) -> dict[str, str]:
    excluded = ("CODEX_", "OPENAI_", "AZURE_OPENAI_")
    names = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(excluded) and key not in names}
    env["CODEX_HOME"] = str(home)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    return env


class _Sink(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, marker: bytes):
        super().__init__(("127.0.0.1", 0), _SinkHandler)
        self.marker = marker
        self.lock = threading.Lock()
        self.received: list[dict] = []

    def summary(self) -> dict:
        with self.lock:
            rows = list(self.received)
        return {"requests": len(rows), "body_bytes": sum(row["bytes"] for row in rows),
                "marker_in_body": any(row["marker_in_body"] for row in rows),
                "body_sha256": [row["sha256"] for row in rows],
                "paths": sorted({row["path"] for row in rows})}


class _SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length_text = self.headers.get("Content-Length", "")
        try:
            length = int(length_text)
        except ValueError:
            length = -1
        body = b""
        if 0 <= length <= MAX_BODY:
            self.connection.settimeout(5)
            try:
                body = self.rfile.read(length)
            except OSError:
                pass
        with self.server.lock:
            self.server.received.append({"bytes": len(body),
                                         "marker_in_body": self.server.marker in body,
                                         "sha256": hashlib.sha256(body).hexdigest(),
                                         "path": "responses" if self.path.startswith("/v1/responses")
                                                 else "other"})
        self.send_response(503)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self.send_response(503)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _fmt: str, *_args: object) -> None:
        pass


@contextmanager
def local_sink(marker: bytes):
    server = _Sink(marker)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def configure(home: Path, port: int) -> None:
    home.mkdir()
    (home / "config.toml").write_text(
        'model = "gpt-5.1-codex"\n'
        'model_provider = "ttrace_local_probe"\n'
        '[model_providers.ttrace_local_probe]\n'
        'name = "Local non-forwarding probe"\n'
        f'base_url = "http://127.0.0.1:{port}/v1"\n'
        'wire_api = "responses"\n'
        'requires_openai_auth = false\n'
        'request_max_retries = 0\n'
        'stream_max_retries = 0\n'
        'supports_websockets = false\n', encoding="utf-8")


def _drain_json(stream, messages: Queue, methods: list[str]) -> None:
    for line in stream:
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if not isinstance(value, dict):
            continue
        name = value.get("method")
        if isinstance(name, str) and len(name) <= 100:
            methods.append(name)
        messages.put(value)


def _request(process: subprocess.Popen, identifier: int, method: str, params: dict) -> None:
    payload = {"method": method, "id": identifier, "params": params}
    process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
    process.stdin.flush()


def _await_id(messages: Queue, identifier: int, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            message = messages.get(timeout=min(0.2, deadline - time.monotonic()))
        except Empty:
            continue
        if message.get("id") == identifier:
            return message
    raise TimeoutError(f"app-server request {identifier} timed out")


def _frida_worker(pid: int, backend: Path, expected_hash: str, adapter: dict,
                  marker: str, fixture: Path, sender) -> None:
    """Disposable process for native attach/load calls that may never return."""
    try:
        target = process_identity(pid)
        if (Path(target["image_path"]).resolve(strict=True) != backend
                or target["image_sha256"] != expected_hash):
            raise ValueError("Frida target is not the archived backend process")
        import frida
        session = frida.attach(pid)
        script = session.create_script(agent_source("backend", adapter, marker, fixture))
        send_lock = threading.Lock()

        def on_message(message, _data):
            if message.get("type") == "send":
                safe = safe_event(message.get("payload"), "backend")
                row = {"event": safe} if safe is not None else {"error": "unexpected_frida_event"}
            elif message.get("type") == "error":
                row = {"error": "frida_script_error"}
            else:
                return
            with send_lock:
                sender.send(row)

        script.on("message", on_message)
        script.load()
        # Keep the session and script alive while the parent sends its test turn.
        threading.Event().wait()
    except Exception as error:
        try:
            sender.send({"error": f"frida_worker_{type(error).__name__}"})
        except (BrokenPipeError, OSError):
            pass
    finally:
        sender.close()


def _read_frida_events(receiver, events: list[dict], errors: list[str],
                       ready: threading.Event) -> None:
    """Drain the pipe so a busy callback cannot stall the test request."""
    try:
        while True:
            row = receiver.recv()
            if isinstance(row, dict) and isinstance(row.get("error"), str):
                errors.append(row["error"])
            elif isinstance(row, dict) and isinstance(row.get("event"), dict):
                event = row["event"]
                if len(events) >= MAX_EVENTS:
                    errors.append("frida_event_bound_exceeded")
                    continue
                events.append(event)
                if event.get("kind") == "probe_ready":
                    ready.set()
            else:
                errors.append("unexpected_frida_worker_message")
    except EOFError:
        pass
    except (BrokenPipeError, OSError):
        errors.append("frida_worker_pipe_error")


def _start_frida_bounded(process: subprocess.Popen, backend: Path,
                         expected_hash: str, adapter: dict, marker: str,
                         fixture: Path, events: list[dict], errors: list[str],
                         timeout: float = 10):
    """A process boundary lets the parent kill a hung native attach/load."""
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    observer = context.Process(target=_frida_worker,
                               args=(process.pid, backend, expected_hash, adapter,
                                     marker, fixture, sender), daemon=True)
    observer.start()
    sender.close()
    ready = threading.Event()
    collector = threading.Thread(target=_read_frida_events,
                                 args=(receiver, events, errors, ready), daemon=True)
    collector.start()
    if not ready.wait(timeout):
        errors.append("frida_attach_or_load_timeout" if observer.is_alive()
                      else "frida_worker_exited_before_ready")
    return observer, receiver, collector, ready.is_set()


def _stop_frida(observer, receiver, collector, errors: list[str]) -> None:
    if observer is None:
        return
    if observer.is_alive():
        observer.terminate()
    observer.join(timeout=2)
    if observer.is_alive():
        observer.kill()
        observer.join(timeout=2)
    if observer.is_alive():
        errors.append("frida_worker_termination_failed")
    receiver.close()
    collector.join(timeout=2)


def compare_http_candidate_body(events: list[dict], sink: dict) -> dict:
    """Compare synthetic HTTP hook metadata with the one received wire body.

    This is equality evidence for this local fixture, not an ABI or coverage
    claim. A second origin request makes the aggregate sink size ambiguous.
    """
    bodies = []
    incomplete = 0
    for event in events:
        if (event.get("kind") != "marker_buffer"
                or event.get("hook") != "model.http"
                or event.get("stage") != "hypothesized-http-body"):
            continue
        size, digest = event.get("bytes"), event.get("sha256")
        if type(size) is int and 0 <= size <= MAX_BODY and isinstance(digest, str) \
                and _SHA256.fullmatch(digest):
            bodies.append({"bytes": size, "sha256": digest})
        else:
            incomplete += 1
    origin_hashes = sink.get("body_sha256", [])
    origin_count = sink.get("requests")
    origin_bytes = sink.get("body_bytes")
    comparable = (type(origin_count) is int and origin_count == 1
                  and isinstance(origin_hashes, list)
                  and len(origin_hashes) == 1 and isinstance(origin_hashes[0], str)
                  and _SHA256.fullmatch(origin_hashes[0]) is not None
                  and type(origin_bytes) is int and 0 <= origin_bytes <= MAX_BODY
                  and sink.get("marker_in_body") is True
                  and sink.get("paths") == ["responses"])
    if not comparable:
        status, exact = "origin_not_comparable", 0
    elif incomplete:
        status, exact = "candidate_metadata_incomplete", 0
    elif not bodies:
        status, exact = "candidate_body_not_observed", 0
    else:
        exact = sum(body["bytes"] == origin_bytes and body["sha256"] == origin_hashes[0]
                    for body in bodies)
        status = ("exact_byte_match" if exact == len(bodies) else
                  "mixed_match_and_mismatch" if exact else "candidate_body_mismatch")
    return {"status": status, "candidate_body_count": len(bodies),
            "incomplete_candidate_metadata_count": incomplete,
            "candidate_bodies": bodies, "exact_match_count": exact,
            "comparison_scope": "one synthetic archived app-server HTTP request only"}


def probe(backend: Path, adapter_path: Path, *, with_frida: bool = False) -> dict:
    backend = backend.resolve(strict=True)
    actual_hash = file_hash(backend)
    if actual_hash != EXPECTED_BACKEND_SHA256:
        raise ValueError("archived backend SHA-256 differs from fixed official package")
    adapter = load_desktop_adapter(adapter_path, require_validated=False)
    if adapter["binary_sha256"] != actual_hash or adapter["status"] != "candidate_unvalidated":
        raise ValueError("static candidate is not for archived backend")

    marker = f"FAKE_DESKTOP_PROMPT_{uuid4().hex}"
    # Codex can spawn a plugin helper that briefly retains files after the
    # app-server exits. A cleanup race must be reported, not mask the probe.
    with tempfile.TemporaryDirectory(prefix="ttrace-desktop-backend-lab-",
                                     ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        home, workspace = root / "home", root / "workspace"
        workspace.mkdir()
        fixture = root / "synthetic-attachment.txt"
        fixture.write_text("Synthetic unused attachment fixture\n", encoding="utf-8")
        with local_sink(marker.encode("ascii")) as sink:
            configure(home, sink.server_port)
            env = isolated_env(home)
            version = subprocess.run([str(backend), "--version"], cwd=workspace,
                                     env=env, capture_output=True, text=True,
                                     timeout=10, check=True).stdout.strip()
            if version != EXPECTED_BACKEND_VERSION:
                raise ValueError("archived backend version differs")
            process = subprocess.Popen([str(backend), "app-server"], cwd=workspace,
                                       env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       text=True, encoding="utf-8", bufsize=1)
            messages: Queue = Queue()
            methods: list[str] = []
            worker = threading.Thread(target=_drain_json,
                                      args=(process.stdout, messages, methods), daemon=True)
            worker.start()
            events: list[dict] = []
            errors: list[str] = []
            observer = receiver = collector = None
            handshake: list[str] = []
            try:
                _request(process, 1, "initialize", {"clientInfo": {
                    "name": "transpect_backend_lab", "title": "Transpect backend lab",
                    "version": "0.1.0"}})
                initialized = _await_id(messages, 1, 15)
                if "error" in initialized:
                    raise RuntimeError("app-server initialize returned an error")
                process.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
                process.stdin.flush()
                handshake.append("initialized")
                _request(process, 2, "thread/start", {"model": "gpt-5.1-codex",
                                                       "cwd": str(workspace),
                                                       "approvalPolicy": "never",
                                                       "sandbox": "read-only"})
                thread = _await_id(messages, 2, 15)
                if "error" in thread:
                    raise RuntimeError("app-server thread/start returned an error")
                thread_id = thread.get("result", {}).get("thread", {}).get("id")
                if not isinstance(thread_id, str):
                    raise RuntimeError("app-server returned no thread ID")
                handshake.append("thread/start")
                if with_frida:
                    observer, receiver, collector, ready = _start_frida_bounded(
                        process, backend, actual_hash, adapter, marker, fixture,
                        events, errors)
                    if not ready:
                        raise RuntimeError("Frida research attach did not complete")
                _request(process, 3, "turn/start", {"threadId": thread_id,
                                                     "input": [{"type": "text", "text": marker}],
                                                     "cwd": str(workspace)})
                started = _await_id(messages, 3, 15)
                if "error" in started:
                    raise RuntimeError("app-server turn/start returned an error")
                handshake.append("turn/start")
                until = time.monotonic() + 30
                while time.monotonic() < until:
                    if sink.summary()["requests"]:
                        time.sleep(0.5)
                        break
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                _stop_frida(observer, receiver, collector, errors)
                if process.poll() is None:
                    if os.name == "nt":
                        try:
                            subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)],
                                           capture_output=True, timeout=3, check=False)
                        except (OSError, subprocess.TimeoutExpired):
                            errors.append("backend_tree_stop_failed")
                    if process.poll() is None:
                        process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                worker.join(timeout=2)
            received = sink.summary()
    if Path(directory).exists():
        errors.append("temp_cleanup_incomplete")
    kinds = [event["kind"] for event in events]
    http_body_comparison = compare_http_candidate_body(events, received)
    candidates = {hook: sum(event["kind"] == "candidate_entry" and event.get("hook") == hook
                            for event in events) for hook in ("model.http", "model.wss")}
    markers = {hook: sum(event["kind"] == "marker_buffer" and event.get("hook") == hook
                         for event in events) for hook in ("model.http", "model.wss",
                                                   "ReadFile", "NtReadFile", "WriteFile",
                                                   "WinHttpWriteData", "WinHttpSendRequest")}
    return {"schema": "transpect.desktop-backend-lab/1.0",
            "research_only": True, "desktop_ui_verified": False,
            "attachment_upload_verified": False, "can_enforce": False,
            "network_permit_opened": False, "target": "archived standalone codex.exe app-server",
            "backend_sha256": actual_hash, "backend_version": version,
            "adapter_sha256": file_hash(adapter_path),
            "marker_sha256": hashlib.sha256(marker.encode("ascii")).hexdigest(),
            "handshake": handshake, "sink": received,
            "http_candidate_body_comparison": http_body_comparison,
            "frida_enabled": with_frida,
            "candidate_entries": sum(kind == "candidate_entry" for kind in kinds),
            "candidate_entries_by_hook": candidates,
            "marker_buffer_hits": sum(kind == "marker_buffer" for kind in kinds),
            "marker_buffer_hits_by_hook": markers,
            "frida_event_kinds": sorted(set(kinds)),
            "app_server_event_methods": sorted(set(methods)),
            "errors": sorted(set(errors))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, default=BACKEND)
    parser.add_argument("--adapter", type=Path, default=ADAPTER)
    parser.add_argument("--with-frida", action="store_true",
                        help="Try bounded read-only Frida candidate hooks (may fail on host)")
    parser.add_argument("--report", type=Path,
                        default=ROOT / "runs/desktop-backend-lab/report.json")
    args = parser.parse_args()
    report = probe(args.backend, args.adapter, with_frida=args.with_frida)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(args.report), "handshake": report["handshake"],
                      "sink": report["sink"], "candidate_entries": report["candidate_entries"],
                      "marker_buffer_hits": report["marker_buffer_hits"],
                      "http_candidate_body_status": report["http_candidate_body_comparison"]["status"],
                      "errors": report["errors"]}, ensure_ascii=False))
    return 0 if report["handshake"] == ["initialized", "thread/start", "turn/start"] \
        and report["sink"]["marker_in_body"] and not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
