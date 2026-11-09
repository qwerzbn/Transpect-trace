"""Isolated current-backend capture fixture without Codex command hooks.

Runs one synthetic app-server turn against a non-forwarding local HTTP or WSS
origin. A Frida observer can pass the marked request bytes to the native
collection engine for encrypted archival and readback. This observation is
not a synchronous send gate. The rollout trace is only a lab reference.
No live desktop process or real user chat is read.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
from queue import Queue
import subprocess
import tempfile
import threading
import time
from uuid import uuid4

import probe_desktop_backend_lab as lab
from probe_codex_tls import Origin, certificate


BACKEND_SHA256 = "40ecc3d8b6899afd8f935a8cccb7d53ba41ffd7c199f679e186d30ddd0d0bf39"
BACKEND_VERSION = "codex-cli 0.167.0-alpha.3.2"
MAX_TRACE_FILES = 256
MAX_TRACE_FILE_BYTES = 16 * 1024 * 1024


class _WssSink:
    def __init__(self, root: Path, marker: bytes):
        cert, key, self.ca = certificate(root)
        self.origin = Origin(root, cert, key, marker)
        self.server_port = self.origin.port

    def summary(self) -> dict:
        rows = list(self.origin.records)
        marked = [row for row in rows if row.get("marker_in_origin_payload") is True]
        other = [row for row in rows if row.get("marker_in_origin_payload") is False]
        return {"requests": len(marked), "body_bytes": sum(row["payload_bytes"] for row in marked),
                "marker_in_body": bool(marked),
                "body_sha256": [row["payload_sha256"] for row in marked],
                "paths": sorted({row.get("protocol", "unknown") for row in marked}),
                "total_origin_records": len(rows),
                "non_target_body_bytes": sum(row.get("payload_bytes", 0) for row in other),
                "non_target_records": [{key: row[key] for key in
                                        ("protocol", "request_line", "payload_bytes", "payload_sha256")
                                        if key in row} for row in other],
                "origin_errors": sorted({row["error"].split(":", 1)[0] for row in rows
                                         if "error" in row})}


@contextmanager
def local_origin(transport: str, root: Path, marker: bytes):
    if transport == "http":
        with lab.local_sink(marker) as sink:
            yield sink
        return
    sink = _WssSink(root, marker)
    sink.origin.thread.start()
    try:
        yield sink
    finally:
        sink.origin.stop.set()
        sink.origin.listener.close()
        sink.origin.thread.join(timeout=3)


def configure_provider(home: Path, port: int, transport: str) -> str:
    if transport == "http":
        lab.configure(home, port)
        return "gpt-5.1-codex"
    home.mkdir()
    (home / "config.toml").write_text(
        'model = "gpt-probe"\nmodel_provider = "ttrace_local_wss"\n'
        '[features]\nplugins = false\napps = false\n'
        '[model_providers.ttrace_local_wss]\nname = "Local non-forwarding WSS probe"\n'
        f'base_url = "https://localhost:{port}"\n'
        'wire_api = "responses"\nrequires_openai_auth = false\n'
        'request_max_retries = 0\nstream_max_retries = 0\n'
        'supports_websockets = true\n', encoding="utf-8")
    return "gpt-probe"


def compact_trace_json(data: bytes) -> bytes:
    """Remove pretty-print whitespace without re-encoding JSON string bytes."""
    json.loads(data)
    output = bytearray()
    inside_string = escaped = False
    for value in data:
        if inside_string:
            output.append(value)
            if escaped:
                escaped = False
            elif value == 0x5C:
                escaped = True
            elif value == 0x22:
                inside_string = False
        elif value == 0x22:
            inside_string = True
            output.append(value)
        elif value not in (0x20, 0x09, 0x0A, 0x0D):
            output.append(value)
    if inside_string or escaped:
        raise ValueError("incomplete trace JSON string")
    return bytes(output)


def trace_inventory(root: Path, marker: bytes) -> list[dict]:
    """Return bounded metadata; never copy trace request contents to a report."""
    def marker_fields(value, prefix: str = "", depth: int = 0) -> list[dict]:
        if depth > 8:
            return []
        if isinstance(value, str):
            raw = value.encode("utf-8")
            return ([{"field": prefix, "bytes": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()}]
                    if marker in raw else [])
        if isinstance(value, dict):
            return [row for key, item in list(value.items())[:128]
                    for row in marker_fields(item, f"{prefix}/{key}", depth + 1)]
        if isinstance(value, list):
            return [row for index, item in enumerate(value[:128])
                    for row in marker_fields(item, f"{prefix}/{index}", depth + 1)]
        return []

    rows = []
    if not root.exists():
        return rows
    for path in sorted(p for p in root.rglob("*") if p.is_file())[:MAX_TRACE_FILES]:
        size = path.stat().st_size
        row = {"path": path.relative_to(root).as_posix(), "bytes": size}
        if size <= MAX_TRACE_FILE_BYTES:
            data = path.read_bytes()
            row.update(sha256=hashlib.sha256(data).hexdigest(), marker_in_file=marker in data)
            if path.suffix.lower() == ".json":
                try:
                    value = json.loads(data)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    row["json_parse_failed"] = True
                else:
                    row["top_level_keys"] = list(value)[:32] if isinstance(value, dict) else []
                    row["marker_fields"] = marker_fields(value)
                    if row["marker_in_file"] and isinstance(value, dict):
                        compact = compact_trace_json(data)
                        row["compact_json"] = {"bytes": len(compact),
                                               "sha256": hashlib.sha256(compact).hexdigest()}
        else:
            row["too_large_to_inspect"] = True
        rows.append(row)
    return rows


def _collect_full_body(body: bytes, *, protocol: str, pid: int,
                       evidence_dir: Path) -> dict:
    """Archive observed bytes, then verify a decrypting readback in this lab.

    The collection engine's capture_only setting records that the observation
    did not control the request. No raw body is returned in report metadata.
    """
    from transpect_trace.guard.policy import GuardRequest
    from transpect_trace.protect.codex_hook_gate import GateConfig
    from transpect_trace.protect.native_collection import NativeCollectionEngine

    payload = body.decode("utf-8", errors="strict")
    if payload.encode("utf-8") != body:
        raise ValueError("native body does not round-trip as UTF-8")
    evidence_dir = evidence_dir.resolve()
    config = GateConfig(mode="observe", archive_directory=evidence_dir / "archive",
                        audit_file=evidence_dir / "audit.jsonl",
                        registration_directory=None, review_override_ttl_seconds=0,
                        collection_file=evidence_dir / "collection.jsonl")
    engine = NativeCollectionEngine(config, archive_full_body=True, capture_only=True)
    request = GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0",
        "request_id": uuid4().hex,
        "guard_session_id": f"synthetic-{uuid4().hex}",
        "pid": pid, "tid": 0, "kind": "model.request", "protocol": protocol,
        "completeness": "complete", "payload_utf8": payload,
    })
    result = engine.collector.collect(request)
    envelope = result.envelope
    record_id = envelope.get("archive_record_id") if envelope else None
    if not isinstance(record_id, str):
        raise RuntimeError("collection did not archive the full model request")
    receipt, restored = engine.gate._archive.read(record_id)
    return {"observation_only": True, "archive_record_id": record_id,
            "archive_directory": str(config.archive_directory),
            "collection_file": str(config.collection_file),
            "body_bytes": receipt.body_bytes, "body_sha256": receipt.body_sha256,
            "readback_exact": restored == body,
            "recorded_decision_point": envelope.get("decision_point"),
            "recorded_route_decision": envelope.get("route_decision"),
            "recorded_released_by_route": envelope.get("released_by_route")}


def probe(backend: Path, *, transport: str = "http", with_frida: bool = False,
          collect_full_body: bool = False, evidence_dir: Path | None = None,
          fail_stop: bool = False) -> dict:
    if transport not in {"http", "wss"}:
        raise ValueError("unknown local lab transport")
    if collect_full_body and (not with_frida or evidence_dir is None):
        raise ValueError("full body collection requires Frida and an evidence directory")
    if fail_stop and (not with_frida or collect_full_body):
        raise ValueError("fail-stop requires Frida and cannot collect a body")
    backend = backend.resolve(strict=True)
    actual_hash = lab.file_hash(backend)
    if actual_hash != BACKEND_SHA256:
        raise ValueError("current backend hash differs from the pinned lab build")
    marker = f"TTRACE_NATIVE_LAB_{uuid4().hex}".encode("ascii")
    with tempfile.TemporaryDirectory(prefix="ttrace-current-capture-",
                                     ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        home, workspace, trace = root / "home", root / "workspace", root / "trace"
        workspace.mkdir()
        with local_origin(transport, root, marker) as sink:
            model = configure_provider(home, sink.server_port, transport)
            env = lab.isolated_env(home)
            env["CODEX_ROLLOUT_TRACE_ROOT"] = str(trace)
            if transport == "wss":
                env.update(CODEX_CA_CERTIFICATE=str(sink.ca),
                           NO_PROXY="localhost,127.0.0.1",
                           HTTP_PROXY="http://127.0.0.1:9",
                           HTTPS_PROXY="http://127.0.0.1:9",
                           ALL_PROXY="http://127.0.0.1:9")
            version = subprocess.run([str(backend), "--version"], cwd=workspace,
                                     env=env, capture_output=True, text=True,
                                     timeout=10, check=True).stdout.strip()
            if version != BACKEND_VERSION:
                raise ValueError("current backend version differs from pinned lab build")
            process = subprocess.Popen([str(backend), "app-server"], cwd=workspace,
                                       env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1)
            messages: Queue = Queue()
            methods: list[str] = []
            worker = threading.Thread(target=lab._drain_json,
                                      args=(process.stdout, messages, methods), daemon=True)
            worker.start()
            handshake: list[str] = []
            errors: list[str] = []
            native_events: list[dict] = []
            process_exit_code = None
            session = None
            try:
                lab._request(process, 1, "initialize", {"clientInfo": {
                    "name": "transpect_capture_lab", "title": "Transpect capture lab",
                    "version": "0.1.0"}})
                initialized = lab._await_id(messages, 1, 15)
                if "error" in initialized:
                    raise RuntimeError("app-server initialize failed")
                process.stdin.write(json.dumps({"method": "initialized", "params": {}}) + "\n")
                process.stdin.flush()
                handshake.append("initialized")
                lab._request(process, 2, "thread/start", {"model": model,
                                                          "cwd": str(workspace),
                                                          "approvalPolicy": "never",
                                                          "sandbox": "read-only"})
                thread = lab._await_id(messages, 2, 15)
                if "error" in thread:
                    raise RuntimeError("app-server thread/start failed")
                thread_id = thread.get("result", {}).get("thread", {}).get("id")
                if not isinstance(thread_id, str):
                    raise RuntimeError("app-server returned no thread ID")
                handshake.append("thread/start")
                if with_frida:
                    if fail_stop:
                        from _desktop_failstop_frida import FailStopSession as CaptureSession
                    else:
                        from _desktop_capture_frida import CaptureSession
                    from transpect_trace.observe.windows import identity

                    observed = identity(process.pid)
                    session = CaptureSession(process.pid, backend, BACKEND_SHA256,
                                             observed["creation_filetime"], marker,
                                             capture_wss=transport == "wss",
                                             **({} if fail_stop else
                                                {"capture_body": collect_full_body}))
                    session.start()
                lab._request(process, 3, "turn/start", {"threadId": thread_id,
                                                        "input": [{"type": "text", "text": marker.decode()}],
                                                        "cwd": str(workspace)})
                started = lab._await_id(messages, 3, 15)
                if "error" in started:
                    raise RuntimeError("app-server turn/start failed")
                handshake.append("turn/start")
                until = time.monotonic() + 30
                while time.monotonic() < until and not sink.summary()["requests"]:
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                if sink.summary()["requests"]:
                    time.sleep(0.3)
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                if session is not None:
                    native_events = session.finish()
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                process_exit_code = process.returncode
                worker.join(timeout=2)
            received = sink.summary()
            traces = trace_inventory(trace, marker)
            hooks_file_present = (home / "hooks.json").exists()
    marked = [row for row in traces if row.get("marker_in_file")]
    trace_origin_exact = (
        received["requests"] == 1 and len(marked) == 1
        and marked[0].get("compact_json", {}).get("bytes") == received["body_bytes"]
        and marked[0].get("compact_json", {}).get("sha256") == received["body_sha256"][0]
    )
    native_hits = [row for row in native_events if row.get("kind") == "synthetic_http_hit"]
    synthetic_http_origin_exact = (
        with_frida and transport == "http" and trace_origin_exact and bool(native_hits)
        and all(row["bytes"] == received["body_bytes"]
                and row["sha256"] == received["body_sha256"][0]
                for row in native_hits)
    )
    wss_hits = [row for row in native_events if row.get("kind") == "synthetic_wss_hit"]
    synthetic_wss_origin_exact = (
        with_frida and transport == "wss" and trace_origin_exact and bool(wss_hits)
        and all(row["bytes"] == received["body_bytes"]
                and row["sha256"] == received["body_sha256"][0]
                for row in wss_hits)
    )
    selected_hits = native_hits if transport == "http" else wss_hits
    exact = synthetic_http_origin_exact if transport == "http" else synthetic_wss_origin_exact
    native_trace_exact = (
        len(marked) == 1 and bool(selected_hits)
        and all(row["bytes"] == marked[0].get("compact_json", {}).get("bytes")
                and row["sha256"] == marked[0].get("compact_json", {}).get("sha256")
                for row in selected_hits)
    )
    failstop_events = [row for row in native_events
                       if row.get("kind") == "synthetic_failstop_triggered"]
    failstop_validated = (
        fail_stop and native_trace_exact and len(failstop_events) == 1
        and failstop_events[0].get("hook") == transport
        and failstop_events[0].get("bytes") == selected_hits[0]["bytes"]
        and failstop_events[0].get("sha256") == selected_hits[0]["sha256"]
        and received["requests"] == 0 and received["body_bytes"] == 0
        and process_exit_code == 76 and not errors and not hooks_file_present
    )
    collection = None
    collection_error = None
    if collect_full_body:
        if (exact and selected_hits and all(isinstance(row.get("body"), bytes)
                                            and hashlib.sha256(row["body"]).hexdigest()
                                            == received["body_sha256"][0]
                                            for row in selected_hits)):
            try:
                collection = _collect_full_body(selected_hits[0]["body"], protocol=transport,
                                                pid=process.pid, evidence_dir=evidence_dir)
            except Exception as error:
                collection_error = type(error).__name__
        else:
            collection_error = "native_body_not_exact"
    safe_events = [{key: value for key, value in row.items() if key != "body"}
                   for row in native_events]
    collected_exact = bool(collection and collection["readback_exact"]
                           and collection["body_bytes"] == received["body_bytes"]
                           and collection["body_sha256"] == received["body_sha256"][0]
                           and collection["recorded_decision_point"] == "none"
                           and collection["recorded_route_decision"] == "not_enforceable"
                           and collection["recorded_released_by_route"] is None)
    return {"schema": "transpect.desktop-current-capture-lab/1.0",
            "backend_sha256": actual_hash, "backend_version": version,
            "transport": transport,
            "synthetic_only": True, "local_origin_only": True,
            "codex_command_hooks_present": hooks_file_present,
            "marker_sha256": hashlib.sha256(marker).hexdigest(),
            "handshake": handshake, "origin": received, "trace_files": traces,
            "trace_origin_exact": trace_origin_exact,
            "native_trace_exact": native_trace_exact,
            "frida_enabled": with_frida, "native_events": safe_events,
            "synthetic_http_origin_exact": synthetic_http_origin_exact,
            "synthetic_wss_origin_exact": synthetic_wss_origin_exact,
            "full_body_collection_enabled": collect_full_body,
            "collection": collection, "collection_error": collection_error,
            "synthetic_collection_validated": collected_exact,
            "synthetic_failstop_validated": failstop_validated,
            "fail_stop": fail_stop, "process_exit_code": process_exit_code,
            "app_server_event_methods": sorted(set(methods)), "errors": errors,
            "native_capture_validated": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--transport", choices=("http", "wss"), default="http")
    parser.add_argument("--with-frida", action="store_true",
                        help="Observe pinned HTTP/WSS candidates in this synthetic process only")
    parser.add_argument("--collect-full-body", action="store_true",
                        help="Archive synthetic native bytes and verify encrypted readback")
    parser.add_argument("--fail-stop", action="store_true",
                        help="Terminate the isolated backend before marked HTTP/WSS send")
    parser.add_argument("--evidence-dir", type=Path,
                        help="Directory for encrypted synthetic lab evidence")
    args = parser.parse_args()
    evidence_dir = (args.evidence_dir or args.report.parent / (args.report.stem + "-evidence")
                    if args.collect_full_body else None)
    report = probe(args.backend, transport=args.transport, with_frida=args.with_frida,
                   collect_full_body=args.collect_full_body, evidence_dir=evidence_dir,
                   fail_stop=args.fail_stop)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(args.report), "handshake": report["handshake"],
                      "origin": report["origin"], "trace_files": len(report["trace_files"]),
                      "trace_origin_exact": report["trace_origin_exact"],
                      "synthetic_http_origin_exact": report["synthetic_http_origin_exact"],
                      "synthetic_wss_origin_exact": report["synthetic_wss_origin_exact"],
                      "synthetic_collection_validated": report["synthetic_collection_validated"],
                      "synthetic_failstop_validated": report["synthetic_failstop_validated"],
                      "collection_error": report["collection_error"],
                      "native_hits": sum(row.get("kind") == ("synthetic_http_hit" if args.transport == "http"
                                                            else "synthetic_wss_hit")
                                         for row in report["native_events"]),
                      "errors": report["errors"]}))
    return 0 if (report["handshake"] == ["initialized", "thread/start", "turn/start"]
                 and (report["synthetic_failstop_validated"] if args.fail_stop else
                      (report["origin"]["marker_in_body"] and report["trace_origin_exact"]
                       and (not args.with_frida or (
                           report["synthetic_http_origin_exact"] if args.transport == "http"
                           else report["synthetic_wss_origin_exact"]))
                       and (not args.collect_full_body or report["synthetic_collection_validated"])))
                 and not report["errors"]
                 and not report["codex_command_hooks_present"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
