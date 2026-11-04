"""Read-only thread attribution for one synthetic current-desktop prompt.

The fixed backend source puts core-owned thread_id in client_metadata for both
HTTP and WSS model bodies. This probe verifies that claim in the active build
without exporting the ID or any request text. It attaches only to the exact
pinned app-server, can interrupt chats sharing it, and never denies a request.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
from pathlib import Path
import re
import sys
import threading
import time

from _build_support import ROOT, enter_repository

sys.path.insert(0, str(ROOT / "src"))

from probe_desktop_paths_current import require_current_user, verify_current_targets
from probe_desktop_paths_host import (
    _stop_frida, hold_processes, registered_package, verify_archived_msix,
)
from probe_desktop_paths_vm import _hash, load_fixtures, verify_static_entries
from transpect_trace.guard.desktop import load_desktop_adapter
from transpect_trace.observe.windows import identity as process_identity


SCHEMA = "transpect.desktop-current-thread-metadata/1.0"
TEST_THREAD_ID = "01a1a5ad-14de-7861-afe8-7670bfb99d3b"
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_EVENTS = frozenset(("hook_installed", "probe_ready", "marker_metadata",
                     "hook_unavailable", "entry_mismatch", "read_error"))
_HOOKS = frozenset(("model.http", "model.wss"))
_PARSE_STATES = frozenset(("parsed", "missing_client_metadata", "missing_thread_id",
                           "invalid_thread_id", "invalid_json", "oversized_json",
                           "unexpected_request_shape", "hash_unavailable"))
_MAX_EVENTS = 128


AGENT = r"""
const CONFIG = __CONFIG__;
const marker = new Uint8Array(CONFIG.marker);
const markerString = String.fromCharCode.apply(null, CONFIG.marker);
const maxBody = 512 * 1024;
const maxJson = 256 * 1024;
function markerOffset(bytes) {
  if (bytes.length < marker.length) return -1;
  outer: for (let i = 0; i <= bytes.length - marker.length; i++) {
    for (let j = 0; j < marker.length; j++)
      if (bytes[i + j] !== marker[j]) continue outer;
    return i;
  }
  return -1;
}
function prefixMatches(target, prefix) {
  const actual = new Uint8Array(target.readVolatile(prefix.length));
  return actual.length === prefix.length &&
    actual.every((value, index) => value === prefix[index]);
}
function containsMarker(value) {
  try { return JSON.stringify(value).includes(markerString); }
  catch (_) { return false; }
}
function inspect(data, length, protocol) {
  if (data.isNull() || !Number.isSafeInteger(length) ||
      length < marker.length || length > maxBody) return;
  let bytes;
  try { bytes = new Uint8Array(data.readVolatile(length)); }
  catch (_) { send({kind:'read_error', hook:'model.' + protocol}); return; }
  if (markerOffset(bytes) < 0) return;
  let digest = null;
  try { digest = Checksum.compute('sha256', bytes.buffer); }
  catch (_) {}
  const row = {kind:'marker_metadata', hook:'model.' + protocol,
    bytes:length, sha256:digest, parse_state:'parsed',
    thread_id_match:null, function_output_marker:null, user_content_marker:null};
  if (digest === null) row.parse_state = 'hash_unavailable';
  if (length > maxJson) {
    row.parse_state = 'oversized_json'; send(row); return;
  }
  let value;
  try { value = JSON.parse(data.readUtf8String(length)); }
  catch (_) { row.parse_state = 'invalid_json'; send(row); return; }
  if (!value || typeof value !== 'object' ||
      (protocol === 'wss' && value.type !== 'response.create') ||
      typeof value.model !== 'string' || !Array.isArray(value.input)) {
    row.parse_state = 'unexpected_request_shape'; send(row); return;
  }
  row.function_output_marker = value.input.some(item => item &&
    item.type === 'function_call_output' && containsMarker(item.output));
  row.user_content_marker = value.input.some(item => item &&
    item.role === 'user' && containsMarker(item.content));
  const metadata = value.client_metadata;
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    row.parse_state = 'missing_client_metadata'; send(row); return;
  }
  const threadId = metadata.thread_id;
  if (typeof threadId !== 'string') {
    row.parse_state = 'missing_thread_id'; send(row); return;
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(threadId)) {
    row.parse_state = 'invalid_thread_id'; send(row); return;
  }
  row.thread_id_match = threadId === CONFIG.test_thread_id;
  send(row);
}
const base = Process.mainModule.base;
function install(name, spec) {
  const target = base.add(ptr(spec.rva));
  try {
    if (!prefixMatches(target, spec.prefix)) {
      send({kind:'entry_mismatch', hook:name}); return;
    }
    if (name === 'model.http') {
      Interceptor.attach(target, {onEnter(args) {
        try {
          const body = args[3];
          inspect(body.add(8).readPointer(), body.add(16).readU64().toNumber(), 'http');
        } catch (_) { send({kind:'read_error', hook:name}); }
      }});
    } else {
      Interceptor.attach(target, {onEnter(args) { this.result = args[0]; },
        onLeave(_) {
          try {
            if (this.result.readU64().toNumber() !== 0x1f) return;
            inspect(this.result.add(16).readPointer(),
                    this.result.add(24).readU64().toNumber(), 'wss');
          } catch (_) { send({kind:'read_error', hook:name}); }
        }});
    }
    send({kind:'hook_installed', hook:name});
  } catch (_) { send({kind:'hook_unavailable', hook:name}); }
}
install('model.http', CONFIG.http);
install('model.wss', CONFIG.wss);
send({kind:'probe_ready'});
"""


def require_observation(args) -> None:
    if not (getattr(args, "active_current_client", False)
            and getattr(args, "observation_only", False)):
        raise ValueError("explicit current-client observation-only flags are required")
    if type(args.seconds) is not int or not 5 <= args.seconds <= 120:
        raise ValueError("probe duration must be 5..120 seconds")


def agent_source(adapter: dict, marker: str) -> str:
    hooks = {item["layer"]: item for item in adapter["hooks"]}
    config = {"marker": list(marker.encode("ascii")), "test_thread_id": TEST_THREAD_ID}
    for name, layer in (("http", "http_encoded_body_preparation"),
                        ("wss", "wss_request_serialization")):
        hook = hooks[layer]
        config[name] = {"rva": hook["rva"],
                        "prefix": list(bytes.fromhex(hook["entry_prefix_hex"]))}
    return AGENT.replace("__CONFIG__", json.dumps(config, separators=(",", ":")))


def safe_event(payload: object) -> dict | None:
    """Discard every field other than bounded enum/boolean/length/digest data."""
    if not isinstance(payload, dict) or payload.get("kind") not in _EVENTS:
        return None
    kind = payload["kind"]
    hook = payload.get("hook")
    if kind != "probe_ready" and hook not in _HOOKS:
        return None
    row = {"kind": kind, "observed_unix_ns": time.time_ns()}
    if hook in _HOOKS:
        row["hook"] = hook
    if kind == "marker_metadata":
        size, digest = payload.get("bytes"), payload.get("sha256")
        if type(size) is not int or not 0 < size <= 512 * 1024:
            return None
        if digest is not None and (not isinstance(digest, str)
                                   or not _SHA256.fullmatch(digest)):
            return None
        state = payload.get("parse_state")
        if state not in _PARSE_STATES:
            return None
        row.update(bytes=size, sha256=digest, parse_state=state)
        for name in ("thread_id_match", "function_output_marker", "user_content_marker"):
            value = payload.get(name)
            if value is not None and type(value) is not bool:
                return None
            row[name] = value
    return row


def summarize(rows: list[dict], errors: list[str]) -> dict:
    installed = {row.get("hook") for row in rows if row.get("kind") == "hook_installed"}
    missing = [row for row in rows if row.get("kind") in {
        "hook_unavailable", "entry_mismatch", "read_error"}]
    markers = [row for row in rows if row.get("kind") == "marker_metadata"]
    attributed = [row for row in markers if row.get("parse_state") == "parsed"
                  and row.get("thread_id_match") is True
                  and row.get("function_output_marker") is True]
    return {"status": "metadata_attributed_to_test_thread" if attributed and not errors and not missing
            and installed == _HOOKS and any(row.get("kind") == "probe_ready" for row in rows)
            else "unvalidated",
            "marker_events": len(markers),
            "test_thread_function_output_matches": len(attributed),
            "other_thread_marker_events": sum(row.get("thread_id_match") is False
                                              for row in markers),
            "missing_or_invalid_thread_metadata_events": sum(
                row.get("thread_id_match") is None for row in markers),
            "installed_hooks": sorted(installed)}


def _worker(adapter: dict, package: dict, targets: dict, desktop_pid: int,
            backend_pid: int, sid: str, marker: str, sender) -> None:
    session = None
    lock = threading.Lock()
    try:
        require_current_user(sid)
        import frida
        with hold_processes(targets):
            if verify_current_targets(adapter, package, desktop_pid, backend_pid, sid) != targets:
                raise ValueError("target changed before attach")
            session = frida.attach(backend_pid)
            script = session.create_script(agent_source(adapter, marker))

            def receive(message, _data):
                if message.get("type") == "send":
                    event = safe_event(message.get("payload"))
                    row = {"event": event} if event is not None else {"error": "unexpected_agent_event"}
                elif message.get("type") == "error":
                    row = {"error": "frida_script_error"}
                else:
                    return
                try:
                    with lock:
                        sender.send(row)
                except (BrokenPipeError, OSError):
                    pass

            script.on("message", receive)
            script.load()
            if verify_current_targets(adapter, package, desktop_pid, backend_pid, sid) != targets:
                raise ValueError("target changed after attach")
            threading.Event().wait()
    except Exception as error:
        try:
            with lock:
                sender.send({"error": "frida_worker_" + type(error).__name__})
        except (BrokenPipeError, OSError):
            pass
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        sender.close()


def _collect(receiver, rows: list[dict], errors: list[str], ready: threading.Event) -> None:
    try:
        while True:
            item = receiver.recv()
            if not isinstance(item, dict):
                errors.append("unexpected_worker_message")
            elif isinstance(item.get("error"), str):
                errors.append(item["error"][:80])
            elif isinstance(item.get("event"), dict):
                event = safe_event(item["event"])
                if event is None or len(rows) >= _MAX_EVENTS:
                    errors.append("event_bound_or_shape")
                else:
                    rows.append(event)
                    if event["kind"] in {"hook_unavailable", "entry_mismatch"}:
                        errors.append(event["kind"])
                    if event["kind"] == "probe_ready":
                        ready.set()
            else:
                errors.append("unexpected_worker_message")
    except EOFError:
        pass
    except (BrokenPipeError, OSError):
        errors.append("worker_pipe_error")


def run_probe(args) -> dict:
    require_observation(args)
    require_current_user(args.expected_sid)
    adapter_path = args.adapter.resolve(strict=True)
    adapter = load_desktop_adapter(adapter_path, require_validated=False)
    fixture, prompt, _ = load_fixtures(args.fixtures)
    marker = fixture["prompt_marker"]
    if prompt.read_text(encoding="utf-8") != f"请简短回复。测试标记：{marker}\n":
        raise ValueError("fixture prompt is not the exact synthetic text")
    msix_sha = verify_archived_msix(args.msix, adapter)
    package = registered_package(adapter)
    targets = verify_current_targets(adapter, package, args.desktop_pid,
                                     args.backend_pid, args.expected_sid)
    backend_path = Path(process_identity(args.backend_pid)["image_path"])
    static = verify_static_entries(adapter, backend_path)
    source = agent_source(adapter, marker)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows: list[dict] = []
    errors: list[str] = []
    observer = receiver = collector = None
    began = time.time_ns()
    try:
        with hold_processes(targets):
            if verify_current_targets(adapter, package, args.desktop_pid,
                                      args.backend_pid, args.expected_sid) != targets:
                raise ValueError("current target changed before worker startup")
            context = multiprocessing.get_context("spawn")
            receiver, sender = context.Pipe(duplex=False)
            observer = context.Process(target=_worker,
                                       args=(adapter, package, targets, args.desktop_pid,
                                             args.backend_pid, args.expected_sid, marker, sender),
                                       daemon=True)
            observer.start()
            sender.close()
            ready = threading.Event()
            collector = threading.Thread(target=_collect,
                                         args=(receiver, rows, errors, ready), daemon=True)
            collector.start()
            if ready.wait(20) and not errors:
                print(f"Current-client thread-metadata observation ready for {args.seconds}s. "
                      f"Send the exact synthetic fixture from {prompt} to the pinned Local test chat.",
                      flush=True)
                until = time.monotonic() + args.seconds
                while time.monotonic() < until:
                    if not observer.is_alive():
                        errors.append("frida_worker_exited_during_observation")
                        break
                    time.sleep(min(0.1, until - time.monotonic()))
            else:
                errors.append("frida_attach_or_load_timeout" if observer.is_alive()
                              else "frida_worker_exited_before_ready")
    except Exception as error:
        errors.append(type(error).__name__)
    finally:
        _stop_frida(observer, receiver, collector, errors)
        try:
            if verify_current_targets(adapter, package, args.desktop_pid,
                                      args.backend_pid, args.expected_sid) != targets:
                errors.append("target_identity_changed")
        except Exception:
            errors.append("target_identity_unavailable_after_observation")
        summary = summarize(rows, errors)
        report = {"schema": SCHEMA, "observation_only": True, "can_enforce": False,
                  "coverage_status": "unvalidated", "active_client_attached": observer is not None,
                  "shared_backend_with_user_chat": True,
                  "current_app_interruption_risk": True,
                  "raw_body_persisted": False, "thread_id_persisted": False,
                  "expected_thread_id_persisted": False,
                  "max_body_scanned_bytes": 512 * 1024,
                  "max_json_parsed_bytes": 256 * 1024,
                  "oversized_body_uninspected": True,
                  "remote_origin_zero_bytes_verified": False,
                  "status": summary["status"], "metadata_summary": summary,
                  "archived_msix_sha256": msix_sha,
                  "adapter_sha256": _hash(adapter_path),
                  "synthetic_fixture_sha256": _hash(prompt),
                  "marker_sha256": hashlib.sha256(marker.encode("ascii")).hexdigest(),
                  "static_candidates_sha256": hashlib.sha256(json.dumps(
                      static["candidates"], sort_keys=True).encode()).hexdigest(),
                  "agent_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                  "targets": targets, "elapsed_ms": (time.time_ns() - began) / 1_000_000,
                  "errors": sorted(set(errors)), "events": rows}
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n",
                                             encoding="utf-8")
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active-current-client", action="store_true", required=True)
    parser.add_argument("--observation-only", action="store_true", required=True)
    parser.add_argument("--msix", type=Path, required=True)
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--desktop-pid", type=int, required=True)
    parser.add_argument("--backend-pid", type=int, required=True)
    parser.add_argument("--expected-sid", required=True)
    parser.add_argument("--seconds", type=int, choices=range(5, 121), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    enter_repository()
    report = run_probe(args)
    print(json.dumps({key: report[key] for key in ("status", "metadata_summary", "errors")},
                     indent=2))
    if report["errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
