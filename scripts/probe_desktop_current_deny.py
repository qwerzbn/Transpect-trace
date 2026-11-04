"""Opt-in synthetic-only denial probe for the active pinned Codex desktop.

This is a short research experiment, not an installed DLP guard. It can
interrupt every chat sharing the current app-server. It recognizes one exact
synthetic fixture marker, and leaves other requests untouched. Both fixed-build
WSS and HTTP candidates are installed because WSS denial can fall back to HTTP.
Neither a Hook event nor a UI error proves that the remote origin got zero bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
from pathlib import Path
import re
import struct
import sys
import threading
import time

from _build_support import ROOT, enter_repository

sys.path.insert(0, str(ROOT / "src"))

from probe_desktop_paths_current import verify_current_targets, require_current_user
from probe_desktop_paths_host import (
    _stop_frida, hold_processes, registered_package, verify_archived_msix,
)
from probe_desktop_paths_vm import _hash, load_fixtures, verify_static_entries
from probe_desktop_current_thread_metadata import TEST_THREAD_ID
from transpect_trace.guard.desktop import load_desktop_adapter
from transpect_trace.observe.windows import identity as process_identity


SCHEMA = "transpect.desktop-current-synthetic-denial/1.0"
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_EVENTS = frozenset(("hook_installed", "probe_ready", "non_target_marker",
                     "synthetic_match",
                     "synthetic_denied", "synthetic_denial_failed",
                     "hook_inspection_error"))
_HOOKS = frozenset(("model.http", "model.wss"))
_DROP_HEADERS_RVA = "0xa6320"
# This is the observed prologue in the archived 26.1029.7803.0 backend.
_DROP_HEADERS_PREFIX = "555657534883ec58"
_MAX_EVENTS = 128


AGENT = r"""
const CONFIG = __CONFIG__;
const marker = new Uint8Array(CONFIG.marker);
const markerString = String.fromCharCode.apply(null, CONFIG.marker);
// Bound unrelated live requests copied for the marker search. The fixture
// route previously observed in this build is far below this limit.
const maxBody = 512 * 1024;
const maxJson = 256 * 1024;
function prefixMatches(target, prefix) {
  const actual = new Uint8Array(target.readVolatile(prefix.length));
  return actual.length === prefix.length &&
    actual.every((value, index) => value === prefix[index]);
}
function markerOffset(bytes) {
  if (bytes.length < marker.length) return -1;
  outer: for (let i = 0; i <= bytes.length - marker.length; i++) {
    for (let j = 0; j < marker.length; j++)
      if (bytes[i + j] !== marker[j]) continue outer;
    return i;
  }
  return -1;
}
function containsMarker(value) {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === 'string' && encoded.includes(markerString);
  } catch (_) { return false; }
}
function checkSynthetic(data, length, protocol) {
  if (data.isNull() || !Number.isSafeInteger(length) || length < marker.length ||
      length > maxBody) return null;
  const bytes = new Uint8Array(data.readVolatile(length));
  if (markerOffset(bytes) < 0) return null;
  // A marker in another chat's tool output is not the target. The fixed
  // backend owns client_metadata.thread_id; require this exact test chat and
  // an input field that the connector actually used for its synthetic prompt.
  if (length > maxJson)
    return {target:false, reason:'oversized_json'};
  let value;
  try { value = JSON.parse(data.readUtf8String(length)); }
  catch (_) { return {target:false, reason:'invalid_json'}; }
  if (!value || typeof value !== 'object' ||
      (protocol === 'wss' && value.type !== 'response.create') ||
      typeof value.model !== 'string' || !Array.isArray(value.input))
    return {target:false, reason:'unexpected_request_shape'};
  const metadata = value.client_metadata;
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata))
    return {target:false, reason:'missing_client_metadata'};
  if (typeof metadata.thread_id !== 'string')
    return {target:false, reason:'missing_thread_id'};
  if (metadata.thread_id !== CONFIG.test_thread_id)
    return {target:false, reason:'thread_id_mismatch'};
  let target = false;
  try {
    target = value.input.some(item => item && (
      (item.type === 'function_call_output' &&
       containsMarker(item.output)) ||
      (item.role === 'user' &&
       containsMarker(item.content))));
  } catch (_) {
    return {target:false, reason:'shape_check_error'};
  }
  if (!target) return {target:false, reason:'marker_not_in_test_input'};
  let digest;
  try { digest = Checksum.compute('sha256', bytes.buffer); }
  catch (_) { return {target:true, valid:false, reason:'digest_failed', bytes:length,
                        sha256:'0000000000000000000000000000000000000000000000000000000000000000'}; }
  return {target:true, valid:true, bytes:length, sha256:digest};
}
function emit(kind, hook, details) {
  send(Object.assign({kind:kind, hook:hook}, details || {}));
}
const base = Process.mainModule.base;
const httpTarget = base.add(ptr(CONFIG.http.rva));
const wssTarget = base.add(ptr(CONFIG.wss.rva));
const dropTarget = base.add(ptr(CONFIG.drop.rva));
if (!prefixMatches(httpTarget, CONFIG.http.prefix) ||
    !prefixMatches(wssTarget, CONFIG.wss.prefix) ||
    !prefixMatches(dropTarget, CONFIG.drop.prefix))
  throw new Error('fixed candidate or owned HeaderMap drop prologue changed');
const dropHeaders = new NativeFunction(dropTarget, 'void', ['pointer']);
const kernel = Process.getModuleByName('kernel32.dll');
const currentProcess = new NativeFunction(kernel.getExportByName('GetCurrentProcess'),
    'pointer', []);
const terminateProcess = new NativeFunction(kernel.getExportByName('TerminateProcess'),
    'bool', ['pointer', 'uint32']);
function failStop() { terminateProcess(currentProcess(), 76); }
const originalHttp = new NativeFunction(httpTarget, 'pointer',
    ['pointer', 'pointer', 'pointer', 'pointer']);
Interceptor.replace(httpTarget, new NativeCallback(function(result, request, headers, body) {
  let checked = null;
  try {
    const data = body.add(8).readPointer();
    const length = body.add(16).readU64().toNumber();
    checked = checkSynthetic(data, length, 'http');
  } catch (_) {
    // An unrelated or unreadable body is never interpreted as the fixture.
    return originalHttp(result, request, headers, body);
  }
  if (checked === null) return originalHttp(result, request, headers, body);
  if (!checked.target) {
    emit('non_target_marker', 'model.http', {reason:checked.reason});
    return originalHttp(result, request, headers, body);
  }
  emit('synthetic_match', 'model.http',
       {bytes:checked.bytes, sha256:checked.sha256, valid:checked.valid});
  if (!checked.valid)
    emit('synthetic_denial_failed', 'model.http', {reason:checked.reason});
  // The fixed-build isolated CLI established the HeaderMap ownership and
  // Err(String) tag 3 layout. Do not invoke the original send function.
  try {
    if (!headers.isNull()) dropHeaders(headers);
    result.writeU64(3);
    result.add(8).writeU64(0);
    result.add(16).writePointer(ptr(1));
    result.add(24).writeU64(0);
    emit('synthetic_denied', 'model.http', {bytes:checked.bytes, sha256:checked.sha256});
    return result;
  } catch (_) {
    // Once ownership may have been released, pass-through is never allowed.
    try {
      result.writeU64(3);
      result.add(8).writeU64(0);
      result.add(16).writePointer(ptr(1));
      result.add(24).writeU64(0);
      emit('synthetic_denial_failed', 'model.http',
           {reason:'native_error_construction'});
      return result;
    } catch (_) { failStop(); return result; }
  }
}, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']));
emit('hook_installed', 'model.http');
Interceptor.attach(wssTarget, {
  onEnter(args) { this.result = args[0]; },
  onLeave(_) {
    let matched = false;
    let checked = null;
    try {
      if (this.result.readU64().toNumber() !== 0x1f) return;
      const capacity = this.result.add(8).readU64().toNumber();
      const data = this.result.add(16).readPointer();
      const length = this.result.add(24).readU64().toNumber();
      checked = checkSynthetic(data, length, 'wss');
      if (checked === null) return;
      if (!checked.target) {
        emit('non_target_marker', 'model.wss', {reason:checked.reason});
        return;
      }
      matched = true;
      emit('synthetic_match', 'model.wss',
           {bytes:checked.bytes, sha256:checked.sha256, valid:checked.valid});
      if (!checked.valid)
        emit('synthetic_denial_failed', 'model.wss', {reason:checked.reason});
      const reason = 'Transpect synthetic request denied';
      const encoded = Array.from(reason).map(char => char.charCodeAt(0));
      if (!Number.isSafeInteger(capacity) || capacity < length) {
        emit('synthetic_denial_failed', 'model.wss', {reason:'invalid_capacity'});
        failStop();
        return;
      }
      if (capacity >= encoded.length) {
        data.writeByteArray(encoded);
        this.result.add(24).writeU64(encoded.length);
      } else {
        this.result.add(24).writeU64(0);
      }
      this.result.writeU64(0x0d);
      emit('synthetic_denied', 'model.wss',
           {bytes:checked.bytes, sha256:checked.sha256});
    } catch (_) {
      emit('hook_inspection_error', 'model.wss');
      if (matched) failStop();
    }
  }
});
emit('hook_installed', 'model.wss');
send({kind:'probe_ready'});
"""


def require_opt_in(args) -> None:
    if not (getattr(args, "active_current_client", False)
            and getattr(args, "synthetic_only", False)
            and getattr(args, "accept_interruption", False)):
        raise ValueError("explicit current-client, synthetic-only and interruption flags are required")
    if type(args.seconds) is not int or not 5 <= args.seconds <= 120:
        raise ValueError("probe duration must be 5..120 seconds")


def synthetic_source(adapter: dict, marker: str) -> str:
    hooks = {item["layer"]: item for item in adapter["hooks"]}
    config = {
        "marker": list(marker.encode("ascii")), "test_thread_id": TEST_THREAD_ID,
        "http": {"rva": hooks["http_encoded_body_preparation"]["rva"],
                 "prefix": list(bytes.fromhex(
                     hooks["http_encoded_body_preparation"]["entry_prefix_hex"]))},
        "wss": {"rva": hooks["wss_request_serialization"]["rva"],
                "prefix": list(bytes.fromhex(
                    hooks["wss_request_serialization"]["entry_prefix_hex"]))},
        "drop": {"rva": _DROP_HEADERS_RVA,
                 "prefix": list(bytes.fromhex(_DROP_HEADERS_PREFIX))},
    }
    return AGENT.replace("__CONFIG__", json.dumps(config, separators=(",", ":")))


def verify_drop_headers_entry(binary: Path) -> None:
    """Reject a changed or non-code HeaderMap destructor before Frida attaches."""
    prefix = bytes.fromhex(_DROP_HEADERS_PREFIX)
    with Path(binary).open("rb") as stream:
        header = stream.read(65536)
        if len(header) < 64 or header[:2] != b"MZ":
            raise ValueError("fixed backend PE header unavailable")
        pe = struct.unpack_from("<I", header, 60)[0]
        if pe + 24 > len(header) or header[pe:pe + 4] != b"PE\0\0":
            raise ValueError("fixed backend PE signature changed")
        count = struct.unpack_from("<H", header, pe + 6)[0]
        opt_size = struct.unpack_from("<H", header, pe + 20)[0]
        table = pe + 24 + opt_size
        if count > 96 or table + count * 40 > len(header):
            raise ValueError("fixed backend PE sections unavailable")
        code = None
        for index in range(count):
            offset = table + index * 40
            name = header[offset:offset + 8].rstrip(b"\0")
            if name == b".text":
                virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                    "<IIII", header, offset + 8)
                code = (rva, min(virtual_size, raw_size), raw_offset)
                break
        if code is None:
            raise ValueError("fixed backend executable section unavailable")
        rva = int(_DROP_HEADERS_RVA, 16)
        base, size, raw = code
        if not base <= rva <= base + size - len(prefix):
            raise ValueError("fixed HeaderMap destructor is outside .text")
        stream.seek(raw + rva - base)
        if stream.read(len(prefix)) != prefix:
            raise ValueError("fixed HeaderMap destructor prologue changed")


def safe_event(payload: object) -> dict | None:
    """Keep only explicit fixture metadata, never arbitrary Frida payloads."""
    if not isinstance(payload, dict) or payload.get("kind") not in _EVENTS:
        return None
    kind = payload["kind"]
    hook = payload.get("hook")
    if kind != "probe_ready" and hook not in _HOOKS:
        return None
    row = {"kind": kind, "observed_unix_ns": time.time_ns()}
    if hook in _HOOKS:
        row["hook"] = hook
    if kind in {"synthetic_match", "synthetic_denied"}:
        size, digest = payload.get("bytes"), payload.get("sha256")
        if type(size) is not int or not 0 < size <= 16 * 1024 * 1024:
            return None
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            return None
        row.update(bytes=size, sha256=digest)
        if kind == "synthetic_match" and type(payload.get("valid")) is bool:
            row["valid"] = payload["valid"]
    elif kind == "synthetic_denial_failed":
        if payload.get("reason") in {"oversized_json", "invalid_json",
                                     "unexpected_request_shape", "marker_not_in_user_input",
                                     "digest_failed", "shape_check_error",
                                     "null_headers", "native_error_construction",
                                     "invalid_capacity"}:
            row["reason"] = payload["reason"]
    elif kind == "non_target_marker":
        if payload.get("reason") in {"oversized_json", "invalid_json",
                                     "unexpected_request_shape", "shape_check_error",
                                     "missing_client_metadata", "missing_thread_id",
                                     "thread_id_mismatch", "marker_not_in_test_input"}:
            row["reason"] = payload["reason"]
    return row


def summarize(rows: list[dict], errors: list[str]) -> dict:
    installed = {row.get("hook") for row in rows if row.get("kind") == "hook_installed"}
    ready = any(row.get("kind") == "probe_ready" for row in rows)
    denied = {row.get("hook") for row in rows if row.get("kind") == "synthetic_denied"}
    failed = [row for row in rows if row.get("kind") in {
        "synthetic_denial_failed", "hook_inspection_error"}]
    invalid_matches = [row for row in rows if row.get("kind") == "synthetic_match"
                       and row.get("valid") is False]
    if errors or failed or invalid_matches or installed != _HOOKS or not ready:
        status = "unvalidated_probe_or_denial_error"
    elif denied == _HOOKS:
        status = "both_candidate_denials_observed_without_origin_proof"
    elif denied:
        status = "one_candidate_denial_observed_without_origin_proof"
    else:
        status = "no_synthetic_denial_observed"
    return {"status": status, "installed_hooks": sorted(installed),
            "non_target_marker_by_hook": {
                name: sum(row.get("kind") == "non_target_marker"
                          and row.get("hook") == name for row in rows)
                for name in sorted(_HOOKS)},
            "synthetic_denials_by_hook": {name: sum(row.get("kind") == "synthetic_denied"
                                                   and row.get("hook") == name for row in rows)
                                          for name in sorted(_HOOKS)},
            "synthetic_matches_by_hook": {name: sum(row.get("kind") == "synthetic_match"
                                                   and row.get("hook") == name for row in rows)
                                          for name in sorted(_HOOKS)},
            "synthetic_denial_failures": len(failed)}


def _worker(adapter: dict, package: dict, targets: dict, desktop_pid: int,
            backend_pid: int, sid: str, marker: str, sender) -> None:
    session = None
    lock = threading.Lock()
    try:
        require_current_user(sid)
        import frida
        with hold_processes(targets):
            if verify_current_targets(adapter, package, desktop_pid, backend_pid, sid) != targets:
                raise ValueError("target changed before attachment")
            session = frida.attach(backend_pid)
            script = session.create_script(synthetic_source(adapter, marker))

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
                raise ValueError("target changed after attachment")
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
                    if event["kind"] == "probe_ready":
                        ready.set()
            else:
                errors.append("unexpected_worker_message")
    except EOFError:
        pass
    except (BrokenPipeError, OSError):
        errors.append("worker_pipe_error")


def run_probe(args) -> dict:
    require_opt_in(args)
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
    verify_drop_headers_entry(backend_path)
    source = synthetic_source(adapter, marker)
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
            pipe_recv, pipe_send = multiprocessing.get_context("spawn").Pipe(duplex=False)
            receiver = pipe_recv
            observer = multiprocessing.get_context("spawn").Process(
                target=_worker, args=(adapter, package, targets, args.desktop_pid,
                                      args.backend_pid, args.expected_sid, marker, pipe_send),
                daemon=True)
            observer.start()
            pipe_send.close()
            ready = threading.Event()
            collector = threading.Thread(target=_collect,
                                         args=(receiver, rows, errors, ready), daemon=True)
            collector.start()
            if ready.wait(20) and not errors:
                print(f"Synthetic-only current-client denial probe ready for {args.seconds}s. "
                      f"Submit the pinned fixture in the separate Local test chat: {prompt}",
                      flush=True)
                until = time.monotonic() + args.seconds
                while time.monotonic() < until:
                    if not observer.is_alive():
                        errors.append("frida_worker_exited_during_probe")
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
            errors.append("target_identity_unavailable_after_probe")
        summary = summarize(rows, errors)
        report = {"schema": SCHEMA, "scope": "active_current_pinned_desktop_synthetic_only",
                  "status": summary["status"], "candidate_results": summary,
                  "coverage_status": "unvalidated", "production_ready": False,
                  "desktop_ui_full_coverage_verified": False,
                  "remote_origin_zero_bytes_verified": False,
                  "attachment_upload_covered": False,
                  "agent_tool_egress_covered": False,
                  "dlp_decision_integrated": False,
                  "test_thread_identity_required": True,
                  "test_thread_id_persisted": False,
                  "function_call_output_target_supported": True,
                  "fail_stop_can_terminate_shared_backend": True,
                  "shared_backend_with_user_chat": True,
                  "current_app_interruption_risk": True,
                  "http_fallback_requires_both_hooks": True,
                  "max_body_scanned_bytes": 512 * 1024,
                  "oversized_body_uninspected": True,
                  "raw_body_persisted": False,
                  "synthetic_fixture_sha256": _hash(prompt),
                  "marker_sha256": hashlib.sha256(marker.encode("ascii")).hexdigest(),
                  "archive_msix_sha256": msix_sha,
                  "adapter_sha256": _hash(adapter_path),
                  "static_candidates_sha256": hashlib.sha256(json.dumps(
                      static["candidates"], sort_keys=True).encode()).hexdigest(),
                  "agent_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                  "targets": targets, "elapsed_ms": (time.time_ns() - began) / 1_000_000,
                  "errors": sorted(set(errors)),
                  "events": rows}
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n",
                                             encoding="utf-8")
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active-current-client", action="store_true", required=True)
    parser.add_argument("--synthetic-only", action="store_true", required=True)
    parser.add_argument("--accept-interruption", action="store_true", required=True)
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
    print(json.dumps({key: report[key] for key in
                      ("status", "coverage_status", "remote_origin_zero_bytes_verified",
                       "shared_backend_with_user_chat", "errors")}, indent=2))
    if report["errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
