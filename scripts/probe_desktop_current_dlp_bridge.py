"""Synthetic-only DLP bridge probe for one pinned Local desktop chat.

This is an opt-in research probe, not a persistent guard. Do not attach it to
the current app as part of ordinary tests: Frida and fail-stop may interrupt
every chat sharing the app-server. The only content exported to Python is a
complete serialized model request whose core-owned thread ID and typed input
both match the pinned synthetic fixture. That request may include system and
developer instructions and the test chat's history. It is encrypted before
policy approval; reports retain metadata only. Local Hook evidence does not
establish remote-origin zero bytes.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import sys
import threading
import time
from uuid import uuid4

from _build_support import ROOT, enter_repository
sys.path.insert(0, str(ROOT / "src"))

from probe_desktop_current_deny import verify_drop_headers_entry
from probe_desktop_current_thread_metadata import TEST_THREAD_ID
from probe_desktop_paths_current import require_current_user, verify_current_targets
from probe_desktop_paths_host import (
    _stop_frida, hold_processes, registered_package, verify_archived_msix,
)
from probe_desktop_paths_vm import _hash, load_fixtures, verify_static_entries
from transpect_trace.guard.desktop import load_desktop_adapter
from transpect_trace.guard.policy import GuardRequest
from transpect_trace.observe.windows import identity as process_identity
from transpect_trace.protect.archive import EncryptedRequestArchive
from transpect_trace.protect.desktop_bridge import DesktopDLPBridge
from transpect_trace.protect.desktop_registration import load_desktop_registration


SCHEMA = "transpect.desktop-current-synthetic-dlp-bridge/1.0"
MAX_BODY = 16 * 1024 * 1024
DECISION_TIMEOUT_SECONDS = 2.0
MAX_EVENTS = 256
_MARKER = re.compile(r"FAKE_DESKTOP_PROMPT_[a-f0-9]{32}\Z")
_UUID = re.compile(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\Z", re.I)
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_HOOKS = {"model.http", "model.wss"}
_DROP_RVA = "0xa6320"
_DROP_PREFIX = "555657534883ec58"
FAKE_SECRET = "password=FakeSecret12345"

# Every reference is synthetic. A fixed hash guards accidental edits to the
# four-layer fixture before a live shared-backend experiment can start.
SYNTHETIC_REGISTRATION = {
    "employees.json": b'{"synthetic-1":{"name":"Ada Sample","email":"ada@example.test","id":"ZX98765432"}}\n',
    "internal.md": b'Internal Apollo schedule is restricted to the review team. The launch window opens after final approval.\n',
    "module.py": b'def calculate_private_score(values):\n    total = sum(values)\n    return total / len(values)\n',
    "registration.json": b'{"schema":"transpect.desktop-dlp-registration/1.0","records":"employees.json","documents":[{"id":"apollo","category":"INTERNAL_DOC","path":"internal.md"},{"id":"module","category":"SOURCE_CODE","path":"module.py"}]}\n',
}
SYNTHETIC_REGISTRATION_SHA256 = {
    "employees.json": "f84050421883db9677b737d75ae8c881da51d4af9cbb3952cb93d7e0de587980",
    "internal.md": "bfa230e9cb26ee1ee912f556d61e2e70dffcb15b12c166bf4ee36cc075c6026f",
    "module.py": "772dfe158543ce18dbe183f9a3edc52bbd75221b4951d77f95fe41c1382a412c",
    "registration.json": "22c165390d63a8f6a3db45a22a2d94731f47904cc996294aedc5c5a6ece85d82",
}


DUPLICATE_SCAN_JS = r"""
function parseUniqueJson(text) {
  // JSON.parse accepts duplicate names. Check all object keys first, decoding
  // escaped spellings so "thread_id" and "thread\u005fid" are the same name.
  const stack = [];
  let nodes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      const start = i;
      i++;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === '"') break;
        i++;
      }
      if (i >= text.length) throw new Error('unterminated_json_string');
      let next = i + 1;
      while (next < text.length && /\s/.test(text[next])) next++;
      const frame = stack[stack.length - 1];
      if (frame && frame.kind === 'object' && text[next] === ':') {
        const key = JSON.parse(text.slice(start, i + 1));
        if (frame.keys.has(key)) throw new Error('duplicate_json_key');
        frame.keys.add(key);
        if (++nodes > 200000) throw new Error('json_node_limit');
      }
    } else if (c === '{' || c === '[') {
      if (stack.length >= 64 || ++nodes > 200000) throw new Error('json_structure_limit');
      stack.push(c === '{' ? {kind:'object', keys:new Set()} : {kind:'array'});
    } else if (c === '}' || c === ']') {
      stack.pop();
    }
  }
  return JSON.parse(text);
}
"""


DENIAL_ABI_JS = r"""
function constructHttpDenial(result, headers, dropHeaders) {
  if (headers.isNull()) throw new Error('null_headers');
  dropHeaders(headers);
  result.writeU64(3);
  result.add(8).writeU64(0);
  result.add(16).writePointer(ptr(1));
  result.add(24).writeU64(0);
  return result;
}
function constructWssDenial(result, data, length, capacity, failStop) {
  if (!Number.isSafeInteger(capacity) || capacity < length) failStop();
  const reason = 'Transpect synthetic DLP denied';
  const encoded = Array.from(reason).map(ch => ch.charCodeAt(0));
  if (capacity >= encoded.length) {
    data.writeByteArray(encoded);
    result.add(24).writeU64(encoded.length);
  } else result.add(24).writeU64(0);
  result.writeU64(0x0d);
}
"""


AGENT = r"""
const CONFIG = __CONFIG__;
const markerString = CONFIG.marker;
const fakeSecret = CONFIG.fake_secret;
const maxBody = 16 * 1024 * 1024;
__DUPLICATE_SCAN__
function prefixMatches(target, prefix) {
  const actual = new Uint8Array(target.readVolatile(prefix.length));
  return actual.length === prefix.length &&
    actual.every((value, index) => value === prefix[index]);
}
function literalIn(value, literal) {
  try { return JSON.stringify(value).includes(literal); }
  catch (_) { return false; }
}
function classify(data, length, protocol) {
  if (data.isNull() || !Number.isSafeInteger(length) || length <= 0 || length > maxBody)
    return {state:'unattributable', reason:'size_or_pointer'};
  let text, value;
  try { text = data.readUtf8String(length); value = parseUniqueJson(text); }
  catch (_) { return {state:'unattributable', reason:'json_or_read_error'}; }
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (protocol === 'wss' && value.type !== 'response.create') ||
      (protocol === 'http' && Object.prototype.hasOwnProperty.call(value,'type')) ||
      typeof value.model !== 'string' || !Array.isArray(value.input) || !value.input.length)
    return {state:'unattributable', reason:'request_shape'};
  const metadata = value.client_metadata;
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata) ||
      typeof metadata.thread_id !== 'string' ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(metadata.thread_id))
    return {state:'unattributable', reason:'thread_metadata'};
  // This comparison precedes every content/marker search. Other chats never
  // send or archive request bytes; their parsed values stay in this process.
  if (metadata.thread_id !== CONFIG.test_thread_id) return {state:'other_chat'};
  let source = null;
  for (const item of value.input) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    if (item.type === 'function_call_output' && literalIn(item.output,markerString) &&
        (!CONFIG.require_secret || literalIn(item.output,fakeSecret))) {
      source = 'function_call_output'; break;
    }
    if (item.role === 'user' && literalIn(item.content,markerString) &&
        (!CONFIG.require_secret || literalIn(item.content,fakeSecret))) {
      source = 'user_content'; break;
    }
  }
  if (source === null) return {state:'test_chat_without_marker'};
  try {
    const body = data.readVolatile(length);
    return {state:'target', source:source, body:body, bytes:length,
            sha256:Checksum.compute('sha256',body)};
  } catch (_) { return {state:'target_error',reason:'body_capture'}; }
}
const kernel = Process.getModuleByName('kernel32.dll');
const currentProcess = new NativeFunction(kernel.getExportByName('GetCurrentProcess'),
    'pointer', []);
const terminateProcess = new NativeFunction(kernel.getExportByName('TerminateProcess'),
    'bool', ['pointer', 'uint32']);
function failStop() {
  terminateProcess(currentProcess(), 76);
  while (true) {} // Never resume the native sender if termination fails.
}
__DENIAL_ABI__
let requestNumber = 0;
function decide(hook, checked) {
  const requestId = String(++requestNumber);
  send({kind:'target_body',hook:hook,request_id:requestId,
        source:checked.source,bytes:checked.bytes,sha256:checked.sha256}, checked.body);
  let action = 'deny';
  try {
    recv('target_decision_' + requestId, function(message) {
      if (message && message.payload && message.payload.action === 'allow')
        action = 'allow';
    }).wait();
  } catch (_) { failStop(); }
  return {action:action,request_id:requestId};
}
const base = Process.mainModule.base;
const httpTarget = base.add(ptr(CONFIG.http.rva));
const wssTarget = base.add(ptr(CONFIG.wss.rva));
const dropTarget = base.add(ptr(CONFIG.drop.rva));
if (!prefixMatches(httpTarget, CONFIG.http.prefix) ||
    !prefixMatches(wssTarget, CONFIG.wss.prefix) ||
    !prefixMatches(dropTarget, CONFIG.drop.prefix))
  throw new Error('fixed entry or HeaderMap destructor prologue changed');
const dropHeaders = new NativeFunction(dropTarget, 'void', ['pointer']);
const originalHttp = new NativeFunction(httpTarget, 'pointer',
    ['pointer','pointer','pointer','pointer']);
Interceptor.replace(httpTarget, new NativeCallback(function(result, request, headers, body) {
  let checked;
  try { checked = classify(body.add(8).readPointer(),
                            body.add(16).readU64().toNumber(),'http'); }
  catch (_) { send({kind:'unattributable',hook:'model.http',reason:'read_error'});
              return originalHttp(result,request,headers,body); }
  if (checked.state === 'unattributable')
    send({kind:'unattributable',hook:'model.http',reason:checked.reason});
  if (checked.state === 'target_error') failStop();
  if (checked.state !== 'target') return originalHttp(result,request,headers,body);
  const verdict = decide('model.http',checked);
  if (verdict.action === 'allow') {
    send({kind:'target_allowed',hook:'model.http',request_id:verdict.request_id,
          bytes:checked.bytes,sha256:checked.sha256});
    return originalHttp(result,request,headers,body);
  }
  try {
    const denied = constructHttpDenial(result,headers,dropHeaders);
    send({kind:'target_denied',hook:'model.http',request_id:verdict.request_id,
          bytes:checked.bytes,sha256:checked.sha256});
    return denied;
  } catch (_) { failStop(); return result; }
}, 'pointer', ['pointer','pointer','pointer','pointer']));
send({kind:'hook_installed',hook:'model.http'});
Interceptor.attach(wssTarget,{onEnter(args){this.result=args[0];},onLeave(_){
  let checked = null;
  try {
    if (this.result.readU64().toNumber() !== 0x1f) return;
    const data = this.result.add(16).readPointer();
    const length = this.result.add(24).readU64().toNumber();
    checked = classify(data,length,'wss');
    if (checked.state === 'unattributable')
      send({kind:'unattributable',hook:'model.wss',reason:checked.reason});
    if (checked.state === 'target_error') failStop();
    if (checked.state !== 'target') return;
    const verdict = decide('model.wss',checked);
    if (verdict.action === 'allow') {
      send({kind:'target_allowed',hook:'model.wss',request_id:verdict.request_id,
            bytes:checked.bytes,sha256:checked.sha256});
      return;
    }
    const capacity = this.result.add(8).readU64().toNumber();
    constructWssDenial(this.result,data,length,capacity,failStop);
    send({kind:'target_denied',hook:'model.wss',request_id:verdict.request_id,
          bytes:checked.bytes,sha256:checked.sha256});
  } catch (_) { if (checked && checked.state === 'target') failStop();
              else send({kind:'unattributable',hook:'model.wss',reason:'read_error'}); }
}});
send({kind:'hook_installed',hook:'model.wss'});
send({kind:'probe_ready'});
"""


def synthetic_source(adapter: dict, marker: str, *, require_secret: bool = False) -> str:
    if not _MARKER.fullmatch(marker):
        raise ValueError("fixture marker is not a bounded synthetic prompt marker")
    hooks = {item["layer"]: item for item in adapter["hooks"]}
    config = {"marker": marker, "test_thread_id": TEST_THREAD_ID,
              "fake_secret": FAKE_SECRET, "require_secret": require_secret}
    for name, layer in (("http", "http_encoded_body_preparation"),
                        ("wss", "wss_request_serialization")):
        item = hooks[layer]
        config[name] = {"rva": item["rva"],
                        "prefix": list(bytes.fromhex(item["entry_prefix_hex"]))}
    config["drop"] = {"rva": _DROP_RVA, "prefix": list(bytes.fromhex(_DROP_PREFIX))}
    return (AGENT.replace("__CONFIG__", json.dumps(config, separators=(",", ":")))
            .replace("__DUPLICATE_SCAN__", DUPLICATE_SCAN_JS)
            .replace("__DENIAL_ABI__", DENIAL_ABI_JS))


def write_synthetic_registration(root: Path) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=False)
    for name, data in SYNTHETIC_REGISTRATION.items():
        if hashlib.sha256(data).hexdigest() != SYNTHETIC_REGISTRATION_SHA256[name]:
            raise ValueError("fixed synthetic registration changed")
        (root / name).write_bytes(data)
    return SYNTHETIC_REGISTRATION_SHA256.copy()


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate serialized JSON field")
        result[key] = value
    return result


def validate_target_body(raw: bytes, protocol: str, marker: str,
                         expected_thread_id: str = TEST_THREAD_ID,
                         *, require_secret: bool = False) -> str:
    """Recheck the Frida attribution before any request is archived."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BODY:
        raise ValueError("target body size unavailable")
    if protocol not in {"http", "wss"} or not _MARKER.fullmatch(marker):
        raise ValueError("invalid target protocol or fixture")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields)
    if (not isinstance(value, dict) or
            (protocol == "wss" and value.get("type") != "response.create") or
            (protocol == "http" and "type" in value) or
            not isinstance(value.get("model"), str) or
            not isinstance(value.get("input"), list) or not value["input"]):
        raise ValueError("target request shape unavailable")
    metadata = value.get("client_metadata")
    if (not isinstance(metadata, dict) or
            not isinstance(metadata.get("thread_id"), str) or
            not _UUID.fullmatch(metadata["thread_id"]) or
            metadata["thread_id"] != expected_thread_id):
        raise ValueError("request is not the pinned test chat")
    for item in value["input"]:
        if not isinstance(item, dict):
            continue
        if (item.get("type") == "function_call_output" and
                marker in json.dumps(item.get("output"), ensure_ascii=False) and
                (not require_secret or FAKE_SECRET in json.dumps(
                    item.get("output"), ensure_ascii=False))):
            return "function_call_output"
        if (item.get("role") == "user" and
                marker in json.dumps(item.get("content"), ensure_ascii=False) and
                (not require_secret or FAKE_SECRET in json.dumps(
                    item.get("content"), ensure_ascii=False))):
            return "user_content"
    raise ValueError("synthetic marker not in typed test input")


def evaluate_target(bridge: DesktopDLPBridge, archive: EncryptedRequestArchive,
                    raw: bytes, *, protocol: str, source: str, marker: str,
                    backend_pid: int, claimed_bytes: int, claimed_sha256: str,
                    require_secret: bool = False) -> dict:
    if (type(claimed_bytes) is not int or claimed_bytes != len(raw) or
            not isinstance(claimed_sha256, str) or not _SHA.fullmatch(claimed_sha256) or
            claimed_sha256 != hashlib.sha256(raw).hexdigest()):
        raise ValueError("Frida target digest mismatch")
    verified_source = validate_target_body(raw, protocol, marker,
                                           require_secret=require_secret)
    if verified_source != source:
        raise ValueError("Frida target source mismatch")
    request = GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0", "request_id": uuid4().hex,
        "guard_session_id": "current-synthetic-dlp-bridge", "pid": backend_pid,
        "tid": 1, "kind": "model.request", "protocol": protocol,
        "completeness": "complete", "payload_utf8": raw.decode("utf-8"),
    })
    decision, audit = bridge.evaluate(request)
    receipt_id = audit.get("archive_record_id")
    receipt, checked = archive.read(receipt_id) if receipt_id else (None, b"")
    archived_exactly = bool(receipt and checked == raw and
                            receipt.body_sha256 == claimed_sha256 and
                            receipt.body_bytes == claimed_bytes)
    return {"action": "allow" if decision.decision == "allow" and archived_exactly else "deny",
            "dlp_decision": "ALLOW" if decision.decision == "allow" else "DENY_OR_REVIEW",
            "reason": decision.reason, "rule_ids": audit.get("matched_rule_ids", []),
            "protocol": protocol, "source": verified_source, "bytes": len(raw),
            "sha256": claimed_sha256, "archive_readback_matches": archived_exactly,
            "archive_record_created": receipt is not None}


def await_and_post_policy(future, script, request_id: str,
                          stop_backend) -> tuple[dict, bool, bool | None]:
    """A policy failure replies DENY; a reply failure terminates the pinned backend."""
    result = {"action": "deny", "reason": "EVALUATION_FAILED"}
    try:
        candidate = future.result(timeout=DECISION_TIMEOUT_SECONDS)
        if not isinstance(candidate, dict) or candidate.get("action") not in {"allow", "deny"}:
            raise ValueError("invalid policy result")
        if (candidate["action"] == "allow" and
                candidate.get("archive_readback_matches") is not True):
            raise ValueError("allow without exact archive readback")
        result = candidate
    except FutureTimeout:
        result["reason"] = "POLICY_TIMEOUT"
    except Exception as error:
        result["reason"] = "POLICY_" + type(error).__name__
    try:
        script.post({"type": "target_decision_" + request_id,
                     "payload": {"action": result["action"]}})
    except Exception:
        stopped = bool(stop_backend())
        result["action"] = "deny"
        result["reason"] = "DECISION_REPLY_FAILED"
        return result, False, stopped
    return result, True, None


def safe_event(payload: object) -> dict | None:
    """Suppress all Frida fields not explicitly permitted in metadata reports."""
    if not isinstance(payload, dict):
        return None
    kind = payload.get("kind")
    if kind not in {"hook_installed", "probe_ready", "unattributable",
                    "target_allowed", "target_denied"}:
        return None
    hook = payload.get("hook")
    if kind != "probe_ready" and hook not in _HOOKS:
        return None
    row = {"kind": kind, "observed_unix_ns": time.time_ns()}
    if hook in _HOOKS:
        row["hook"] = hook
    if kind == "unattributable":
        if payload.get("reason") not in {"size_or_pointer", "json_or_read_error",
                                         "request_shape", "thread_metadata", "read_error"}:
            return None
        row["reason"] = payload["reason"]
    elif kind in {"target_allowed", "target_denied"}:
        size, digest = payload.get("bytes"), payload.get("sha256")
        request_id = payload.get("request_id")
        if (type(size) is not int or not 0 < size <= MAX_BODY or
                not isinstance(digest, str) or not _SHA.fullmatch(digest) or
                not isinstance(request_id, str) or not request_id.isdigit()):
            return None
        row.update(request_id=request_id, bytes=size, sha256=digest)
    return row


@contextmanager
def pinned_backend_stop(pid: int, birth_filetime: int):
    """Hold one verified process handle with terminate rights during the probe."""
    if os.name != "nt" or type(pid) is not int or type(birth_filetime) is not int:
        raise RuntimeError("pinned backend fail-stop requires Windows process identity")

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(FileTime)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x0001 | 0x00100000 | 0x1000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        times = [FileTime() for _ in range(4)]
        if (not kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in times)) or
                (times[0].low | (times[0].high << 32)) != birth_filetime or
                kernel.WaitForSingleObject(handle, 0) != 258):
            raise ValueError("backend changed before fail-stop handle acquired")

        def stop() -> bool:
            if kernel.WaitForSingleObject(handle, 0) == 0:
                return True
            return bool(kernel.TerminateProcess(handle, 76))

        yield stop
    finally:
        kernel.CloseHandle(handle)


def _worker(adapter: dict, package: dict, targets: dict, desktop_pid: int,
            backend_pid: int, expected_sid: str, marker: str, require_secret: bool,
            output: Path,
            sender) -> None:
    session = None
    executor = None
    send_lock = threading.Lock()

    def send_safe(item: dict) -> None:
        with send_lock:
            sender.send(item)

    try:
        require_current_user(expected_sid)
        import frida
        with hold_processes(targets), pinned_backend_stop(
                backend_pid, targets["backend"]["birth"]) as stop_backend:
            def record_fail_stop(reason: str, *, already_stopped: bool | None = None) -> bool:
                stopped = bool(stop_backend()) if already_stopped is None else already_stopped
                try:
                    send_safe({"fail_stop_result": {"reason": reason, "succeeded": stopped}})
                except (BrokenPipeError, OSError):
                    pass
                return stopped

            if verify_current_targets(adapter, package, desktop_pid,
                                      backend_pid, expected_sid) != targets:
                raise ValueError("pinned desktop pair changed before attachment")
            archive = EncryptedRequestArchive(output / "encrypted-archive")
            registration = output / "synthetic-registration"
            write_synthetic_registration(registration)
            engine, policy_version, loaded_hashes = load_desktop_registration(
                registration, archive)
            if loaded_hashes != SYNTHETIC_REGISTRATION_SHA256:
                raise ValueError("loaded synthetic references differ from fixed hashes")
            bridge = DesktopDLPBridge({"pid": backend_pid}, archive, engine,
                                      policy_version=policy_version)
            send_safe({"registration": loaded_hashes,
                       "policy_version": policy_version})
            executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="desktop-dlp-evaluate")
            session = frida.attach(backend_pid)
            script = session.create_script(synthetic_source(
                adapter, marker, require_secret=require_secret))
            active_targets: set[str] = set()

            def receive(message, data):
                if message.get("type") == "error":
                    try:
                        send_safe({"error": "frida_script_error"})
                    finally:
                        if active_targets:
                            record_fail_stop("frida_script_error")
                    return
                if message.get("type") != "send":
                    return
                payload = message.get("payload")
                if isinstance(payload, dict) and payload.get("kind") == "target_body":
                    request_id = payload.get("request_id")
                    hook = payload.get("hook")
                    protocol = {"model.http": "http", "model.wss": "wss"}.get(hook)
                    source = payload.get("source")
                    size, digest = payload.get("bytes"), payload.get("sha256")
                    if (not isinstance(request_id, str) or not request_id.isdigit() or
                            protocol is None or source not in {"function_call_output", "user_content"} or
                            not isinstance(data, bytes) or type(size) is not int or
                            not 0 < size <= MAX_BODY or len(data) != size or
                            not isinstance(digest, str) or not _SHA.fullmatch(digest)):
                        try:
                            send_safe({"error": "invalid_target_body_event"})
                        finally:
                            record_fail_stop("invalid_target_body_event")
                        return
                    active_targets.add(request_id)
                    try:
                        send_safe({"pending": {"request_id": request_id, "hook": hook,
                                               "observed_monotonic": time.monotonic(),
                                               "bytes": size, "sha256": digest,
                                               "source": source}})
                    except (BrokenPipeError, OSError):
                        record_fail_stop("pending_event_delivery_failed")
                        return
                    row = {"request_id": request_id, "hook": hook, "action": "deny",
                           "reason": "EVALUATION_FAILED", "bytes": size, "sha256": digest,
                           "source": source}
                    try:
                        future = executor.submit(
                            evaluate_target, bridge, archive, data, protocol=protocol,
                            source=source, marker=marker, backend_pid=backend_pid,
                            claimed_bytes=size, claimed_sha256=digest,
                            require_secret=require_secret)
                        result, replied, stopped = await_and_post_policy(
                            future, script, request_id, stop_backend)
                        row = {"request_id": request_id, "hook": hook, **result}
                        if not replied:
                            record_fail_stop("decision_reply_failed", already_stopped=stopped)
                            return
                    except Exception as error:
                        row["reason"] = "POLICY_" + type(error).__name__
                        try:
                            script.post({"type": "target_decision_" + request_id,
                                         "payload": {"action": "deny"}})
                        except Exception:
                            record_fail_stop("decision_reply_failed")
                            return
                    try:
                        send_safe({"resolved": row})
                    except (BrokenPipeError, OSError):
                        record_fail_stop("resolved_event_delivery_failed")
                    return
                event = safe_event(payload)
                if event is not None:
                    if event["kind"] in {"target_denied", "target_allowed"}:
                        active_targets.discard(event["request_id"])
                    send_safe({"event": event})
                else:
                    send_safe({"error": "unexpected_agent_event"})
                    if active_targets:
                        record_fail_stop("unexpected_agent_event")

            script.on("message", receive)
            script.load()
            if verify_current_targets(adapter, package, desktop_pid,
                                      backend_pid, expected_sid) != targets:
                raise ValueError("pinned desktop pair changed after attachment")
            threading.Event().wait()
    except Exception as error:
        try:
            send_safe({"error": "worker_" + type(error).__name__})
        except (BrokenPipeError, OSError):
            pass
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        sender.close()


def _collect(receiver, rows: list[dict], decisions: list[dict],
             pending: dict[str, dict], errors: list[str],
             ready: threading.Event, lock: threading.Lock,
             registration: dict, fail_stops: list[dict]) -> None:
    try:
        while True:
            item = receiver.recv()
            with lock:
                if not isinstance(item, dict):
                    errors.append("unexpected_worker_message")
                elif isinstance(item.get("error"), str):
                    errors.append(item["error"][:80])
                elif isinstance(item.get("registration"), dict):
                    registration.update({
                        name: digest for name, digest in item["registration"].items()
                        if name in SYNTHETIC_REGISTRATION_SHA256 and
                        isinstance(digest, str) and _SHA.fullmatch(digest)})
                    registration["policy_version"] = item.get("policy_version")
                elif isinstance(item.get("fail_stop_result"), dict):
                    outcome = item["fail_stop_result"]
                    if (outcome.get("reason") not in {
                            "frida_script_error", "invalid_target_body_event",
                            "pending_event_delivery_failed", "decision_reply_failed",
                            "resolved_event_delivery_failed", "unexpected_agent_event"} or
                            type(outcome.get("succeeded")) is not bool):
                        errors.append("invalid_fail_stop_result")
                    else:
                        fail_stops.append({"reason": outcome["reason"],
                                           "succeeded": outcome["succeeded"]})
                        if not outcome["succeeded"]:
                            errors.append("backend_fail_stop_failed")
                elif isinstance(item.get("event"), dict):
                    event = safe_event(item["event"])
                    if event is None or len(rows) >= MAX_EVENTS:
                        errors.append("event_bound_or_shape")
                    else:
                        rows.append(event)
                        installed = {row.get("hook") for row in rows
                                     if row.get("kind") == "hook_installed"}
                        if event["kind"] == "probe_ready" and installed == _HOOKS:
                            ready.set()
                elif isinstance(item.get("pending"), dict):
                    target = item["pending"]
                    request_id = target.get("request_id")
                    if (not isinstance(request_id, str) or not request_id.isdigit() or
                            request_id in pending or target.get("hook") not in _HOOKS):
                        errors.append("invalid_pending_target")
                    else:
                        pending[request_id] = {key: target[key] for key in
                                               ("hook", "bytes", "sha256", "source")}
                        pending[request_id]["observed_monotonic"] = time.monotonic()
                elif isinstance(item.get("resolved"), dict):
                    result = item["resolved"]
                    request_id = result.get("request_id")
                    if (request_id not in pending or len(decisions) >= MAX_EVENTS or
                            result.get("action") not in {"allow", "deny"}):
                        errors.append("invalid_resolved_target")
                    else:
                        pending.pop(request_id)
                        decisions.append({key: result[key] for key in (
                            "request_id", "hook", "action", "reason", "bytes", "sha256", "source")
                            if key in result} | {
                            "rule_ids": [rule for rule in result.get("rule_ids", [])
                                         if isinstance(rule, str) and re.fullmatch(
                                             r"[A-Za-z0-9_.:-]{1,128}", rule)],
                            "archive_readback_matches": result.get("archive_readback_matches") is True,
                            "archive_record_created": result.get("archive_record_created") is True,
                        })
                else:
                    errors.append("unexpected_worker_message")
    except EOFError:
        pass
    except (BrokenPipeError, OSError):
        with lock:
            errors.append("worker_pipe_error")


def require_opt_in(args) -> None:
    if not (getattr(args, "active_current_client", False) and
            getattr(args, "synthetic_only", False) and
            getattr(args, "accept_interruption", False)):
        raise ValueError("current-client, synthetic-only, interruption flags are required")
    if type(args.seconds) is not int or not 5 <= args.seconds <= 120:
        raise ValueError("probe duration must be 5..120 seconds")
    if getattr(args, "case", None) not in {"benign", "secret"}:
        raise ValueError("an explicit synthetic case is required")


def classify_target_evidence(rows: list[dict], decisions: list[dict],
                             errors: list[str], *, case: str,
                             unresolved: int) -> dict:
    """A WSS denial cannot conceal a later HTTP fallback ALLOW."""
    installed = {row.get("hook") for row in rows if row.get("kind") == "hook_installed"}
    native = [row for row in rows if row.get("kind") in {"target_denied", "target_allowed"}]
    unattributed = sum(row.get("kind") == "unattributable" for row in rows)
    def key(row: dict) -> tuple:
        return (row.get("request_id"), row.get("hook"),
                row.get("bytes"), row.get("sha256"))
    native_keys = Counter(key(row) for row in native)
    decision_keys = Counter(key(row) for row in decisions)
    linked = (native_keys == decision_keys and
              all(count == 1 for count in native_keys.values()) and
              all((decision.get("action") == "deny") == (event.get("kind") == "target_denied")
                  for decision in decisions for event in native
                  if key(decision) == key(event)))
    ready = (not errors and unresolved == 0 and installed == _HOOKS and linked and
             any(row.get("kind") == "probe_ready" for row in rows))
    all_denied = bool(decisions) and all(row.get("action") == "deny" for row in decisions)
    all_allowed = bool(decisions) and all(row.get("action") == "allow" for row in decisions)
    archived = all(row.get("archive_readback_matches") is True and
                   row.get("archive_record_created") is True for row in decisions)
    dlp_denied = all(row.get("reason") == "SENSITIVE_OR_UNINSPECTABLE_CONTENT" and
                     bool(row.get("rule_ids")) and
                     (case != "secret" or "ASSIGNED_SECRET" in row["rule_ids"])
                     for row in decisions)
    dlp_allowed = all(row.get("reason") == "REQUIRED_CHECKS_COMPLETE"
                      for row in decisions)
    if not ready:
        status = "unvalidated_probe_or_target_chain"
    elif not decisions:
        status = "no_attributed_synthetic_request_observed"
    elif all_denied and archived and dlp_denied:
        status = ("archived_synthetic_secret_rule_denial_without_origin_proof"
                  if case == "secret" else
                  "benign_current_input_denied_full_request_requires_review")
    elif all_allowed and archived and dlp_allowed:
        status = "attributed_synthetic_dlp_allow_without_origin_proof"
    elif all_denied:
        status = "attributed_target_fail_closed_without_complete_dlp_proof"
    else:
        status = "unvalidated_mixed_target_decisions"
    return {
        "status": status, "installed_hooks": sorted(installed),
        "target_decision_count": len(decisions),
        "target_denial_events": sum(row.get("kind") == "target_denied" for row in native),
        "target_allow_events": sum(row.get("kind") == "target_allowed" for row in native),
        "completed_dlp_denial_events": (len(decisions) if ready and all_denied and archived
                                        and dlp_denied else 0),
        "unattributable_candidate_events": unattributed,
        "target_chain_one_to_one": linked,
    }


def run_probe(args) -> dict:
    require_opt_in(args)
    require_current_user(args.expected_sid)
    adapter_path = args.adapter.resolve(strict=True)
    adapter = load_desktop_adapter(adapter_path, require_validated=False)
    fixture, prompt, _ = load_fixtures(args.fixtures)
    marker = fixture["prompt_marker"]
    if (not _MARKER.fullmatch(marker) or
            prompt.read_text(encoding="utf-8") != f"请简短回复。测试标记：{marker}\n"):
        raise ValueError("fixture must be the exact synthetic prompt text")
    expected_submission = prompt.read_text(encoding="utf-8").strip()
    if args.case == "secret":
        expected_submission += " " + FAKE_SECRET
    msix_sha = verify_archived_msix(args.msix, adapter)
    package = registered_package(adapter)
    targets = verify_current_targets(adapter, package, args.desktop_pid,
                                     args.backend_pid, args.expected_sid)
    backend_path = Path(process_identity(args.backend_pid)["image_path"])
    static = verify_static_entries(adapter, backend_path)
    verify_drop_headers_entry(backend_path)
    source = synthetic_source(adapter, marker, require_secret=args.case == "secret")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    submission_file = output / "synthetic-submission.txt"
    submission_file.write_text(expected_submission + "\n", encoding="utf-8")
    rows: list[dict] = []
    decisions: list[dict] = []
    pending: dict[str, dict] = {}
    errors: list[str] = []
    registration: dict = {}
    fail_stops: list[dict] = []
    state_lock = threading.Lock()
    observer = receiver = collector = None
    fail_stopped = False
    began = time.time_ns()
    try:
        with hold_processes(targets), pinned_backend_stop(
                args.backend_pid, targets["backend"]["birth"]) as stop_backend:
            if verify_current_targets(adapter, package, args.desktop_pid,
                                      args.backend_pid, args.expected_sid) != targets:
                raise ValueError("current pinned pair changed before worker startup")
            pipe_recv, pipe_send = multiprocessing.get_context("spawn").Pipe(duplex=False)
            receiver = pipe_recv
            observer = multiprocessing.get_context("spawn").Process(
                target=_worker,
                args=(adapter, package, targets, args.desktop_pid, args.backend_pid,
                      args.expected_sid, marker, args.case == "secret",
                      output, pipe_send), daemon=True)
            observer.start()
            pipe_send.close()
            ready = threading.Event()
            collector = threading.Thread(
                target=_collect,
                args=(receiver, rows, decisions, pending, errors, ready,
                      state_lock, registration, fail_stops), daemon=True)
            collector.start()
            if ready.wait(20) and not errors:
                print(f"Synthetic DLP bridge ready for {args.seconds}s. "
                      f"Submit the synthetic text from {submission_file} in the pinned Local test chat.",
                      flush=True)
                until = time.monotonic() + args.seconds
                while time.monotonic() < until:
                    with state_lock:
                        timed_out = any(time.monotonic() - row["observed_monotonic"] >
                                        DECISION_TIMEOUT_SECONDS + 1 for row in pending.values())
                        unresolved = bool(pending)
                    if timed_out or (not observer.is_alive() and unresolved):
                        fail_stopped = stop_backend()
                        errors.append("target_unresolved_fail_stop")
                        break
                    if not observer.is_alive():
                        errors.append("frida_worker_exited_during_probe")
                        break
                    time.sleep(min(0.05, max(0, until - time.monotonic())))
            else:
                errors.append("frida_attach_or_load_timeout" if observer.is_alive()
                              else "frida_worker_exited_before_ready")
            with state_lock:
                unresolved_at_shutdown = bool(pending)
            if unresolved_at_shutdown and not fail_stopped:
                fail_stopped = stop_backend()
                errors.append("target_pending_at_shutdown_fail_stop")
            if observer is not None and receiver is not None and collector is not None:
                _stop_frida(observer, receiver, collector, errors)
                observer = None
    except Exception as error:
        errors.append(type(error).__name__)
    finally:
        if observer is not None and receiver is not None and collector is not None:
            # A worker crash or attach hang cannot leave a confirmed pending
            # target silently allowed. The normal path fail-stops before here.
            _stop_frida(observer, receiver, collector, errors)
        with state_lock:
            unresolved = len(pending)
        evidence = classify_target_evidence(rows, decisions, errors,
                                            case=args.case, unresolved=unresolved)
        report = {
            "schema": SCHEMA, "status": evidence["status"],
            "case": args.case,
            "scope": "one pinned Local test thread and one synthetic marker",
            "coverage_status": "unvalidated", "production_ready": False,
            "remote_origin_zero_bytes_verified": False,
            "desktop_ui_full_coverage_verified": False,
            "attachment_upload_covered": False, "agent_tool_egress_covered": False,
            "function_call_output_source_distinct_from_ui_user_prompt": True,
            "synthetic_secret_case": args.case == "secret",
            "synthetic_secret_sha256": hashlib.sha256(FAKE_SECRET.encode()).hexdigest(),
            "test_thread_id_persisted": False,
            "other_chat_nonexport_verified_only_by_implementation": True,
            "unattributable_requests_passthrough": True,
            "encrypted_snapshot_contains_full_model_request": True,
            "snapshot_may_include_system_developer_and_test_history": True,
            "plaintext_in_report": False,
            "archive_same_windows_account_prototype": True,
            "backend_fail_stopped_for_safety": fail_stopped or any(
                row["succeeded"] for row in fail_stops),
            "worker_fail_stop_results": fail_stops,
            "unresolved_target_count": unresolved,
            **evidence,
            "synthetic_registration_sha256": registration,
            "archive_msix_sha256": msix_sha,
            "adapter_sha256": _hash(adapter_path),
            "static_candidates_sha256": hashlib.sha256(json.dumps(
                static["candidates"], sort_keys=True).encode()).hexdigest(),
            "agent_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "synthetic_fixture_sha256": _hash(prompt),
            "synthetic_submission_sha256": _hash(submission_file),
            "marker_sha256": hashlib.sha256(marker.encode()).hexdigest(),
            "targets": targets,
            "elapsed_ms": (time.time_ns() - began) / 1_000_000,
            "errors": sorted(set(errors)),
            "events": rows,
            "decisions": decisions,
        }
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
    parser.add_argument("--case", choices=("benign", "secret"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    enter_repository()
    report = run_probe(args)
    print(json.dumps({key: report[key] for key in (
        "status", "coverage_status", "remote_origin_zero_bytes_verified",
        "target_decision_count", "target_denial_events", "errors")}, indent=2))
    if report["errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
