"""Bounded, synthetic-only Frida observation of the current desktop backend.

This helper never installs a Codex command hook or writes a request body. It
checks fixed HTTP/WSS candidates and reports only the length and SHA-256 of a
buffer containing the caller's random lab marker. The byte match to the local
origin must be assessed by the caller; a candidate hit is not coverage proof.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import ntpath
from pathlib import Path
import re
import threading
import time


HTTP_RVA = "0xab2d670"
HTTP_PREFIX_HEX = "5541574156415541545657534881ec28"
WSS_RVA = "0x400c4d0"
WSS_PREFIX_HEX = "5541574156415541545657534881ecd8"
WSS_SUCCESS_TAG_CANDIDATE = 0x20
MAX_BUFFER = 16 * 1024 * 1024
MAX_EVENTS = 256
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_AGENT = r"""
const config = __CONFIG__;
const marker = new Uint8Array(config.marker);
let httpEntries = 0;
let httpHits = 0;
let wssEntries = 0;
let wssHits = 0;
function failStopSyntheticBackend(hook, length, digest) {
  send({kind: 'synthetic_failstop_triggered', hook: hook,
    bytes: length, sha256: digest});
  // The controller must receive this evidence before the isolated process is
  // stopped. Missing ACK leaves the sender suspended until the lab watchdog.
  recv('synthetic_failstop_ack', function() {}).wait();
  const kernel = Process.getModuleByName('kernel32.dll');
  const current = new NativeFunction(kernel.getExportByName('GetCurrentProcess'),
    'pointer', []);
  const terminate = new NativeFunction(kernel.getExportByName('TerminateProcess'),
    'bool', ['pointer', 'uint32']);
  terminate(current(), 76);
  while (true) {}
}
function markerOffset(data) {
  const bytes = new Uint8Array(data);
  outer: for (let i = 0; i <= bytes.length - marker.length; i++) {
    for (let j = 0; j < marker.length; j++) {
      if (bytes[i + j] !== marker[j]) continue outer;
    }
    return i;
  }
  return -1;
}
function requestShape(pointer, length) {
  if (length > 64 * 1024) return 'too-large-to-check';
  try {
    const value = JSON.parse(pointer.readUtf8String(length));
    return value && value.type === 'response.create' &&
      typeof value.model === 'string' &&
      (Array.isArray(value.input) || typeof value.input === 'string')
      ? 'response.create-input' : 'other-json';
  } catch (_) { return 'invalid-json'; }
}
function checkedTarget(rva, prefix, hook) {
  try {
    const target = Process.mainModule.base.add(ptr(rva));
    const actual = new Uint8Array(target.readVolatile(prefix.length));
    if (actual.length !== prefix.length ||
        actual.some((value, index) => value !== prefix[index])) {
      send({kind: 'entry_mismatch', hook: hook}); return null;
    }
    return target;
  } catch (_) {
    send({kind: 'hook_unavailable', hook: hook}); return null;
  }
}
const httpTarget = checkedTarget(config.http_rva, config.http_prefix, 'http');
if (httpTarget !== null) {
  try {
    Interceptor.attach(httpTarget, {onEnter(args) {
      httpEntries++;
      if (httpEntries <= 8) send({kind: 'candidate_entry', hook: 'http'});
      // Old-build layout hypothesis only. Exact synthetic bytes must match an
      // independent trace and receiver before the layout is accepted.
      try {
        const body = args[3];
        const data = body.add(8).readPointer();
        const length = body.add(16).readU64().toNumber();
        if (data.isNull() || length < marker.length || length > config.max_buffer)
          return;
        const bytes = data.readVolatile(length);
        const offset = markerOffset(bytes);
        if (offset < 0) return;
        httpHits++;
        const digest = Checksum.compute('sha256', bytes);
        if (httpHits <= config.max_events) send({kind: 'synthetic_http_hit',
          bytes: length, sha256: digest,
          marker_offset: offset}, config.capture_body ? bytes : undefined);
        if (config.fail_stop_on_marker)
          failStopSyntheticBackend('http', length, digest);
      } catch (_) {
        if (httpEntries <= 8) send({kind: 'read_hypothesis_failed', hook: 'http'});
      }
    }});
    send({kind: 'hook_ready', hook: 'http'});
  } catch (_) { send({kind: 'hook_unavailable', hook: 'http'}); }
}
if (config.capture_wss) {
  const wssTarget = checkedTarget(config.wss_rva, config.wss_prefix, 'wss');
  if (wssTarget !== null) {
    try {
      Interceptor.attach(wssTarget, {onEnter(args) {
        this.result = args[0];
        wssEntries++;
        if (wssEntries <= 8) send({kind: 'candidate_entry', hook: 'wss'});
      }, onLeave(_) {
        try {
          if (this.result.isNull()) return;
          const tag = this.result.readU64().toNumber();
          if (tag !== config.wss_success_tag_candidate) {
            if (wssEntries <= 8) send({kind: 'wss_non_success_tag', tag: tag});
            return;
          }
          const data = this.result.add(16).readPointer();
          const length = this.result.add(24).readU64().toNumber();
          if (data.isNull() || length < marker.length || length > config.max_buffer)
            return;
          const bytes = data.readVolatile(length);
          const offset = markerOffset(bytes);
          if (offset < 0) return;
          wssHits++;
          const digest = Checksum.compute('sha256', bytes);
          if (wssHits <= config.max_events) send({kind: 'synthetic_wss_hit',
            bytes: length, sha256: digest,
            marker_offset: offset, request_shape: requestShape(data, length)},
            config.capture_body ? bytes : undefined);
          if (config.fail_stop_on_marker)
            failStopSyntheticBackend('wss', length, digest);
        } catch (_) {
          if (wssEntries <= 8) send({kind: 'read_hypothesis_failed', hook: 'wss'});
        }
      }});
      send({kind: 'hook_ready', hook: 'wss'});
    } catch (_) { send({kind: 'hook_unavailable', hook: 'wss'}); }
  }
}
"""


def _safe_event(value: object) -> dict | None:
    """Drop any Frida field outside the synthetic metadata contract."""
    if not isinstance(value, dict):
        return None
    kind = value.get("kind")
    if kind in {"hook_ready", "candidate_entry", "entry_mismatch",
                "read_hypothesis_failed", "hook_unavailable"}:
        hook = value.get("hook")
        return {"kind": kind, "hook": hook} if hook in {"http", "wss"} else None
    if kind == "wss_non_success_tag":
        tag = value.get("tag")
        return {"kind": kind, "tag": tag} if isinstance(tag, int) and 0 <= tag <= 255 else None
    if kind == "synthetic_failstop_triggered":
        length, digest, hook = value.get("bytes"), value.get("sha256"), value.get("hook")
        if (hook not in {"http", "wss"} or not isinstance(length, int)
                or isinstance(length, bool) or not 0 < length <= MAX_BUFFER
                or not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
            return None
        return {"kind": kind, "hook": hook, "bytes": length, "sha256": digest}
    if kind not in {"synthetic_http_hit", "synthetic_wss_hit"}:
        return None
    length, offset, digest = value.get("bytes"), value.get("marker_offset"), value.get("sha256")
    if (not isinstance(length, int) or isinstance(length, bool) or not 0 < length <= MAX_BUFFER
            or not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset < length
            or not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
        return None
    result = {"kind": kind, "bytes": length, "sha256": digest, "marker_offset": offset}
    if kind == "synthetic_wss_hit":
        shape = value.get("request_shape")
        if shape not in {"response.create-input", "other-json", "invalid-json",
                         "too-large-to-check"}:
            return None
        result["request_shape"] = shape
    return result


def _worker(channel, pid: int, backend_path: str, backend_sha256: str,
            creation_filetime: int, marker: bytes, capture_wss: bool,
            capture_body: bool, fail_stop_on_marker: bool) -> None:
    session = None
    script = None
    send_lock = threading.Lock()

    def emit(row: dict) -> None:
        with send_lock:
            channel.send(row)

    try:
        from transpect_trace.observe.windows import identity

        observed = identity(pid)
        if (observed["creation_filetime"] != creation_filetime
                or observed["image_sha256"] != backend_sha256
                or ntpath.normcase(observed["image_path"]) != ntpath.normcase(backend_path)):
            raise ValueError("target_identity_changed")
        import frida

        config = {"marker": list(marker), "http_rva": HTTP_RVA,
                  "http_prefix": list(bytes.fromhex(HTTP_PREFIX_HEX)),
                  "wss_rva": WSS_RVA,
                  "wss_prefix": list(bytes.fromhex(WSS_PREFIX_HEX)),
                  "wss_success_tag_candidate": WSS_SUCCESS_TAG_CANDIDATE,
                  "capture_wss": capture_wss,
                  "capture_body": capture_body,
                  "fail_stop_on_marker": fail_stop_on_marker,
                  "max_buffer": MAX_BUFFER,
                  "max_events": 4 if capture_body else MAX_EVENTS}
        agent = _AGENT.replace("__CONFIG__", json.dumps(config, separators=(",", ":")))
        session = frida.attach(pid)
        script = session.create_script(agent)

        def on_message(message, data) -> None:
            if message.get("type") == "send":
                row = _safe_event(message.get("payload"))
                if row is not None:
                    if capture_body and row["kind"] in {"synthetic_http_hit", "synthetic_wss_hit"}:
                        if (not isinstance(data, bytes) or len(data) != row["bytes"]
                                or hashlib.sha256(data).hexdigest() != row["sha256"]
                                or marker not in data):
                            emit({"kind": "capture_body_mismatch"})
                            return
                        row["body"] = data
                    emit(row)
                    if row["kind"] == "synthetic_failstop_triggered":
                        script.post({"type": "synthetic_failstop_ack"})
            elif message.get("type") == "error":
                emit({"kind": "frida_script_error"})

        script.on("message", on_message)
        script.load()
        while True:
            if channel.poll(0.2) and channel.recv() == "stop":
                break
    except Exception as error:
        emit({"kind": "worker_error", "error_type": type(error).__name__})
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        try:
            emit({"kind": "worker_stopped"})
        except (BrokenPipeError, EOFError, OSError):
            pass
        channel.close()


class CaptureSession:
    """Keep a disposable Frida worker alive through one synthetic lab turn."""

    def __init__(self, pid: int, backend_path: Path, backend_sha256: str,
                 creation_filetime: int, marker: bytes, *, capture_wss: bool = False,
                 capture_body: bool = False, fail_stop_on_marker: bool = False):
        if (pid < 1 or creation_filetime < 1 or not _SHA256.fullmatch(backend_sha256)
                or not marker.startswith(b"TTRACE_NATIVE_LAB_")
                or not 24 <= len(marker) <= 80):
            raise ValueError("invalid synthetic capture scope")
        backend = Path(backend_path).resolve(strict=True)
        with backend.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != backend_sha256:
            raise ValueError("pinned backend hash mismatch")
        if fail_stop_on_marker and capture_body:
            raise ValueError("fail-stop lab cannot retain a request body in IPC")
        self.args = (pid, str(backend), backend_sha256, creation_filetime,
                     marker, capture_wss, capture_body, fail_stop_on_marker)
        self.capture_wss = capture_wss
        self.capture_body = capture_body
        self.process = None
        self.channel = None
        self.events: list[dict] = []
        self._events_lock = threading.Lock()
        self._signal = threading.Event()
        self._reader = None

    def _collect(self, timeout: float) -> bool:
        try:
            available = self.channel is not None and self.channel.poll(timeout)
        except (BrokenPipeError, EOFError, OSError):
            return False
        if available:
            try:
                row = self.channel.recv()
            except (BrokenPipeError, EOFError, OSError):
                return False
            with self._events_lock:
                if len(self.events) < MAX_EVENTS + 8:
                    self.events.append(row)
            self._signal.set()
            return True
        return False

    def _drain(self) -> None:
        while True:
            if not self._collect(0.1) and not self.process.is_alive():
                self._signal.set()
                return

    def _snapshot(self) -> list[dict]:
        with self._events_lock:
            return list(self.events)

    def start(self, timeout: float = 10) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        self.channel = parent
        self.process = context.Process(target=_worker, args=(child, *self.args), daemon=True)
        self.process.start()
        child.close()
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            events = self._snapshot()
            ready = {row.get("hook") for row in events if row["kind"] == "hook_ready"}
            if {"http", "wss" if self.capture_wss else "http"}.issubset(ready):
                return
            if any(row["kind"] in {"entry_mismatch", "hook_unavailable",
                                    "frida_script_error", "worker_error", "worker_stopped"}
                   for row in events):
                break
            if not self.process.is_alive():
                break
            self._signal.wait(min(0.2, until - time.monotonic()))
            self._signal.clear()
        self.finish()
        raise RuntimeError("synthetic HTTP candidate did not become ready")

    def finish(self, timeout: float = 5) -> list[dict]:
        if self.process is None:
            return self._snapshot()
        if self.process.is_alive() and self.channel is not None:
            try:
                self.channel.send("stop")
            except (BrokenPipeError, EOFError, OSError):
                pass
        self.process.join(timeout=timeout)
        if self.process.is_alive():
            self.process.terminate()
        self.process.join(timeout=2)
        if self._reader is not None:
            self._reader.join(timeout=2)
        if self.channel is not None:
            self.channel.close()
        self.channel = None
        self.process = None
        return self._snapshot()
