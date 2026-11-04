"""Research-only Frida trace of fixed Codex desktop send-path candidates.

Run only in the isolated QEMU Windows VM, under a controller account distinct
from the dedicated Codex user. This script never installs a WFP permit, edits
Codex files, blocks a request, or promotes an adapter to validated. It hashes
matched synthetic buffers in the target process and persists metadata only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from uuid import uuid4

from _build_support import ROOT, enter_repository
sys.path.insert(0, str(ROOT / "src"))

from discover_codex_hooks import discover
from transpect_trace.behavior.desktop_wfp import WfpBoundary
from transpect_trace.guard.desktop import (
    _cim_process, current_user_sid, desktop_mode, load_desktop_adapter,
    windows_powershell_env,
)
from transpect_trace.guard.native import command_arguments
from transpect_trace.observe.windows import identity as process_identity


FIXTURE_SCHEMA = "transpect.desktop-path-fixtures/1.0"
TRACE_SCHEMA = "transpect.desktop-path-trace/1.0"
MAX_EVENTS = 10000
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_MARKER = re.compile(r"FAKE_DESKTOP_(?:PROMPT|UPLOAD)_[a-f0-9]{32}\Z")
_MODULE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_RVA = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")


AGENT = r"""
const CONFIG = __CONFIG__;
const marker = new Uint8Array(CONFIG.marker);
const installed = new Set();
const maxBuffer = CONFIG.max_buffer;
function location(address) {
  try {
    const module = Process.findModuleByAddress(address);
    return module === null ? null : {module: module.name,
      rva: address.sub(module.base).toString()};
  } catch (_) { return null; }
}
function stack(context) {
  try { return Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 12)
    .map(location).filter(x => x !== null); } catch (_) { return []; }
}
function markerOffset(bytes) {
  if (marker.length === 0 || bytes.length < marker.length) return -1;
  outer: for (let i = 0; i <= bytes.length - marker.length; i++) {
    for (let j = 0; j < marker.length; j++) if (bytes[i + j] !== marker[j]) continue outer;
    return i;
  }
  return -1;
}
function inspectBuffer(pointer, length, hook, stage, context) {
  if (marker.length === 0 || pointer.isNull() || length < marker.length || length > maxBuffer)
    return;
  try {
    const data = pointer.readVolatile(length);
    const offset = markerOffset(new Uint8Array(data));
    if (offset < 0) return;
    send({kind: 'marker_buffer', hook: hook, stage: stage, bytes: length,
      marker_offset: offset, sha256: Checksum.compute('sha256', data),
      caller: location(context.returnAddress), stack: stack(context.context),
      thread_id: Process.getCurrentThreadId()});
  } catch (_) { send({kind: 'read_hypothesis_failed', hook: hook, stage: stage}); }
}
function installCandidate(name, spec) {
  const target = Process.mainModule.base.add(ptr(spec.rva));
  try {
    const actual = new Uint8Array(target.readVolatile(spec.prefix.length));
    if (actual.length !== spec.prefix.length ||
        actual.some((v, i) => v !== spec.prefix[i])) {
      send({kind: 'entry_mismatch', hook: name, rva: spec.rva}); return;
    }
    if (name === 'model.http') {
      Interceptor.attach(target, {onEnter(args) {
        send({kind: 'candidate_entry', hook: name, rva: spec.rva,
          thread_id: Process.getCurrentThreadId(), caller: location(this.returnAddress)});
        // This is only the old CLI layout hypothesis; never interpreted as an ABI proof.
        try { const body = args[3], data = body.add(8).readPointer();
          const length = body.add(16).readU64().toNumber();
          inspectBuffer(data, length, name, 'hypothesized-http-body', this);
        } catch (_) { send({kind: 'read_hypothesis_failed', hook: name,
          stage: 'hypothesized-http-body'}); }
      }});
    } else {
      Interceptor.attach(target, {onEnter(args) { this.result = args[0];
        send({kind: 'candidate_entry', hook: name, rva: spec.rva,
          thread_id: Process.getCurrentThreadId(), caller: location(this.returnAddress)});
      }, onLeave(_) {
        // The result tag and String fields are a read-only, unvalidated CLI hypothesis.
        try { if (this.result.readU64().toNumber() !== 0x1c) return;
          const data = this.result.add(16).readPointer();
          const length = this.result.add(24).readU64().toNumber();
          inspectBuffer(data, length, name, 'hypothesized-wss-serialized', this);
        } catch (_) { send({kind: 'read_hypothesis_failed', hook: name,
          stage: 'hypothesized-wss-serialized'}); }
      }});
    }
    send({kind: 'hook_installed', hook: name, rva: spec.rva});
  } catch (_) { send({kind: 'hook_unavailable', hook: name, rva: spec.rva}); }
}
function installExport(module, name, handler) {
  const target = module.findExportByName(name);
  if (target === null || installed.has(target.toString())) return;
  installed.add(target.toString());
  try { Interceptor.attach(target, handler);
    send({kind: 'hook_installed', hook: name, module: module.name,
      rva: target.sub(module.base).toString()});
  } catch (_) { send({kind: 'hook_unavailable', hook: name, module: module.name}); }
}
if (CONFIG.role === 'backend') {
  installCandidate('model.http', CONFIG.http);
  installCandidate('model.wss', CONFIG.wss);
}
Process.attachModuleObserver({onAdded(module) {
  const name = module.name.toLowerCase();
  if (name === 'kernel32.dll' || name === 'kernelbase.dll') {
    installExport(module, 'CreateFileW', {onEnter(args) {
      this.matched = false;
      try { this.matched = args[0].readUtf16String(32768).toLowerCase()
        .includes(CONFIG.fixture_path.toLowerCase()); } catch (_) {}
      this.caller = location(this.returnAddress);
    }, onLeave(result) { if (this.matched && !result.equals(ptr('0xffffffffffffffff')))
      send({kind: 'fixture_open', hook: 'CreateFileW', caller: this.caller}); }});
    installExport(module, 'ReadFile', {onEnter(args) {
      this.buffer = args[1]; this.requested = args[2].toUInt32(); this.count = args[3];
      this.returnAddressSaved = this.returnAddress; this.contextSaved = this.context;
    }, onLeave(result) { try { if (result.isNull() || this.count.isNull()) return;
      const length = this.count.readU32();
      if (length <= this.requested) inspectBuffer(this.buffer, length,
        'ReadFile', 'completed-read', {returnAddress: this.returnAddressSaved,
        context: this.contextSaved}); } catch (_) {} }});
    installExport(module, 'WriteFile', {onEnter(args) {
      inspectBuffer(args[1], args[2].toUInt32(), 'WriteFile', 'pre-write', this); }});
  }
  if (name === 'ntdll.dll') installExport(module, 'NtReadFile', {onEnter(args) {
    this.status = args[4]; this.buffer = args[5]; this.requested = args[6].toUInt32();
    this.returnAddressSaved = this.returnAddress; this.contextSaved = this.context;
  }, onLeave(result) { try { if (result.toInt32() !== 0 || this.status.isNull()) return;
    const length = this.status.add(8).readU64().toNumber();
    if (length <= this.requested) inspectBuffer(this.buffer, length,
      'NtReadFile', 'completed-read', {returnAddress: this.returnAddressSaved,
      context: this.contextSaved}); } catch (_) {} }});
  if (name === 'winhttp.dll') {
    installExport(module, 'WinHttpWriteData', {onEnter(args) {
      inspectBuffer(args[1], args[2].toUInt32(), 'WinHttpWriteData', 'pre-write', this); }});
    installExport(module, 'WinHttpSendRequest', {onEnter(args) {
      inspectBuffer(args[3], args[4].toUInt32(), 'WinHttpSendRequest', 'optional-body', this); }});
  }
}});
send({kind: 'probe_ready', role: CONFIG.role});
"""


def _hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_wfp_tool(executable: Path) -> Path:
    executable = Path(executable).resolve(strict=True)
    manifest_path = executable.parent / "build-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = ROOT / "native" / "behavior" / "wfp_desktop.c"
    if (manifest.get("schema") != "transpect.desktop-wfp-build/1.0"
            or manifest.get("executable_sha256") != _hash(executable)
            or manifest.get("source_sha256") != _hash(source)):
        raise ValueError("VM WFP status tool does not match the local pinned build")
    return executable


def prepare_fixtures(directory: Path) -> dict:
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    prompt_marker = f"FAKE_DESKTOP_PROMPT_{uuid4().hex}"
    upload_marker = f"FAKE_DESKTOP_UPLOAD_{uuid4().hex}"
    prompt = directory / "text-prompt.txt"
    attachment = directory / "synthetic-attachment.txt"
    prompt.write_text(f"请简短回复。测试标记：{prompt_marker}\n", encoding="utf-8")
    attachment.write_text(f"Synthetic desktop upload fixture.\n{upload_marker}\n", encoding="utf-8")
    result = {"schema": FIXTURE_SCHEMA, "prompt_marker": prompt_marker,
              "upload_marker": upload_marker, "prompt_file": prompt.name,
              "attachment_file": attachment.name,
              "prompt_sha256": _hash(prompt), "attachment_sha256": _hash(attachment)}
    (directory / "fixtures.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def load_fixtures(path: Path) -> tuple[dict, Path, Path]:
    manifest = Path(path).resolve(strict=True)
    if manifest.stat().st_size > 64 * 1024:
        raise ValueError("desktop trace fixture manifest exceeds limit")
    root = manifest.parent
    value = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != FIXTURE_SCHEMA:
        raise ValueError("invalid desktop trace fixture manifest")
    files = []
    for kind in ("prompt", "attachment"):
        marker = value.get(f"{kind}_marker") if kind == "prompt" else value.get("upload_marker")
        name = value.get(f"{kind}_file")
        checksum = value.get(f"{kind}_sha256")
        prefix = "FAKE_DESKTOP_PROMPT_" if kind == "prompt" else "FAKE_DESKTOP_UPLOAD_"
        if (not isinstance(marker, str) or not _MARKER.fullmatch(marker) or not marker.startswith(prefix)
                or not isinstance(name, str) or Path(name).name != name
                or not isinstance(checksum, str) or not _SHA.fullmatch(checksum)):
            raise ValueError("invalid synthetic trace fixture")
        file = (root / name).resolve(strict=True)
        if not file.is_relative_to(root) or not file.is_file() or file.stat().st_size > 1024 * 1024:
            raise ValueError("trace fixture path or size invalid")
        data = file.read_bytes()
        if _hash(file) != checksum or marker.encode("ascii") not in data:
            raise ValueError("synthetic trace fixture hash or marker changed")
        files.append(file)
    return value, files[0], files[1]


def require_qemu_vm() -> dict:
    if os.name != "nt":
        raise RuntimeError("desktop path trace requires Windows in the isolated QEMU VM")
    command = ('Get-CimInstance Win32_ComputerSystem | '
               'Select-Object Manufacturer,Model | ConvertTo-Json -Compress')
    result = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                            capture_output=True, text=True, encoding="utf-8", errors="replace",
                            timeout=15, check=False, env=windows_powershell_env())
    if result.returncode:
        raise RuntimeError("cannot establish isolated VM identity")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or not any("qemu" in str(value.get(key, "")).lower()
                                               for key in ("Manufacturer", "Model")):
        raise RuntimeError("desktop path trace requires a QEMU guest, not the current host client")
    return {"provider": "QEMU", "confirmed": True}


def verify_trace_targets(adapter: dict, desktop_pid: int, backend_pid: int,
                         network_pid: int | None, expected_sid: str) -> dict:
    """Read-only identity check for unvalidated static candidates in a guest."""
    if adapter.get("status") != "candidate_unvalidated":
        raise ValueError("research trace requires an unvalidated static candidate")
    if len({x for x in (desktop_pid, backend_pid, network_pid) if x is not None}) != (3 if network_pid else 2):
        raise ValueError("trace process identities must be distinct")
    if current_user_sid() == expected_sid:
        raise ValueError("trace controller must use a separate Windows account")
    desktop, backend = process_identity(desktop_pid), process_identity(backend_pid)
    deskrow, backrow = _cim_process(desktop_pid), _cim_process(backend_pid)
    if (desktop["image_sha256"] != adapter["desktop_image_sha256"]
            or adapter["package_full_name"].lower() not in desktop["image_path"].lower()
            or Path(desktop["image_path"]).name.lower() != "chatgpt.exe"
            or deskrow.get("UserSid") != expected_sid):
        raise ValueError("desktop process is not the pinned MSIX instance")
    if (backend["image_sha256"] != adapter["binary_sha256"]
            or Path(backend["image_path"]).name.lower() != "codex.exe"
            or backrow.get("ParentProcessId") != desktop_pid
            or backrow.get("UserSid") != expected_sid
            or desktop_mode(command_arguments(backrow.get("CommandLine") or "")) != "app-server"):
        raise ValueError("backend is not the pinned desktop app-server")
    result = {"desktop": {"pid": desktop_pid, "birth": desktop["creation_filetime"],
                            "image_sha256": desktop["image_sha256"]},
              "backend": {"pid": backend_pid, "birth": backend["creation_filetime"],
                            "image_sha256": backend["image_sha256"]}}
    if network_pid is not None:
        network, row = process_identity(network_pid), _cim_process(network_pid)
        if (network["image_sha256"] != adapter["desktop_image_sha256"]
                or adapter["package_full_name"].lower() not in network["image_path"].lower()
                or row.get("ParentProcessId") != desktop_pid
                or row.get("UserSid") != expected_sid
                or "network.mojom.NetworkService" not in (row.get("CommandLine") or "")):
            raise ValueError("network service is not a pinned desktop child")
        result["network"] = {"pid": network_pid, "birth": network["creation_filetime"],
                             "image_sha256": network["image_sha256"]}
    return result


def verify_static_entries(adapter: dict, backend_image: Path) -> dict:
    discovery = discover(backend_image)
    if discovery["binary_sha256"] != adapter["binary_sha256"]:
        raise ValueError("static candidate backend hash changed")
    found = {item["layer"]: item for item in discovery["candidates"]}
    expected = {"http_encoded_body_preparation": "http_body_preparation",
                "wss_request_serialization": "serialization"}
    for hook in adapter["hooks"]:
        candidate = found.get(expected[hook["layer"]])
        if (candidate is None or candidate["function_rva"] != hook["rva"]
                or candidate["entry_prefix_hex"] != hook["entry_prefix_hex"]):
            raise ValueError("static candidate RVA or prologue changed")
    return discovery


def agent_source(role: str, adapter: dict, marker: str, attachment: Path) -> str:
    hooks = {item["layer"]: item for item in adapter["hooks"]}
    config = {"role": role, "marker": list(marker.encode("ascii")),
              "max_buffer": 16 * 1024 * 1024,
              "fixture_path": str(attachment.resolve()),
              "http": {"rva": hooks["http_encoded_body_preparation"]["rva"],
                       "prefix": list(bytes.fromhex(hooks["http_encoded_body_preparation"]["entry_prefix_hex"]))},
              "wss": {"rva": hooks["wss_request_serialization"]["rva"],
                      "prefix": list(bytes.fromhex(hooks["wss_request_serialization"]["entry_prefix_hex"]))}}
    return AGENT.replace("__CONFIG__", json.dumps(config, separators=(",", ":")))


def _location(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    module, rva = value.get("module"), value.get("rva")
    if not isinstance(module, str) or not _MODULE.fullmatch(module):
        return None
    if not isinstance(rva, str) or not _RVA.fullmatch(rva):
        return None
    return {"module": module, "rva": rva.lower()}


def safe_event(payload: object, role: str) -> dict | None:
    """Discard all unexpected fields, including anything resembling plaintext."""
    if not isinstance(payload, dict):
        return None
    kind = payload.get("kind")
    if kind not in {"probe_ready", "hook_installed", "hook_unavailable", "entry_mismatch",
                    "candidate_entry", "marker_buffer", "fixture_open", "read_hypothesis_failed"}:
        return None
    result = {"kind": kind, "role": role, "observed_unix_ns": time.time_ns()}
    for key in ("hook", "stage"):
        value = payload.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
            result[key] = value
    for key in ("rva",):
        value = payload.get(key)
        if isinstance(value, str) and _RVA.fullmatch(value):
            result[key] = value.lower()
    for key in ("bytes", "marker_offset", "thread_id"):
        value = payload.get(key)
        if type(value) is int and 0 <= value <= 16 * 1024 * 1024:
            result[key] = value
    value = payload.get("sha256")
    if isinstance(value, str) and _SHA.fullmatch(value):
        result["sha256"] = value
    module = payload.get("module")
    if isinstance(module, str) and _MODULE.fullmatch(module):
        result["module"] = module
    caller = _location(payload.get("caller"))
    if caller:
        result["caller"] = caller
    stack = payload.get("stack")
    if isinstance(stack, list):
        result["stack"] = [item for item in (_location(x) for x in stack[:12]) if item]
    return result


def run_trace(args) -> dict:
    if not args.isolated_vm:
        raise ValueError("--isolated-vm is required")
    vm = require_qemu_vm()
    adapter_path = args.adapter.resolve(strict=True)
    adapter = load_desktop_adapter(adapter_path, require_validated=False)
    fixtures, prompt, attachment = load_fixtures(args.fixtures)
    wfp_exe = verify_wfp_tool(args.wfp_exe)
    WfpBoundary(wfp_exe, args.expected_sid, isolated_vm=True,
                tool_sids=args.tool_sid).assert_default_deny()
    targets = verify_trace_targets(adapter, args.desktop_pid, args.backend_pid,
                                   args.network_pid, args.expected_sid)
    backend_image = process_identity(args.backend_pid)["image_path"]
    static = verify_static_entries(adapter, Path(backend_image))
    marker = (fixtures["prompt_marker"] if args.case == "text" else
              fixtures["upload_marker"] if args.case == "upload" else "")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows: list[dict] = []
    errors: list[str] = []
    lock = threading.Lock()
    sessions = []
    source_hashes = {}
    frida_version = None
    began = time.time_ns()
    try:
        import frida  # Research dependency, never a production guard dependency.
        frida_version = getattr(frida, "__version__", "unknown")
        for role, target in targets.items():
            source = agent_source(role, adapter, marker, attachment)
            source_hashes[role] = hashlib.sha256(source.encode("utf-8")).hexdigest()
            session = frida.attach(target["pid"])
            script = session.create_script(source)
            def receive(message, _data, *, role=role):
                with lock:
                    if message.get("type") == "send":
                        event = safe_event(message.get("payload"), role)
                        if event is None:
                            errors.append("unexpected_agent_message")
                        elif len(rows) < MAX_EVENTS:
                            rows.append(event)
                            if event["kind"] in {"entry_mismatch", "hook_unavailable"}:
                                errors.append(event["kind"])
                        else:
                            errors.append("event_bound_exceeded")
                    elif message.get("type") == "error":
                        errors.append("agent_script_error")
            script.on("message", receive)
            sessions.append(session)
            script.load()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with lock:
                ready = {row["role"] for row in rows if row["kind"] == "probe_ready"}
            if ready == set(targets):
                break
            time.sleep(0.02)
        else:
            errors.append("research_probe_not_ready")
        if "research_probe_not_ready" not in errors:
            print(f"Research trace ready for {args.case}; duration {args.seconds}s.", flush=True)
            if args.case == "text":
                print(f"Paste only the synthetic text in {prompt} into the VM desktop task.", flush=True)
            elif args.case == "upload":
                print(f"Attach only the synthetic file {attachment} in the VM desktop task.", flush=True)
            until = time.monotonic() + args.seconds
            while time.monotonic() < until:
                time.sleep(min(0.1, until - time.monotonic()))
    except Exception as error:
        errors.append(type(error).__name__)
    finally:
        for session in reversed(sessions):
            try:
                session.detach()
            except Exception:
                errors.append("frida_detach_failed")
        try:
            after = verify_trace_targets(adapter, args.desktop_pid, args.backend_pid,
                                         args.network_pid, args.expected_sid)
            if after != targets:
                errors.append("target_identity_changed")
        except Exception:
            errors.append("target_identity_unavailable_after_trace")
        with lock:
            evidence = list(rows)
        event_path = output / "events.jsonl"
        event_bytes = b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")
                               for row in evidence)
        event_path.write_bytes(event_bytes)
        result = {"schema": TRACE_SCHEMA, "research_only": True, "can_enforce": False,
                  "coverage_status": "unvalidated", "network_permit_opened": False,
                  "raw_body_persisted": False, "case": args.case, "vm": vm,
                  "adapter_sha256": _hash(adapter_path),
                  "wfp_tool_sha256": _hash(wfp_exe),
                  "frida_version": frida_version,
                  "fixture_manifest_sha256": _hash(args.fixtures),
                  "marker_sha256": hashlib.sha256(marker.encode("ascii")).hexdigest() if marker else None,
                  "fixture_file_sha256": fixtures["attachment_sha256"],
                  "target_images": targets, "static_candidate_hash": hashlib.sha256(
                      json.dumps(static["candidates"], sort_keys=True).encode()).hexdigest(),
                  "network_service_traced": "network" in targets,
                  "agent_source_sha256": source_hashes,
                  "events_sha256": hashlib.sha256(event_bytes).hexdigest(),
                  "event_count": len(evidence), "errors": sorted(set(errors)),
                  "elapsed_ms": (time.time_ns() - began) / 1_000_000,
                  "http_candidate_entries": sum(row.get("hook") == "model.http" and row["kind"] == "candidate_entry"
                                                for row in evidence),
                  "wss_candidate_entries": sum(row.get("hook") == "model.wss" and row["kind"] == "candidate_entry"
                                               for row in evidence),
                  "marker_buffer_hits": sum(row["kind"] == "marker_buffer" for row in evidence),
                  "interpretation": "hits locate research candidates only; ABI, completeness, denial and zero-byte coverage unproved"}
        (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="Create bounded synthetic prompt and upload fixtures")
    prepare.add_argument("--output", type=Path, required=True)
    trace = sub.add_parser("trace", help="Research-only trace in the isolated QEMU VM")
    trace.add_argument("--isolated-vm", action="store_true", required=True)
    trace.add_argument("--adapter", type=Path, required=True)
    trace.add_argument("--fixtures", type=Path, required=True)
    trace.add_argument("--desktop-pid", type=int, required=True)
    trace.add_argument("--backend-pid", type=int, required=True)
    trace.add_argument("--network-pid", type=int)
    trace.add_argument("--expected-sid", required=True)
    trace.add_argument("--wfp-exe", type=Path, required=True)
    trace.add_argument("--tool-sid", action="append", default=[])
    trace.add_argument("--case", choices=("idle", "text", "upload"), required=True)
    trace.add_argument("--seconds", type=int, choices=range(5, 301), metavar="5..300", required=True)
    trace.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    enter_repository()
    if args.command == "prepare":
        print(json.dumps(prepare_fixtures(args.output), indent=2))
    else:
        result = run_trace(args)
        print(json.dumps({key: result[key] for key in ("case", "coverage_status", "event_count",
                                                      "http_candidate_entries", "wss_candidate_entries",
                                                      "marker_buffer_hits", "errors")}, indent=2))
        if result["errors"]:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
