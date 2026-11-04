"""Reproduce fixed-backend WSS and HTTP denial against a localhost-only origin.

This is a synthetic CLI ABI fixture for the same pinned codex.exe bundled with
the desktop. It does not validate desktop UI routing, file uploads, WFP, or
production enforcement. No current app process, login or external provider is
used. Only metadata survives after the local TLS wire/key artifacts are removed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import probe_desktop_backend_lab as lab
from probe_codex_tls import Origin, certificate
from probe_desktop_paths_vm import agent_source, safe_event, verify_static_entries
from transpect_trace.guard.detection import inspection_text
from transpect_trace.guard.desktop import load_desktop_adapter
from transpect_trace.guard.policy import GuardRequest
from transpect_trace.protect.archive import EncryptedRequestArchive
from transpect_trace.protect.desktop_bridge import (
    DesktopDLPBridge, _nested_field_context, _protocol_metadata_view,
)
from transpect_trace.protect.content_dlp import (
    DLPVerdict, _ENTROPY_TOKENS, _RULES, _canonical_forms, _entropy, _luhn,
)


_SAFE_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,40}\Z")


class _TransportAllowControl:
    """Isolated ABI control only; never use as a content policy."""

    def inspect_text(self, _text: str) -> DLPVerdict:
        return DLPVerdict("ALLOW", "LOCALHOST_TRANSPORT_CONTROL_STUB")

    def inspect_file_bytes(self, _filename: str, _data: bytes) -> DLPVerdict:
        raise ValueError("transport control does not support attachments")


def _entropy_field_diagnostics(value: object, base: str) -> dict:
    """Describe lexical false positives without copying request text to the report."""
    rows: list[dict] = []
    total = 0
    stack = [(value, base)]
    while stack:
        item, path = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                label = key if isinstance(key, str) and _SAFE_FIELD.fullmatch(key) else "[key]"
                stack.append((child, path + "." + label))
        elif isinstance(item, list):
            stack.extend((child, path + "[]") for child in item)
        elif isinstance(item, str):
            for match in _ENTROPY_TOKENS.finditer(item):
                token = match.group()
                if (re.fullmatch(r"[a-fA-F0-9]{32,128}", token)
                        or not any(char.isalpha() for char in token)
                        or not any(char.isdigit() for char in token)
                        or _entropy(token) < 3.6):
                    continue
                total += 1
                if len(rows) >= 32:
                    continue
                neighborhood = item[max(0, match.start() - 32):match.end() + 32].casefold()
                context = [word for word in ("token", "secret", "key", "credential", "密钥", "令牌")
                           if word in neighborhood]
                kind = ("lab_marker" if token.startswith("TTRACE_BENIGN_")
                        else "synthetic_example" if token.startswith("FAKE")
                        else "base64_like" if any(c in token for c in "+/=")
                        else "symbolic_id" if any(c in token for c in "_-")
                        else "alphanumeric")
                rows.append({"path": path, "field_length": len(item),
                             "token_length": len(token), "token_type": kind,
                             "entropy_bits_per_char": round(_entropy(token), 2),
                             "context_keywords": context})
    return {"candidate_count": total, "candidates": rows}


def _id_format_diagnostics(item: object) -> dict | None:
    if not isinstance(item, dict) or not isinstance(item.get("id"), str):
        return None
    value = item["id"]
    prefix = value.split("_", 1)[0] if "_" in value else ""
    tail = value[len(prefix) + 1:]
    return {"length": len(value), "prefix": prefix if prefix in {"msg", "item"} else "other",
            "tail_is_hex": bool(re.fullmatch(r"[0-9a-fA-F]+", tail)),
            "tail_length": len(tail),
            "tail_is_uuid": bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", tail))}


def _card_field_diagnostics(value: object) -> dict:
    pattern = next(rule[2] for rule in _RULES if rule[0] == "PAYMENT_CARD")
    stack = [(value, "root")]
    rows: list[dict] = []
    while stack:
        item, path = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                label = key if isinstance(key, str) and _SAFE_FIELD.fullmatch(key) else "[key]"
                stack.append((child, path + "." + label))
        elif isinstance(item, list):
            stack.extend((child, path + "[]") for child in item)
        elif isinstance(item, str):
            for form_index, form in enumerate(_canonical_forms(item, time.monotonic() + 1.0)):
                for match in pattern.finditer(form):
                    if _luhn(match.group()) and len(rows) < 16:
                        rows.append({"path": path, "field_length": len(item),
                                     "digits": sum(c.isdigit() for c in match.group()),
                                     "decoded": form_index > 0})
    full_rows = []
    for view_name, view in (("flattened", inspection_text(value)),
                            ("nested_context", _nested_field_context(value))):
        for form_index, form in enumerate(_canonical_forms(view, time.monotonic() + 1.0)):
            for match in pattern.finditer(form):
                if _luhn(match.group()) and len(full_rows) < 16:
                    full_rows.append({"view": view_name, "digits": sum(c.isdigit() for c in match.group()),
                                      "decoded": form_index > 0})
    return {"field_matches": rows, "field_match_count": len(rows),
            "full_view_matches": full_rows, "full_view_match_count": len(full_rows)}


def _report(events: list[dict], origin_rows: list[dict], *, mode: str,
            target_sha256: str, marker_sha256: str, exit_code: int,
            errors: list[str]) -> dict:
    """Require independent origin evidence; never infer coverage from Hook hits."""
    hits = [{k: row[k] for k in ("hook", "bytes", "sha256", "request_shape")
             if k in row} for row in events if row.get("kind") == "marker_buffer"]
    denials = [row for row in events if row.get("kind") in {
        "synthetic_denied", "synthetic_denial_failed_precondition",
        "synthetic_http_denied_owned", "synthetic_http_denial_failed"}]
    allows = [row for row in events if row.get("kind") == "synthetic_bridge_allowed"]
    origin = [{k: row[k] for k in (
        "protocol", "payload_bytes", "payload_sha256", "marker_in_origin_payload",
        "wss_wire_body_bytes_received") if k in row}
        | ({"error_type": row["error"].split(":", 1)[0]} if row.get("error") else {})
        for row in origin_rows]
    marked = [row for row in origin if row.get("marker_in_origin_payload") is True]
    marked_wss = [row for row in marked if row.get("protocol") == "websocket"]
    candidate_wss = [row for row in hits if row.get("hook") == "model.wss"]
    empty_wss = [row for row in origin if row.get("protocol") == "websocket"
                 and row.get("wss_wire_body_bytes_received") == 0]
    nonempty_origin = [row for row in origin if isinstance(row.get("payload_bytes"), int)
                       and row["payload_bytes"] > 0]
    unmarked_warmup = [row for row in nonempty_origin
                       if row.get("protocol") == "websocket"
                       and row.get("marker_in_origin_payload") is False]
    wss_denied = sum(row["kind"] == "synthetic_denied" for row in denials)
    http_denied = sum(row["kind"] == "synthetic_http_denied_owned" for row in denials)
    invalid_hooks = [row for row in events if row.get("kind") in {
        "hook_unavailable", "entry_mismatch", "read_hypothesis_failed"}]
    installed = {row.get("hook") for row in events if row.get("kind") == "hook_installed"}
    valid = (not errors and not invalid_hooks and
             {"model.http", "model.wss"}.issubset(installed) and
             not any("failed" in row["kind"] for row in denials))
    if mode == "allow":
        passed = (valid and len(candidate_wss) == len(marked_wss) == 1
                  and candidate_wss[0]["bytes"] == marked_wss[0].get("payload_bytes")
                  and candidate_wss[0]["sha256"] == marked_wss[0].get("payload_sha256")
                  and candidate_wss[0].get("request_shape") == "response.create-input")
        status = "exact_wss_payload_match" if passed else "unvalidated"
    elif mode == "wss-only":
        passed = (valid and wss_denied == 1 and len(empty_wss) >= 1 and not marked_wss
                  and any(row.get("protocol") == "http" for row in marked))
        status = "wss_denied_http_fallback_leaked" if passed else "unvalidated"
    elif mode == "all":
        passed = (valid and exit_code == 1 and wss_denied == http_denied == 1
                  and len(empty_wss) >= 1 and not marked
                  and len(nonempty_origin) == len(unmarked_warmup) == 1
                  and any(row.get("hook") == "model.http" for row in hits))
        status = "synthetic_marker_denied_all_observed_paths" if passed else "unvalidated"
    else:
        # Synchronous bridge mode adds its decision/origin criteria below.
        passed = False
        status = "unvalidated"
    return {
        "schema": "transpect.desktop-local-denial-lab/1.0",
        "scope": "archived fixed CLI only; desktop UI and complete route coverage unvalidated",
        "mode": mode, "status": status, "passed": passed,
        "target_sha256": target_sha256, "marker_sha256": marker_sha256,
        "cli_exit_code": exit_code, "origin_is_local_nonforwarding": True,
        "candidate_entries": {hook: sum(row.get("kind") == "candidate_entry"
                                         and row.get("hook") == hook for row in events)
                              for hook in ("model.http", "model.wss")},
        "marker_hits": hits, "denial_events": denials, "allow_events": allows,
        "origin": origin, "origin_marked_payload_count": len(marked),
        "wss_zero_frame_connection_count": len(empty_wss),
        "origin_nonempty_body_count": len(nonempty_origin),
        "total_origin_body_bytes": sum(row["payload_bytes"] for row in nonempty_origin),
        "unmarked_warmup_body_count": len(unmarked_warmup),
        "unmarked_warmup_body_bytes": sum(row["payload_bytes"] for row in unmarked_warmup),
        "errors": sorted(set(errors)),
        "invalid_hook_events": len(invalid_hooks),
        "raw_body_persisted": False,
        "production_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("allow", "wss-only", "all", "bridge"), required=True)
    parser.add_argument("--bridge-evaluate", action="store_true",
                        help="Evaluate marked synthetic WSS bytes offline; does not gate sending")
    parser.add_argument("--case", choices=("benign", "secret"), default="benign")
    parser.add_argument("--simulate-bridge-loss", action="store_true",
                        help="Withhold the synthetic controller reply and verify bounded fail-stop")
    parser.add_argument("--simulate-wss-capacity-failure", action="store_true",
                        help="Force the synthetic WSS capacity precondition to fail")
    parser.add_argument("--transport-allow-control", action="store_true",
                        help="Stub ALLOW for the fake localhost benign request; not a DLP result")
    args = parser.parse_args()
    mode = args.mode
    if args.bridge_evaluate and mode != "allow":
        parser.error("bridge evaluation is observation only and requires --mode allow")
    if args.simulate_bridge_loss and mode != "bridge":
        parser.error("controller-loss simulation requires --mode bridge")
    if args.simulate_wss_capacity_failure and (mode != "bridge" or args.simulate_bridge_loss):
        parser.error("capacity simulation requires --mode bridge without controller loss")
    if args.transport_allow_control and (mode != "bridge" or args.case != "benign" or
                                         args.simulate_bridge_loss or args.simulate_wss_capacity_failure):
        parser.error("transport ALLOW control requires an ordinary benign bridge run")
    backend = lab.BACKEND.resolve(strict=True)
    backend_sha256 = lab.file_hash(backend)
    if backend_sha256 != lab.EXPECTED_BACKEND_SHA256:
        raise RuntimeError("archived fixed backend changed")
    adapter = load_desktop_adapter(lab.ADAPTER, require_validated=False)
    if (adapter.get("status") != "candidate_unvalidated" or
            adapter.get("binary_sha256") != backend_sha256):
        raise RuntimeError("unvalidated fixed adapter changed")
    verify_static_entries(adapter, backend)
    marker = f"TTRACE_BENIGN_{uuid4().hex[:8]}"
    output = ROOT / "runs/desktop-backend-lab" / f"wss-deny-{uuid4().hex[:8]}"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(exist_ok=False)
    cert, key, ca = certificate(output)
    origin = Origin(output, cert, key, marker.encode("ascii"))
    origin.thread.start()
    session = None
    proc = None
    events = []
    errors = []
    bridge_result: dict | None = None
    bridge_results: list[dict] = []
    bridge_done = threading.Event()
    report: dict | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="ttrace-wss-cli-local-") as name:
            home = Path(name) / "home"
            work = Path(name) / "workspace"
            home.mkdir()
            work.mkdir()
            (home / "config.toml").write_text(
                'model = "gpt-probe"\n'
                'model_provider = "tls_probe"\n'
                '[features]\nplugins = false\napps = false\n'
                '[model_providers.tls_probe]\n'
                'name = "Local TLS test origin"\n'
                f'base_url = "https://localhost:{origin.port}"\n'
                'wire_api = "responses"\n'
                'requires_openai_auth = false\n'
                'request_max_retries = 0\n'
                'stream_max_retries = 0\n'
                'supports_websockets = true\n', encoding="utf-8")
            env = lab.isolated_env(home)
            env.update(CODEX_CA_CERTIFICATE=str(ca), NO_PROXY="localhost,127.0.0.1",
                       HTTP_PROXY="http://127.0.0.1:9",
                       HTTPS_PROXY="http://127.0.0.1:9",
                       ALL_PROXY="http://127.0.0.1:9", RUST_LOG="warn")
            proc = subprocess.Popen(
                [str(backend), "exec", "--json", "--ephemeral", "--skip-git-repo-check",
                 "--model", "gpt-probe", "--cd", str(work), "-"],
                cwd=work, env=env, stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace")
            time.sleep(0.5)
            if proc.poll() is not None:
                raise RuntimeError("fixed CLI exited before observer attached")
            import frida
            session = frida.attach(proc.pid)
            source = agent_source("backend", adapter, marker, output / "unused.txt", observe_io=False)
            if mode != "allow":
                needle = "const marker = new Uint8Array(CONFIG.marker);"
                fail_stop = needle + """
const syntheticKernel = Process.getModuleByName('kernel32.dll');
const syntheticCurrentProcess = new NativeFunction(
  syntheticKernel.getExportByName('GetCurrentProcess'), 'pointer', []);
const syntheticTerminateProcess = new NativeFunction(
  syntheticKernel.getExportByName('TerminateProcess'), 'bool', ['pointer', 'uint32']);
function failStopSyntheticBackend() {
  syntheticTerminateProcess(syntheticCurrentProcess(), 76);
  // If termination unexpectedly fails, never resume the network sender.
  while (true) {}
}
"""
                if source.count(needle) != 1:
                    raise RuntimeError("fail-stop insertion point changed")
                source = source.replace(needle, fail_stop)
            if mode == "bridge":
                needle = "const marker = new Uint8Array(CONFIG.marker);"
                sync_bridge = needle + """
let bridgeSequence = 0;
function bridgeDecision(hook, data, length) {
  const requestId = String(++bridgeSequence);
  send({kind:'synthetic_bridge_candidate', hook:hook,
        protocol:hook === 'model.wss' ? 'wss' : 'http',
        request_id:requestId, bytes:length}, data.readVolatile(length));
  let decision = 'deny';
  recv('synthetic_bridge_decision_' + requestId, function(message) {
    if (message && message.payload && message.payload.decision === 'allow')
      decision = 'allow';
  }).wait();
  return decision;
}
"""
                if source.count(needle) != 1:
                    raise RuntimeError("synchronous bridge insertion point changed")
                source = source.replace(needle, sync_bridge)
            if args.bridge_evaluate:
                needle = "inspectBuffer(data, length, name, 'hypothesized-wss-serialized', this);"
                capture = needle + """
          if (length > 0 && length <= 16 * 1024 * 1024 &&
              requestShape(data, length) === 'response.create-input' &&
              markerOffset(new Uint8Array(data.readVolatile(length))) >= 0)
            send({kind:'synthetic_bridge_candidate', hook:name, bytes:length},
                 data.readVolatile(length));
"""
                if source.count(needle) != 1:
                    raise RuntimeError("WSS bridge capture point changed")
                source = source.replace(needle, capture)
            if mode == "bridge":
                needle = "inspectBuffer(data, length, name, 'hypothesized-wss-serialized', this);"
                replacement = needle + """
          if (length > 0 && length <= 16 * 1024 * 1024 &&
              requestShape(data, length) === 'response.create-input' &&
              markerOffset(new Uint8Array(data.readVolatile(length))) >= 0) {
            let decision = 'deny';
            try { decision = bridgeDecision(name, data, length); }
            catch (_) { failStopSyntheticBackend(); }
            if (decision === 'allow') {
              send({kind:'synthetic_bridge_allowed',hook:name,original_bytes:length});
            } else {
              const capacity = this.result.add(8).readU64().toNumber();
              const reason = 'Transpect synthetic DLP denied';
              const encoded = new Uint8Array(Array.from(reason).map(ch => ch.charCodeAt(0)));
              if (!Number.isSafeInteger(capacity) || capacity < length || capacity < encoded.length) {
                send({kind:'synthetic_denial_failed_precondition',hook:name});
                failStopSyntheticBackend();
              } else {
                data.writeByteArray(encoded);
                this.result.add(24).writeU64(encoded.length);
                this.result.writeU64(0x0d);
                send({kind:'synthetic_denied',hook:name,original_bytes:length,
                      capacity_sane:true,error_tag:'0x0d'});
              }
            }
          }
"""
                if source.count(needle) != 1:
                    raise RuntimeError("WSS synchronous bridge insertion point changed")
                source = source.replace(needle, replacement)
            if mode in {"wss-only", "all"}:
                needle = "inspectBuffer(data, length, name, 'hypothesized-wss-serialized', this);"
                replacement = needle + """
          if (length > 0 && length <= 16 * 1024 * 1024 &&
              requestShape(data, length) === 'response.create-input') {
            const bytes = new Uint8Array(data.readVolatile(length));
            if (markerOffset(bytes) >= 0) {
              const capacity = this.result.add(8).readU64().toNumber();
              const reason = 'Transpect synthetic request denied';
              const encoded = new Uint8Array(Array.from(reason).map(ch => ch.charCodeAt(0)));
              if (!Number.isSafeInteger(capacity) || capacity < length || capacity < encoded.length) {
                send({kind:'synthetic_denial_failed_precondition', hook:name});
                failStopSyntheticBackend();
              } else {
                data.writeByteArray(encoded);
                this.result.add(24).writeU64(encoded.length);
                this.result.writeU64(0x0d);
                send({kind:'synthetic_denied', hook:name, original_bytes:length,
                      capacity_sane:true, error_tag:'0x0d'});
              }
            }
          }
"""
                if source.count(needle) != 1:
                    raise RuntimeError("WSS observer insertion point changed")
                source = source.replace(needle, replacement)
            if mode in {"all", "bridge"}:
                skip = "  installCandidate('model.http', CONFIG.http);"
                if source.count(skip) != 1:
                    raise RuntimeError("HTTP observer replacement point changed")
                source = source.replace(skip, "")
                needle = "send({kind: 'probe_ready', role: CONFIG.role});"
                bridge_http_action = ("""
    let decision = 'deny';
    try { decision = bridgeDecision('model.http',data,length); }
    catch (_) { failStopSyntheticBackend(); }
    if (decision === 'allow') {
      send({kind:'synthetic_bridge_allowed',hook:'model.http',original_bytes:length});
      return originalHttp(result,request,headers,body);
    }
""" if mode == "bridge" else "")
                http_replace = """
if (CONFIG.role === 'backend') {
  const base = Process.mainModule.base;
  const httpTarget = base.add(ptr(CONFIG.http.rva));
  const actualHttp = new Uint8Array(httpTarget.readVolatile(CONFIG.http.prefix.length));
  if (actualHttp.some((v,i) => v !== CONFIG.http.prefix[i]))
    throw new Error('pinned HTTP candidate prologue changed');
  const dropTarget = base.add(0xa6320);
  const actualDrop = new Uint8Array(dropTarget.readVolatile(8));
  const expectedDrop = [0x55,0x56,0x57,0x53,0x48,0x83,0xec,0x58];
  if (actualDrop.some((v,i) => v !== expectedDrop[i]))
    throw new Error('pinned HeaderMap drop prologue changed');
  const dropHeaders = new NativeFunction(dropTarget, 'void', ['pointer']);
  const originalHttp = new NativeFunction(httpTarget, 'pointer',
      ['pointer','pointer','pointer','pointer']);
  Interceptor.replace(httpTarget, new NativeCallback(function(result, request, headers, body) {
    let data=null, length=0, matched=false;
    try {
      data = body.add(8).readPointer();
      length = body.add(16).readU64().toNumber();
      if (length > 0 && length <= 16 * 1024 * 1024)
        matched = markerOffset(new Uint8Array(data.readVolatile(length))) >= 0;
    } catch (_) {}
    send({kind:'candidate_entry', hook:'model.http'});
    if (!matched) return originalHttp(result,request,headers,body);
    inspectBuffer(data,length,'model.http','hypothesized-http-body',this);
""" + bridge_http_action + """
    try {
      dropHeaders(headers);
      result.writeU64(3);
      result.add(8).writeU64(0);
      result.add(16).writePointer(ptr(1));
      result.add(24).writeU64(0);
      send({kind:'synthetic_http_denied_owned',hook:'model.http',
            drop_headers_rva:'0xa6320',original_bytes:length});
      return result;
    } catch (_) {
      // A malformed fixed-build error ABI must never resume the sender.
      send({kind:'synthetic_http_denial_failed',hook:'model.http'});
      failStopSyntheticBackend();
      return result;
    }
  }, 'pointer', ['pointer','pointer','pointer','pointer']));
  send({kind:'hook_installed',hook:'model.http',rva:CONFIG.http.rva});
}
""" + needle
                if source.count(needle) != 1:
                    raise RuntimeError("HTTP observer replacement point changed")
                source = source.replace(needle, http_replace)
            if args.simulate_wss_capacity_failure:
                needle = "const capacity = this.result.add(8).readU64().toNumber();"
                if source.count(needle) != 1:
                    raise RuntimeError("WSS capacity precondition insertion point changed")
                source = source.replace(needle, "const capacity = 0; // isolated fault injection")
            script = session.create_script(source)
            archive = (EncryptedRequestArchive(output / "encrypted-archive")
                       if args.bridge_evaluate or mode == "bridge" else None)
            bridge = (DesktopDLPBridge({"pid": proc.pid}, archive,
                                       dlp=_TransportAllowControl() if args.transport_allow_control else None)
                      if archive else None)
            def receive(message, _data):
                nonlocal bridge_result
                if message.get("type") == "send":
                    payload = message.get("payload")
                    if ((args.bridge_evaluate or mode == "bridge") and isinstance(payload, dict)
                            and payload.get("kind") == "synthetic_bridge_candidate"):
                        reply_decision = "deny"
                        reply_id = payload.get("request_id")
                        try:
                            if ((mode != "bridge" and bridge_result is not None)
                                    or not isinstance(_data, bytes)):
                                raise ValueError("missing or duplicate synthetic bridge body")
                            protocol = payload.get("protocol", "wss")
                            if protocol not in {"http", "wss"}:
                                raise ValueError("invalid bridge protocol")
                            raw = _data
                            if marker.encode("ascii") not in raw:
                                raise ValueError("synthetic marker missing from candidate")
                            if args.simulate_bridge_loss:
                                bridge_results.append({
                                    "protocol": protocol, "decision": "controller_unavailable",
                                    "body_sha256": hashlib.sha256(raw).hexdigest(),
                                    "body_bytes": len(raw), "reply_sent": False,
                                })
                                return
                            request = GuardRequest.model_validate({
                                "schema": "transpect.guard.request/1.0",
                                "request_id": uuid4().hex,
                                "guard_session_id": "isolated-synthetic-lab",
                                "pid": proc.pid, "tid": 1,
                                "kind": "model.request", "protocol": protocol,
                                "completeness": "complete", "payload_utf8": raw.decode("utf-8"),
                            })
                            decision, audit = bridge.evaluate(request)
                            if mode == "bridge" and not args.simulate_bridge_loss:
                                receipt_id = audit.get("archive_record_id")
                                archived, checked = archive.read(receipt_id) if receipt_id else (None, b"")
                                readback_matches = checked == raw and archived is not None
                                scored, _ = bridge._attachments(json.loads(raw))
                                scored = _protocol_metadata_view(scored)
                                dlp_decision = bridge.dlp.inspect_text(
                                    inspection_text(scored) + "\n" +
                                    _nested_field_context(scored)).decision
                                bridge_results.append({
                                    "protocol": protocol, "decision": decision.decision,
                                    "dlp_decision": dlp_decision,
                                    "reason": decision.reason,
                                    "rule_ids": audit.get("matched_rule_ids", []),
                                    "body_sha256": hashlib.sha256(raw).hexdigest(),
                                    "body_bytes": len(raw),
                                    "archive_sha256": archived.body_sha256 if archived else None,
                                    "archive_bytes": archived.body_bytes if archived else None,
                                    "archive_readback_matches": readback_matches,
                                })
                                reply_decision = ("allow" if decision.decision == "allow"
                                                  and readback_matches else "deny")
                                return
                            parsed = json.loads(raw)
                            pending = [(parsed, "root")]
                            history_field_count = 0
                            attachment_field_count = 0
                            attachment_key_sections: dict[str, int] = {}
                            while pending:
                                item, section = pending.pop()
                                if isinstance(item, dict):
                                    history_field_count += sum(key in item for key in (
                                        "previous_response_id", "conversation_id", "conversation"))
                                    file_keys = (
                                        "file_id", "file_data", "file_url", "file_path",
                                        "image_url", "image_base64")
                                    attachment_field_count += sum(key in item for key in file_keys)
                                    for key in file_keys:
                                        if key in item:
                                            label = section + "." + key
                                            attachment_key_sections[label] = attachment_key_sections.get(label, 0) + 1
                                    pending.extend((value, key if section == "root" and key in {
                                        "input", "tools"} else section) for key, value in item.items())
                                elif isinstance(item, list):
                                    pending.extend((value, section) for value in item)
                            structure = {
                                "flat_response_create": parsed.get("type") == "response.create",
                                "top_level_previous_response_id": "previous_response_id" in parsed,
                                "top_level_conversation_id": "conversation_id" in parsed,
                                "input_is_list": isinstance(parsed.get("input"), list),
                                "input_count": (len(parsed["input"])
                                                if isinstance(parsed.get("input"), list) else None),
                                "history_field_count": history_field_count,
                                "attachment_field_count": attachment_field_count,
                                "attachment_key_sections": attachment_key_sections,
                            }
                            segment_verdicts = {}
                            for section in ("input", "tools"):
                                segment = parsed.get(section)
                                if segment is not None:
                                    checked_text = (inspection_text(segment) + "\n" +
                                                    _nested_field_context(segment))
                                    checked_verdict = bridge.dlp.inspect_text(checked_text)
                                    segment_verdicts[section] = {
                                        "decision": checked_verdict.decision,
                                        "rule_ids": checked_verdict.rule_ids,
                                    }
                            input_item_verdicts = []
                            if isinstance(parsed.get("input"), list):
                                for index, item in enumerate(parsed["input"]):
                                    item_text = (inspection_text(item) + "\n" +
                                                 _nested_field_context(item))
                                    item_verdict = bridge.dlp.inspect_text(item_text)
                                    role = item.get("role") if isinstance(item, dict) else None
                                    kind = item.get("type") if isinstance(item, dict) else None
                                    input_item_verdicts.append({
                                        "index": index,
                                        "role": role if role in {"system", "developer", "user",
                                                                "assistant", "tool"} else "other",
                                        "type": kind if kind in {"message", "function_call_output"} else "other",
                                        "decision": item_verdict.decision,
                                        "rule_ids": item_verdict.rule_ids,
                                        "id_format": _id_format_diagnostics(item),
                                        "entropy_fields": _entropy_field_diagnostics(
                                            item, f"input[{index}]"),
                                    })
                            receipt_id = audit.get("archive_record_id")
                            archived, checked = archive.read(receipt_id) if receipt_id else (None, b"")
                            bridge_result = {"decision": decision.decision,
                                             "reason": decision.reason,
                                             "matched_rule_ids": audit.get("matched_rule_ids", []),
                                             "archive_sha256": archived.body_sha256 if archived else None,
                                             "archive_bytes": archived.body_bytes if archived else None,
                                             "archive_readback_matches": checked == raw,
                                             "body_sha256": hashlib.sha256(raw).hexdigest(),
                                             "body_bytes": len(raw),
                                             "shape": structure,
                                             "segment_verdicts": segment_verdicts,
                                             "input_item_verdicts": input_item_verdicts,
                                             "card_fields": _card_field_diagnostics(parsed)}
                        except Exception as error:
                            errors.append("bridge_" + type(error).__name__)
                        finally:
                            if mode == "bridge" and not args.simulate_bridge_loss:
                                try:
                                    if not isinstance(reply_id, str) or not reply_id.isdigit():
                                        raise ValueError("invalid bridge reply id")
                                    script.post({"type": "synthetic_bridge_decision_" + reply_id,
                                                 "payload": {"decision": reply_decision}})
                                except Exception as error:
                                    errors.append("bridge_reply_" + type(error).__name__)
                            bridge_done.set()
                        return
                    if isinstance(payload, dict) and payload.get("kind") in {
                            "synthetic_denied", "synthetic_denial_failed_precondition",
                            "synthetic_http_denied_owned",
                            "synthetic_http_denial_failed", "synthetic_bridge_allowed"}:
                        events.append({k: payload[k] for k in ("kind", "hook", "original_bytes",
                                                                "capacity_sane", "error_tag", "drop_headers_rva")
                                       if k in payload})
                        return
                    row = safe_event(message.get("payload"), "backend")
                    if row is not None:
                        events.append(row)
                elif message.get("type") == "error":
                    errors.append("frida_script_error")
            script.on("message", receive)
            script.load()
            install_deadline = time.monotonic() + 3
            while time.monotonic() < install_deadline:
                installed = {row.get("hook") for row in events
                             if row.get("kind") == "hook_installed"}
                if {"model.http", "model.wss"}.issubset(installed) or errors:
                    break
                time.sleep(0.05)
            if not {"model.http", "model.wss"}.issubset(installed) or errors:
                raise RuntimeError("fixed candidate hooks unavailable before prompt")
            prompt = ("Do not use tools. Reply OK. Synthetic marker: " + marker +
                      (" password=FakeSecret12345" if args.case == "secret" else "") + "\n")
            proc.stdin.write(prompt)
            proc.stdin.close()
            deadline = time.monotonic() + (4 if args.simulate_bridge_loss else 30)
            while time.monotonic() < deadline and proc.poll() is None:
                if mode == "allow" and any(
                        row.get("marker_in_origin_payload") for row in origin.records):
                    break
                time.sleep(0.1)
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            if session is not None:
                session.detach()
                session = None
            if mode != "allow":
                # Give the local receiver time to observe EOF/no frame.
                time.sleep(1)
            if (args.bridge_evaluate or mode == "bridge") and not bridge_done.wait(2):
                errors.append("bridge_candidate_not_observed")
            # Avoid printing stdout/stderr because they may repeat the marker.
            report = _report(events, origin.records, mode=mode,
                             target_sha256=lab.file_hash(backend),
                             marker_sha256=hashlib.sha256(marker.encode()).hexdigest(),
                             exit_code=proc.returncode, errors=errors)
            if args.bridge_evaluate:
                origins = [row for row in report["origin"]
                           if row.get("marker_in_origin_payload") is True]
                report["bridge_evaluation"] = bridge_result
                report["bridge_origin_hash_match"] = (
                    bridge_result is not None and len(origins) == 1 and
                    bridge_result["archive_sha256"] == origins[0].get("payload_sha256") and
                    bridge_result["archive_bytes"] == origins[0].get("payload_bytes") and
                    bridge_result["archive_readback_matches"] is True)
            if mode == "bridge":
                report["bridge_decisions"] = bridge_results
                origin_marked = [row for row in report["origin"]
                                 if row.get("marker_in_origin_payload") is True]
                bridge_receipts_valid = all(
                    row.get("archive_readback_matches") is True and
                    row.get("archive_sha256") == row.get("body_sha256") and
                    row.get("archive_bytes") == row.get("body_bytes")
                    for row in bridge_results)
                denied = {(row["protocol"], row["decision"]) for row in bridge_results}
                denial_hooks = {row.get("hook") for row in report["denial_events"]}
                denied_path_verified = (
                    not errors and bridge_receipts_valid and
                    denied == {("wss", "deny"), ("http", "deny")} and
                    len(bridge_results) == 2 and not origin_marked and
                    report["origin_nonempty_body_count"] == 1 and
                    report["unmarked_warmup_body_count"] == 1 and
                    report["wss_zero_frame_connection_count"] >= 1 and
                    denial_hooks == {"model.wss", "model.http"} and
                    report["cli_exit_code"] == 1)
                if args.simulate_wss_capacity_failure:
                    report["fault_injection"] = "forced_zero_wss_capacity_after_bridge_denial"
                    passed = (not errors and
                              report["cli_exit_code"] == 76 and
                              len(report["marker_hits"]) == 1 and
                              report["marker_hits"][0].get("hook") == "model.wss" and
                              len(bridge_results) == 1 and
                              bridge_results[0]["protocol"] == "wss" and
                              bridge_results[0]["decision"] == "deny" and
                              report["candidate_entries"]["model.http"] == 0 and
                              report["origin_marked_payload_count"] == 0 and
                              report["origin_nonempty_body_count"] == 1 and
                              report["unmarked_warmup_body_count"] == 1 and
                              report["wss_zero_frame_connection_count"] >= 1)
                    report["status"] = "capacity_precondition_stopped_before_send" if passed else "unvalidated"
                elif args.simulate_bridge_loss:
                    passed = (not errors and len(bridge_results) == 1 and
                              bridge_results[0]["protocol"] == "wss" and
                              bridge_results[0]["decision"] == "controller_unavailable" and
                              report["candidate_entries"]["model.http"] == 0 and
                              report["origin_marked_payload_count"] == 0 and
                              report["origin_nonempty_body_count"] == 1 and
                              report["unmarked_warmup_body_count"] == 1 and
                              report["wss_zero_frame_connection_count"] >= 1)
                    report["status"] = "controller_loss_stopped_before_target_send" if passed else "unvalidated"
                elif args.case == "benign":
                    passed = (not errors and bridge_receipts_valid and
                              len(bridge_results) == len(origin_marked) == 1 and
                              bridge_results[0]["protocol"] == "wss" and
                              bridge_results[0]["decision"] == "allow" and
                              bridge_results[0]["dlp_decision"] == "ALLOW" and
                              len(report["allow_events"]) == 1 and
                              report["allow_events"][0].get("hook") == "model.wss" and
                              bridge_results[0]["body_sha256"] == origin_marked[0].get("payload_sha256") and
                              bridge_results[0]["body_bytes"] == origin_marked[0].get("payload_bytes"))
                    review_denied = (denied_path_verified and all(
                        row.get("dlp_decision") == "REVIEW" for row in bridge_results))
                    report["enforcement_passed"] = review_denied or passed
                    report["benign_allow_passed"] = passed and not args.transport_allow_control
                    report["transport_allow_control"] = args.transport_allow_control
                    report["transport_allow_passed"] = passed if args.transport_allow_control else None
                    report["status"] = ("stub_allowed_exact_origin_payload" if passed and args.transport_allow_control else
                                        "bridge_allowed_exact_origin_payload" if passed else
                                        "review_denied_zero_target_payload" if review_denied else
                                        "unvalidated")
                else:
                    passed = (denied_path_verified and all(
                        row.get("dlp_decision") == "BLOCK" and
                        "ASSIGNED_SECRET" in row.get("rule_ids", [])
                        for row in bridge_results))
                    report["enforcement_passed"] = passed
                    report["status"] = "target_marker_denied_zero_origin_payload" if passed else "unvalidated"
                report["passed"] = bool(passed and report["invalid_hook_events"] == 0)
    finally:
        if session is not None:
            session.detach()
        if proc is not None and proc.poll() is None:
            proc.kill()
        origin.stop.set()
        origin.listener.close()
        origin.thread.join(timeout=3)
        if origin.thread.is_alive():
            raise RuntimeError("local origin did not stop")
        origin.context.keylog_filename = None
        # The local origin stores TLS wire and session keys to validate a run;
        # keep only the metadata report after the receiver has stopped.
        for file in output.glob("client-wire-*.bin"):
            file.unlink(missing_ok=True)
        for name in ("origin-session.keys", "origin-key.pem", "origin-cert.pem", "origin-ca.pem"):
            (output / name).unlink(missing_ok=True)
    if report is not None:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n",
                                             encoding="utf-8")
        print(json.dumps({key: report[key] for key in ("mode", "status", "passed",
                       "candidate_entries", "origin_marked_payload_count",
                       "wss_zero_frame_connection_count", "total_origin_body_bytes",
                       "unmarked_warmup_body_bytes", "bridge_evaluation",
                       "bridge_origin_hash_match", "bridge_decisions", "enforcement_passed",
                       "benign_allow_passed", "transport_allow_control",
                       "transport_allow_passed", "errors") if key in report}, indent=2))


if __name__ == "__main__":
    main()
