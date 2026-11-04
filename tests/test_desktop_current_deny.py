"""The active-client denial probe is opt-in and records fixture metadata only."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import probe_desktop_current_deny as probe  # noqa: E402


def _adapter() -> dict:
    return {"hooks": [
        {"layer": "http_encoded_body_preparation", "rva": "0xb117de0",
         "entry_prefix_hex": "5541574156415541545657534881ece8"},
        {"layer": "wss_request_serialization", "rva": "0x41e3330",
         "entry_prefix_hex": "5541574156415541545657534881ecd8"},
    ]}


def test_requires_three_explicit_flags_before_any_current_process_access(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("process preflight must not run")
    monkeypatch.setattr(probe, "require_current_user", forbidden)
    for flag in ("active_current_client", "synthetic_only", "accept_interruption"):
        values = {name: True for name in (
            "active_current_client", "synthetic_only", "accept_interruption")}
        values[flag] = False
        with pytest.raises(ValueError, match="explicit current-client"):
            probe.run_probe(SimpleNamespace(**values, seconds=5))


def test_source_pins_both_hooks_and_owned_headers_drop_without_raw_report():
    source = probe.synthetic_source(_adapter(), "FAKE_DESKTOP_PROMPT_" + "a" * 32)
    assert "__CONFIG__" not in source
    assert "0xb117de0" in source and "0x41e3330" in source
    assert "0xa6320" in source
    assert "0x1f" in source and "0x0d" in source
    assert "dropHeaders(headers)" in source
    assert "if (checked === null) return originalHttp" in source
    assert "metadata.thread_id !== CONFIG.test_thread_id" in source
    assert "item.type === 'function_call_output'" in source
    assert "send({kind:'probe_ready'})" in source
    assert "payload_utf8" not in source


def test_frida_source_has_valid_javascript_syntax():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for JavaScript parser check")
    source = probe.synthetic_source(_adapter(), "FAKE_DESKTOP_PROMPT_" + "b" * 32)
    result = subprocess.run([node, "--check", "-"], input=source, text=True,
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_owned_headers_destructor_entry_must_match_before_live_attach(tmp_path):
    image = bytearray(1024)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 60, 128)
    image[128:132] = b"PE\0\0"
    struct.pack_into("<H", image, 134, 1)
    struct.pack_into("<H", image, 148, 0)
    image[152:157] = b".text"
    struct.pack_into("<IIII", image, 160, 512, 0xA6300, 512, 512)
    image[544:552] = bytes.fromhex("555657534883ec58")
    path = tmp_path / "codex.exe"
    path.write_bytes(image)
    probe.verify_drop_headers_entry(path)
    image[544] ^= 0xFF
    path.write_bytes(image)
    with pytest.raises(ValueError, match="prologue changed"):
        probe.verify_drop_headers_entry(path)


def test_non_user_marker_passes_through_but_target_failures_still_deny():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for the isolated Frida behavior simulation")
    source = probe.synthetic_source(_adapter(), "FAKE_DESKTOP_PROMPT_" + "c" * 32)
    harness = r"""
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(0, 'utf8');
const hooks = {}, events = [];
let originals = 0, drops = 0, terminated = 0, throwHash = false;
const prefixes = {
  '0xb117de0': '5541574156415541545657534881ece8',
  '0x41e3330': '5541574156415541545657534881ecd8',
  '0xa6320': '555657534883ec58',
};
const base = {add(rva) { return {name:rva,
  readVolatile(n) { return Buffer.from(prefixes[rva], 'hex').subarray(0,n); }}; }};
const Process = {mainModule:{base}, getModuleByName() {
  return {getExportByName(name) { return {name}; }};
}};
const Interceptor = {
  replace(_target, callback) { hooks.http = callback; },
  attach(_target, handler) { hooks.wss = handler; },
};
function NativeFunction(target) {
  if (target.name === '0xb117de0') return () => { originals++; return null; };
  if (target.name === '0xa6320') return () => { drops++; };
  if (target.name === 'GetCurrentProcess') return () => 1;
  if (target.name === 'TerminateProcess') return () => { terminated++; return true; };
  throw Error('unexpected native function');
}
function NativeCallback(fn) { return fn; }
const Checksum = {compute(_type, bytes) {
  if (throwHash) throw Error('hash fixture error');
  return crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
}};
vm.runInNewContext(source, {Process, Interceptor, NativeFunction,
  NativeCallback, Checksum,
  ptr:value => value, send:event => events.push(event), Buffer});
function u(value) { return {toNumber() { return value; }}; }
function data(text) {
  let bytes = Buffer.from(text, 'utf8');
  return {isNull() { return false; },
    readVolatile(n) { return bytes.subarray(0,n); },
    readUtf8String(n) { return bytes.subarray(0,n).toString('utf8'); },
    writeByteArray(list) { Buffer.from(list).copy(bytes, 0); },
    size() { return bytes.length; }};
}
function fields(values) {
  const map = new Map(Object.entries(values).map(([key,value]) => [Number(key),value]));
  return {add(offset) { return {
      readPointer() { return map.get(offset); },
      readU64() { return u(map.get(offset)); },
      writeU64(value) { map.set(offset,value); },
      writePointer(value) { map.set(offset,value); },
    }; },
    readU64() { return u(map.get(0)); },
    writeU64(value) { map.set(0,value); },
    tag() { return map.get(0); }};
}
const marker = 'FAKE_DESKTOP_PROMPT_' + 'c'.repeat(32);
const testId = '01a1a5ad-14de-7861-afe8-7670bfb99d3b';
const rootId = '01a1a5ad-14de-7861-afe8-7670bfb99d3c';
const nonTarget = JSON.stringify({type:'response.create',model:'fixture',
  client_metadata:{thread_id:rootId},
  input:[{type:'function_call_output',output:marker},
         {role:'user',content:'ordinary text'}]});
const bodyData = data(nonTarget);
const body = fields({8:bodyData,16:bodyData.size()});
const header = {isNull() { return false; }};
const httpResult = fields({});
hooks.http(httpResult, {}, header, body);
if (originals !== 1 || drops !== 0 || httpResult.tag() !== undefined)
  throw Error('non-user HTTP marker interrupted an unrelated request');
const wssResult = fields({0:0x1f,8:bodyData.size(),16:bodyData,24:bodyData.size()});
const wssContext = {};
hooks.wss.onEnter.call(wssContext, [wssResult]);
hooks.wss.onLeave.call(wssContext, null);
if (wssResult.tag() !== 0x1f || terminated !== 0)
  throw Error('non-user WSS marker interrupted an unrelated request');
const wrongUser = data(JSON.stringify({type:'response.create',model:'fixture',
  client_metadata:{thread_id:rootId},input:[{role:'user',content:marker}]}));
const wrongBody = fields({8:wrongUser,16:wrongUser.size()});
const wrongResult = fields({});
hooks.http(wrongResult, {}, header, wrongBody);
if (originals !== 2 || wrongResult.tag() !== undefined)
  throw Error('wrong-thread user marker was denied');
const missing = data(JSON.stringify({type:'response.create',model:'fixture',
  input:[{type:'function_call_output',output:marker}]}));
const missingBody = fields({8:missing,16:missing.size()});
const missingResult = fields({});
hooks.http(missingResult, {}, header, missingBody);
if (originals !== 3 || missingResult.tag() !== undefined)
  throw Error('missing-thread marker was denied');
const target = JSON.stringify({type:'response.create',model:'fixture',
  client_metadata:{thread_id:testId},
  input:[{type:'function_call_output',output:marker}]});
const nullData = data(target);
const nullBody = fields({8:nullData,16:nullData.size()});
const nullResult = fields({});
hooks.http(nullResult, {}, {isNull() { return true; }}, nullBody);
if (originals !== 3 || drops !== 0 || nullResult.tag() !== 3)
  throw Error('null-header target HTTP marker was forwarded');
throwHash = true;
const hashData = data(JSON.stringify({type:'response.create',model:'fixture',
  client_metadata:{thread_id:testId},
  input:[{role:'user',content:marker}]}));
const hashBody = fields({8:hashData,16:hashData.size()});
const hashHttpResult = fields({});
hooks.http(hashHttpResult, {}, header, hashBody);
if (originals !== 3 || drops !== 1 || hashHttpResult.tag() !== 3)
  throw Error('hash-failure HTTP marker was forwarded');
const hashWssResult = fields({0:0x1f,8:hashData.size(),16:hashData,24:hashData.size()});
const hashContext = {};
hooks.wss.onEnter.call(hashContext, [hashWssResult]);
hooks.wss.onLeave.call(hashContext, null);
if (hashWssResult.tag() !== 0x0d || terminated !== 0)
  throw Error('hash-failure WSS marker was forwarded');
if (events.filter(event => event.kind === 'synthetic_denied').length !== 3)
  throw Error('missing deny metadata');
if (events.filter(event => event.kind === 'non_target_marker').length !== 4)
  throw Error('missing non-target marker metadata');
if (!events.some(event => event.kind === 'non_target_marker' &&
    event.reason === 'thread_id_mismatch'))
  throw Error('wrong-thread reason missing');
if (events.some(event => JSON.stringify(event).includes(testId) ||
    JSON.stringify(event).includes(rootId)))
  throw Error('thread ID entered event metadata');
if (events.some(event => JSON.stringify(event).includes(nonTarget)))
  throw Error('request plaintext entered metadata');
"""
    result = subprocess.run([node, "-e", harness], input=source, text=True,
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_event_sanitizer_drops_arbitrary_plaintext_and_unknown_hooks():
    digest = hashlib.sha256(b"synthetic").hexdigest()
    event = probe.safe_event({"kind": "synthetic_denied", "hook": "model.wss",
                              "bytes": 41, "sha256": digest,
                              "payload_utf8": "PRIVATE", "token": "PRIVATE"})
    assert set(event) == {"kind", "hook", "bytes", "sha256", "observed_unix_ns"}
    assert "PRIVATE" not in str(event)
    assert probe.safe_event({"kind": "synthetic_denied", "hook": "ReadFile",
                             "bytes": 41, "sha256": digest}) is None
    assert probe.safe_event({"kind": "synthetic_denied", "hook": "model.http",
                             "bytes": 41, "sha256": "PRIVATE"}) is None
    failed = probe.safe_event({"kind": "synthetic_denial_failed", "hook": "model.http",
                               "reason": "PRIVATE", "raw": "PRIVATE"})
    assert "PRIVATE" not in str(failed)


def test_summary_never_converts_hook_events_into_origin_or_coverage_proof():
    base = [
        {"kind": "hook_installed", "hook": "model.http"},
        {"kind": "hook_installed", "hook": "model.wss"},
        {"kind": "probe_ready"},
        {"kind": "synthetic_denied", "hook": "model.http"},
        {"kind": "synthetic_denied", "hook": "model.wss"},
    ]
    result = probe.summarize(base, [])
    assert result["status"] == "both_candidate_denials_observed_without_origin_proof"
    assert result["synthetic_denials_by_hook"] == {"model.http": 1, "model.wss": 1}
    assert probe.summarize(base[:-1], [])["status"] == \
        "one_candidate_denial_observed_without_origin_proof"
    assert probe.summarize(base + [{"kind": "hook_inspection_error", "hook": "model.wss"}],
                           [])["status"] == "unvalidated_probe_or_denial_error"
    assert probe.summarize(base, ["frida_script_error"])["status"] == \
        "unvalidated_probe_or_denial_error"
