"""Current-client thread attribution stays read-only and metadata-only."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import probe_desktop_current_thread_metadata as probe  # noqa: E402


def _adapter() -> dict:
    return {"hooks": [
        {"layer": "http_encoded_body_preparation", "rva": "0xb117de0",
         "entry_prefix_hex": "5541574156415541545657534881ece8"},
        {"layer": "wss_request_serialization", "rva": "0x41e3330",
         "entry_prefix_hex": "5541574156415541545657534881ecd8"},
    ]}


def test_live_observation_requires_flags_before_process_access(monkeypatch):
    monkeypatch.setattr(probe, "require_current_user", lambda *_: pytest.fail(
        "current process must not be accessed without both opt-in flags"))
    for flags in ((False, False), (True, False), (False, True)):
        with pytest.raises(ValueError, match="observation-only"):
            probe.run_probe(SimpleNamespace(active_current_client=flags[0],
                                            observation_only=flags[1], seconds=5))


def test_event_sanitizer_keeps_only_thread_comparison_and_shape_metadata():
    digest = hashlib.sha256(b"synthetic").hexdigest()
    event = probe.safe_event({"kind": "marker_metadata", "hook": "model.http",
                              "bytes": 4000, "sha256": digest, "parse_state": "parsed",
                              "thread_id_match": True, "function_output_marker": True,
                              "user_content_marker": False,
                              "thread_id": probe.TEST_THREAD_ID,
                              "payload_utf8": "PRIVATE", "raw": "PRIVATE"})
    assert set(event) == {"kind", "hook", "observed_unix_ns", "bytes", "sha256",
                          "parse_state", "thread_id_match", "function_output_marker",
                          "user_content_marker"}
    assert "PRIVATE" not in str(event) and probe.TEST_THREAD_ID not in str(event)
    assert probe.safe_event({"kind": "marker_metadata", "hook": "ReadFile",
                             "bytes": 4000, "sha256": digest,
                             "parse_state": "parsed"}) is None
    assert probe.safe_event({"kind": "marker_metadata", "hook": "model.wss",
                             "bytes": 4000, "sha256": digest,
                             "parse_state": "parsed", "thread_id_match": "yes"}) is None


def test_missing_thread_id_never_counts_as_attributed():
    installed = [{"kind": "hook_installed", "hook": hook}
                 for hook in ("model.http", "model.wss")]
    ready = {"kind": "probe_ready"}
    row = {"kind": "marker_metadata", "hook": "model.wss", "parse_state": "parsed",
           "thread_id_match": None, "function_output_marker": True}
    assert probe.summarize(installed + [ready, row], [])["status"] == "unvalidated"
    row = {**row, "thread_id_match": True}
    assert probe.summarize(installed + [ready, row], [])["status"] == \
        "metadata_attributed_to_test_thread"
    assert probe.summarize(installed + [ready, row], ["frida_script_error"])["status"] == \
        "unvalidated"


def test_frida_script_distinguishes_test_thread_from_shared_backend_sibling():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for isolated JavaScript behavior check")
    source = probe.agent_source(_adapter(), "FAKE_DESKTOP_PROMPT_" + "d" * 32)
    grammar = subprocess.run([node, "--check", "-"], input=source, text=True,
                             capture_output=True, timeout=10, check=False)
    assert grammar.returncode == 0, grammar.stderr
    harness = r"""
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(0, 'utf8');
const events = [], hooks = {};
const prefixes = {
  '0xb117de0':'5541574156415541545657534881ece8',
  '0x41e3330':'5541574156415541545657534881ecd8',
};
const Process = {mainModule:{base:{add(rva) { return {name:rva,
  readVolatile(n) { return Buffer.from(prefixes[rva], 'hex').subarray(0,n); }}; }}}};
const Interceptor = {attach(target, handler) { hooks[target.name] = handler; }};
const Checksum = {compute(_kind, data) {
  return crypto.createHash('sha256').update(Buffer.from(data)).digest('hex');
}};
vm.runInNewContext(source, {Process, Interceptor, Checksum,
  ptr:value => value, send:row => events.push(row), Buffer});
function u(value) { return {toNumber() { return value; }}; }
function data(value) {
  const bytes = Buffer.from(JSON.stringify(value));
  return {isNull() { return false; },
    readVolatile(n) { return bytes.subarray(0,n); },
    readUtf8String(n) { return bytes.subarray(0,n).toString(); },
    length:bytes.length};
}
function struct(values) {
  return {add(n) { return {
    readPointer() { return values[n]; },
    readU64() { return u(values[n]); },
  }; }, readU64() { return u(values[0]); }};
}
const marker = 'FAKE_DESKTOP_PROMPT_' + 'd'.repeat(32);
const testId = '01a1a5ad-14de-7861-afe8-7670bfb99d3b';
const rootId = '01a1a5ad-14de-7861-afe8-7670bfb99d3c';
function body(threadId, item) {
  return {type:'response.create',model:'fixture',input:[item],
    client_metadata:threadId === null ? {} : {thread_id:threadId}};
}
function http(value) {
  const content = data(value);
  hooks['0xb117de0'].onEnter([null,null,null,
    struct({8:content,16:content.length})]);
}
function wss(value) {
  const content = data(value);
  const result = struct({0:0x1f,16:content,24:content.length});
  const scope = {};
  hooks['0x41e3330'].onEnter.call(scope,[result]);
  hooks['0x41e3330'].onLeave.call(scope,null);
}
http(body(testId,{type:'function_call_output',output:marker}));
wss(body(rootId,{type:'function_call_output',output:marker}));
http(body(null,{role:'user',content:marker}));
const rows = events.filter(row => row.kind === 'marker_metadata');
if (rows.length !== 3) throw Error('expected three marker metadata events');
if (rows[0].thread_id_match !== true || rows[0].function_output_marker !== true ||
    rows[0].user_content_marker !== false) throw Error('test thread attribution failed');
if (rows[1].thread_id_match !== false || rows[1].function_output_marker !== true)
  throw Error('sibling thread was misattributed');
if (rows[2].thread_id_match !== null || rows[2].parse_state !== 'missing_thread_id')
  throw Error('missing metadata was attributed');
if (events.some(row => 'thread_id' in row || 'payload_utf8' in row ||
    JSON.stringify(row).includes(marker))) throw Error('plaintext metadata leak');
"""
    result = subprocess.run([node, "-e", harness], input=source, text=True,
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
