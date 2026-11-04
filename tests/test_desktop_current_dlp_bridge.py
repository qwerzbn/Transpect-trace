"""Synthetic-only current desktop bridge attribution and archive safety."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from probe_desktop_current_dlp_bridge import (  # noqa: E402
    AGENT, DENIAL_ABI_JS, DUPLICATE_SCAN_JS, FAKE_SECRET, SYNTHETIC_REGISTRATION_SHA256,
    await_and_post_policy, classify_target_evidence, evaluate_target,
    require_opt_in, safe_event, synthetic_source,
    validate_target_body, write_synthetic_registration,
)
from probe_desktop_current_thread_metadata import TEST_THREAD_ID  # noqa: E402
from transpect_trace.protect.archive import EncryptedRequestArchive  # noqa: E402
from transpect_trace.protect.desktop_bridge import DesktopDLPBridge  # noqa: E402


MARKER = "FAKE_DESKTOP_PROMPT_" + "a" * 32
OTHER_THREAD = "10000000-0000-4000-8000-000000000000"


def body(*, protocol="wss", thread_id=TEST_THREAD_ID, source="function_call_output",
         content=None):
    content = content or f"Synthetic marker {MARKER} password=FakeSecret12345"
    item = ({"type": "function_call_output", "output": content}
            if source == "function_call_output" else
            {"type": "message", "role": "user", "content": content})
    value = {"model": "fixture", "stream": True, "input": [item],
             "client_metadata": {"thread_id": thread_id}}
    if protocol == "wss":
        value = {"type": "response.create", **value}
    return json.dumps(value, separators=(",", ":")).encode()


def test_only_exact_thread_and_typed_input_can_be_archived(tmp_path):
    assert validate_target_body(body(), "wss", MARKER) == "function_call_output"
    assert validate_target_body(body(), "wss", MARKER,
                                require_secret=True) == "function_call_output"
    assert validate_target_body(body(protocol="http", source="user"), "http", MARKER) == "user_content"
    with pytest.raises(ValueError, match="not in typed test input"):
        validate_target_body(body(content=f"Synthetic marker {MARKER}"), "wss", MARKER,
                             require_secret=True)
    archive = EncryptedRequestArchive(tmp_path / "archive")
    root = tmp_path / "references"
    assert write_synthetic_registration(root) == SYNTHETIC_REGISTRATION_SHA256
    bridge = DesktopDLPBridge.from_registration({"pid": 123}, archive, root)
    raw = body()
    result = evaluate_target(bridge, archive, raw, protocol="wss",
                             source="function_call_output", marker=MARKER,
                             backend_pid=123, claimed_bytes=len(raw),
                             claimed_sha256=hashlib.sha256(raw).hexdigest())
    assert result["action"] == "deny"
    assert "ASSIGNED_SECRET" in result["rule_ids"]
    assert result["archive_readback_matches"] is True
    count = len(list((tmp_path / "archive").glob("*.enc")))
    with pytest.raises(ValueError, match="not the pinned test chat"):
        evaluate_target(bridge, archive, body(thread_id=OTHER_THREAD), protocol="wss",
                        source="function_call_output", marker=MARKER,
                        backend_pid=123, claimed_bytes=len(body(thread_id=OTHER_THREAD)),
                        claimed_sha256=hashlib.sha256(body(thread_id=OTHER_THREAD)).hexdigest())
    assert len(list((tmp_path / "archive").glob("*.enc"))) == count


@pytest.mark.parametrize("raw", [
    b'{"type":"response.create","model":"fixture","input":[{"role":"user","content":"FAKE_DESKTOP_PROMPT_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"client_metadata":{"thread_id":"01a1a5ad-14de-7861-afe8-7670bfb99d3b"},"client_metadata":{"thread_id":"01a1a5ad-14de-7861-afe8-7670bfb99d3b"}}',
    b'{"type":"response.create","model":"fixture","input":[{"role":"user","content":"FAKE_DESKTOP_PROMPT_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"client_metadata":{"thread_id":"01a1a5ad-14de-7861-afe8-7670bfb99d3b","thread\\u005fid":"01a1a5ad-14de-7861-afe8-7670bfb99d3b"}}',
])
def test_duplicate_structural_keys_rejected_before_archive(raw):
    with pytest.raises(ValueError, match="duplicate"):
        validate_target_body(raw, "wss", MARKER)


def test_marker_outside_typed_input_and_other_thread_rejected():
    with pytest.raises(ValueError, match="not the pinned test chat"):
        validate_target_body(body(thread_id=OTHER_THREAD), "wss", MARKER)
    value = json.loads(body())
    value["input"] = [{"role": "assistant", "content": MARKER}]
    with pytest.raises(ValueError, match="not in typed test input"):
        validate_target_body(json.dumps(value).encode(), "wss", MARKER)


def test_frida_lexical_scan_rejects_duplicate_and_escaped_keys():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for Frida JavaScript lexical test")
    samples = [
        '{"client_metadata":{"thread_id":"a"}}',
        '{"client_metadata":{},"client_metadata":{}}',
        '{"client_metadata":{"thread_id":"a","thread\\u005fid":"b"}}',
        '{"input":[{"role":"user","role":"assistant"}]}',
    ]
    source = DUPLICATE_SCAN_JS + "\nconsole.log(JSON.stringify(JSON.parse(process.argv[1]).map(s => {try {parseUniqueJson(s); return 'ok'} catch(e) {return 'reject'}})))"
    completed = subprocess.run([node, "-e", source, json.dumps(samples)],
                               capture_output=True, text=True, timeout=10, check=True)
    assert json.loads(completed.stdout) == ["ok", "reject", "reject", "reject"]


def test_agent_config_and_report_events_never_include_thread_or_body():
    adapter = {"hooks": [
        {"layer": "http_encoded_body_preparation", "rva": "0xb117de0",
         "entry_prefix_hex": "5541574156415541545657534881ece8"},
        {"layer": "wss_request_serialization", "rva": "0x41e3330",
         "entry_prefix_hex": "5541574156415541545657534881ecd8"},
    ]}
    source = synthetic_source(adapter, MARKER)
    assert "__CONFIG__" not in source and "__DUPLICATE_SCAN__" not in source
    assert "__DENIAL_ABI__" not in source
    assert "parseUniqueJson" in source and "target_decision_" in source
    event = safe_event({"kind": "target_denied", "hook": "model.http",
                        "request_id": "1", "bytes": 123, "sha256": "a" * 64,
                        "thread_id": TEST_THREAD_ID, "payload_utf8": "PRIVATE"})
    assert event is not None and TEST_THREAD_ID not in str(event) and "PRIVATE" not in str(event)
    assert safe_event({"kind": "target_body", "payload_utf8": "PRIVATE"}) is None


def test_explicit_opt_in_required():
    class Args:
        active_current_client = True
        synthetic_only = True
        accept_interruption = False
        seconds = 20
        case = "secret"
    with pytest.raises(ValueError, match="flags are required"):
        require_opt_in(Args())


def test_frida_classification_does_not_copy_other_chat_body():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for Frida JavaScript classification test")
    adapter = {"hooks": [
        {"layer": "http_encoded_body_preparation", "rva": "0xb117de0",
         "entry_prefix_hex": "5541574156415541545657534881ece8"},
        {"layer": "wss_request_serialization", "rva": "0x41e3330",
         "entry_prefix_hex": "5541574156415541545657534881ecd8"},
    ]}
    prefix = synthetic_source(adapter, MARKER, require_secret=True).split(
        "const kernel = Process.getModuleByName", 1)[0]
    js = ("global.Checksum={compute:()=>\"a\".repeat(64)};\n" + prefix +
          "\nconst counter={n:0};function pointer(text){return {isNull:()=>false,"
          "readUtf8String:()=>text,readVolatile:()=>{counter.n++;return Buffer.from(text)}};}"
          "const inputs=JSON.parse(process.argv[1]);"
          "const run=inputs.map(s=>{const prior=counter.n;const x=classify(pointer(s),"
          "Buffer.byteLength(s),'wss');return {state:x.state,source:x.source||null,"
          "copied:counter.n-prior}});console.log(JSON.stringify(run));")
    samples = [body(thread_id=OTHER_THREAD).decode(), body().decode(),
               body(content=f"Synthetic marker {MARKER}").decode()]
    completed = subprocess.run([node, "-e", js, json.dumps(samples)],
                               capture_output=True, text=True, timeout=10, check=True)
    assert json.loads(completed.stdout) == [
        {"state": "other_chat", "source": None, "copied": 0},
        {"state": "target", "source": "function_call_output", "copied": 1},
        {"state": "test_chat_without_marker", "source": None, "copied": 0},
    ]


def test_frida_denial_abi_drops_http_headers_and_returns_rust_errors():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for Frida JavaScript ABI test")
    js = ("const ptr=x=>x;" + DENIAL_ABI_JS +
          "let dropped=0;const values={};const result={writeU64:v=>values[0]=v,"
          "add:n=>({writeU64:v=>values[n]=v,writePointer:v=>values[n]=v})};"
          "const headers={isNull:()=>false};"
          "constructHttpDenial(result,headers,()=>{dropped++});"
          "const w={};const wresult={writeU64:v=>w[0]=v,"
          "add:n=>({writeU64:v=>w[n]=v})};let written=0;"
          "constructWssDenial(wresult,{writeByteArray:b=>written=b.length},100,120,"
          "()=>{throw new Error('fail stop')});"
          "console.log(JSON.stringify({dropped,http:values,wss:w,written}));")
    completed = subprocess.run([node, "-e", js], capture_output=True,
                               text=True, timeout=10, check=True)
    result = json.loads(completed.stdout)
    assert result["dropped"] == 1
    assert result["http"] == {"0": 3, "8": 0, "16": 1, "24": 0}
    assert result["wss"]["0"] == 13 and result["wss"]["24"] == result["written"] > 0


def test_policy_timeout_replies_deny_and_reply_failure_stops_backend():
    from concurrent.futures import TimeoutError as FutureTimeout

    class TimeoutFuture:
        def result(self, timeout):
            assert timeout > 0
            raise FutureTimeout()

    class Script:
        def __init__(self, fail=False):
            self.fail = fail
            self.messages = []

        def post(self, message):
            if self.fail:
                raise OSError("detached")
            self.messages.append(message)

    stopped = []
    script = Script()
    result, replied, stop_result = await_and_post_policy(
        TimeoutFuture(), script, "1", lambda: stopped.append(True) or True)
    assert result == {"action": "deny", "reason": "POLICY_TIMEOUT"}
    assert replied and stop_result is None and not stopped
    assert script.messages == [{"type": "target_decision_1", "payload": {"action": "deny"}}]
    result, replied, stop_result = await_and_post_policy(
        TimeoutFuture(), Script(fail=True), "2", lambda: stopped.append(True) or True)
    assert not replied and stop_result is True and stopped == [True]
    assert result["action"] == "deny" and result["reason"] == "DECISION_REPLY_FAILED"


def test_frida_blocking_reply_wait_and_exception_fail_stop():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for Frida blocking-reply test")
    decide = "let requestNumber = 0;" + AGENT.split(
        "let requestNumber = 0;", 1)[1].split("const base = Process.mainModule.base;", 1)[0]
    js = ("let sent=0,waited=0,stopped=0,fail=false;"
          "const send=()=>{sent++};const failStop=()=>{stopped++;throw Error('stopped')};"
          "function recv(type,callback){return {wait:()=>{waited++;"
          "if(fail)throw Error('disconnected');callback({payload:{action:'allow'}})}}};"
          + decide +
          "const first=decide('model.wss',{source:'function_call_output',bytes:9,"
          "sha256:'a'.repeat(64),body:new Uint8Array(9)});fail=true;"
          "let threw=false;try{decide('model.http',{source:'user_content',bytes:9,"
          "sha256:'b'.repeat(64),body:new Uint8Array(9)})}catch(_){threw=true}"
          "console.log(JSON.stringify({first,sent,waited,stopped,threw}));")
    completed = subprocess.run([node, "-e", js], capture_output=True,
                               text=True, timeout=10, check=True)
    result = json.loads(completed.stdout)
    assert result == {"first": {"action": "allow", "request_id": "1"},
                      "sent": 2, "waited": 2, "stopped": 1, "threw": True}


def test_report_requires_every_fallback_decision_and_native_event_to_deny():
    hooks = [{"kind": "hook_installed", "hook": hook}
             for hook in ("model.wss", "model.http")] + [{"kind": "probe_ready"}]
    decisions = [
        {"request_id": "1", "hook": "model.wss", "bytes": 100, "sha256": "a" * 64,
         "action": "deny", "reason": "SENSITIVE_OR_UNINSPECTABLE_CONTENT",
         "rule_ids": ["ASSIGNED_SECRET"], "archive_readback_matches": True,
         "archive_record_created": True},
        {"request_id": "2", "hook": "model.http", "bytes": 101, "sha256": "b" * 64,
         "action": "deny", "reason": "SENSITIVE_OR_UNINSPECTABLE_CONTENT",
         "rule_ids": ["ASSIGNED_SECRET"], "archive_readback_matches": True,
         "archive_record_created": True},
    ]
    events = [{"kind": "target_denied", "request_id": d["request_id"],
               "hook": d["hook"], "bytes": d["bytes"],
               "sha256": d["sha256"]} for d in decisions]
    complete = classify_target_evidence(hooks + events, decisions, [],
                                        case="secret", unresolved=0)
    assert complete["status"] == "archived_synthetic_secret_rule_denial_without_origin_proof"
    assert complete["completed_dlp_denial_events"] == 2
    mixed_decisions = [decisions[0], {**decisions[1], "action": "allow",
                                        "reason": "REQUIRED_CHECKS_COMPLETE", "rule_ids": []}]
    mixed_events = [events[0], {**events[1], "kind": "target_allowed"}]
    assert classify_target_evidence(hooks + mixed_events, mixed_decisions, [],
                                    case="secret", unresolved=0)["status"] == "unvalidated_mixed_target_decisions"
    orphan = {**events[0], "request_id": "3"}
    assert classify_target_evidence(hooks + events + [orphan], decisions, [],
                                    case="secret", unresolved=0)["status"] == "unvalidated_probe_or_target_chain"
    assert classify_target_evidence(hooks + events[:1], decisions, [],
                                    case="secret", unresolved=0)["status"] == "unvalidated_probe_or_target_chain"
    assert classify_target_evidence(hooks + [events[0], {**events[1], "bytes": 102}],
                                    decisions, [], case="secret", unresolved=0)["status"] == "unvalidated_probe_or_target_chain"
    assert classify_target_evidence(hooks[:-1] + events, decisions, [],
                                    case="secret", unresolved=0)["status"] == "unvalidated_probe_or_target_chain"
    assert classify_target_evidence(hooks + events, decisions, [],
                                    case="secret", unresolved=1)["status"] == "unvalidated_probe_or_target_chain"


def test_report_does_not_call_timeout_deny_a_completed_dlp_result():
    hooks = [{"kind": "hook_installed", "hook": hook}
             for hook in ("model.wss", "model.http")] + [{"kind": "probe_ready"}]
    decision = {"request_id": "1", "hook": "model.http", "bytes": 100,
                "sha256": "a" * 64,
                "action": "deny", "reason": "POLICY_TIMEOUT", "rule_ids": [],
                "archive_readback_matches": False, "archive_record_created": False}
    event = {"kind": "target_denied", "request_id": "1",
             "hook": "model.http", "bytes": 100, "sha256": "a" * 64}
    report = classify_target_evidence(hooks + [event], [decision], [],
                                      case="secret", unresolved=0)
    assert report["status"] == "attributed_target_fail_closed_without_complete_dlp_proof"
    assert report["completed_dlp_denial_events"] == 0
