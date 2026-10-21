import json
from pathlib import Path

import pytest

from transpect_trace.guard.baseline import inspect_binary
from transpect_trace.guard.evidence import grade_source
from transpect_trace.guard.etw import EtwIndex,PROCESS,FILE
from transpect_trace.guard.policy import GuardPolicy,GuardRequest,Marker,PolicyEngine
from transpect_trace.guard.wire import decode_frame,encode_frame
from transpect_trace.guard.native import cli_mode


def request(text="hello",session="session",protocol="http",**fields):
    body={"model":"fixture","input":[{"role":"user","content":[{"type":"input_text","text":text}]}]}
    if protocol=="wss":body["type"]="response.create"
    return GuardRequest.model_validate({"schema":"transpect.guard.request/1.0","request_id":"request",
        "guard_session_id":session,"pid":12,"tid":34,"kind":"model.request","protocol":protocol,
        "destination":None,"completeness":"complete","payload_utf8":json.dumps(body),**fields})


@pytest.mark.parametrize("text,rule",[
    ("mysql_password=fixture-only-password","CONFIG_CREDENTIAL"),
    ("-----BEGIN PRIVATE KEY-----\nfake-key-material\n-----END PRIVATE KEY-----","PRIVATE_KEY_BLOCK"),
    ("aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key="+"A"*40,"AWS_CREDENTIAL_PAIR"),
])
def test_credentials_block_and_audit_is_redacted(text,rule):
    decision,audit=PolicyEngine(GuardPolicy()).evaluate(request(text))
    assert decision.decision=="deny" and decision.action=="block_request"
    assert rule in audit["matched_rule_ids"]
    assert text not in json.dumps(audit)
    assert audit["action_execution"]=="not_yet_confirmed"


@pytest.mark.parametrize("text",["hello","AKIAABCDEFGHIJKLMNOP","password=${PASSWORD}",
                                  "password=********","A public source code example: print('hello')"])
def test_plain_code_and_unpaired_identifiers_are_not_blanket_blocked(text):
    assert PolicyEngine(GuardPolicy()).evaluate(request(text))[0].decision=="allow"


def test_escaped_tool_result_is_checked_without_file_provenance():
    body={"model":"fixture","input":[{"type":"function_call_output","call_id":"c",
        "output":"mysql_password=fixture-only-secret"}]}
    decision,audit=PolicyEngine(GuardPolicy()).evaluate(request(payload_utf8=json.dumps(body)))
    assert decision.decision=="deny"
    assert audit["source_confidence"]=="Unknown" and not audit["candidate_source_paths"]


def test_block_request_does_not_latch_unrelated_request():
    engine=PolicyEngine(GuardPolicy())
    assert engine.evaluate(request("password=fixture-only-secret"))[0].decision=="deny"
    assert engine.evaluate(request("a genuinely unrelated clean request"))[0].decision=="allow"


def test_block_session_persists_but_other_session_is_allowed():
    engine=PolicyEngine(GuardPolicy(deny_action="block_session"))
    assert engine.evaluate(request("password=fixture-only-secret"))[0].action=="block_session"
    assert engine.evaluate(request("clean"))[0].reason=="SESSION_BLOCKED"
    assert engine.evaluate(request("clean",session="different"))[0].decision=="allow"


def test_termination_is_explicit_and_unknown_never_escalates():
    engine=PolicyEngine(GuardPolicy(deny_action="terminate_process"))
    assert engine.evaluate(request("password=fixture-only-secret"))[0].action=="terminate_process"
    assert engine.evaluate(request(completeness="partial"))[0].action=="block_request"
    assert engine.evaluate(request(payload_utf8="not JSON"))[0].action=="block_request"


def test_registration_snapshot_matching_is_not_a_read_proof(tmp_path):
    file=tmp_path/"secret.txt";text="registered-confidential-fixture-content-"*10;file.write_text(text)
    engine=PolicyEngine(GuardPolicy(registered_files=[file],credential_rules=False))
    decision,audit=engine.evaluate(request(text))
    assert decision.decision=="deny" and audit["candidate_source_paths"]==[str(file)]
    assert audit["source_confidence"]=="Unknown"


def test_legacy_gateway_marker_policy_remains_compatible():
    policy=GuardPolicy.load(Path("tests/fixtures/exfiltration/policy.json"))
    marker=next(m for m in policy.content_markers if m.source_path not in policy.allowed_source_paths)
    # The adapter cannot invent an upstream host: explicit upstream restrictions
    # cause unknown rather than a silently accepted destination.
    assert PolicyEngine(policy).evaluate(request(marker.value))[0].decision!="allow"


def test_unknown_destination_and_wss_type_are_not_certified():
    engine=PolicyEngine(GuardPolicy(allowed_upstreams=["example.test"]))
    assert engine.evaluate(request())[0].reason=="DESTINATION_UNAVAILABLE"
    body=json.dumps({"model":"fixture","input":"hello","type":"response.interrupt"})
    assert PolicyEngine(GuardPolicy()).evaluate(request(protocol="wss",payload_utf8=body))[0].reason=="UNSUPPORTED_CONTENT"


def test_wire_is_utf8_json_and_rejects_truncation():
    value={"text":"中文\ncontext","request_id":"r"}
    frame=encode_frame(value)
    assert decode_frame(frame)==value
    for invalid in [frame[:-1],frame+b"x",b"\0\0\0\0",b"{}"]:
        with pytest.raises(ValueError):decode_frame(invalid)


@pytest.mark.parametrize("extra,grade",[
    ({},"High"),({"paths":["one","two"]},"Medium"),
    ({"dropped_events":1},"Medium"),({"snapshot_current":False},"Medium"),
    ({"reliable_identity":False,"time_related":True},"Low"),
    ({"file_event_ids":[],"time_related":False},"Unknown"),
])
def test_source_confidence_is_evidence_strength_not_taint(extra,grade):
    fields=dict(paths=["one"],file_event_ids=["f"],process_event_ids=["p"],
                content_event_ids=["c"],reliable_identity=True)
    fields.update(extra);evidence=grade_source(**fields)
    assert evidence.confidence==grade and evidence.byte_level_taint_proof is False


def test_unsupported_binary_is_not_executed(tmp_path,monkeypatch):
    file=tmp_path/"fake.exe";file.write_bytes(b"MZ"+b"\0"*100)
    monkeypatch.setattr("subprocess.run",lambda *a,**k:pytest.fail("unsupported image executed"))
    assert inspect_binary(file)["supported"] is False


def test_etw_filters_other_process_and_marks_access_not_contents():
    index=EtwIndex(12,100)
    other={"kind":"etw.event","provider":FILE,"task":"Read","sequence":1,"timestamp_qpc":5,
           "header_pid":99,"header_tid":2,"opcode":67,"properties":{"FileName":"other.txt"}}
    assert index.consume(other) is None
    own={**other,"header_pid":12,"properties":{"FileName":"registered.txt"}}
    row=index.consume(own)
    assert row["normalized_kind"]=="system.file.read"
    assert row["read_success"]=="not_inferred_from_access_event"


def test_child_read_can_support_source_and_later_reads_cannot():
    index=EtwIndex(12,100)
    def event(provider,task,seq,tick,pid,props,opcode=1):
        return {"kind":"etw.event","provider":provider,"task":task,"sequence":seq,
                "timestamp_qpc":tick,"header_pid":pid,"header_tid":2,"opcode":opcode,"properties":props}
    index.consume(event(PROCESS,"ProcessStart",1,10,20,{"ProcessID":"20","ParentProcessID":"12","CreateTime":"123"}))
    index.consume(event(FILE,"Read",2,20,20,{"FileName":"C:\\fixture\\secret.txt"},67))
    decision={"pid":12,"request_id":"r","candidate_source_paths":["c:/fixture/secret.txt"],
              "captured_qpc":30,"qpc_frequency":10_000_000}
    assert index.correlate(decision)["source_relation"]["confidence"]=="High"
    decision["captured_qpc"]=15
    assert index.correlate(decision)["source_relation"]["confidence"]=="Unknown"


def test_reused_root_pid_does_not_join_old_run():
    index=EtwIndex(12,100)
    row={"kind":"etw.event","provider":PROCESS,"task":"ProcessStop","sequence":1,
         "timestamp_qpc":20,"header_pid":12,"header_tid":2,"opcode":2,"properties":{"ProcessID":"12"}}
    index.consume(row)
    assert index.consume({**row,"task":"ProcessStart","sequence":2,"timestamp_qpc":40,"opcode":1}) is None


def test_binary_attachment_is_unknown_not_a_false_allow():
    body=json.dumps({"model":"fixture","input":[{"type":"input_file","file_id":"external-upload"}]})
    decision,_=PolicyEngine(GuardPolicy()).evaluate(request(payload_utf8=body))
    assert decision.decision=="unknown" and decision.action=="block_request"


@pytest.mark.parametrize("args,mode",[
    (["codex.exe","exec","Explain app-server"],"exec"),
    (["codex.exe","-c","x=1","app-server"],"unsupported"),
    (["codex.exe","--model","gpt","--no-daemon"],"tui_no_daemon"),
    (["codex.exe","--model","gpt"],"unsupported"),
    (["codex.exe","exec-server"],"unsupported"),
])
def test_cli_scope_does_not_parse_prompt_text_as_a_subcommand(args,mode):
    assert cli_mode(args)==mode


def test_tui_scope_accepts_known_flag_values_but_rejects_initial_prompt_and_app_server():
    assert cli_mode(['codex.exe','--no-daemon','--sandbox','read-only','--ask-for-approval','never'])=='tui_no_daemon'
    assert cli_mode(['codex.exe','--no-daemon','--sandbox','read-only','initial user prompt'])=='unsupported'
    assert cli_mode(['codex.exe','--no-daemon','app-server'])=='unsupported'
    assert cli_mode(['codex.exe','--no-daemon','--','INITIAL_SECRET_PROMPT'])=='unsupported'
    assert cli_mode(['codex.exe','--no-daemon','--','--initial-literal-prompt'])=='unsupported'


def test_external_engine_audit_drops_raw_payload_and_unknown_records():
    from transpect_trace.guard.external import audit_metadata
    assert audit_metadata({"kind":"policy.decision","request_id":"r","payload_utf8":"secret",
                           "authorization":"secret","decision":"deny"})=={
                               "kind":"policy.decision","request_id":"r","decision":"deny"}
    assert audit_metadata({"kind":"raw.request","body":"secret"}) is None
    assert audit_metadata(["not an object"]) is None


def test_recent_file_evidence_without_content_match_cannot_earn_high():
    index=EtwIndex(12,100)
    index.consume({"kind":"etw.event","provider":FILE,"task":"Read","sequence":1,"timestamp_qpc":20,
                   "header_pid":12,"header_tid":2,"opcode":67,"properties":{"FileName":"candidate.txt"}})
    relation=index.correlate({"pid":12,"request_id":"r","captured_qpc":30,"qpc_frequency":10,
                              "candidate_source_paths":[]})["source_relation"]
    assert relation["confidence"]=="Medium" and "candidate.txt" in relation["candidate_source_paths"]
    assert relation["byte_level_taint_proof"] is False


def test_validation_does_not_certify_a_cleanup_kill_or_missing_denial(tmp_path):
    from transpect_trace.guard import BINARY_SHA256
    from transpect_trace.guard.validation import validate_run
    summary={"transport":"http","runtime":"native","frida_used":False,"proxy_used":False,
             "tls_replaced":False,"binary_sha256_before":BINARY_SHA256,"binary_sha256_after":BINARY_SHA256,
             "disk_unchanged":True,"action":"block_request","returncode":1,"native_ready":True,
             "blocked_sensitive_body_zero_at_oracle":True,"fixture_cleanup_terminated_child":True,
             "same_process_alive_after_denial":True,"subsequent_request_allowed":True,"denied":False}
    (tmp_path/"summary.json").write_text(json.dumps(summary))
    result=validate_run(tmp_path)["capabilities"][0]
    assert result["request_rejection"]["status"]=="not_verified"
    assert result["block_request_semantics"]["status"]=="not_verified"


def test_child_pid_reuse_without_stop_does_not_keep_old_lineage():
    index=EtwIndex(12,100)
    event={"kind":"etw.event","provider":PROCESS,"task":"ProcessStart","sequence":1,
           "timestamp_qpc":10,"header_pid":20,"header_tid":2,"opcode":1,
           "properties":{"ProcessID":"20","ParentProcessID":"12","CreateTime":"123"}}
    assert index.consume(event) is not None
    assert index.consume({**event,"sequence":2,"timestamp_qpc":40,
                          "properties":{"ProcessID":"20","ParentProcessID":"99","CreateTime":"456"}}) is None
    assert 20 not in index.processes


def test_missing_child_creation_time_downgrades_content_relation():
    index=EtwIndex(12,100)
    index.consume({"kind":"etw.event","provider":PROCESS,"task":"ProcessStart","sequence":1,
                   "timestamp_qpc":10,"header_pid":20,"header_tid":2,"opcode":1,
                   "properties":{"ProcessID":"20","ParentProcessID":"12"}})
    index.consume({"kind":"etw.event","provider":FILE,"task":"Read","sequence":2,
                   "timestamp_qpc":20,"header_pid":20,"header_tid":2,"opcode":67,
                   "properties":{"FileName":"candidate.txt"}})
    relation=index.correlate({"pid":12,"request_id":"r","captured_qpc":30,"qpc_frequency":10,
                              "candidate_source_paths":["candidate.txt"]})["source_relation"]
    assert relation["confidence"]=="Low"
