"""Capability report from actual runtime/oracle evidence, not installed hooks."""
import json
from pathlib import Path
from . import BINARY_SHA256


def validate_run(path:Path) -> dict:
    summary=json.loads((path/"summary.json").read_text(encoding="utf-8"))
    runs=summary.get("experiments",[summary])
    result=[]
    for run in runs:
        audit=run.get("policy_events",[])
        origins=run.get("origin_connections",[])
        comparisons=[row for row in audit if row.get("kind")=="policy.decision" and
                     any(origin.get("payload_sha256")==row.get("content_sha256") for origin in origins)]
        constraints=bool(run.get("disk_unchanged") and run.get("frida_used") is False
                         and run.get("runtime")=="native" and run.get("proxy_used") is False
                         and run.get("tls_replaced") is False
                         and run.get("binary_sha256_before")==BINARY_SHA256
                         and run.get("binary_sha256_after")==BINARY_SHA256)
        tui=run.get("same_process_alive_after_denial") is True
        zero=run.get("blocked_sensitive_body_zero_at_oracle") is True
        error_path=run.get("native_error_displayed") is True or any(row.get("kind")=="native.outcome" for row in audit)
        if not error_path:
            # Older experiments have raw fake-client output rather than this
            # metadata bit. Read its actual native policy error as evidence.
            folder=path/run["transport"] if (path/run["transport"]).is_dir() else path
            error_path=any((folder/name).is_file() and b"request denied by local policy" in (folder/name).read_bytes()
                           for name in ("client.stdout.jsonl","client.stderr.log"))
        request_semantics=tui and zero and run.get("denied") is True and run.get("action")=="block_request" and run.get("subsequent_request_allowed") is True
        session_semantics=tui and zero and run.get("denied") is True and run.get("action")=="block_session" and run.get("subsequent_session_rejection") is True
        result.append({"transport":run["transport"],"constraints_passed":constraints,
                       "observation":{"status":"passed" if comparisons else "not_verified",
                                      "exact_payload_hash_matches":len(comparisons)},
                       "request_rejection":{"status":"passed" if constraints and zero and error_path and run.get("returncode")==1
                                             and not run.get("fixture_cleanup_terminated_child") else "not_verified"},
                       "block_request_semantics":{"status":"passed" if constraints and request_semantics else "not_verified"},
                       "block_session_semantics":{"status":"passed" if constraints and session_semantics else "not_verified"},
                       "explicit_termination":{"status":"passed" if constraints and zero and run.get("action")=="terminate_process" and run.get("returncode")==76 else "not_verified"},
                       "native_migration":{"status":"passed" if constraints and run.get("native_ready",tui) else "not_verified"},
                       "fault_handling":{"status":"passed" if constraints and zero and error_path and run.get("fault","none")!="none"
                                          and run.get("returncode")==1 and not run.get("fixture_cleanup_terminated_child") else "not_verified",
                                          "scenario":run.get("fault","none")},
                       "live_etw":{"status":"not_verified"},"wss_streaming_coverage":"not_claimed"})
    return {"schema":"transpect.guard.validation/1.0","run_directory":str(path.resolve()),
            "capabilities":result,"whole_system_protection":False,
            "confidence_is_taint_proof":False}
