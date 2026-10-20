"""Summarize explicitly selected experiments without copying payloads or credentials.

The manifest names evidence, not expected successes. Visibility is independently
checked against complete observation records and source hashes. This does not
certify default AI websites, full UI paths, or live ETW source attribution.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.validation import validate_run


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []


def visibility(root, entry):
    folder=root/entry["directory"]
    summary=read(folder/"summary.json")
    # Public launcher writes into its managed run; direct probes write in root.
    paths=list(folder.glob("managed/*/observations.jsonl")) or [folder/"observations.jsonl"]
    if len(paths)!=1:raise ValueError("Manifest must select one observation run")
    path=paths[0];rows=records(path)
    assessments=records(path.parent/"assessments.jsonl")
    gaps=records(path.parent/"coverage-gaps.jsonl")
    source=summary.get("source_decoded_hashes")
    if source is None:source=[r["payload_sha256"] for r in summary.get("origin_connections",[]) if r.get("payload_sha256")]
    origin=Counter(source)
    matched=Counter(row["content_sha256"] for row in rows if row.get("completeness")=="complete")
    metadata_only=bool(rows and assessments and all(row.get("can_enforce") is False for row in rows)
                       and all(row.get("can_enforce") is False and row.get("effective_action")=="audit" for row in assessments))
    passed=bool(summary.get("passed") is True and summary.get("can_enforce") is False
                and summary.get("actual_ai_channel_certified") is False and origin
                and all(matched[digest]>=count for digest,count in origin.items())
                and not summary.get("native_errors",summary.get("collector_errors",[])) and not gaps and metadata_only)
    alpn=entry.get("require_alpn")
    if alpn:passed=passed and all(r.get("alpn")==alpn for r in summary.get("origin_connections",[]))
    references=[folder/"summary.json",path,path.parent/"assessments.jsonl",path.parent/"source-relations.jsonl"]
    return {"target":entry["target"],"scope":entry["scope"],"status":"passed" if passed else "not_verified",
            "observer_dll_sha256":summary.get("observer_dll_sha256"),
            "origin_payloads":len(source),"complete_observations":sum(matched.values()),
            "source_hashes_matched":all(matched[h]>=n for h,n in origin.items()) and bool(origin),
            "coverage_gaps":len(gaps),"observation_only_verified":metadata_only,
            "can_enforce":False,"actual_ai_channel_certified":False,
            "evidence":[{"path":str(p.relative_to(root)),"sha256":sha(p)} for p in references if p.is_file()]}


def build_report(root, manifest):
    visible=[visibility(root,item) for item in manifest.get("visibility",[])]
    guard=[]
    coexist=[]
    for directory in manifest.get("guard",[]):
        folder=root/directory
        summary=read(folder/"summary.json")
        checked=validate_run(folder)
        guard.append({"directory":directory,"summary_sha256":sha(folder/"summary.json"),"capabilities":checked["capabilities"]})
        for sample in summary.get("experiments",[summary]):
            if "observer_conflict_refused" in sample:
                coexist.append({"transport":sample["transport"],"observer_conflict_refused":sample["observer_conflict_refused"],
                                "guard_still_rejected":sample.get("blocked_sensitive_body_zero_at_oracle") is True
                                    and sample.get("returncode")==1 and sample.get("disk_unchanged") is True})
    control={}
    for transport in ("http","wss"):
        capabilities=[item for run in guard for item in run["capabilities"] if item["transport"]==transport]
        control[transport]={name:("passed" if any(item[name]["status"]=="passed" for item in capabilities) else "not_verified")
                            for name in ("observation","request_rejection","block_request_semantics","block_session_semantics",
                                         "explicit_termination","native_migration","fault_handling")}
    limitations=[]
    for entry in manifest.get("limitations",[]):
        path=root/entry["summary"]
        value=read(path)
        limitations.append({"target":entry["target"],"status":"not_verified","reason":entry["reason"],
                            "origin_delivery":value.get("origin_delivery_passed"),
                            "plaintext_validation":value.get("application_plaintext_capture_passed",value.get("plaintext_validation_passed")),
                            "evidence":{"path":entry["summary"],"sha256":sha(path)}})
    etw=[]
    for item in manifest.get("visibility",[]):
        directory=root/item["directory"]
        for path in directory.glob("managed/*/status.json"):
            state=read(path).get("etw",{})
            etw.append({"path":str(path.relative_to(root)),"sha256":sha(path),"state":state.get("state","unknown"),
                        "win32_error":state.get("details",{}).get("win32_error")})
    return {"schema_version":"transpect.observe.validation-suite/1.0",
            "visibility":visible,"unverified_visibility":limitations,
            "control":{"guard_binary_sha256":BINARY_SHA256,"guard":control,"guard_evidence":guard,
                       "observation_adapters":{"can_enforce":False,"blocked_requests":0},"hook_coexistence":coexist},
            "source_evidence":{"status":"not_verified","live_confidence":"Unknown","etw":etw,
                               "byte_level_taint_proof":False,"simulated_rule_tests_are_live_evidence":False},
            "actual_ai_channel_certified":False,"complete_wss_streaming":False,"whole_system_protection":False,
            "notes":["Synthetic source matches certify only the stated fixture/backend paths.",
                     "Serialization observations are not source receipt evidence without independent hash comparison.",
                     "Failure to observe is not evidence of no egress."]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest",type=Path,required=True,help="Explicit local experiment manifest; raw historical evidence is not distributed.")
    parser.add_argument("--root",type=Path,default=Path.cwd())
    parser.add_argument("--output",type=Path,default=Path("runs/observe-validation/20261015/report.json"))
    args=parser.parse_args()
    result=build_report(args.root.resolve(),read(args.manifest))
    result["manifest_sha256"]=sha(args.manifest)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"output":str(args.output.resolve()),"visibility":{x["target"]:x["status"] for x in result["visibility"]},
                      "unverified":[x["target"] for x in result["unverified_visibility"]],
                      "guard":result["control"]["guard"],"live_source_evidence":result["source_evidence"]["status"]},indent=2))


if __name__=="__main__":main()
