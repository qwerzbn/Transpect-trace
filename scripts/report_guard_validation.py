"""Aggregate explicitly selected fake-data experiments, retaining evidence hashes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from transpect_trace.guard import BINARY_SHA256, VERSION
from transpect_trace.guard.validation import validate_run


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs",nargs="+",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    reports=[];layouts=set();failures=[]
    for path in args.runs:
        source=path/"summary.json"
        summary=json.loads(source.read_text(encoding="utf-8"))
        report=validate_run(path)
        report["summary_sha256"]=hashlib.sha256(source.read_bytes()).hexdigest()
        reports.append(report)
        for sample in summary.get("experiments",[summary]):
            if sample.get("module_base"):layouts.add(sample["module_base"])
            if sample.get("manager_state",{}):
                etw=sample["manager_state"].get("etw",{})
                if etw.get("state")=="unavailable":failures.append(etw)
    outcomes={}
    for transport in ("http","wss"):
        items=[x for report in reports for x in report["capabilities"] if x["transport"]==transport]
        outcomes[transport]={name:("passed" if any(x[name]["status"]=="passed" for x in items) else "not_verified")
                  for name in ("observation","request_rejection","block_request_semantics",
                               "block_session_semantics","explicit_termination","native_migration","fault_handling")}
    result={"schema":"transpect.guard.validation-suite/1.0","version":VERSION,"binary_sha256":BINARY_SHA256,
            "validated_scope":["HTTP EncodedJsonBody","WSS response.create JSON","exec","--no-daemon TUI"],
            "capabilities":outcomes,"distinct_module_bases":sorted(layouts),
            "different_layouts_observed":len(layouts)>1,"runs":reports,
            "live_etw":{"status":"not_verified","unavailable_evidence":failures},
            "whole_system_protection":False,"wss_streaming_coverage":"not_claimed"}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"output":str(args.output.resolve()),"capabilities":outcomes,
                      "different_layouts_observed":len(layouts)>1,"live_etw":"not_verified"},indent=2))


if __name__=="__main__":main()
