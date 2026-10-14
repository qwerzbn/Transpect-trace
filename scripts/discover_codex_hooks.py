"""Reproduce fixed-build candidate discovery; static hits are NOT capabilities."""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct

from transpect_trace.guard import BINARY_SHA256

ANCHORS={
    "request_construction":"responses_websocket.stream_request",
    "serialization":"failed to encode websocket request",
    "http_body_preparation":"Compressed request body with zstd",
    "http_trace_body":"<raw body:",
    "received_event_counterexample":"responses websocket timing",
}


def discover(binary:Path):
    data=binary.read_bytes()
    if hashlib.sha256(data).hexdigest()!=BINARY_SHA256:raise ValueError("fixed baseline mismatch")
    pe=struct.unpack_from("<I",data,60)[0];opt=pe+24
    count=struct.unpack_from("<H",data,pe+6)[0];option_bytes=struct.unpack_from("<H",data,pe+20)[0]
    sections=[]
    for i in range(count):
        offset=opt+option_bytes+i*40;virtual_size,rva,raw_bytes,raw_offset=struct.unpack_from("<IIII",data,offset+8)
        sections.append((data[offset:offset+8].rstrip(b"\0").decode(),rva,virtual_size,raw_bytes,raw_offset))
    text=next(s for s in sections if s[0]==".text");ro=next(s for s in sections if s[0]==".rdata")
    unwind=next(s for s in sections if s[0]==".pdata")
    functions=list(struct.iter_unpack("<III",data[unwind[4]:unwind[4]+unwind[2]//12*12]))
    starts=[x[0] for x in functions]
    anchors=[]
    for layer,phrase in ANCHORS.items():
        position=data.find(phrase.encode())
        if position>=0:anchors.append((ro[1]+position-ro[4],layer,phrase))
    hits=[]
    # Compiler format programs can point just before the literal text.
    pattern=re.compile(rb"[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....",re.DOTALL)
    for match in pattern.finditer(data,text[4],text[4]+text[3]):
        instruction=text[1]+match.start()-text[4]
        target=instruction+7+struct.unpack_from("<i",data,match.start()+3)[0]
        for anchor,layer,phrase in anchors:
            if anchor-32<=target<anchor+len(phrase):
                index=bisect.bisect_right(starts,instruction)-1
                if index<0 or instruction>=functions[index][1]:continue
                start,end=functions[index][:2]
                raw=text[4]+start-text[1]
                hits.append({"layer":layer,"anchor":phrase,"xref_rva":hex(instruction),
                             "function_rva":hex(start),"function_end_rva":hex(end),
                             "entry_prefix":data[raw:raw+16].hex(),"status":"static_candidate_only"})
    return {"binary_sha256":BINARY_SHA256,"method":"RIP-relative LEA + PE unwind ranges",
            "candidates":hits,"pdb_required":False,"protection_verified":False,
            "low_layer":{"schannel":"requires_dynamic_validation","winsock":"network_evidence_not_prompt"}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex",type=Path,default=shutil.which("codex"))
    parser.add_argument("--output",type=Path,default=Path("runs/guard-discovery/candidates.json"))
    args=parser.parse_args();result=discover(args.codex)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":main()
