"""Local deterministic text detectors and versioned exact registration index."""
from __future__ import annotations
import hashlib,json,re
from typing import Literal
from pathlib import Path
from pydantic import Field,model_validator
from .models import Record,DetectionFinding
from transpect_trace.guard.detection import detect_text
from transpect_trace.guard.policy import GuardPolicy,strings

VERSION='text-detectors/1'

class Registration(Record):
    registration_id: str=Field(min_length=1,max_length=128,pattern=r'^[A-Za-z0-9_.:-]+$')
    sensitivity: Literal['PUBLIC','INTERNAL','CONFIDENTIAL','SECRET','UNKNOWN']='CONFIDENTIAL'
    data_types: list[Literal['credential','private_key','source_code','personal_information','registered_text']]=Field(default_factory=lambda:['registered_text'])
    # Hash-only index. Chunk lengths allow exact matches without storing secrets.
    chunks: dict[int,list[str]]

    @model_validator(mode='after')
    def valid_chunks(self):
        if not self.chunks or len(self.chunks)>32:raise ValueError('invalid chunk length set')
        for size,hashes in self.chunks.items():
            if not 32<=size<=4096 or not 0<len(hashes)<=65536 or any(not re.fullmatch('[a-f0-9]{64}',h) for h in hashes):raise ValueError('invalid fingerprint')
        return self

class ContentIndex(Record):
    schema_version: Literal['transpect.protect.content-index/1.0']='transpect.protect.content-index/1.0'
    version: str=Field(min_length=1,max_length=127)
    registrations: list[Registration]=Field(default_factory=list,max_length=4096)

    @classmethod
    def register(cls,version,items,chunk_size=128):
        if not 32<=chunk_size<=4096:raise ValueError('chunk size out of bounds')
        rows=[]
        for registration_id,text,sensitivity,data_types in items:
            if sensitivity not in {'PUBLIC','INTERNAL','CONFIDENTIAL','SECRET','UNKNOWN'}:raise ValueError('invalid sensitivity')
            if len(text)<32:raise ValueError('registration requires 32 characters')
            chunks={}
            for offset in range(0,len(text),chunk_size):
                chunk=text[offset:offset+chunk_size]
                if len(chunk)>=32:chunks.setdefault(len(chunk),[]).append(hashlib.sha256(chunk.encode()).hexdigest())
            rows.append(Registration(registration_id=registration_id,sensitivity=sensitivity,data_types=data_types,chunks=chunks))
        return cls(version=version,registrations=rows)

    def matches(self,text):
        # Cache each length once. Bounded fields and maximum lengths are enforced by caller.
        lengths={size for r in self.registrations for size in r.chunks}
        if len(lengths)>32:raise ValueError('too many registration chunk lengths')
        if len(text)*sum(lengths)>32*1024*1024:raise ValueError('fingerprint work budget exceeded')
        hashes={size:{hashlib.sha256(text[p:p+size].encode()).hexdigest() for p in range(len(text)-size+1)} for size in lengths}
        for row in self.registrations:
            if any(set(wanted)&hashes[size] for size,wanted in row.chunks.items()):yield row

def detect(fields,index=None):
    findings=[]
    def add(rule,field,strength,sensitivity,types,severity,registration_id=None,index_version=None):
        findings.append(DetectionFinding(detector_version=VERSION,rule_id=rule,location=field.location,
            severity=severity,strength=strength,sensitivity=sensitivity,data_types=types,evidence_sha256=field.sha256,
            registration_id=registration_id,index_version=index_version))
    for field in fields:
        if not field.inspected:continue
        text=field.value if isinstance(field.value,str) else '\n'.join(strings(field.value))
        # Tool arguments often contain a JSON string inside the outer JSON.
        if field.kind=='tool_call' and isinstance(field.value,dict):
            arguments=field.value.get('arguments') or (field.value.get('function') or {}).get('arguments')
            if isinstance(arguments,str):
                try:text+='\n'+'\n'.join(strings(json.loads(arguments)))
                except (ValueError,TypeError):pass
        if len(text)>1024*1024:raise ValueError('detector text limit')
        normalized=re.sub(r'''["'](password|passwd|mysql_password|api_secret|private_key)["']\s*:''',r'\1=',text,flags=re.I)
        hits,_=detect_text(normalized,GuardPolicy(),[])
        for hit in sorted(set(hits)):
            add(hit,field,'exact' if hit=='PRIVATE_KEY_BLOCK' else 'contextual','SECRET',
                ['private_key'] if hit=='PRIVATE_KEY_BLOCK' else ['credential'],'critical')
        for match in re.finditer(r'''(?i)\b(?:api_key|access_token|client_secret)["']?\s*[:=]\s*["']?([^\s"',;]{16,})''',text):
            candidate=match.group(1)
            if not candidate.startswith(('${','<','TRANSPECT_PUBLIC')) and candidate.lower() not in {'your_api_key_here','example_api_key_here'}:
                add('CONTEXTUAL_API_CREDENTIAL',field,'contextual','SECRET',['credential'],'critical');break
        for rule,pattern,types in [
            ('JWT_SHAPE',r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b',['credential']),
            ('EMAIL_SHAPE',r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',['personal_information']),
            ('INTERNAL_IP',r'\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2})\b',[])]:
            if re.search(pattern,text):add(rule,field,'weak','UNKNOWN',types,'info')
        if index:
            for row in index.matches(text):add('REGISTERED_EXACT',field,'exact',row.sensitivity,row.data_types,
                'critical' if row.sensitivity in {'SECRET','CONFIDENTIAL'} else 'info',row.registration_id,index.version)
    return findings
