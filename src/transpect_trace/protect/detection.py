"""Local deterministic text detectors and versioned exact registration index."""
from __future__ import annotations
import hashlib,re,time
from typing import Literal
from pathlib import Path
from pydantic import Field,PrivateAttr,model_validator
from .models import Record,DetectionFinding
from transpect_trace.guard.detection import (checked_text, detect_rules, inspection_text,
                                            normalize_registered_text, MAX_TEXT_BYTES)

VERSION='text-detectors/2'

_MASK=(1<<64)-1
_BASE=257


def _rolling(text):
    value=0
    for char in text:value=(value*_BASE+ord(char))&_MASK
    return f'{value:016x}'


def _has_fingerprint(text,size,wanted,rolling=None,deadline=None):
    """SHA-256 remains authoritative; rolling hashes only reject candidates.

    Legacy hash-only indexes remain readable. Their explicitly bounded slower
    scan fails closed when it cannot finish within the legacy work budget.
    Newly generated indexes use a linear, constant-memory prefilter.
    """
    if len(text)<size:return False
    wanted=set(wanted)
    if rolling:
        candidates={int(value,16) for value in rolling}
        factor=pow(_BASE,size-1,1<<64)
        value=int(_rolling(text[:size]),16)
        for offset in range(len(text)-size+1):
            if not offset%16384 and deadline is not None and time.monotonic()>deadline:
                raise ValueError('fingerprint deadline exceeded')
            if value in candidates and hashlib.sha256(text[offset:offset+size].encode()).hexdigest() in wanted:
                return True
            end=offset+size
            if end<len(text):value=((value-ord(text[offset])*factor)*_BASE+ord(text[end]))&_MASK
        return False
    if len(text)*size>32*1024*1024:
        raise ValueError('legacy fingerprint work budget exceeded; rebuild the index for large fields')
    for offset in range(len(text)-size+1):
        if not offset%16384 and deadline is not None and time.monotonic()>deadline:
            raise ValueError('fingerprint deadline exceeded')
        if hashlib.sha256(text[offset:offset+size].encode()).hexdigest() in wanted:return True
    return False

class Registration(Record):
    registration_id: str=Field(min_length=1,max_length=128,pattern=r'^[A-Za-z0-9_.:-]+$')
    sensitivity: Literal['PUBLIC','INTERNAL','CONFIDENTIAL','SECRET','UNKNOWN']='CONFIDENTIAL'
    data_types: list[Literal['credential','private_key','source_code','personal_information','registered_text']]=Field(default_factory=lambda:['registered_text'])
    # Hash-only index. Chunk lengths allow exact matches without storing secrets.
    chunks: dict[int,list[str]]
    rolling: dict[int,list[str]]=Field(default_factory=dict)
    normalized_chunks: dict[int,list[str]]=Field(default_factory=dict)
    normalized_rolling: dict[int,list[str]]=Field(default_factory=dict)
    raw_sha256: str|None=Field(default=None,pattern=r'^[a-f0-9]{64}$')
    normalized_sha256: str|None=Field(default=None,pattern=r'^[a-f0-9]{64}$')

    @model_validator(mode='after')
    def valid_chunks(self):
        if not self.chunks or len(self.chunks)>32:raise ValueError('invalid chunk length set')
        for size,hashes in self.chunks.items():
            if not 32<=size<=4096 or not 0<len(hashes)<=65536 or any(not re.fullmatch('[a-f0-9]{64}',h) for h in hashes):raise ValueError('invalid fingerprint')
        if len(self.normalized_chunks)>32:raise ValueError('invalid normalized chunk length set')
        for size,hashes in self.normalized_chunks.items():
            if not 32<=size<=4096 or not 0<len(hashes)<=65536 or any(not re.fullmatch('[a-f0-9]{64}',h) for h in hashes):raise ValueError('invalid normalized fingerprint')
        for actual,expected in ((self.rolling,self.chunks),(self.normalized_rolling,self.normalized_chunks)):
            if actual and (set(actual)!=set(expected) or any(len(values)!=len(expected[size]) or any(not re.fullmatch('[a-f0-9]{16}',v) for v in values) for size,values in actual.items())):
                raise ValueError('invalid rolling fingerprint prefilter')
        return self

class ContentIndex(Record):
    schema_version: Literal['transpect.protect.content-index/1.0']='transpect.protect.content-index/1.0'
    version: str=Field(min_length=1,max_length=127)
    registrations: list[Registration]=Field(default_factory=list,max_length=4096)
    # Optional registration-time snapshots stay in this process only. Serialized
    # hash-only indexes remain portable and use the bounded hash matcher instead.
    _runtime_chunks: dict[str,tuple[list[str],list[str]]]=PrivateAttr(default_factory=dict)

    @model_validator(mode='after')
    def unique_registration_ids(self):
        identifiers=[row.registration_id for row in self.registrations]
        if len(identifiers)!=len(set(identifiers)):raise ValueError('duplicate registration identity')
        return self

    @classmethod
    def register(cls,version,items,chunk_size=128):
        if not 32<=chunk_size<=4096:raise ValueError('chunk size out of bounds')
        rows=[];runtime_chunks={}
        for registration_id,text,sensitivity,data_types in items:
            if sensitivity not in {'PUBLIC','INTERNAL','CONFIDENTIAL','SECRET','UNKNOWN'}:raise ValueError('invalid sensitivity')
            if len(text)<32:raise ValueError('registration requires 32 characters')
            checked_text(text)
            def fingerprints(value):
                chunks={};rolling={}
                for offset in range(0,len(value),chunk_size):
                    chunk=value[offset:offset+chunk_size]
                    if len(chunk)>=32:
                        chunks.setdefault(len(chunk),[]).append(hashlib.sha256(chunk.encode()).hexdigest())
                        rolling.setdefault(len(chunk),[]).append(_rolling(chunk))
                return chunks,rolling
            normalized=normalize_registered_text(text)
            chunks,rolling=fingerprints(text)
            normalized_chunks,normalized_rolling=fingerprints(normalized)
            rows.append(Registration(registration_id=registration_id,sensitivity=sensitivity,data_types=data_types,
                chunks=chunks,rolling=rolling,normalized_chunks=normalized_chunks,normalized_rolling=normalized_rolling,
                raw_sha256=hashlib.sha256(text.encode()).hexdigest(),normalized_sha256=hashlib.sha256(normalized.encode()).hexdigest()))
            runtime_chunks[registration_id]=(
                [text[offset:offset+chunk_size] for offset in range(0,len(text),chunk_size) if len(text[offset:offset+chunk_size])>=32],
                [normalized[offset:offset+chunk_size] for offset in range(0,len(normalized),chunk_size) if len(normalized[offset:offset+chunk_size])>=32])
        index=cls(version=version,registrations=rows)
        index._runtime_chunks=runtime_chunks
        return index

    def matches(self,text):
        for row,_ in self.matches_with_methods(text):yield row

    def matches_with_methods(self,text,*,deadline=None):
        # Index requests remain bounded; never allocate a hash set per position.
        checked_text(text)
        lengths={size for r in self.registrations for size in r.chunks}
        if len(lengths)>32 or len(text)*max(1,len(lengths))>64*1024*1024:
            raise ValueError('fingerprint work budget exceeded')
        normalized=None
        if deadline is None:deadline=time.monotonic()+1.25
        for row in self.registrations:
            if time.monotonic()>deadline:raise ValueError('fingerprint deadline exceeded')
            runtime=self._runtime_chunks.get(row.registration_id)
            if runtime:
                def contains(chunks,value):
                    for chunk in chunks:
                        if time.monotonic()>deadline:raise ValueError('fingerprint deadline exceeded')
                        if chunk in value:return True
                    return False
                if contains(runtime[0],text):yield row,'exact';continue
                if normalized is None:normalized=normalize_registered_text(text)
                if (normalized!=text or runtime[1]!=runtime[0]) and contains(runtime[1],normalized):yield row,'normalized_bom_crlf'
                continue
            if any(_has_fingerprint(text,size,wanted,row.rolling.get(size),deadline) for size,wanted in row.chunks.items()):
                yield row,'exact';continue
            if row.normalized_chunks:
                if normalized is None:normalized=normalize_registered_text(text)
                if normalized==text and row.normalized_chunks==row.chunks:continue
                if any(_has_fingerprint(normalized,size,wanted,row.normalized_rolling.get(size),deadline) for size,wanted in row.normalized_chunks.items()):
                    yield row,'normalized_bom_crlf'

def detect(fields,index=None,*,pii_rules=False):
    findings=[]
    deadline=time.monotonic()+1.25
    def add(rule,field,strength,sensitivity,types,severity,registration_id=None,index_version=None):
        findings.append(DetectionFinding(detector_version=VERSION,rule_id=rule,location=field.location,
            severity=severity,strength=strength,sensitivity=sensitivity,data_types=types,evidence_sha256=field.sha256,
            registration_id=registration_id,index_version=index_version))
    for field in fields:
        if not field.inspected:continue
        if time.monotonic()>deadline:raise ValueError('detector deadline exceeded')
        text=inspection_text(field.value)
        for hit in detect_rules(text,pii_rules=pii_rules):
            add(hit,field,'exact' if hit=='PRIVATE_KEY_BLOCK' else 'contextual','SECRET',
                ['private_key'] if hit=='PRIVATE_KEY_BLOCK' else ['personal_information'] if hit=='CONTEXTUAL_PERSONAL_INFORMATION' else ['credential'],'critical')
        for rule,pattern,types in [
            ('JWT_SHAPE',r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b',['credential']),
            ('EMAIL_SHAPE',r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',['personal_information']),
            ('INTERNAL_IP',r'\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2})\b',[])]:
            sentinel={'JWT_SHAPE':'eyJ','EMAIL_SHAPE':'@','INTERNAL_IP':'.'}[rule]
            if sentinel in text and re.search(pattern,text):add(rule,field,'weak','UNKNOWN',types,'info')
        if index:
            for row,method in index.matches_with_methods(text,deadline=deadline):add('REGISTERED_EXACT' if method=='exact' else 'REGISTERED_NORMALIZED',field,'exact',row.sensitivity,row.data_types,
                'critical' if row.sensitivity in {'SECRET','CONFIDENTIAL'} else 'info',row.registration_id,index.version)
    return findings
