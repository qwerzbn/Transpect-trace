"""Offline-only semantic detector contract; no model is shipped or simulated."""
from typing import Protocol
from .models import Record
from pydantic import Field

LABELS=('credential','private_key','source_code','personal_information','internal_document','none','unknown')

class SemanticResult(Record):
    detector_version: str
    labels: list[str]=Field(default_factory=list)
    status: str='not_run'
    limitations: list[str]=Field(default_factory=lambda:['no_local_semantic_model_configured'])

class LocalSemanticDetector(Protocol):
    """Call only from explicit offline evaluation, never from ProtectionEngine."""
    def evaluate(self,text:str)->SemanticResult:...

def evaluate_offline(dataset,detector=None):
    import hashlib,time
    rows=[]
    for item in dataset:
        began=time.perf_counter()
        result=detector.evaluate(item['text']) if detector else SemanticResult(detector_version='unconfigured')
        if any(label not in LABELS for label in result.labels):raise ValueError('unknown semantic label')
        rows.append({'case_id':item['case_id'],'text_sha256':hashlib.sha256(item['text'].encode()).hexdigest(),
            'expected_labels':item['labels'],'result':result.model_dump(),'elapsed_ms':(time.perf_counter()-began)*1000})
    scored=[r for r in rows if r['result']['status']=='completed']
    return {'schema_version':'transpect.protect.semantic-evaluation/1.0','cases':rows,'evaluated_cases':len(scored),
        'exact_label_matches':sum(set(r['expected_labels'])==set(r['result']['labels']) for r in scored),
        'semantic_capability_passed':False,'online_hard_block_enabled':False}
