"""Per-rule reproducible offline evaluation; input text is never exported."""
import hashlib,time
from .detection import detect
from .semantic import evaluate_offline
from transpect_trace.observe.unified import extract_fields

def evaluate_dataset(dataset):
    if dataset.get('schema_version')!='transpect.protect.evaluation/1.0':raise ValueError('unsupported dataset version')
    rows=[];counts={}
    for case in dataset['cases']:
        text=case['text'];expected=set(case['expected_rules']);start=time.perf_counter()
        findings=detect(extract_fields({'input':text}));actual={f.rule_id for f in findings}
        elapsed=(time.perf_counter()-start)*1000
        for rule in expected|actual:
            counter=counts.setdefault(rule,{'true_positive':0,'false_positive':0,'false_negative':0})
            counter['true_positive' if rule in expected and rule in actual else 'false_positive' if rule in actual else 'false_negative']+=1
        rows.append({'case_id':case['case_id'],'text_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'expected_rules':sorted(expected),'actual_rules':sorted(actual),'elapsed_ms':elapsed,'matched_expectation':expected==actual})
    for counter in counts.values():
        tp,fp,fn=(counter[k] for k in ('true_positive','false_positive','false_negative'))
        counter['precision']=tp/(tp+fp) if tp+fp else None;counter['recall']=tp/(tp+fn) if tp+fn else None
    return {'schema_version':'transpect.protect.evaluation-report/1.0','dataset_version':dataset['version'],
        'cases':rows,'rules':counts,'total_ms':sum(r['elapsed_ms'] for r in rows),'passed':all(r['matched_expectation'] for r in rows),
        'semantic':evaluate_offline([{'case_id':c['case_id'],'text':c['text'],'labels':c.get('labels',['unknown'])} for c in dataset['cases']]),
        'online_policy_changed':False}
