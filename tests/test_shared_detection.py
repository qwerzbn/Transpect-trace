"""Shared inspection regressions, including former business coverage gaps."""
import hashlib
import json

import pytest

from transpect_trace.guard.detection import (
    MAX_TEXT_BYTES, WINDOW_CHARS, detect_rules, inspection_text,
)
from transpect_trace.guard.policy import GuardPolicy, GuardRequest, PolicyEngine
from transpect_trace.observe.unified import ContentField
from transpect_trace.protect.detection import ContentIndex, detect


def guard(text, policy=None):
    payload=json.dumps({'model':'synthetic','input':[{'type':'function_call_output','call_id':'test','output':text}]})
    return PolicyEngine(policy or GuardPolicy()).evaluate(GuardRequest(
        schema='transpect.guard.request/1.0',request_id='shared-test',guard_session_id='shared-test',
        pid=1,tid=1,kind='model.request',protocol='http',completeness='complete',payload_utf8=payload))


def field(value):
    raw=json.dumps(value,ensure_ascii=False).encode()
    return ContentField(kind='tool_result',location='/input/0',bytes=len(raw),
                        sha256=hashlib.sha256(raw).hexdigest(),value=value)


@pytest.mark.parametrize('text,rule',[
    ('api_key=FAKE_ONLY_0123456789abcdef','CONTEXTUAL_API_CREDENTIAL'),
    ('access_token=FAKE_ONLY_0123456789abcdef','CONTEXTUAL_API_CREDENTIAL'),
    ('client_secret=FAKE_ONLY_0123456789abcdef','CONTEXTUAL_API_CREDENTIAL'),
    ('Authorization: Bearer FAKE_ONLY_0123456789abcdef','AUTHORIZATION_BEARER_CREDENTIAL'),
    ('database_url=postgresql://fixture:FAKE_ONLY_0123456789abcdef@localhost/fixture','URI_CREDENTIAL'),
    (json.dumps({'api_secret':'FAKE_ONLY_0123456789abcdef'}),'CONFIG_CREDENTIAL'),
    (json.dumps({'nested':json.dumps({'api_key':'FAKE_ONLY_0123456789abcdef'})}),'CONTEXTUAL_API_CREDENTIAL'),
])
def test_guard_and_protect_share_required_rule_evidence(text,rule):
    decision,audit=guard(text)
    findings=detect([field(text)])
    assert decision.decision=='deny'
    assert rule in audit['matched_rule_ids'] and rule in {finding.rule_id for finding in findings}
    assert 'FAKE_ONLY_0123456789abcdef' not in json.dumps(audit)
    assert 'FAKE_ONLY_0123456789abcdef' not in ''.join(f.model_dump_json() for f in findings)


@pytest.mark.parametrize('text',[
    'api_key=${LOCAL_API_KEY}', 'access_token=<YOUR_TOKEN>', 'api_secret=********',
    'password=changeme', 'api_key=your_api_key_here',
    'Authorization: Basic ZmFrZTpmYWtl', 'Bearer is the name of a test utility',
    'Authorization: Bearer TRANSPECT_PUBLIC_FAKE_123456789',
    'database_url=postgresql://fixture:your_password@localhost/fixture',
    'contact fixture@example.invalid', 'phone=13800000000',
    'email=fixture@example.invalid', 'code function hello() { return 1; }',
    '{"properties":{"password":{"type":"string"},"api_key":{"type":"string"}}}',
])
def test_contextual_rules_do_not_promote_public_or_weak_values_to_secrets(text):
    assert guard(text)[0].decision=='allow'
    assert all(f.strength=='weak' for f in detect([field(text)]))


@pytest.mark.parametrize('text',[
    '-----END PRIVATE KEY-----\nsynthetic\n-----BEGIN PRIVATE KEY-----',
    '-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END EC PRIVATE KEY-----',
    '-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----',
])
def test_private_key_requires_matching_ordered_nonempty_block(text):
    assert 'PRIVATE_KEY_BLOCK' not in detect_rules(text)


def test_pii_requires_explicit_policy_and_joint_labeled_evidence():
    text='SYNTHETIC customer phone=13800000000 email=fixture@example.invalid'
    assert guard(text)[0].decision=='allow'
    assert guard(text,GuardPolicy(pii_rules=True))[0].decision=='deny'
    assert not any(f.rule_id=='CONTEXTUAL_PERSONAL_INFORMATION' for f in detect([field(text)]))
    assert any(f.rule_id=='CONTEXTUAL_PERSONAL_INFORMATION' for f in detect([field(text)],pii_rules=True))
    assert guard('email=fixture@example.invalid',GuardPolicy(pii_rules=True))[0].decision=='allow'


def test_structured_numeric_phone_retains_context_only_with_joint_pii_evidence():
    value={'phone':13800000000,'email':'fixture@example.invalid'}
    assert any(f.rule_id=='CONTEXTUAL_PERSONAL_INFORMATION' for f in detect([field(value)],pii_rules=True))
    assert not any(f.rule_id=='CONTEXTUAL_PERSONAL_INFORMATION' for f in detect([field(value)]))
    for public in ({'order_count':13800000000,'email':'fixture@example.invalid'},
                   {'phone':13800000000}, {'email':'fixture@example.invalid'},
                   {'phone':True,'email':'fixture@example.invalid'}):
        assert not any(f.rule_id=='CONTEXTUAL_PERSONAL_INFORMATION' for f in detect([field(public)],pii_rules=True))


def test_large_normal_text_is_allowed_and_cross_window_secret_is_not_missed():
    clean='diagnostic normal text '*(2*1024*1024//23)
    assert len(clean)>1024*1024
    assert guard(clean)[0].decision=='allow'
    assert not detect([field(clean)])
    prefix='x'*(WINDOW_CHARS-10)+'\n'
    text=prefix+'api_secret=FAKE_ONLY_0123456789abcdef'+'\n'+'x'*WINDOW_CHARS
    assert guard(text)[0].decision=='deny'
    assert any(f.rule_id=='CONFIG_CREDENTIAL' for f in detect([field(text)]))


def test_utf8_byte_limit_and_json_work_limits_fail_closed():
    text='汉'*(MAX_TEXT_BYTES//3+1)
    assert guard(text)[0].decision=='unknown'
    nested={'api_secret':'FAKE_ONLY_0123456789abcdef'}
    for _ in range(9):nested={'value':json.dumps(nested)}
    assert guard(json.dumps(nested))[0].decision=='unknown'


def test_guard_registration_preserves_raw_and_normalized_evidence(tmp_path):
    raw='\ufeff# synthetic company module\r\ndef transform(value):\r\n    return value * 0.731\r\n'
    source=tmp_path/'registered.txt';source.write_bytes(raw.encode())
    normalized=raw.removeprefix('\ufeff').replace('\r\n','\n')
    decision,audit=guard(normalized,GuardPolicy(registered_files=[source]))
    assert decision.decision=='deny'
    evidence=audit['registered_match_evidence'][0]
    assert evidence['method']=='normalized_bom_crlf'
    assert evidence['registration_raw_sha256']==hashlib.sha256(raw.encode()).hexdigest()
    assert evidence['registration_normalized_sha256']==hashlib.sha256(normalized.encode()).hexdigest()
    assert raw not in json.dumps(audit)
    assert guard(normalized.replace('    return','return'),GuardPolicy(registered_files=[source]))[0].decision=='allow'


def test_guard_registered_crlf_split_at_chunk_boundary_is_still_detected(tmp_path):
    raw='a'*255+'\r\n'+'z'*31
    source=tmp_path/'boundary.txt';source.write_bytes(raw.encode())
    policy=GuardPolicy(registered_files=[source])
    decision,audit=guard(raw.replace('\r\n','\n'),policy)
    assert decision.decision=='deny'
    assert any(row['method']=='normalized_bom_crlf' for row in audit['registered_match_evidence'])
    assert guard(raw,policy)[0].decision=='deny'
    assert guard(raw.replace('\r\n',' '),policy)[0].decision=='allow'


def test_guard_lf_registration_matches_later_crlf_without_relaxing_whitespace(tmp_path):
    raw='# synthetic company module\ndef transform(value):\n    return value * 0.731\n'
    source=tmp_path/'registered-lf.txt';source.write_bytes(raw.encode())
    policy=GuardPolicy(registered_files=[source])
    decision,audit=guard(raw.replace('\n','\r\n'),policy)
    assert decision.decision=='deny'
    assert any(row['method']=='normalized_bom_crlf' for row in audit['registered_match_evidence'])
    assert guard(raw.replace('    return','return'),policy)[0].decision=='allow'


def test_registration_does_not_remove_an_interior_bom_at_chunk_boundary(tmp_path):
    raw='a'*256+'\ufeff'+'z'*40
    source=tmp_path/'interior-bom.txt';source.write_bytes(raw.encode())
    policy=GuardPolicy(registered_files=[source])
    # Isolate the second chunk: the original BOM is data, not a file prefix.
    assert guard('\ufeff'+'z'*40,policy)[0].decision=='deny'
    assert guard('z'*40,policy)[0].decision=='allow'


def test_hash_only_index_roundtrip_normalizes_bom_crlf_without_storing_text():
    original='\ufeff# synthetic company module\r\ndef transform(value):\r\n    return value * 0.731\r\n'
    normalized=original.removeprefix('\ufeff').replace('\r\n','\n')
    index=ContentIndex.register('fixture/2',[('fixture',original,'SECRET',['source_code'])])
    encoded=index.model_dump_json()
    assert 'transform(value)' not in encoded
    restored=ContentIndex.model_validate_json(encoded)
    findings=detect([field(normalized)],restored)
    assert any(f.rule_id=='REGISTERED_NORMALIZED' for f in findings)
    assert not list(restored.matches(normalized.replace('    return','return')))


def test_registration_runtime_snapshots_support_large_requests_without_serializing_plaintext():
    secret='fake synthetic registered business document. '*3
    index=ContentIndex.register('fixture/2',[('fixture',secret,'CONFIDENTIAL',['registered_text'])])
    clean='x'*(2*1024*1024)
    assert not list(index.matches(clean))
    assert list(index.matches(clean+secret))[0].registration_id=='fixture'
    assert secret not in index.model_dump_json() and 'runtime_chunks' not in index.model_dump_json()


def test_legacy_indexes_stay_readable_and_expensive_work_is_refused():
    secret='synthetic registration payload-0123456789'
    index=ContentIndex.model_validate({'version':'legacy/1','registrations':[{
        'registration_id':'fixture','chunks':{str(len(secret)):[hashlib.sha256(secret.encode()).hexdigest()]}}]})
    assert list(index.matches('prefix '+secret))[0].registration_id=='fixture'
    with pytest.raises(ValueError,match='legacy fingerprint work budget'):
        list(index.matches('x'*(2*1024*1024)))


def test_hash_index_deadline_stops_work_instead_of_running_after_a_gate_timeout(monkeypatch):
    import transpect_trace.protect.detection as module
    index=ContentIndex.register('fixture/2',[('fixture','synthetic registration payload '*4,'SECRET',['registered_text'])])
    restored=ContentIndex.model_validate_json(index.model_dump_json())
    ticks=iter([0.0,0.0,2.0])
    monkeypatch.setattr(module.time,'monotonic',lambda:next(ticks))
    with pytest.raises(ValueError,match='fingerprint deadline'):
        list(restored.matches('x'*1000))


def test_duplicate_registration_identity_is_rejected_instead_of_using_wrong_runtime_snapshot():
    with pytest.raises(ValueError,match='duplicate registration identity'):
        ContentIndex.register('fixture/2',[
            ('same','synthetic confidential registration payload '*2,'SECRET',['registered_text']),
            ('same','different public registration payload '*2,'PUBLIC',['registered_text']),
        ])


def test_detector_deadline_is_shared_by_all_fields(monkeypatch):
    import transpect_trace.protect.detection as module
    ticks=iter([0.0,0.1,2.0])
    monkeypatch.setattr(module.time,'monotonic',lambda:next(ticks))
    with pytest.raises(ValueError,match='detector deadline'):
        detect([field('first benign text'),field('second benign text')])


def test_legacy_registered_scan_stops_when_default_budget_expires(monkeypatch):
    import transpect_trace.guard.detection as module
    ticks=iter([0.0,0.0,0.1,2.0])
    monkeypatch.setattr(module.time,'monotonic',lambda:next(ticks))
    registered=[('fixture','absent first registered block'),('fixture','absent second registered block')]
    with pytest.raises(ValueError,match='registered inspection deadline'):
        list(module.registered_matches('ordinary request',registered))


def test_guard_registration_timeout_denies_request_and_does_not_reset_for_evidence(tmp_path,monkeypatch):
    import transpect_trace.guard.detection as module
    source=tmp_path/'budget.txt';source.write_text('synthetic confidential registration '*3)
    engine=PolicyEngine(GuardPolicy(registered_files=[source]))
    request=GuardRequest(schema='transpect.guard.request/1.0',request_id='budget',guard_session_id='budget',
        pid=1,tid=1,kind='model.request',protocol='http',completeness='complete',
        payload_utf8=json.dumps({'model':'synthetic','input':'ordinary request'}))
    seen=[]
    original=module.registered_matches
    clock={'now':0.0}
    monkeypatch.setattr(module.time,'monotonic',lambda:clock['now'])
    def expires_before_evidence(text,registered,*,deadline=None):
        seen.append(deadline)
        if len(seen)==2:clock['now']=2.0
        yield from original(text,registered,deadline=deadline)
    monkeypatch.setattr(module,'registered_matches',expires_before_evidence)
    decision,audit=engine.evaluate(request)
    assert len(seen)==2 and seen[0]==seen[1]==module.INSPECTION_SECONDS
    assert decision.decision=='unknown' and decision.action=='block_request'
    assert audit['reason']=='UNSUPPORTED_CONTENT'
