import hashlib,json
import pytest
from transpect_trace.protect.models import SemanticCaptureEvent,AdapterCapability
from transpect_trace.protect.policy import ProtectionEngine,ProtectionPolicy
from transpect_trace.protect.detection import ContentIndex
from transpect_trace.protect.correlation import RequestCorrelator
from transpect_trace.protect.unified import normalize
from transpect_trace.protect.semantic import evaluate_offline

def event(value=None,**kwargs):
    raw=json.dumps(value or {'model':'fixture','input':'hello'},ensure_ascii=False).encode()
    return SemanticCaptureEvent(run_id='fixture-run',adapter_id='fixture-native',application='python-api',channel='api',
        pid=123,creation_filetime=456,image_sha256='a'*64,protocol='http',destination_host='localhost',api_path='/responses',
        completeness='complete',body_sha256=hashlib.sha256(raw).hexdigest(),body_bytes=len(raw),body=raw,**kwargs)

@pytest.mark.parametrize('text',['hello','代码 function hello() {}','fixture@example.test','10.0.0.1','eyJabc.def.ghi'])
def test_weak_signals_do_not_block(text):
    result=ProtectionEngine().evaluate(event({'model':'x','input':text}))
    assert result.decision=='ALLOW'
    assert result.actual_action=='not_confirmed'

@pytest.mark.parametrize('value',[
    {'model':'x','input':'password=FakeSecret12345'},
    {'model':'x','input':[{'type':'function_call_output','call_id':'a','output':'password=FakeSecret12345'}]},
    {'model':'x','input':[{'type':'function_call','name':'tool','arguments':'{"password":"FakeSecret12345"}'}]},
    {'model':'x','messages':[{'role':'tool','content':'password=FakeSecret12345'}]},
])
def test_secrets_block_in_actual_content(value):
    result=ProtectionEngine().evaluate(event(value))
    assert result.decision=='BLOCK'
    assert result.requested_action=='block_request'
    assert 'FakeSecret12345' not in result.model_dump_json()

def test_tool_definition_remains_distinct_but_secrets_in_description_are_inspected():
    request=event({'model':'x','input':'hello','tools':[{'type':'function','description':'password=FakeSecret12345'}]})
    assert ProtectionEngine().evaluate(request).decision=='BLOCK'
    fields=normalize(request).fields
    assert any(f.kind=='tool_definition' for f in fields)
    assert not any(f.kind=='tool_call' for f in fields)

def test_tool_schema_declaration_does_not_become_actual_tool_call_or_secret():
    request=event({'model':'x','input':'hello','tools':[{'type':'function','name':'function_call','parameters':{'type':'object','properties':{'password':{'type':'string'}}}}]})
    assert ProtectionEngine().evaluate(request).decision=='ALLOW'
    assert not any(f.kind=='tool_call' for f in normalize(request).fields)

def test_review_and_unknown_fail_closed():
    result=ProtectionEngine(ProtectionPolicy(review_rules=['EMAIL_SHAPE'])).evaluate(event({'model':'x','input':'fixture@example.test'}))
    assert result.decision=='REVIEW' and result.requested_action=='block_request'
    request=event();request.completeness='partial'
    assert ProtectionEngine().evaluate(request).decision=='UNKNOWN'
    request=event();request.body=b'corrupted'
    assert ProtectionEngine().evaluate(request).decision=='UNKNOWN'

def test_metadata_cannot_be_used_to_reconstruct_gate_body():
    request=event({'model':'x','input':'UNIQUE_FAKE_SECRET_123456789'})
    serialized=request.model_dump_json()
    assert 'UNIQUE_FAKE_SECRET_123456789' not in serialized
    assert 'UNIQUE_FAKE_SECRET_123456789' not in normalize(request).model_dump_json()
    assert ProtectionEngine().evaluate(SemanticCaptureEvent.model_validate_json(serialized)).decision=='UNKNOWN'

def test_versioned_registration_matches_at_shifted_offsets_without_storing_secret():
    secret='fake-private-company-code-'*4
    index=ContentIndex.register('fixture/1',[('fake',secret,'CONFIDENTIAL',['source_code'])],chunk_size=32)
    assert secret not in index.model_dump_json()
    result=ProtectionEngine(index=index).evaluate(event({'model':'x','input':'prefix'+secret+'suffix'}))
    assert result.decision=='BLOCK'
    assert any(f.rule_id=='REGISTERED_EXACT' and f.sensitivity=='CONFIDENTIAL' for f in result.findings)

def test_source_unknown_does_not_allow_registered_secret():
    secret='fake-registration-'*8
    index=ContentIndex.register('1',[('fixture',secret,'SECRET',['registered_text'])])
    assert ProtectionEngine(index=index).evaluate(event({'model':'x','input':secret})).decision=='BLOCK'

def test_session_block_persists_across_processes_in_same_run():
    engine=ProtectionEngine(ProtectionPolicy(deny_action='block_session'))
    assert engine.evaluate(event({'model':'x','input':'password=FakeSecret12345'})).requested_action=='block_session'
    later=event();later.pid=999;later.creation_filetime=999
    assert engine.evaluate(later).reason=='SESSION_BLOCKED'

def test_identical_parallel_prompts_and_retries_are_not_deduplicated():
    correlator=RequestCorrelator();a,b=event(),event()
    correlator.add(a);correlator.add(b)
    assert correlator.relate(a.observation_id,b.observation_id).grade=='CANDIDATE'
    assert correlator.root(a.observation_id)!=correlator.root(b.observation_id)
    # Even an asserted mapping cannot merge distinct attempts.
    assert correlator.relate(a.observation_id,b.observation_id,direct_mapping_evidence='fixture').grade!='EXACT'

def test_direct_mapping_and_single_gate_owner():
    a=event(gate_owner='native');b=event();b.attempt_id=a.attempt_id
    c=RequestCorrelator(verified_mappings={'verified-event-1':{'observation_ids':[a.observation_id,b.observation_id],'attempt_id':a.attempt_id}})
    c.add(a);c.add(b)
    assert c.relate(a.observation_id,b.observation_id,direct_mapping_evidence='verified-event-1').grade=='EXACT'
    assert c.root(a.observation_id)==c.root(b.observation_id)
    other=event(gate_owner='other');other.attempt_id=a.attempt_id
    with pytest.raises(ValueError):c.add(other)

def test_unregistered_proof_id_is_not_exact():
    a,b=event(),event();b.attempt_id=a.attempt_id;c=RequestCorrelator();c.add(a);c.add(b)
    assert c.relate(a.observation_id,b.observation_id,direct_mapping_evidence='asserted-but-not-verified').grade=='CANDIDATE'

def test_strong_requires_closed_unique_connection_evidence_and_does_not_merge():
    a,b=event(),event();b.adapter_id='independent-tls-fixture'
    for item in (a,b):item.connection_id='verified-fixture-connection';item.connection_identity='stable';item.captured_qpc=1000;item.qpc_frequency=1000
    c=RequestCorrelator();c.add(a);c.add(b)
    assert c.relate(a.observation_id,b.observation_id).grade=='CANDIDATE'
    c.seal()
    assert c.relate(a.observation_id,b.observation_id).grade=='STRONG'
    assert c.root(a.observation_id)!=c.root(b.observation_id)
    with pytest.raises(ValueError):c.add(event())
    third=event();third.connection_id=a.connection_id;third.connection_identity='stable';third.captured_qpc=1000;third.qpc_frequency=1000
    ambiguous=RequestCorrelator()
    for item in (a,b,third):ambiguous.add(item)
    ambiguous.seal()
    assert ambiguous.relate(a.observation_id,b.observation_id).grade=='CANDIDATE'

def test_process_reuse_prevents_exact_mapping():
    c=RequestCorrelator();a,b=event(),event();b.attempt_id=a.attempt_id;b.creation_filetime+=1
    c.add(a);c.add(b)
    assert c.relate(a.observation_id,b.observation_id,direct_mapping_evidence='fixture').grade!='EXACT'

def test_no_semantic_model_does_not_pretend_evaluation_passed():
    result=evaluate_offline([{'case_id':'1','text':'fake','labels':['none']}])
    assert result['evaluated_cases']==0 and not result['semantic_capability_passed']

def test_no_gate_capability_without_certification():
    with pytest.raises(ValueError):AdapterCapability(adapter_id='fake',channel='web',image_sha256='a'*64,entry='candidate',
        protocols=['http'],capture_stage='unknown',content_scope=['text'],can_enforce=True)

def test_audit_rejects_full_url_and_query():
    with pytest.raises(ValueError):SemanticCaptureEvent.model_validate({**event().model_dump(),'destination_host':'https://host/?token=secret'})

def test_compressed_payload_has_distinct_wire_and_decoded_hashes():
    import gzip
    e=event({'model':'x','input':'password=FakeSecret12345'});raw=e.body;e.body=gzip.compress(raw)
    e.body_sha256=hashlib.sha256(e.body).hexdigest();e.body_bytes=len(e.body);e.encoding_state='compressed';e.content_encoding='gzip'
    unified=normalize(e)
    assert unified.raw_payload_sha256!=unified.decoded_payload_sha256
    assert unified.decoded_payload_sha256==hashlib.sha256(raw).hexdigest()
    assert ProtectionEngine().evaluate(e).decision=='BLOCK'
    e.body=e.body[:-1];e.body_sha256=hashlib.sha256(e.body).hexdigest();e.body_bytes=len(e.body)
    assert ProtectionEngine().evaluate(e).decision=='UNKNOWN'

def test_declared_capture_gap_prevents_allow():
    e=event();e.limitations=['ordering_gap']
    assert ProtectionEngine().evaluate(e).decision=='UNKNOWN'

def test_json_credential_and_api_key_are_contextual():
    for text in ['{"password":"FakeSecret12345"}','api_key=FakeSyntheticApiKey12345']:
        assert ProtectionEngine().evaluate(event({'model':'x','input':text})).decision=='BLOCK'

def test_semantic_wire_is_separate_and_refuses_corrupt_body():
    import base64
    from transpect_trace.protect.pipe import parse_event
    request=event();subject={'pid':request.pid,'creation_filetime':request.creation_filetime,'image_sha256':request.image_sha256}
    wire={'schema_version':'transpect.protect.request/1.0','event':request.model_dump(),'body_b64':base64.b64encode(request.body).decode()}
    assert parse_event(json.dumps(wire),subject).body==request.body
    wire['body_b64']=base64.b64encode(b'changed').decode()
    with pytest.raises(ValueError):parse_event(json.dumps(wire),subject)

def test_upload_element_does_not_become_complete_request():
    e=event();e.completeness='unknown';e.limitations=['upload_element_not_complete_request']
    assert normalize(e).classification.category=='UNKNOWN'
    assert ProtectionEngine().evaluate(e).decision=='UNKNOWN'

def test_native_execution_evidence_does_not_claim_origin_delivery():
    from transpect_trace.protect.models import ExecutionEvidence
    e=ExecutionEvidence(attempt_id='fixture',pid=123,action='none',result='transport_authorized',qpc=123)
    assert 'origin' not in e.model_dump_json()
    with pytest.raises(ValueError):ExecutionEvidence(attempt_id='fixture',pid=123,action='none',result='native_rejection',qpc=123)
