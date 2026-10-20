import base64
import gzip
import hashlib
import io
import json
from pathlib import Path

import jsonschema
import pytest
from transpect_trace.observe.classification import classify
from transpect_trace.observe.models import CaptureEvent
from transpect_trace.observe.pipeline import Pipeline, report
from transpect_trace.observe.unified import normalize
from transpect_trace.observe.protocol import Body
from transpect_trace.observe.assessment import Assessor
from transpect_trace.guard.policy import GuardPolicy
from transpect_trace.observe.ecapture_enhanced import HEADER, StructuredCapture


def capture(data=b'', **kwargs):
    values=dict(provider='fixture',capture_point='http-body',pid=12,tid=1,creation_filetime=100,
                connection_id='one',direction='send',sequence=1,captured_qpc=20,qpc_frequency=10,
                application='python-api',data_b64=base64.b64encode(data).decode())
    values.update(kwargs)
    return CaptureEvent(**values)


@pytest.mark.parametrize('value,path,category',[
    ({'model':'m','input':'hello'},'/v1/responses','LLM'),
    ({'model':'m','messages':[{'role':'user','content':'hello'}]},'/v1/chat/completions','LLM'),
    ({'type':'response.create','input':[{'type':'function_call_output','output':'fake'}]},'/responses','LLM'),
    ({'type':'response.create','response':{'instructions':'hello'}},'/responses','LLM'),
    ({'type':'response.create'},'/responses','UNKNOWN'),
    ({'model':'m','input':[{'anything':'hello'}]},'/responses','UNKNOWN'),
    ({'messages':'arbitrary'},'/responses','UNKNOWN'),
    ({'model':'m','tools':[{'type':'function'}]},'/responses','UNKNOWN'),
    ({'health':'ok'},'/responses','UNKNOWN'),
    ({'events':[]},'/telemetry','NON_LLM'),
    ({'events':[],'input':'hidden'},'/telemetry','UNKNOWN'),
    ({'action':'next','messages':[{'author':{'role':'user'},'content':{'parts':['text']}}]},'/backend-api/conversation','UNKNOWN'),
])
def test_classifier_shapes(value,path,category):
    r=classify('id',value,{':path':path,':method':'POST'},'python-api',complete=True)
    assert r.category==category and not r.can_enforce


@pytest.mark.parametrize('complete,decoded',[(False,True),(True,False),(False,False)])
def test_incomplete_is_never_identified(complete,decoded):
    assert classify('id',{'model':'m','input':'test'},{':path':'/responses'},'python-api',complete=complete,decoded=decoded).category=='UNKNOWN'


def test_domain_application_and_method_do_not_identify_llm():
    assert classify('id',{'input':'hello'},{'host':'api.openai.com',':method':'POST'},'codex-cli',complete=True).category=='UNKNOWN'
    assert classify('id',{'model':'m','input':'hello'},{':path':'/unrelated'},'unknown',complete=True).category=='UNKNOWN'
    assert classify('id',None,{':path':'/health',':method':'GET'},'unknown',complete=True).category=='UNKNOWN'


def test_unified_separates_wire_encoding_parsing_and_semantics(tmp_path):
    value={'model':'m','instructions':'FAKE_CONTEXT','input':[
        {'role':'user','content':'FAKE_PROMPT'},
        {'type':'function_call','name':'run','arguments':'FAKE_ARGS'},
        {'type':'function_call_output','output':'FAKE_RESULT'},
        {'role':'user','content':[{'type':'input_image','image_url':'data:image/png;base64,FAKE_IMAGE'}]}],
        'tools':[{'type':'function','parameters':{'properties':{'role':{'type':'string'}}}}]}
    raw=json.dumps(value).encode();compressed=gzip.compress(raw)
    b=Body(compressed,{'content-encoding':'gzip',':path':'/responses','host':'example.test'},'http/2',stream_id=3)
    e=capture(compressed);obs,_=Assessor(GuardPolicy()).assess(e,b);u=normalize(e,b,obs)
    assert u.classification.category=='LLM' and u.completeness=='complete'
    assert u.encoding_state=='decoded' and u.parsing_state=='parsed'
    assert u.raw_payload_sha256==hashlib.sha256(compressed).hexdigest()
    assert u.decoded_payload_sha256==hashlib.sha256(raw).hexdigest()
    kinds=[f.kind for f in u.fields]
    assert kinds.count('tool_call')==1 and kinds.count('tool_definition')==1
    assert {'context','message','tool_result','attachment_inline'}<=set(kinds)
    assert u.fields[0].value is not None
    exported=u.model_dump_json()
    assert 'FAKE_' not in exported and '"value"' not in exported
    schema=json.loads(Path('schemas/unified-llm-request-v1.schema.json').read_text())
    jsonschema.validate(json.loads(exported),schema)


def test_malformed_compressed_or_json_is_unknown():
    for data,encoding,state in [(b'broken','gzip','compressed'),(b'not-json','','identity'),(b'bytes','brotli','unsupported')]:
        e=capture(data);body=Body(data,{'content-encoding':encoding},'http/1.1')
        obs,_=Assessor(GuardPolicy()).assess(e,body);u=normalize(e,body,obs)
        assert u.classification.category=='UNKNOWN' and u.encoding_state==state
        assert u.completeness=='complete'  # framing is independent of semantic parsing


def test_additive_report_and_privacy(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy())
    p.consume(capture(b'{"model":"m","input":"FAKE_SENSITIVE_TEXT"}'))
    p.finish()
    r=report(tmp_path)
    assert r['classification']['counts']['LLM']==1 and r['control']['blocked_requests']==0
    assert 'FAKE_SENSITIVE_TEXT' not in ''.join(f.read_text() for f in tmp_path.glob('*.jsonl'))
    assert r['unified_requests'][0]['observation_id']==p.rows[0]['observation_id']
    (tmp_path/'unified-requests.jsonl').unlink();(tmp_path/'classifications.jsonl').unlink()
    assert report(tmp_path)['unified_requests']==[]  # old v1 runs still read
    (tmp_path/'summary.json').write_text(json.dumps({'scope':'companion_only_no_ETW','collector_variant':'enhanced-companion'}))
    assert report(tmp_path)['experiment']['scope']=='companion_only_no_ETW'
    assert report(tmp_path)['experiment']['runtime_certification']=='not_performed_by_this_report'


def frame(kind=0,data=b'',sequence=1,generation=1,**kwargs):
    values=dict(magic=b'ECW2',length=len(data),pid=12,tid=1,kind=kind,direction=0,flags=0,reserved=0,
        birth=100,session_lo=1,session_hi=2,low=3,high=4,generation=generation,sequence=sequence,qpc=20,frequency=10,lost=0)
    if kind in {1,3}:values.update(low=0,high=0,generation=0,sequence=0)
    values.update(kwargs)
    return HEADER.pack(*values.values()),data


def reader(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy());r=StructuredCapture({'pid':12,'creation_filetime':100},'python-api',p)
    r.consume(*frame(kind=1));return r,p


def test_structured_binary_over_preview_limit_and_generations(tmp_path):
    r,p=reader(tmp_path)
    body=json.dumps({'model':'m','input':'中文'*150}).encode()
    wire=b'POST /responses HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
    r.consume(*frame(data=wire[:200]));r.consume(*frame(data=wire[200:],sequence=2))
    r.consume(*frame(kind=2,sequence=3));r.consume(*frame(data=wire,generation=2))
    r.consume(*frame(kind=3));p.finish()
    assert r.terminal and not p.gaps and len(p.rows)==2
    assert all(row['content_sha256']==hashlib.sha256(body).hexdigest() for row in p.rows)


@pytest.mark.parametrize('changes',[{'pid':13},{'birth':101},{'session_lo':9},{'frequency':20},{'length':65537},{'reserved':1},{'magic':b'bad!'}])
def test_structured_identity_and_bounds_rejected(tmp_path,changes):
    r,p=reader(tmp_path)
    with pytest.raises(ValueError):r.consume(*frame(data=b'x',**changes))
    assert not p.rows


@pytest.mark.parametrize('changes',[{'sequence':2},{'flags':256},{'flags':512},{'lost':1}])
def test_structured_gaps_cannot_certify(tmp_path,changes):
    r,p=reader(tmp_path)
    r.consume(*frame(data=b'POST /responses HTTP/1.1\r\nHost: e\r\nContent-Length: 2\r\n\r\n{}',**changes))
    assert p.gaps and not p.rows


def test_terminal_loss_and_truncated_frame(tmp_path):
    r,p=reader(tmp_path);r.consume(*frame(kind=3,lost=1))
    assert p.gaps[-1]['reason']=='terminal_capture_loss'
    with pytest.raises(ValueError):r.consume(*frame(kind=1))
    r,p=reader(tmp_path/'second')
    header,data=frame(data=b'fake')
    with pytest.raises(EOFError):r.read(io.BytesIO(header+data[:2]))


@pytest.mark.parametrize('value',[
    {'model':'m','input':[{'type':{},'role':[],'content':'text'}]},
    {'model':'m','messages':[{'role':{},'content':'text'}]},
    {'model':'m','input':{'type':'strange'}},
    {'type':'response.create','response':[]},
])
def test_malformed_field_types_do_not_break_auditing(tmp_path,value):
    p=Pipeline(tmp_path,GuardPolicy());p.consume(capture(json.dumps(value).encode()))
    assert len(p.rows)==1 and len(report(tmp_path)['unified_requests'])==1


def test_build_verification_rejects_tampering_and_variant_confusion(tmp_path):
    from transpect_trace.observe.ecapture import verify_build,PIN
    folder=tmp_path;exe=folder/'ecapture.exe';dll=folder/'schannel_hook.dll'
    exe.write_bytes(b'fake_exe');dll.write_bytes(b'fake_dll')
    root=Path('patches/ecapture-windows');patches=json.loads((root/'manifest.json').read_text())['sha256']
    m={**PIN,'variant':'enhanced','protocol':'ECW2','patches_sha256':patches,
       'artifacts_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [exe,dll]}}
    manifest=folder/'ecapture-build.json';manifest.write_text(json.dumps(m))
    assert verify_build(exe)['variant']=='enhanced'
    m['protocol']='other';manifest.write_text(json.dumps(m))
    with pytest.raises(ValueError):verify_build(exe)
    m['protocol']='ECW2';m['patches_sha256']={};manifest.write_text(json.dumps(m))
    with pytest.raises(ValueError):verify_build(exe)
    m['variant']='upstream';m['protocol']='upstream-preview';manifest.write_text(json.dumps(m))
    assert verify_build(exe)['variant']=='upstream'
    dll.write_bytes(b'tampered')
    with pytest.raises(ValueError):verify_build(exe)


def test_matrix_requires_receipts_health_and_ecapture_not_native(tmp_path):
    from transpect_trace.observe.validation import validate_manifest
    folder=tmp_path/'sample';folder.mkdir()
    manifest=tmp_path/'manifest.json'
    manifest.write_text(json.dumps({'schema_version':'transpect.ecapture.experiments/1.0',
        'experiments':[{'channel':'api','directory':'sample'}]}))
    s={'runtime_available':True,'collector_variant':'enhanced','terminal_health_confirmed':True,
       'collector_errors':[],'capture_status':'supported','process':{'pid':12,'creation_filetime':100}}
    (folder/'summary.json').write_text(json.dumps(s))
    def check():return validate_manifest(manifest,tmp_path)['visibility'][0]
    assert check()['status']=='not_verified'
    r,p=reader(folder)
    data=b'{"model":"m","input":"fake"}'
    wire=b'POST /responses HTTP/1.1\r\nHost: e\r\nContent-Length: '+str(len(data)).encode()+b'\r\n\r\n'+data
    r.consume(*frame(data=wire));r.consume(*frame(kind=3));p.finish()
    (folder/'origin-receipts.jsonl').write_text(json.dumps({'payload_sha256':hashlib.sha256(data).hexdigest()})+'\n')
    assert check()['status']=='supported' and check()['parsing_status']=='passed'
    original=(folder/'classifications.jsonl').read_text()
    (folder/'classifications.jsonl').write_text(original.replace(p.rows[0]['observation_id'],'unrelated'))
    assert check()['parsing_status']=='not_verified'
    (folder/'classifications.jsonl').write_text(original)
    rows=(folder/'observations.jsonl').read_text().replace('ecapture-windows','native-observer')
    (folder/'observations.jsonl').write_text(rows)
    assert check()['status']=='partial'
    (folder/'observations.jsonl').write_text(rows.replace('native-observer','ecapture-windows'))
    (folder/'collector-health.jsonl').unlink()
    assert check()['status']=='partial'
    assert not check()['control']['can_enforce']
