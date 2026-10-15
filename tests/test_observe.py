import base64
import gzip
import hashlib
import json
import struct
from pathlib import Path

import pytest

from transpect_trace.guard.policy import GuardPolicy,Marker
from transpect_trace.observe.models import CaptureEvent
from transpect_trace.observe.pipeline import Pipeline,report
from transpect_trace.observe.protocol import Connection,decode_body,CoverageGap


def capture(data,seq=1,**extra):
    fields=dict(provider="fixture",capture_point="tls",pid=12,creation_filetime=100,tid=1,
                connection_id="c",direction="send",sequence=seq,captured_qpc=100,qpc_frequency=10,
                data_b64=base64.b64encode(data).decode(),application="python-api")
    fields.update(extra);return CaptureEvent(**fields)


def request(body,headers=b"",close=False):
    return (b"POST /responses?token=SHOULD_NOT_LOG HTTP/1.1\r\nHost: api.example.test\r\n"
            b"Authorization: Bearer FAKE_HEADER_SECRET\r\nCookie: FAKE_COOKIE_SECRET\r\nContent-Type: application/json\r\n"
            +headers+(b"Connection: close\r\n" if close else b"")+f"Content-Length: {len(body)}\r\n\r\n".encode()+body)


def test_split_unicode_gzip_redacted_risk_is_a_recommendation(tmp_path):
    body=json.dumps({"model":"fixture","input":[{"role":"user","content":"中文私有内容"},
             {"type":"function_call_output","output":"mysql_password=FakeSensitive123"}]},ensure_ascii=False).encode()
    wire=request(gzip.compress(body),b"Content-Encoding: gzip\r\n",close=True)
    pipeline=Pipeline(tmp_path,GuardPolicy())
    for i,start in enumerate(range(0,len(wire),7),1):pipeline.consume(capture(wire[start:start+7],i))
    pipeline.finish();result=report(tmp_path)
    assert len(pipeline.rows)==1 and not pipeline.gaps
    obs=pipeline.rows[0];risk=pipeline.assessments[0]
    assert obs["content_sha256"]==hashlib.sha256(body).hexdigest() and obs["completeness"]=="complete"
    assert set(obs["semantics"])=={"prompt","tool_result"}
    assert risk["recommended_action"]=="block_request" and risk["effective_action"]=="audit" and not risk["can_enforce"]
    text="".join(p.read_text() for p in tmp_path.glob("*.jsonl"))
    for private in ["FakeSensitive123","中文私有内容","FAKE_HEADER_SECRET","FAKE_COOKIE_SECRET","SHOULD_NOT_LOG"]:assert private not in text
    assert result["control"]["blocked_requests"]==0 and result["source_evidence"][0]["confidence"]=="Unknown"


def test_http_connection_reuse_and_distinct_births(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy());body=b'{"model":"m","input":"hello"}'
    p.consume(capture(request(body)+request(body)))
    p.consume(capture(request(body),creation_filetime=200))
    assert len(p.rows)==3 and not p.gaps


@pytest.mark.parametrize("change",[{"sequence":2},{"truncated":True},{"lost_events":1},{"connection_identity":"unknown"}])
def test_gap_is_not_a_clean_request(change,tmp_path):
    p=Pipeline(tmp_path,GuardPolicy());p.consume(capture(request(b'{"input":"x"}'),**change))
    assert p.gaps and not p.rows


def test_incomplete_body_at_end_is_a_coverage_gap(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy());p.consume(capture(request(b'{"input":"x"}')[:-4]));p.finish()
    assert not p.rows and p.gaps[-1]["reason"]=="capture_ended_with_incomplete_request"


def test_partial_header_and_empty_fragment_remain_pending(tmp_path):
    from transpect_trace.observe.protocol import WebSocket
    p=Pipeline(tmp_path,GuardPolicy())
    p.consume(capture(b'POST /responses HTTP/1.1\r\nHost: incomplete'))
    p.finish()
    assert p.gaps and not p.rows
    ws=WebSocket({})
    assert not ws.feed(frame(b'',fin=False)) and ws.pending


@pytest.mark.parametrize('tail_bytes',[1,4])
def test_truncated_zstd_checksum_cannot_be_complete(tail_bytes,tmp_path):
    import zstandard
    body=b'{"model":"m","input":"complete-looking JSON"}'
    encoded=zstandard.ZstdCompressor(write_checksum=True).compress(body)
    with pytest.raises(CoverageGap):decode_body(encoded[:-tail_bytes],'zstd')
    p=Pipeline(tmp_path,GuardPolicy())
    p.consume(capture(request(encoded[:-tail_bytes],b'Content-Encoding: zstd\r\n')))
    assert p.rows[0]['completeness']=='unknown' and p.assessments[0]['risk']=='unknown'


def test_zstd_bounded_frames_with_known_and_unknown_size():
    import zstandard
    body=b'{"model":"m","input":"hello"}'
    for known_size in (True,False):
        encoded=zstandard.ZstdCompressor(write_checksum=True,write_content_size=known_size).compress(body)
        assert decode_body(encoded,'zstd')==body
        with pytest.raises(CoverageGap):decode_body(encoded+encoded,'zstd')


@pytest.mark.parametrize('returncode',[0,1])
def test_ecapture_unexpected_exit_is_a_failure(returncode,tmp_path):
    from types import SimpleNamespace
    from transpect_trace.observe.ecapture import ECaptureCollector
    p=Pipeline(tmp_path,GuardPolicy())
    collector=ECaptureCollector({'pid':12,'creation_filetime':100},SimpleNamespace(application='fixture'),None,p)
    collector.process=SimpleNamespace(poll=lambda:returncode)
    collector.ready.set()
    with pytest.raises(RuntimeError):collector.check_health()
    assert 'ecapture_process_exited' in collector.errors
    collector.close();collector.close()


def test_failed_cleanup_still_finishes_evidence_without_secret_logs(tmp_path):
    from types import SimpleNamespace
    from transpect_trace.observe.cli import finalize_capture
    calls=[]
    def fail():raise OSError('SHOULD_NOT_LOG_SECRET')
    def etw_close(*args):calls.append('etw');fail()
    def finish(index):calls.append(('pipeline',index))
    collector=SimpleNamespace(close=fail,errors=[])
    etw=SimpleNamespace(close=etw_close,index='unfinalized evidence')
    status={}
    assert finalize_capture(tmp_path,status,collector,etw,SimpleNamespace(finish=finish))
    assert calls==['etw',('pipeline',None)] and status['etw']['confidence']=='Unknown'
    assert 'SHOULD_NOT_LOG_SECRET' not in json.dumps(status)


def test_native_close_is_idempotent_and_releases_controller_after_disable_error():
    import threading
    from types import SimpleNamespace
    from ctypes import wintypes
    from transpect_trace.observe.native import NativeCollector
    calls=[]
    def fail():calls.append('disable');raise OSError('SHOULD_NOT_LOG_SECRET')
    collector=NativeCollector.__new__(NativeCollector)
    collector._closed=False;collector._disable_capture=fail;collector.errors=[]
    collector.stop=threading.Event();collector.name='fixture';collector.thread=None
    collector.security=SimpleNamespace(descriptor=1)
    collector.k=SimpleNamespace(CreateFileW=lambda *args:wintypes.HANDLE(-1).value,
                               LocalFree=lambda *args:calls.append('free'))
    collector.close();collector.close()
    assert calls==['disable','free'] and collector.stop.is_set()
    assert collector.errors==['disable_unconfirmed']


@pytest.mark.parametrize('trailing,error,raises',[(False,109,False),(True,0,True),(False,5,True)])
def test_native_frame_waits_for_peer_eof(trailing,error,raises,monkeypatch):
    from types import SimpleNamespace
    from transpect_trace.observe import native
    def read(pipe,buffer,size,count,overlapped):
        count._obj.value=1 if trailing else 0
        return trailing
    monkeypatch.setattr(native.c,'get_last_error',lambda:error,raising=False)
    collector=native.NativeCollector.__new__(native.NativeCollector)
    collector.k=SimpleNamespace(ReadFile=read)
    if raises:
        with pytest.raises((ValueError,OSError)):collector.finish_frame(1)
    else:collector.finish_frame(1)


def test_http2_multiplexing_continuations_and_compression_state(tmp_path):
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    client=H2Connection(config=H2Configuration(client_side=True,header_encoding='utf-8'));client.initiate_connection()
    bodies={1:b'{"model":"m","input":"first"}',3:b'{"model":"m","input":"second"}'}
    for stream in bodies:
        client.send_headers(stream,[(":method","POST"),(":scheme","https"),(":authority","example.test"),(":path","/responses"),("content-type","application/json")])
    client.send_data(3,bodies[3],end_stream=True);client.send_data(1,bodies[1],end_stream=True)
    wire=client.data_to_send();p=Pipeline(tmp_path,GuardPolicy())
    for i,start in enumerate(range(0,len(wire),5),1):p.consume(capture(wire[start:start+5],i))
    p.finish()
    assert not p.gaps and {row["stream_id"] for row in p.rows}=={1,3}
    assert {row["content_sha256"] for row in p.rows}=={hashlib.sha256(b).hexdigest() for b in bodies.values()}


def frame(data,opcode=1,fin=True):
    mask=b"mask";length=len(data)
    size=bytes([length|128]) if length<126 else b"\xfe"+struct.pack("!H",length)
    return bytes([opcode|(128 if fin else 0)])+size+mask+bytes(x^mask[i%4] for i,x in enumerate(data))


def test_wss_upgrade_fragmentation_and_interleaved_control(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy());body=b'{"type":"response.create","model":"m","input":"hello"}'
    upgrade=b'GET /responses HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'
    p.consume(capture(upgrade))
    p.consume(capture(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n',direction='recv'))
    p.consume(capture(frame(body[:20],fin=False)+frame(b"p",opcode=9)+frame(body[20:],opcode=0),2))
    p.finish()
    assert not p.gaps and len(p.rows)==1 and p.rows[0]["content_sha256"]==hashlib.sha256(body).hexdigest()


def test_wss_false_upgrade_cannot_certify_text(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy())
    p.consume(capture(b'GET /responses HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'))
    p.consume(capture(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n',direction='recv'))
    p.consume(capture(frame(b'{"input":"hello"}'),2))
    assert p.gaps and not p.rows


def test_suite_verifies_hash_receipt_and_audit_instead_of_summary_passed(tmp_path):
    import runpy
    validate=runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/report_observe_validation.py'))['visibility']
    root=tmp_path/'fixture';root.mkdir()
    digest=hashlib.sha256(b'fake').hexdigest()
    summary={'passed':True,'can_enforce':False,'actual_ai_channel_certified':False,'source_decoded_hashes':[digest]}
    (root/'summary.json').write_text(json.dumps(summary))
    entry={'directory':'fixture','target':'fixture','scope':'fake-only'}
    assert validate(tmp_path,entry)['status']=='not_verified'
    (root/'observations.jsonl').write_text(json.dumps({'content_sha256':digest,'completeness':'complete','can_enforce':False})+'\n')
    (root/'assessments.jsonl').write_text(json.dumps({'effective_action':'audit','can_enforce':False})+'\n')
    assert validate(tmp_path,entry)['status']=='passed'
    (root/'assessments.jsonl').write_text(json.dumps({'effective_action':'block_request','can_enforce':True})+'\n')
    assert validate(tmp_path,entry)['status']=='not_verified'


def test_unsupported_encoding_and_attachment_do_not_become_safe(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy())
    p.consume(capture(request(b'not_decoded',b'Content-Encoding: unknown\r\n')))
    assert p.rows[0]['completeness']=='unknown' and p.assessments[0]['risk']=='unknown'
    p.consume(capture(request(b'{"model":"m","input":[{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}'),2))
    assert 'attachment_reference_or_inline' in p.rows[-1]['semantics']
    assert not p.rows[-1]['can_enforce']


def test_ip_or_domain_alone_is_not_llm_identification(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy());p.consume(capture(request(b'{"health":"ok"}')))
    assert p.rows[0]['llm_identification']=='unknown'


def test_compression_bomb_is_rejected_before_full_expansion():
    from transpect_trace.observe.models import BODY_LIMIT
    data=gzip.compress(b'x'*(BODY_LIMIT+100))
    with pytest.raises(CoverageGap):decode_body(data,'gzip')


def test_capture_default_serialization_omits_raw_bytes():
    event=capture(b"secret")
    assert 'data_b64' not in event.model_dump() and 'secret' not in event.model_dump_json()


def test_ecapture_preview_never_claims_a_complete_connection(tmp_path):
    from transpect_trace.observe.ecapture import ECaptureCollector
    from types import SimpleNamespace
    p=Pipeline(tmp_path,GuardPolicy())
    collector=ECaptureCollector({'pid':12,'creation_filetime':100},SimpleNamespace(application='python-api'),None,p)
    collector.line('PID:12 TID:2 SSPIAppData send len=500 data="POST /responses HTTP/1.1"')
    assert p.gaps and not p.rows


def test_partial_wss_message_on_close_is_not_silently_dropped():
    from transpect_trace.observe.protocol import WebSocket
    conn=Connection();conn.ws=WebSocket({})
    assert not conn.feed(capture(frame(b'half',fin=False)))[1]
    _,gaps=conn.feed(capture(b'',2,event='closed'))
    assert gaps


def test_tool_json_schema_is_not_a_runtime_tool_call(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy())
    body=json.dumps({'model':'m','input':[{'role':'user','content':'hello'}],
                     'tools':[{'type':'function','parameters':{'properties':{'type':{'type':'string'},'role':{'type':'string'}}}}]}).encode()
    p.consume(capture(body,capture_point='http-body'))
    assert len(p.rows)==1 and p.rows[0]['semantics']==['prompt','tool_specifications']


def test_etw_enrichment_does_not_rewrite_the_original_assessment(tmp_path):
    from transpect_trace.guard.etw import EtwIndex,FILE
    policy=GuardPolicy(content_markers=[Marker(marker_id='registered',value='FAKE_REGISTERED_CONTENT',source_path='C:/fixture/private.txt')])
    pipeline=Pipeline(tmp_path,policy)
    pipeline.consume(capture(request(b'{"model":"m","input":"FAKE_REGISTERED_CONTENT"}')))
    index=EtwIndex(12,100)
    index.consume({'kind':'etw.event','provider':FILE,'task':'Read','sequence':1,'timestamp_qpc':20,'header_pid':12,'header_tid':1,'opcode':67,'properties':{'FileName':'C:/fixture/private.txt'}})
    pipeline.finish(index)
    sources=[json.loads(row) for row in (tmp_path/'source-relations.jsonl').read_text().splitlines()]
    assert sources[0]['confidence']=='High' and not sources[0]['byte_level_taint_proof']
    original=json.loads((tmp_path/'assessments.jsonl').read_text())
    assert original['source_confidence']=='Unknown' and original['risk']=='critical' and original['effective_action']=='audit'


def test_observation_profile_cannot_be_enabled_as_a_gate():
    from transpect_trace.observe.windows import Profile
    with pytest.raises(ValueError):Profile(image_sha256='a'*64,application='python-api',mode='schannel',can_enforce=True)


def test_capture_loss_quarantines_future_fragments(tmp_path):
    p=Pipeline(tmp_path,GuardPolicy());wire=request(b'{"model":"m","input":"private"}')
    p.consume(capture(wire[:35]));p.consume(capture(wire[35:70],3));p.consume(capture(wire[70:],4))
    assert not p.rows and p.gaps


def test_context_and_weak_signals_do_not_override_hard_secrets(tmp_path):
    from transpect_trace.observe.policy import ObservationPolicy
    policy=ObservationPolicy(warning_keywords=['internal draft'],allowed_application_hashes=['a'*64],
                             content_policy=GuardPolicy(allowed_upstreams=['trusted.test']))
    p=Pipeline(tmp_path,policy)
    p.consume(capture(request(b'{"model":"m","input":"internal draft"}'),image_sha256='b'*64))
    assert p.assessments[0]['risk']=='warning' and p.assessments[0]['recommended_action']=='warn'
    p.consume(capture(b'{"model":"m","input":"mysql_password=FakeSecret123"}',capture_point='http-body',connection_id='other'))
    assert p.assessments[-1]['risk']=='critical' and p.assessments[-1]['recommended_action']=='block_request'
    assert p.assessments[-1]['source_confidence']=='Unknown' and p.assessments[-1]['effective_action']=='audit'
