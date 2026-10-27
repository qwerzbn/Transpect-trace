import base64
import hashlib
import io
import json
from pathlib import Path
import struct

import jsonschema
import pytest

from transpect_trace.flow.browser.decoder import BrowserDecoder, loopback_origin
from transpect_trace.flow.browser.host import read_frame, write_frame, serve
from transpect_trace.flow.browser.models import BrowserRequestObservation, LIMIT, WIRE_LIMIT
from transpect_trace.flow.browser.runtime import report_browser_run, extension_identity

ROOT = Path(__file__).resolve().parents[1]


def config(tmp_path=None):
    return {'browser_run_id':'browser-test', 'origin':'https://localhost:9443',
            'extension_id':'a'*32, 'enrollment_token':'c'*64,
            'audit_directory':str(tmp_path/'audit') if tmp_path else 'unused'}


def frame(sequence, kind='request', **fields):
    body = fields.pop('body', b'{"message":"public incident count 2"}')
    row = {'protocol':'BWO1', 'browser_run_id':'browser-test', 'enrollment_token':'c'*64,
           'extension_session_id':'worker-1', 'sequence':sequence, 'kind':kind}
    if kind == 'ready': row['extension_id'] = 'a'*32
    if kind == 'request':
        row.update(request_id='request-1', request_stage=1, tab_id=1, frame_id=0,
                   document_id='doc-1', url='https://localhost:9443/upload?token=must-not-persist',
                   method='POST', event_phase='before_send_headers', body_bytes=len(body),
                   body_base64=base64.b64encode(body).decode(), raw_complete=True, gaps=[],
                   content_type='application/json; charset=utf-8', content_encoding='identity')
    row.update(fields)
    return row


def decoder():
    value = BrowserDecoder(config())
    value.consume(frame(1, 'ready'))
    return value


def pack(*frames):
    stream = io.BytesIO()
    for item in frames:
        data = json.dumps(item).encode()
        stream.write(struct.pack('<I', len(data)) + data)
    return io.BytesIO(stream.getvalue())


def test_plaintext_detection_schema_and_default_privacy():
    record = decoder().consume(frame(2, body=b'{"nested":{"password":"browser_fake_secret_123456"}}',
        Authorization='Bearer NOT-PERSIST', Cookie='NEVER-PERSIST'))
    data = record.model_dump()
    assert data['completeness'] == 'complete' and data['detection_status'] == 'matched'
    assert data['network_process'] is None and data['can_enforce'] is False
    text = record.model_dump_json()
    assert all(value not in text for value in ('browser_fake_secret', 'NOT-PERSIST', 'NEVER-PERSIST', 'must-not-persist'))
    jsonschema.validate(data, json.loads((ROOT/'schemas/browser-request-observation-v1.schema.json').read_text()))


def test_ordinary_and_sensitive_read_only_negative():
    record = decoder().consume(frame(2))
    assert record.detection_status == 'no_match'
    assert record.findings == []
    assert 'safe' not in record.model_dump_json().lower()


def test_same_content_tabs_and_redirect_stages_remain_independent():
    engine = decoder()
    first = engine.consume(frame(2))
    second = engine.consume(frame(3, request_id='request-2', tab_id=2, document_id='doc-2'))
    third = engine.consume(frame(4, request_stage=2, document_id='doc-new'))
    assert len({r.observation_id for r in (first, second, third)}) == 3
    assert first.body_sha256 == second.body_sha256 == third.body_sha256
    assert first.request_id_sha256 == third.request_id_sha256 != second.request_id_sha256
    assert first.document_id_sha256 != third.document_id_sha256
    with pytest.raises(ValueError, match='duplicate_request_stage'):
        engine.consume(frame(5, request_stage=2))


@pytest.mark.parametrize('changes', [
    {'gaps':['file_reference'], 'raw_complete':False, 'body':b''},
    {'gaps':['form_data_unsupported'], 'raw_complete':False, 'body':b''},
    {'gaps':['body_limit'], 'body_bytes':LIMIT+1, 'raw_complete':False, 'body':b''},
    {'body_bytes':999},
    {'content_type':'multipart/form-data; boundary=x'},
    {'content_encoding':'gzip'},
    {'event_phase':'request_aborted_before_headers', 'gaps':['headers_unavailable']},
])
def test_unsupported_or_missing_body_never_complete(changes):
    row = decoder().consume(frame(2, **changes))
    assert row.completeness == 'partial' and row.detection_status == 'incomplete'


@pytest.mark.parametrize('body,content', [(b'\xff', 'text/plain'), (b'{broken', 'application/json')])
def test_transport_boundary_does_not_imply_parse_success(body,content):
    row = decoder().consume(frame(2, body=body, content_type=content))
    assert row.completeness == 'complete'  # complete API bytes, parsing is separate
    assert row.parsing_state == 'failed' and row.detection_status == 'incomplete'


@pytest.mark.parametrize('size', [70000, LIMIT])
def test_large_chinese_and_limit_body(size):
    prefix = '中文普通数据'.encode()
    body = prefix + b'x'*(size-len(prefix))
    row = decoder().consume(frame(2, body=body, content_type='text/plain'))
    assert row.completeness == 'complete' and row.body_bytes == size
    assert row.body_sha256 == hashlib.sha256(body).hexdigest()


@pytest.mark.parametrize('changes', [
    {'enrollment_token':'d'*64}, {'sequence':3}, {'extension_session_id':'worker-2'},
    {'url':'https://example.com/upload'}, {'url':'https://localhost:9443/private'},
    {'url':'https://secret@localhost:9443/upload'}, {'method':'DELETE'},
    {'tab_id':True}, {'body_base64':'!!!!'}, {'body_base64':'A'*(2*LIMIT)},
    {'gaps':['arbitrary secret']}, {'request_id':'request?credential'},
])
def test_invalid_enrollment_identity_payload_and_target(changes):
    value = frame(2)
    value.update(changes)
    with pytest.raises(ValueError): decoder().consume(value)


@pytest.mark.parametrize('origin', ['http://localhost:443', 'https://example.com', 'https://localhost/?token=a',
                                    'https://user:pass@localhost', 'https://localhost/path'])
def test_origin_is_loopback_https_only(origin):
    with pytest.raises(ValueError): loopback_origin(origin)


@pytest.mark.parametrize('raw', [b'\x01', struct.pack('<I', WIRE_LIMIT+1), struct.pack('<I', 0),
                                 struct.pack('<I', 4)+b'{}', struct.pack('<I', 1)+b'\xff'])
def test_malformed_native_frames_are_bounded(raw):
    with pytest.raises((ValueError, EOFError, UnicodeError)):
        read_frame(io.BytesIO(raw))


def test_partial_native_pipe_reads_supported():
    class Fragmented(io.BytesIO):
        def read(self, size=-1): return super().read(min(size, 3))
    value = frame(1,'ready')
    assert read_frame(Fragmented(pack(value).getvalue())) == value
    assert read_frame(io.BytesIO()) is None


def test_terminal_health_and_receiver_counts_are_independent(tmp_path):
    settings = config(tmp_path)
    _ = serve(settings, 'chrome-extension://'+'a'*32+'/',
              pack(frame(1,'ready'), frame(2), frame(3,'request',request_id='request-2'), frame(4,'terminal')), io.BytesIO())
    (tmp_path/'experiment.json').write_text(json.dumps({'browser_run_id':'browser-test'}))
    result = report_browser_run(tmp_path)
    assert result['status'] == 'complete_request_observation'
    assert result['source_receipts'] == 'unverified'
    assert not result['ecapture_certified'] and not result['real_site_certified']
    receipt = {k:result['observations'][0][k] for k in ('body_sha256','body_bytes')}
    assert report_browser_run(tmp_path, receipts=[receipt,receipt])['source_receipts'] == 'multiset_match_candidate'
    assert report_browser_run(tmp_path, receipts=[receipt])['status'] == 'partial'


@pytest.mark.parametrize('tail', [[], [frame(3,'gap',gaps=['queue_overflow'],lost_events=1), frame(4,'terminal')]])
def test_disconnect_and_lost_events_prevent_complete_report(tmp_path,tail):
    health = serve(config(tmp_path), 'chrome-extension://'+'a'*32+'/', pack(frame(1,'ready'),frame(2),*tail),io.BytesIO())
    (tmp_path/'experiment.json').write_text(json.dumps({'browser_run_id':'browser-test'}))
    assert report_browser_run(tmp_path)['status'] == 'partial'
    assert not health['terminal'] or health['lost_events']


def test_worker_restart_preserves_original_missing_terminal(tmp_path):
    settings = config(tmp_path)
    serve(settings,'chrome-extension://'+'a'*32+'/',pack(frame(1,'ready'),frame(2)),io.BytesIO())
    serve(settings,'chrome-extension://'+'a'*32+'/',pack(frame(1,'ready'),frame(2),frame(3,'terminal')),io.BytesIO())
    (tmp_path/'experiment.json').write_text(json.dumps({'browser_run_id':'browser-test'}))
    result = report_browser_run(tmp_path)
    assert len(result['observations']) == 2 and len(result['collector_health']) == 2
    assert result['status'] == 'partial'


def test_missing_persisted_request_cannot_be_hidden_by_matching_remaining_receipt(tmp_path):
    serve(config(tmp_path), 'chrome-extension://'+'a'*32+'/',
          pack(frame(1,'ready'), frame(2), frame(3,request_id='second'), frame(4,'terminal')), io.BytesIO())
    (tmp_path/'experiment.json').write_text(json.dumps({'browser_run_id':'browser-test'}))
    path = next((tmp_path/'audit').glob('*/requests.jsonl'))
    first = path.read_text().splitlines()[0]
    path.write_text(first+'\n')
    receipt = {k:json.loads(first)[k] for k in ('body_sha256','body_bytes')}
    report = report_browser_run(tmp_path,receipts=[receipt])
    assert report['source_receipts'] == 'multiset_match_candidate'
    assert report['status'] == 'partial'
    assert 'request_audit_count_mismatch' in report['limitations']


def test_unregistered_caller_rejected_before_audit_creation(tmp_path):
    with pytest.raises(ValueError,match='caller_not_enrolled'):
        serve(config(tmp_path), 'chrome-extension://'+'b'*32+'/', io.BytesIO(),io.BytesIO())
    assert not (tmp_path/'audit').exists()


def test_extension_identity_and_api_permissions():
    manifest = json.loads((ROOT/'extensions/browser-observe/manifest.json').read_text())
    assert extension_identity(manifest) == 'mdgfhbilljhgcgklilfdnildpgdlpkeg'
    assert set(manifest['permissions']) == {'webRequest','nativeMessaging','storage'}
    assert '<all_urls>' not in manifest['host_permissions']
    assert 'webRequestBlocking' not in manifest['permissions']
    assert BrowserRequestObservation.model_json_schema() == json.loads((ROOT/'schemas/browser-request-observation-v1.schema.json').read_text())
