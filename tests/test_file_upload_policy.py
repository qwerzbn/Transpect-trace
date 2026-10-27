"""Content checks for ordinary outbound JSON, not inferred LLM semantics."""
import hashlib
import json

import pytest

from transpect_trace.flow.file_upload_policy import FileUploadPolicyEngine, LIMIT
from transpect_trace.protect.detection import ContentIndex
from transpect_trace.protect.models import SemanticCaptureEvent


def event(value=None, **changes):
    raw = json.dumps(value if value is not None else {'report':'public statistics'}).encode()
    fields = dict(run_id='test', adapter_id='python-httpx-outbound-native/1', application='python-outbound',
                  channel='api', pid=2, creation_filetime=5, image_sha256='a'*64,
                  protocol='httpx', destination_host='localhost', api_path='unknown',
                  completeness='complete', body_sha256=hashlib.sha256(raw).hexdigest(),
                  body_bytes=len(raw), body=raw)
    fields.update(changes)
    return SemanticCaptureEvent(**fields)


def test_non_llm_public_upload_is_fully_checked_and_allowed():
    engine = FileUploadPolicyEngine()
    verdict = engine.evaluate(event())
    assert verdict.decision == 'ALLOW'
    assert verdict.detection_status == 'no_match'
    assert engine.captures[0]['capture_layer'] == 'request-body'


def test_registered_private_content_blocks_unknown_llm_route():
    secret = 'SYNTHETIC_REGISTERED_PRIVATE_NOTE_0123456789'
    index = ContentIndex.register('test/1', [('note', secret, 'CONFIDENTIAL', ['registered_text'])])
    engine = FileUploadPolicyEngine(index)
    verdict = engine.evaluate(event({'nested':{'note':secret}}))
    assert verdict.decision == 'BLOCK'
    assert verdict.requested_action == 'block_request'
    assert verdict.detection_status == 'matched'
    assert 'REGISTERED_EXACT' in {f.rule_id for f in verdict.findings}
    assert secret not in json.dumps(engine.captures)
    assert secret not in verdict.model_dump_json()


def test_reading_secret_is_not_a_policy_input():
    index = ContentIndex.register('test/1', [('note', 'SYNTHETIC_REGISTERED_PRIVATE_NOTE_0123456789', 'CONFIDENTIAL', ['registered_text'])])
    assert FileUploadPolicyEngine(index).evaluate(event()).decision == 'ALLOW'


@pytest.mark.parametrize('changes', [
    {'completeness':'partial'}, {'completeness':'unknown'}, {'encoding_state':'unsupported'},
    {'encoding_state':'compressed'}, {'content_encoding':'gzip'}, {'limitations':['gap']},
    {'adapter_id':'unverified'}, {'destination_host':'example.invalid'}, {'method':'GET'},
    {'capture_stage':'after_transport'}, {'body':b''},
])
def test_missing_protection_precondition_fails_closed(changes):
    verdict = FileUploadPolicyEngine().evaluate(event(**changes))
    assert verdict.decision == 'UNKNOWN'
    assert verdict.requested_action == 'block_request'
    assert verdict.detection_status == 'incomplete'


@pytest.mark.parametrize('raw', [b'{"key":1,"key":2}', b'{"key":NaN}', b'null', b'"text"', b'\xff', b'{'])
def test_unknown_json_never_allowed(raw):
    value = event(body=raw, body_bytes=len(raw), body_sha256=hashlib.sha256(raw).hexdigest())
    assert FileUploadPolicyEngine().evaluate(value).decision == 'UNKNOWN'


def test_limit_and_identity_snapshot():
    raw = b'{"report":"'+b'x'*LIMIT+b'"}'
    assert FileUploadPolicyEngine().evaluate(event(body=raw, body_bytes=len(raw), body_sha256=hashlib.sha256(raw).hexdigest())).decision == 'UNKNOWN'


def test_detection_error_fails_closed(monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError('required_detector_failed')
    monkeypatch.setattr('transpect_trace.flow.file_upload_policy.detect', fail)
    verdict = FileUploadPolicyEngine().evaluate(event())
    assert verdict.decision == 'UNKNOWN'
    assert verdict.reason == 'REQUIRED_UPLOAD_CHECK_FAILED'
