"""Mail content decisions remain distinct from Native execution evidence."""
from __future__ import annotations

import hashlib
import json

import pytest

from transpect_trace.flow.knowledge_mail.policy import MailPolicyEngine
from transpect_trace.flow.knowledge_mail.tools import LIMIT, NATIVE_OWNER, encode_draft
from transpect_trace.protect.detection import ContentIndex
from transpect_trace.protect.models import SemanticCaptureEvent


SECRET = 'FAKE_ONLY_REGISTERED_PRIVATE_NOTE_0123456789abcdef'


def draft(text='公开的项目摘要，只含允许发送的信息。'):
    return {'From': {'Email': 'codex@transpect.test'},
            'To': [{'Email': 'partner@example.test'}], 'Subject': 'Project summary', 'Text': text}


def event(value=None, **changes):
    raw = encode_draft(draft() if value is None else value)
    fields = dict(run_id='mail-component', adapter_id=NATIVE_OWNER, application='python-outbound',
                  channel='api', pid=22, creation_filetime=123, image_sha256='a' * 64,
                  gate_owner=NATIVE_OWNER, protocol='httpx', destination_host='localhost',
                  completeness='complete', body_sha256=hashlib.sha256(raw).hexdigest(),
                  body_bytes=len(raw), body=raw)
    fields.update(changes)
    return SemanticCaptureEvent(**fields)


def engine(**kwargs):
    index = ContentIndex.register('knowledge-mail-test/1', [('private-note', SECRET, 'CONFIDENTIAL', ['registered_text'])])
    return MailPolicyEngine(index, **kwargs)


def test_normal_text_mail_is_authorized_without_claiming_external_delivery():
    policy = engine()
    verdict = policy.evaluate(event())
    assert verdict.decision == 'ALLOW' and verdict.requested_action == 'none'
    assert verdict.actual_action == 'not_confirmed'
    assert policy.captures[0]['capture_layer'] == 'request-body'
    assert 'host_only' in policy.captures[0]['endpoint_binding']


@pytest.mark.parametrize('location', ['Text', 'Subject', 'FromName', 'ToName'])
def test_secret_in_body_subject_or_display_name_is_blocked(location):
    value = draft()
    if location == 'FromName':
        value['From']['Name'] = SECRET
    elif location == 'ToName':
        value['To'][0]['Name'] = SECRET
    else:
        value[location] = SECRET
    policy = engine()
    verdict = policy.evaluate(event(value))
    assert verdict.decision == 'BLOCK' and verdict.requested_action == 'block_request'
    assert any(hit.rule_id == 'REGISTERED_EXACT' for hit in verdict.findings)
    assert SECRET not in json.dumps(policy.captures)
    assert SECRET not in verdict.model_dump_json()


def test_sensitive_source_read_does_not_block_clean_final_email():
    assert engine().evaluate(event(draft('仅发送公开统计，内容已筛选。'))).decision == 'ALLOW'


@pytest.mark.parametrize('changes', [
    {'completeness': 'partial'}, {'completeness': 'unknown'}, {'encoding_state': 'compressed'},
    {'content_encoding': 'gzip'}, {'limitations': ['lost_frame']}, {'adapter_id': 'unverified'},
    {'gate_owner': None}, {'destination_host': 'example.com'}, {'method': 'GET'},
    {'method': 'PUT'}, {'capture_stage': 'after_transport'}, {'body': b''},
])
def test_missing_preconditions_refuse_the_covered_request(changes):
    verdict = engine().evaluate(event(**changes))
    assert verdict.decision == 'UNKNOWN' and verdict.requested_action == 'block_request'
    assert verdict.detection_status == 'incomplete'


@pytest.mark.parametrize('raw', [b'{"Text":"a","Text":"b"}', b'{"x":NaN}', b'null', b'[]', b'\xff',
    b'{"From":{"Email":"x@example.com"},"To":[],"Subject":"s","Text":"t"}',
    b'{}', b'{"Attachments":[]}'])
def test_malformed_or_unsupported_mail_is_never_authorized(raw):
    value = event().model_copy(update={'body': raw, 'body_bytes': len(raw),
                                      'body_sha256': hashlib.sha256(raw).hexdigest()})
    assert engine().evaluate(value).decision == 'UNKNOWN'


def test_size_hash_and_complete_snapshot_are_checked():
    value = event()
    for changes in ({'body_bytes': value.body_bytes + 1}, {'body_sha256': '0' * 64},
                    {'body': b'a' * (LIMIT + 1), 'body_bytes': LIMIT + 1,
                     'body_sha256': hashlib.sha256(b'a' * (LIMIT + 1)).hexdigest()}):
        assert engine().evaluate(value.model_copy(update=changes)).decision == 'UNKNOWN'


def test_optional_explicit_recipient_and_sender_registration():
    policy = engine(allowed_sender='codex@transpect.test', allowed_recipients=['partner@example.test'])
    assert policy.evaluate(event()).decision == 'ALLOW'
    changed = draft()
    changed['To'][0]['Email'] = 'other@example.test'
    assert policy.evaluate(event(changed)).decision == 'UNKNOWN'
    changed = draft()
    changed['From']['Email'] = 'other@transpect.test'
    assert policy.evaluate(event(changed)).decision == 'UNKNOWN'


@pytest.mark.parametrize('exception', [ValueError, RuntimeError])
def test_detector_failure_is_not_a_no_match(monkeypatch, exception):
    def fail(*args, **kwargs):
        raise exception('private error context')
    monkeypatch.setattr('transpect_trace.flow.knowledge_mail.policy.detect', fail)
    verdict = engine().evaluate(event())
    assert verdict.decision == 'UNKNOWN' and verdict.reason == 'REQUIRED_MAIL_CHECK_FAILED'
    assert 'private error' not in verdict.model_dump_json()
