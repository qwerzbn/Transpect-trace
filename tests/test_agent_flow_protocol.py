import json

import pytest

from transpect_trace.flow.agents import protocol as p


@pytest.mark.parametrize('raw', [b'{"payload":1,"payload":2}', b'{"x":NaN}', b'{"x":Infinity}',
                                     b'\xff', b'"private-secret', b'['*34+b'0'+b']'*34,
                                     b'['+b'0,'*50000+b'0]', b'0'*(p.LIMIT+1)],
                         ids=['duplicate','nan','infinity','utf8','truncated','depth','nodes','size'])
def test_invalid_json_is_bounded_and_error_does_not_echo_content(raw):
    with pytest.raises(ValueError, match='^invalid_bounded_json$'):
        p.parse_json(raw)


def test_total_envelope_size_not_inner_payload_controls_limit():
    base = p.make_message('a'*32, 'b'*32, '')
    exact = p.make_message('a'*32, 'b'*32, 'x'*(p.LIMIT-len(base)))
    assert len(exact) == p.LIMIT
    assert len(p.parse_message(exact)['payload']) == p.LIMIT-len(base)
    with pytest.raises(ValueError, match='size_limit'):
        p.make_message('a'*32, 'b'*32, 'x'*(p.LIMIT-len(base)+1))


def test_exponent_overflow_is_rejected_like_nonfinite_literals():
    with pytest.raises(ValueError, match='invalid_bounded_json'):
        p.parse_json(b'{"number":1e999}')
    with pytest.raises(ValueError, match='invalid_bounded_json'):
        p.encode({'number':float('inf')})


@pytest.mark.parametrize('key,value', [('task_id','not-an-id'), ('message_id','f'*33),
                                    ('sender_agent','agent-b'), ('recipient_agent','agent-a'), ('payload',[]),
                                    ('extra','content')])
def test_message_schema_rejects_identity_and_shape_ambiguity(key,value):
    message = json.loads(p.make_message('a'*32,'b'*32, {'text':'中文'}))
    message[key] = value
    with pytest.raises(ValueError):
        p.parse_message(p.encode(message))


def test_outbound_ids_are_separate_from_content_and_send_attempt_changes():
    first = p.parse_outbound(p.make_outbound('a'*32,'b'*32,'c'*32,'d'*32,{'text':'same'}))
    second = p.parse_outbound(p.make_outbound('a'*32,'b'*32,'c'*32,'e'*32,{'text':'same'}))
    assert first['report'] == second['report'] and first['attempt_id'] != second['attempt_id']
    assert first['parent_message_id'] == 'b'*32


@pytest.mark.parametrize('mode', ['copy','nested','extractive'])
def test_positive_transforms_keep_selected_content_without_unrelated_source_fields(mode):
    raw = p.encode({'public_text':'普通文本','api_key':'SYNTHETIC-CREDENTIAL','document':'登记文本','irrelevant':'OMITTED'})
    payload = p.query_payload(raw)
    encoded = p.encode(p.transform_payload(payload,mode))
    assert '普通文本'.encode() in encoded and b'SYNTHETIC-CREDENTIAL' in encoded
    assert '登记文本'.encode() in encoded and b'OMITTED' not in encoded


def test_both_negative_controls_preserve_read_fact_but_remove_sensitive_output():
    raw = p.encode({'public_text':'ordinary','api_key':'SYNTHETIC-CREDENTIAL','document':'REGISTERED-CONTENT'})
    assert b'SYNTHETIC-CREDENTIAL' in raw
    public_delegation = p.query_payload(raw, public_only=True)
    public_upload = p.transform_payload(p.query_payload(raw),'public')
    for payload in (public_delegation, public_upload):
        assert payload == {'public_text':'ordinary'}
        assert b'SYNTHETIC-CREDENTIAL' not in p.encode(payload)
