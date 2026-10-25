"""Bounded in-memory fixture messages. These are not audit serialization models."""
from __future__ import annotations

import json
import math
import re

LIMIT = 1024 * 1024
MESSAGE_SCHEMA = 'transpect.agent.message/1.0'
OUTBOUND_SCHEMA = 'transpect.agent.outbound/1.0'
MODES = ('copy', 'nested', 'extractive', 'public')


def _id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{32}', value):
        raise ValueError('invalid_protocol_identifier')
    return value


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate_json_key')
        value[key] = item
    return value


def _constant(_):
    raise ValueError('nonfinite_json_number')


def _bounded(value):
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 50000:
            raise ValueError('json_structure_limit')
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError('nonfinite_json_number')
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)


def parse_json(raw):
    try:
        if not isinstance(raw, bytes) or len(raw) > LIMIT:
            raise ValueError('message_size_limit')
        value = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_pairs, parse_constant=_constant)
        _bounded(value)
        return value
    except (UnicodeError, RecursionError, TypeError, ValueError) as error:
        raise ValueError('invalid_bounded_json') from None


def encode(value):
    try:
        _bounded(value)
        data = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (UnicodeError, RecursionError, TypeError, ValueError):
        raise ValueError('invalid_bounded_json') from None
    if len(data) > LIMIT:
        raise ValueError('message_size_limit')
    return data


def parse_message(raw):
    value = parse_json(raw)
    required = {'schema', 'task_id', 'message_id', 'sender_agent', 'recipient_agent', 'payload'}
    if (not isinstance(value, dict) or set(value) != required or value['schema'] != MESSAGE_SCHEMA
            or value['sender_agent'] != 'agent-a' or value['recipient_agent'] != 'agent-b'
            or not isinstance(value['payload'], (str, dict))):
        raise ValueError('invalid_agent_message')
    _id(value['task_id']); _id(value['message_id'])
    return value


def make_message(task_id, message_id, payload):
    data = encode({'schema': MESSAGE_SCHEMA, 'task_id': task_id, 'message_id': message_id,
                   'sender_agent': 'agent-a', 'recipient_agent': 'agent-b', 'payload': payload})
    parse_message(data)
    return data


def parse_outbound(raw):
    value = parse_json(raw)
    required = {'schema', 'task_id', 'parent_message_id', 'tool_call_id', 'attempt_id', 'agent_id', 'report'}
    if (not isinstance(value, dict) or set(value) != required or value['schema'] != OUTBOUND_SCHEMA
            or value['agent_id'] != 'agent-b' or not isinstance(value['report'], (dict, str))):
        raise ValueError('invalid_agent_outbound')
    for key in ('task_id', 'parent_message_id', 'tool_call_id', 'attempt_id'):
        _id(value[key])
    return value


def make_outbound(task_id, parent_message_id, tool_call_id, attempt_id, report):
    data = encode({'schema': OUTBOUND_SCHEMA, 'task_id': task_id, 'parent_message_id': parent_message_id,
                   'tool_call_id': tool_call_id, 'attempt_id': attempt_id, 'agent_id': 'agent-b', 'report': report})
    parse_outbound(data)
    return data


def query_payload(raw, public_only=False):
    """Deterministic test data query; does not imply database instrumentation."""
    value = parse_json(raw)
    if not isinstance(value, dict) or any(not isinstance(value.get(k), str)
                                          for k in ('public_text', 'api_key', 'document')):
        raise ValueError('invalid_fixture_dataset')
    keys = ('public_text',) if public_only else ('public_text', 'api_key', 'document')
    return {key: value[key] for key in keys}


def transform_payload(payload, mode):
    """Deterministic copy/nesting/extract, never a claim of generative summary."""
    if mode not in MODES or not isinstance(payload, (dict, str)):
        raise ValueError('unsupported_transformation')
    if mode == 'copy':
        return parse_json(encode(payload))
    if mode == 'nested':
        return {'sections': [{'kind': 'test-report', 'content': parse_json(encode(payload))}]}
    if mode == 'public':
        # "public" is a fixture selection, not a security label exemption.
        return {'public_text': payload.get('public_text', 'ordinary agent report') if isinstance(payload, dict)
                else 'ordinary agent report'}
    if isinstance(payload, str):
        return payload
    parts = [payload.get('public_text', '')]
    if 'api_key' in payload:
        parts.append('api_key=' + str(payload['api_key']))
    if 'document' in payload:
        parts.append(str(payload['document']))
    return '摘录报告\n' + '\n'.join(parts)
