"""Real MCP wire framing and tool dispatch; mocks are component-only."""
from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest

from transpect_trace.flow.knowledge_mail import mcp
from transpect_trace.flow.knowledge_mail.tools import LIMIT, encode_draft


def draft(text='Only public project information.'):
    return {'From': {'Email': 'codex@transpect.test'},
            'To': [{'Email': 'partner@example.test'}], 'Subject': 'Project update', 'Text': text}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    path = tmp_path / 'private' / 'tools.json'
    path.parent.mkdir()
    output = tmp_path / 'explicit-fake-fixtures' / 'mail.json'
    config = {'bookstack_url': 'http://localhost:18081', 'mailpit_url': 'http://localhost:18025',
              'token_id': 'LOCAL_TOKEN_ID', 'token_secret': 'LOCAL_TOKEN_SECRET',
              'audit_path': str(tmp_path / 'tools.jsonl'), 'run_id': 'mcp-component',
              'page_id': 7, 'draft_path': str(output)}
    path.write_text(json.dumps(config), encoding='utf-8')
    calls = []
    def read_page(self, page_id):
        calls.append(('read', page_id))
        return {'kind': 'bookstack_page', 'page_id': page_id, 'markdown': 'FAKE_ONLY_PRIVATE_SOURCE_TEXT'}
    def send(config_path, draft_path):
        calls.append(('send', config_path, draft_path, draft_path.read_bytes()))
        return {'kind': 'mail_sent', 'execution_verified': True, 'tool_invocation': 'a' * 32,
                'delivery_scope': 'local_mailpit_acceptance', 'Text': 'MUST_NOT_BE_RETURNED',
                'Authorization': 'SECRET_TOKEN'}
    monkeypatch.setattr(mcp.KnowledgeMailTools, 'read_page', read_page)
    monkeypatch.setattr(mcp, 'send_protected', send)
    return path, output, calls


def request(method, params=None, identifier=1):
    result = {'jsonrpc': '2.0', 'id': identifier, 'method': method}
    if params is not None:
        result['params'] = params
    return result


def initialize(server, version='2025-06-18'):
    result = server.handle(request('initialize', {'protocolVersion': version, 'capabilities': {},
                                                 'clientInfo': {'name': 'component-client', 'version': '1'}}))
    assert server.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) is None
    return result


def tool_call(name, arguments):
    return request('tools/call', {'name': name, 'arguments': arguments})


@pytest.mark.parametrize('version', ['2024-11-05', '2025-03-26', '2025-06-18', 'future-version'])
def test_initialize_negotiates_documented_versions(setup, version):
    server = mcp.MCPServer(setup[0])
    response = initialize(server, version)
    assert response['jsonrpc'] == '2.0' and response['id'] == 1
    assert response['result']['protocolVersion'] == (version if version in mcp.VERSIONS else '2024-11-05')
    assert response['result']['capabilities'] == {'tools': {'listChanged': False}}


def test_initialize_notification_is_required_before_tools(setup):
    server = mcp.MCPServer(setup[0])
    assert server.handle(request('tools/list'))['error']['code'] == -32002
    server.handle(request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {}}))
    assert server.handle(request('tools/list'))['error']['code'] == -32002
    server.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
    assert len(server.handle(request('tools/list'))['result']['tools']) == 2
    assert server.handle(request('initialize', {}))['error']['code'] == -32600


def test_real_tools_list_has_input_schemas_and_only_two_tools(setup):
    server = mcp.MCPServer(setup[0])
    initialize(server)
    response = server.handle(request('tools/list'))
    tools = response['result']['tools']
    assert [row['name'] for row in tools] == ['read_page', 'send_mail']
    assert tools[0]['inputSchema']['properties']['page_id']['enum'] == [7]
    assert all(row['inputSchema']['additionalProperties'] is False for row in tools)
    assert 'token' not in json.dumps(response).lower()


def test_read_page_returns_real_mcp_text_content_without_default_body_audit(setup):
    server = mcp.MCPServer(setup[0])
    initialize(server)
    response = server.handle(tool_call('read_page', {'page_id': 7}))
    result = response['result']
    assert result['isError'] is False
    assert 'structuredContent' not in result
    value = json.loads(result['content'][0]['text'])
    assert value['markdown'] == 'FAKE_ONLY_PRIVATE_SOURCE_TEXT'
    assert setup[2] == [('read', 7)]


@pytest.mark.parametrize('arguments', [{'page_id': 8}, {'page_id': True}, {'page_id': 7.0},
                                     {'page_id': '7'}, {}, {'page_id': 7, 'path': 'private'}])
def test_only_registered_page_and_exact_arguments_can_be_read(setup, arguments):
    server = mcp.MCPServer(setup[0])
    initialize(server)
    assert server.handle(tool_call('read_page', arguments))['error']['code'] == -32602
    assert not setup[2]


def test_send_writes_exact_draft_to_fixed_path_then_delegates_native_runner(setup):
    config_path, draft_path, calls = setup
    server = mcp.MCPServer(config_path)
    initialize(server)
    value = draft('中文公开信息。')
    response = server.handle(tool_call('send_mail', {'draft': value}))
    result = response['result']
    assert result['isError'] is False
    assert result['structuredContent']['kind'] == 'mail_sent'
    assert draft_path.read_bytes() == encode_draft(value)
    assert calls[0][:3] == ('send', config_path.resolve(), draft_path.resolve())
    assert calls[0][3] == encode_draft(value)
    public = json.dumps(result)
    assert 'MUST_NOT_BE_RETURNED' not in public and 'SECRET_TOKEN' not in public
    assert value['Text'] not in public


def test_verified_native_block_is_valid_tool_result_and_not_retry_instruction(setup, monkeypatch):
    monkeypatch.setattr(mcp, 'send_protected', lambda *args: {
        'kind': 'mail_blocked', 'execution_verified': True, 'tool_invocation': 'b' * 32,
        'reason': 'NATIVE_PERMISSION_DENIED'})
    server = mcp.MCPServer(setup[0])
    initialize(server)
    response = server.handle(tool_call('send_mail', {'draft': draft()}))['result']
    assert response['isError'] is False
    assert response['structuredContent']['kind'] == 'mail_blocked'
    assert response['structuredContent']['execution_verified'] is True


@pytest.mark.parametrize('value', [None, {}, {'kind': 'mail_sent', 'execution_verified': False},
    {'kind': 'mail_blocked', 'execution_verified': False},
    {'kind': 'tool_failed', 'execution_verified': True},
    {'kind': 'mail_sent', 'execution_verified': True, 'tool_invocation': 'SECRET'},
    {'kind': 'mail_sent', 'execution_verified': True, 'tool_invocation': 'b' * 32,
     'delivery_scope': 'external_delivery'}])
def test_unverified_gate_or_wrong_delivery_scope_is_error(setup, monkeypatch, value):
    monkeypatch.setattr(mcp, 'send_protected', lambda *args: value)
    server = mcp.MCPServer(setup[0])
    initialize(server)
    result = server.handle(tool_call('send_mail', {'draft': draft()}))['result']
    assert result['isError'] is True
    assert result['structuredContent']['kind'] == 'tool_failed'
    assert 'SECRET' not in json.dumps(result)


def test_gate_exception_never_appears_on_protocol_output(setup, monkeypatch):
    def fail(*args):
        raise RuntimeError('SECRET_EXCEPTION_PAYLOAD')
    monkeypatch.setattr(mcp, 'send_protected', fail)
    server = mcp.MCPServer(setup[0])
    initialize(server)
    result = server.handle(tool_call('send_mail', {'draft': draft()}))
    assert result['result']['isError'] is True and 'SECRET_EXCEPTION_PAYLOAD' not in json.dumps(result)


@pytest.mark.parametrize('arguments', [{'draft': {**draft(), 'Attachments': []}},
    {'draft': {**draft(), 'To': [{'Email': 'real@example.com'}]}},
    {'draft': {**draft(), 'Text': 'x' * LIMIT}}, {'draft': draft(), 'path': 'arbitrary.json'},
    {}, {'draft': None}])
def test_bad_draft_extra_arguments_or_path_never_delegate(setup, arguments):
    server = mcp.MCPServer(setup[0])
    initialize(server)
    assert server.handle(tool_call('send_mail', arguments))['error']['code'] == -32602
    assert not setup[2] and not setup[1].exists()


@pytest.mark.parametrize('identifier', [None, True, 1.2, '', 'x' * 129, 2**70])
def test_invalid_request_ids_are_not_executed(setup, identifier):
    server = mcp.MCPServer(setup[0])
    initialize(server)
    response = server.handle(request('tools/call', {'name': 'send_mail', 'arguments': {'draft': draft()}}, identifier))
    assert response['error']['code'] == -32600
    assert not setup[2]


def test_unknown_method_tool_and_extra_params_are_rejected(setup):
    server = mcp.MCPServer(setup[0])
    initialize(server)
    assert server.handle(request('arbitrary/execute'))['error']['code'] == -32601
    assert server.handle(tool_call('arbitrary', {}))['error']['code'] == -32602
    assert server.handle(request('tools/list', {'cursor': 'unknown'}))['error']['code'] == -32602
    value = request('tools/call', {'name': 'read_page', 'arguments': {'page_id': 7}, 'extra': 'bad'})
    assert server.handle(value)['error']['code'] == -32602
    assert not setup[2]


def wire(messages):
    return b''.join(json.dumps(value, ensure_ascii=False).encode() + b'\n' for value in messages)


def test_stdio_lifecycle_and_persistent_multiple_calls(setup):
    messages = [request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {}}),
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                request('ping', identifier='ping-1'), request('tools/list', identifier=2),
                tool_call('read_page', {'page_id': 7}), tool_call('read_page', {'page_id': 7})]
    incoming, outgoing = io.BytesIO(wire(messages)), io.BytesIO()
    assert mcp.serve(setup[0], incoming, outgoing) == 0
    lines = outgoing.getvalue().splitlines()
    assert len(lines) == 5  # initialized notification has no response
    replies = [json.loads(line) for line in lines]
    assert all(value['jsonrpc'] == '2.0' and 'result' in value for value in replies)
    assert replies[1]['id'] == 'ping-1' and replies[1]['result'] == {}
    assert setup[2] == [('read', 7), ('read', 7)]


def test_python_module_is_a_real_stdio_server_without_nonprotocol_stdout(setup):
    messages = [request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {}}),
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                request('tools/list', identifier=2)]
    # Real new Python process and stdin/stdout pipes; no service request or
    # Native certification is claimed by this transport-only component test.
    process = subprocess.run([sys.executable, '-m', 'transpect_trace.flow.knowledge_mail.mcp',
                              '--config', str(setup[0])], input=wire(messages),
                             capture_output=True, timeout=10)
    assert process.returncode == 0 and process.stderr == b''
    lines = process.stdout.splitlines()
    assert len(lines) == 2
    responses = [json.loads(line) for line in lines]
    assert responses[0]['result']['serverInfo']['name'] == 'transpect-knowledge-mail'
    assert [tool['name'] for tool in responses[1]['result']['tools']] == ['read_page', 'send_mail']


@pytest.mark.parametrize('raw', [b'{invalid}\n', b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}\n',
                               b'{"x":NaN}\n', b'\xff\n'])
def test_malformed_or_duplicate_json_is_parse_error_without_echo(setup, raw):
    output = io.BytesIO()
    assert mcp.serve(setup[0], io.BytesIO(raw), output) == 0
    response = json.loads(output.getvalue())
    assert response['error']['code'] == -32700 and response['id'] is None
    assert not setup[2]


@pytest.mark.parametrize('raw', [b'x' * (mcp.MAX_REQUEST + 1) + b'\n', b'{"jsonrpc":"2.0","id":1,"method":"ping"}'],
                         ids=['over-limit', 'unterminated'])
def test_oversized_or_unterminated_frames_stop_before_any_execution(setup, raw):
    output = io.BytesIO()
    assert mcp.serve(setup[0], io.BytesIO(raw), output) == 2
    assert json.loads(output.getvalue())['error']['code'] == -32600
    assert not setup[2]


@pytest.mark.parametrize('change', [{'page_id': True}, {'page_id': 8.5}, {'draft_path': 'relative.json'},
                                  {'draft_path': '/not/explicit-fixtures.json'}])
def test_configuration_cannot_expand_page_or_output_scope(setup, change):
    path = setup[0]
    value = json.loads(path.read_text())
    value.update(change)
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        mcp.MCPServer(path)
