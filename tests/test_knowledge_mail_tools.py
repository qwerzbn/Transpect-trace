"""Component tests do not certify a real BookStack/Mailpit or Native run."""
from __future__ import annotations

from email.message import Message
import hashlib
import json
from types import SimpleNamespace
import urllib.error

import pytest

from transpect_trace.flow.knowledge_mail.tools import (
    KnowledgeMailTools, LIMIT, NATIVE_OWNER, ToolError, encode_draft, local_endpoint,
    strict_json, validate_draft,
)


def draft(text='公开的项目进展，已经完成测试。'):
    return {'From': {'Email': 'codex@transpect.test'},
            'To': [{'Email': 'partner@example.test'}], 'Subject': 'Project update', 'Text': text}


@pytest.fixture
def tool(tmp_path):
    return KnowledgeMailTools({'bookstack_url': 'http://localhost:18081',
        'mailpit_url': 'http://localhost:18025', 'token_id': 'LOCAL_TOKEN_ID',
        'token_secret': 'LOCAL_TOKEN_SECRET', 'run_id': 'component-only',
        'audit_path': str(tmp_path / 'audit.jsonl')})


@pytest.mark.parametrize('url', ['http://localhost:18081', 'http://127.0.0.1:18081/',
                                'https://[::1]:18081'])
def test_fixed_loopback_application_endpoints(url):
    assert local_endpoint(url) == url.rstrip('/')


@pytest.mark.parametrize('url', ['https://example.com', 'http://localhost.evil.test',
    'http://user:secret@localhost', 'http://localhost/api', 'http://localhost?key=secret',
    'http://localhost/#private', 'file:///tmp/data', 'http://localhost:99999',
    'http://localhost:0', None])
def test_remote_or_credential_bearing_endpoints_are_rejected(url):
    with pytest.raises(ToolError, match='LOCAL_ENDPOINT_REQUIRED'):
        local_endpoint(url)


def test_text_mail_json_roundtrip_preserves_unicode():
    value = draft()
    assert strict_json(encode_draft(value)) == value
    assert validate_draft(value) == value


@pytest.mark.parametrize('change', [
    {'HTML': '<p>uninspected</p>'}, {'Attachments': []}, {'Bcc': []},
    {'From': {'Email': 'sender@example.com'}}, {'To': [{'Email': 'victim@example.com'}]},
    {'To': []}, {'To': [{'Email': 'bad\n@example.test'}]},
    {'To': [{'Email': 'partner@example.test', 'Name': 'bad\nheader'}]},
    {'To': [{'Email': 'partner@example.test', 'extra': 'uninspected'}]},
    {'Subject': 'bad\r\nheader'}, {'Text': b'not text'}, {'Text': ''},
    {'Text': 'a' * LIMIT},
], ids=['html', 'attachments', 'bcc', 'sender-domain', 'recipient-domain', 'empty-to',
        'address-newline', 'name-newline', 'unknown-address-field', 'subject-newline',
        'binary-text', 'empty-text', 'over-limit'])
def test_unsupported_or_unbounded_mail_is_not_sent(change):
    with pytest.raises(ToolError):
        validate_draft({**draft(), **change})


@pytest.mark.parametrize('raw', [b'{"Text":1,"Text":2}', b'{"x":NaN}', b'\xff', b'{', b'', b'x' * (LIMIT + 1)],
                         ids=['duplicate', 'nonfinite', 'binary', 'truncated', 'empty', 'over-limit'])
def test_strict_json_rejects_ambiguous_or_uninspectable_input(raw):
    with pytest.raises(ToolError):
        strict_json(raw)


class Response:
    def __init__(self, raw, *, content_type='application/json', status=200):
        self.raw, self.status = raw, status
        self.headers = Message()
        self.headers['Content-Type'] = content_type
    def read(self, size):
        return self.raw[:size]
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


def test_actual_page_api_body_is_returned_but_audit_is_redacted(tool):
    secret = 'FAKE_ONLY_PRIVATE_BODY_01234567890123456789'
    page = {'id': 8, 'name': 'private title ' + secret, 'markdown': secret, 'revision_count': 3}
    requests = []
    def open_(request, timeout):
        requests.append(request)
        assert timeout == 15
        return Response(json.dumps(page).encode())
    tool.opener = SimpleNamespace(open=open_)
    result = tool.read_page(8)
    assert requests[0].full_url == 'http://localhost:18081/api/pages/8'
    assert requests[0].get_method() == 'GET'
    assert requests[0].get_header('Authorization') == 'Token LOCAL_TOKEN_ID:LOCAL_TOKEN_SECRET'
    assert result['markdown'] == secret and result['revision_count'] == 3
    audit = tool.audit_path.read_text()
    assert secret not in audit and 'LOCAL_TOKEN_SECRET' not in audit
    assert 'private title' not in audit
    assert json.loads(audit)['body_sha256'] == hashlib.sha256(secret.encode()).hexdigest()


@pytest.mark.parametrize('identifier', [True, 0, -1, '1/../../private', 2**31])
def test_page_identifier_cannot_change_the_api_route(tool, identifier):
    with pytest.raises(ToolError, match='PAGE_ID_INVALID'):
        tool.read_page(identifier)


def test_page_identity_or_body_type_mismatch_is_rejected(tool):
    for page in ({'id': 7, 'name': 'page', 'markdown': 'text'},
                 {'id': 8, 'name': 'page', 'markdown': None}):
        tool.opener = SimpleNamespace(open=lambda *args, **kwargs: Response(json.dumps(page).encode()))
        with pytest.raises(ToolError, match='BOOKSTACK_PAGE_UNSUPPORTED'):
            tool.read_page(8)


def test_redirect_or_http_error_is_sanitized(tool):
    def fail(request, timeout):
        raise urllib.error.HTTPError('https://unlogged.test/?secret=x', 302, 'SECRET_REMOTE_ERROR', {}, None)
    tool.opener = SimpleNamespace(open=fail)
    with pytest.raises(ToolError, match='BOOKSTACK_REQUEST_FAILED'):
        tool.read_page(8)
    assert 'SECRET' not in tool.audit_path.read_text()


def test_send_requires_controlled_native_startup(tool, monkeypatch):
    import httpx
    monkeypatch.setattr(httpx.HTTPTransport, '_ttrace_owner', None, raising=False)
    with pytest.raises(ToolError, match='NATIVE_GATE_NOT_READY'):
        tool.send_mail(draft())
    assert json.loads(tool.audit_path.read_text())['kind'] == 'mail_not_submitted'


def component_client(monkeypatch, callback):
    import httpx
    monkeypatch.setattr(httpx.HTTPTransport, '_ttrace_owner', NATIVE_OWNER, raising=False)
    class Client:
        def __init__(self, **options):
            assert options['follow_redirects'] is False and options['trust_env'] is False
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def post(self, url, **options):
            assert url == 'http://localhost:18025/api/v1/send'
            assert options['headers'] == {'Content-Type': 'application/json'}
            return callback(options['content'])
    monkeypatch.setattr(httpx, 'Client', Client)


def test_mailpit_success_is_only_local_acceptance(tool, monkeypatch):
    bodies = []
    def accepted(raw):
        bodies.append(raw)
        return SimpleNamespace(status_code=200)
    component_client(monkeypatch, accepted)
    value = draft()
    result = tool.send_mail(value)
    assert strict_json(bodies[0]) == value
    assert result['kind'] == 'mail_sent'
    assert result['delivery_scope'] == 'local_mailpit_acceptance'
    assert result['receipt_verified'] is False
    assert value['Text'] not in tool.audit_path.read_text()


def test_permission_failure_is_not_itself_native_refusal_proof(tool, monkeypatch):
    def denied(raw):
        raise PermissionError('SECRET_SHOULD_NOT_BE_LOGGED')
    component_client(monkeypatch, denied)
    result = tool.send_mail(draft())
    assert result['kind'] == 'mail_blocked' and result['execution_verified'] is False
    assert 'SECRET_SHOULD_NOT_BE_LOGGED' not in tool.audit_path.read_text()


def test_mail_attempts_are_never_deduplicated_by_body_hash(tool, monkeypatch):
    component_client(monkeypatch, lambda raw: SimpleNamespace(status_code=200))
    first, second = tool.send_mail(draft()), tool.send_mail(draft())
    assert first['body_sha256'] == second['body_sha256']
    assert first['tool_attempt_id'] != second['tool_attempt_id']


@pytest.mark.parametrize('status', [301, 302, 307, 400, 500])
def test_redirect_and_failed_submission_are_not_delivery(tool, monkeypatch, status):
    component_client(monkeypatch, lambda raw: SimpleNamespace(status_code=status))
    with pytest.raises(ToolError, match='MAIL_HTTP_FAILURE'):
        tool.send_mail(draft())


def test_default_read_transport_does_not_use_environment_proxy(tool):
    assert not any(getattr(handler, 'proxies', None) for handler in tool.opener.handlers)
    redirects = [handler for handler in tool.opener.handlers
                 if isinstance(handler, __import__('urllib.request', fromlist=['HTTPRedirectHandler']).HTTPRedirectHandler)]
    assert len(redirects) == 1
    assert redirects[0].redirect_request(None, None, 302, '', {}, 'http://evil.test') is None
