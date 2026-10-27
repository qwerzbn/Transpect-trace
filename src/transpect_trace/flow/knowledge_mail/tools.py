"""Bounded tools for a real BookStack -> Mailpit text-mail experiment.

BookStack reads use its normal REST API. Mailpit writes use standard HTTPX,
which must have the controlled Native startup bridge installed. This module
does not implement its own policy bypass or claim a Python exception is proof
of a Native refusal; the controller must verify execution evidence separately.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from uuid import uuid4

LIMIT = 1024 * 1024
NATIVE_OWNER = 'python-httpx-outbound-native/1'


class ToolError(ValueError):
    """Only fixed diagnostic codes, never remote responses or credentials."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw: bytes) -> Any:
    if not raw or len(raw) > LIMIT:
        raise ToolError('JSON_SIZE_UNSUPPORTED')

    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ToolError('JSON_DUPLICATE_KEY')
            result[key] = value
        return result

    try:
        return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ToolError('JSON_NUMBER_UNSUPPORTED')))
    except (UnicodeError, ValueError, RecursionError):
        raise ToolError('JSON_INVALID') from None


def _address(value: Any) -> dict:
    if not isinstance(value, dict) or not set(value) <= {'Email', 'Name'} or 'Email' not in value:
        raise ToolError('MAIL_ADDRESS_INVALID')
    email = value['Email']
    if (not isinstance(email, str) or len(email) > 254
            or not re.fullmatch(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', email)
            or not email.rsplit('@', 1)[-1].lower().endswith('.test')):
        raise ToolError('MAIL_TEST_ADDRESS_REQUIRED')
    name = value.get('Name', '')
    if not isinstance(name, str) or len(name.encode('utf-8')) > 1024 or '\r' in name or '\n' in name:
        raise ToolError('MAIL_ADDRESS_NAME_INVALID')
    return dict(value)


def validate_draft(value: Any) -> dict:
    """Mailpit's text Send API subset; no attachments, HTML, CC or BCC."""
    if not isinstance(value, dict) or set(value) != {'From', 'To', 'Subject', 'Text'}:
        raise ToolError('MAIL_FIELDS_UNSUPPORTED')
    sender = _address(value['From'])
    recipients = value['To']
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 8:
        raise ToolError('MAIL_RECIPIENTS_INVALID')
    recipients = [_address(item) for item in recipients]
    subject, text = value['Subject'], value['Text']
    if (not isinstance(subject, str) or not subject or len(subject.encode('utf-8')) > 998
            or '\r' in subject or '\n' in subject):
        raise ToolError('MAIL_SUBJECT_INVALID')
    if not isinstance(text, str) or not text:
        raise ToolError('MAIL_TEXT_INVALID')
    result = {'From': sender, 'To': recipients, 'Subject': subject, 'Text': text}
    try:
        raw = json.dumps(result, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (UnicodeError, ValueError):
        raise ToolError('MAIL_TEXT_INVALID') from None
    if len(raw) > LIMIT:
        raise ToolError('MAIL_BODY_TOO_LARGE')
    return result


def encode_draft(value: Any) -> bytes:
    return json.dumps(validate_draft(value), ensure_ascii=False, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def local_endpoint(value: Any) -> str:
    if not isinstance(value, str):
        raise ToolError('LOCAL_ENDPOINT_REQUIRED')
    try:
        url = urlsplit(value)
        host, port = url.hostname, url.port
    except ValueError:
        raise ToolError('LOCAL_ENDPOINT_REQUIRED') from None
    if (url.scheme not in {'http', 'https'} or not host or url.username or url.password
            or url.query or url.fragment or url.path not in {'', '/'}
            or (port is not None and not 1 <= port <= 65535)):
        raise ToolError('LOCAL_ENDPOINT_REQUIRED')
    try:
        local = host.lower() == 'localhost' or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if not local:
        raise ToolError('LOCAL_ENDPOINT_REQUIRED')
    return value.rstrip('/')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class KnowledgeMailTools:
    def __init__(self, config: dict):
        self.bookstack_url = local_endpoint(config['bookstack_url'])
        self.mailpit_url = local_endpoint(config['mailpit_url'])
        self.token_id, self.token_secret = config['token_id'], config['token_secret']
        # Reject header injection without printing the supplied values.
        for token in (self.token_id, self.token_secret):
            if not isinstance(token, str) or not token or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', token):
                raise ToolError('BOOKSTACK_TOKEN_INVALID')
        self.run_id = config['run_id']
        if not isinstance(self.run_id, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', self.run_id):
            raise ToolError('RUN_ID_INVALID')
        self.audit_path = Path(config['audit_path'])
        self.ssl_context = ssl.create_default_context(cafile=config.get('ca_certificate'))
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=self.ssl_context))

    def audit(self, kind: str, **metadata) -> None:
        row = {'kind': kind, 'run_id': self.run_id, 'pid': os.getpid(), **metadata}
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open('a', encoding='utf-8') as out:
            out.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')

    def read_page(self, page_id: int) -> dict:
        if isinstance(page_id, bool) or not isinstance(page_id, int) or not 0 < page_id < 2**31:
            raise ToolError('PAGE_ID_INVALID')
        request = urllib.request.Request(
            self.bookstack_url + f'/api/pages/{page_id}',
            headers={'Authorization': f'Token {self.token_id}:{self.token_secret}',
                     'Accept': 'application/json'}, method='GET')
        try:
            with self.opener.open(request, timeout=15) as response:
                if response.status != 200 or response.headers.get_content_type() != 'application/json':
                    raise ToolError('BOOKSTACK_RESPONSE_UNSUPPORTED')
                raw = response.read(LIMIT + 1)
        except (OSError, urllib.error.URLError):
            self.audit('knowledge_read_failed', page_id=page_id, reason='BOOKSTACK_REQUEST_FAILED')
            raise ToolError('BOOKSTACK_REQUEST_FAILED') from None
        value = strict_json(raw)
        if (not isinstance(value, dict) or type(value.get('id')) is not int or value['id'] != page_id
                or not isinstance(value.get('name'), str)
                or not isinstance(value.get('markdown'), str)):
            raise ToolError('BOOKSTACK_PAGE_UNSUPPORTED')
        text = value['markdown']
        text_raw = text.encode('utf-8')
        if len(text_raw) > LIMIT:
            raise ToolError('BOOKSTACK_PAGE_TOO_LARGE')
        revision = value.get('revision_count')
        if revision is not None and (type(revision) is not int or revision < 0):
            raise ToolError('BOOKSTACK_REVISION_INVALID')
        self.audit('knowledge_page_read', page_id=page_id, revision_count=revision,
                   body_sha256=sha256(text_raw), body_bytes=len(text_raw),
                   response_sha256=sha256(raw))
        # This return is transient tool input for the real Agent. No page text
        # or title is written into the default evidence/audit above.
        return {'kind': 'bookstack_page', 'page_id': page_id, 'title': value['name'],
                'markdown': text, 'revision_count': revision,
                'body_sha256': sha256(text_raw), 'body_bytes': len(text_raw)}

    def send_mail(self, draft: dict) -> dict:
        import httpx
        raw = encode_draft(draft)
        attempt = uuid4().hex
        metadata = {'tool_attempt_id': attempt, 'body_sha256': sha256(raw), 'body_bytes': len(raw)}
        if getattr(httpx.HTTPTransport, '_ttrace_owner', None) != NATIVE_OWNER:
            self.audit('mail_not_submitted', **metadata, reason='NATIVE_GATE_NOT_READY')
            raise ToolError('NATIVE_GATE_NOT_READY')
        self.audit('mail_submission_requested', **metadata)
        try:
            with httpx.Client(verify=self.ssl_context, trust_env=False,
                              follow_redirects=False, timeout=15) as client:
                response = client.post(self.mailpit_url + '/api/v1/send', content=raw,
                                       headers={'Content-Type': 'application/json'})
        except PermissionError:
            # This is the client's observation only; the parent controller
            # separately joins Native execution evidence to certify refusal.
            result = {'kind': 'mail_blocked', **metadata, 'reason': 'NATIVE_PERMISSION_DENIED',
                      'execution_verified': False}
            self.audit('mail_submission_denied', **metadata, reason='NATIVE_PERMISSION_DENIED')
            return result
        except Exception:
            self.audit('mail_submission_failed', **metadata, reason='MAIL_TRANSPORT_FAILED')
            raise ToolError('MAIL_TRANSPORT_FAILED') from None
        if response.status_code not in {200, 201, 202}:
            self.audit('mail_submission_failed', **metadata, reason='MAIL_HTTP_FAILURE',
                       status_code=response.status_code)
            raise ToolError('MAIL_HTTP_FAILURE')
        # Mailpit returning success is application acceptance, not external
        # SMTP delivery. Querying the stored message supplies receiver evidence.
        result = {'kind': 'mail_sent', **metadata, 'status_code': response.status_code,
                  'delivery_scope': 'local_mailpit_acceptance', 'receipt_verified': False}
        self.audit('mail_submission_accepted', **metadata, status_code=response.status_code)
        return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    read = commands.add_parser('read-page')
    read.add_argument('page_id', type=int)
    send = commands.add_parser('send-mail')
    send.add_argument('--draft', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = strict_json(args.config.read_bytes())
        tools = KnowledgeMailTools(config)
        if args.command == 'read-page':
            result = tools.read_page(args.page_id)
        else:
            result = tools.send_mail(strict_json(args.draft.read_bytes()))
        print(json.dumps(result, ensure_ascii=False, separators=(',', ':')), flush=True)
        return 2 if result['kind'] == 'mail_blocked' else 0
    except Exception as error:
        reason = str(error) if isinstance(error, ToolError) else 'TOOL_EXECUTION_FAILED'
        print(json.dumps({'kind': 'tool_failed', 'reason': reason}), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
