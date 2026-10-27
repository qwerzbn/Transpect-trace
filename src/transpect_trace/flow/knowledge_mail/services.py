"""Owned, loopback-only real BookStack/MariaDB/Mailpit experiment services.

This module creates application instances, never substitutes mock services for
an unavailable Docker engine. Bodies and credentials are returned in memory;
``identity`` and ``mail_receipts`` expose only non-secret evidence.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4


IMAGES = {
    'database': 'mariadb:11.4.5',
    'bookstack': 'lscr.io/linuxserver/bookstack:version-v26.03.3',
    'mailpit': 'axllent/mailpit:v1.29.7',
}
MAX_RESPONSE = 2 * 1024 * 1024
OWNER_LABEL = 'io.transpect.knowledge-mail.owner'


class ServiceError(RuntimeError):
    """An audit-safe diagnostic code, without command output or secrets."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ServiceError('service_redirect_rejected')


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _available_loopback_port() -> int:
    # Docker remains responsible for the real bind. A race yields a startup
    # failure, never fallback to a public interface or a different origin.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False)
    if os.name == 'nt':
        identity = subprocess.check_output(
            ['whoami', '/user', '/fo', 'csv', '/nh'], encoding='utf-8')
        sid = list(csv.reader(identity.splitlines()))[0][1]
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                        '*' + sid + ':(OI)(CI)F'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        path.chmod(0o700)


class LocalServices:
    """Disposable services with explicit resource ownership and bounded HTTP.

    ``start`` must finish before any experiment participant is released. The
    two public URLs use localhost; container ports are bound to 127.0.0.1.
    No external SMTP relay, credentials, or host application data are mounted.
    """

    def __init__(self, root: Path, *, images: dict[str, str] | None = None):
        self.root = Path(root).resolve()
        self.images = dict(IMAGES if images is None else images)
        if set(self.images) != set(IMAGES) or any(
                not isinstance(image, str) or not image or ':latest' in image
                or ':' not in image.rsplit('/', 1)[-1]
                or any(char.isspace() for char in image) for image in self.images.values()):
            raise ValueError('explicit_versioned_service_images_required')
        self.owner = 'ttrace-km-' + uuid4().hex[:16]
        self.network = self.owner + '-network'
        self.containers: dict[str, str] = {}
        self.volumes: list[str] = []
        self._network_created = False
        self._book_id: int | None = None
        self.bookstack_url = ''
        self.mailpit_url = ''
        self.token_id = secrets.token_hex(16)
        self.token_secret = secrets.token_hex(24)
        self._password = secrets.token_hex(24)
        self.identity: dict = {'state': 'not_started', 'owner': self.owner,
                               'can_enforce': False, 'external_mail_delivery': False}
        self.cleanup_errors: list[str] = []
        self._failed_start_cleanup_unknown = False

    def _docker(self, *args: str, timeout: float = 45,
                stdin: str | None = None) -> str:
        try:
            result = subprocess.run(['docker', '--context', 'desktop-linux', *args],
                                    input=stdin, capture_output=True, text=True,
                                    encoding='utf-8', errors='replace', timeout=timeout,
                                    creationflags=0x08000000 if os.name == 'nt' else 0)
        except FileNotFoundError as error:
            raise ServiceError('docker_not_installed') from error
        except subprocess.TimeoutExpired as error:
            raise ServiceError('docker_operation_timeout') from error
        if result.returncode:
            # Docker stderr can include environment variables or credentials.
            raise ServiceError('docker_operation_failed')
        return result.stdout.strip()

    def _http(self, method: str, url: str, *, value=None,
              authenticated=False, raw=False):
        headers = {'Accept': 'application/json'}
        if authenticated:
            headers['Authorization'] = f'Token {self.token_id}:{self.token_secret}'
        body = None if value is None else json.dumps(
            value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if body is not None:
            headers['Content-Type'] = 'application/json'
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(Request(url, data=body, headers=headers, method=method),
                             timeout=8) as response:
                data = response.read(MAX_RESPONSE + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise ServiceError('service_http_failed') from error
        if len(data) > MAX_RESPONSE:
            raise ServiceError('service_response_limit')
        if raw:
            return data
        try:
            return json.loads(data)
        except (ValueError, UnicodeError) as error:
            raise ServiceError('service_response_invalid_json') from error

    def _port(self, container: str, port: int) -> int:
        data = json.loads(self._docker('inspect', '--format',
                                      '{{json .NetworkSettings.Ports}}', container))
        bindings = data.get(f'{port}/tcp') or []
        if len(bindings) != 1 or bindings[0].get('HostIp') != '127.0.0.1':
            raise ServiceError('service_not_loopback_bound')
        return int(bindings[0]['HostPort'])

    def _env_file(self, role: str, values: dict[str, str]) -> Path:
        target = self.root / 'explicit-local-test-credentials' / (role + '.env')
        target.write_text(''.join(f'{key}={value}\n' for key, value in values.items()),
                          encoding='utf-8')
        return target

    def _run(self, role: str, image: str, *extra: str) -> str:
        name = self.owner + '-' + role
        try:
            identifier = self._docker('run', '--detach', '--name', name,
                                      '--label', f'{OWNER_LABEL}={self.owner}',
                                      '--network', self.network, *extra, image,
                                      timeout=60)
            if not re.fullmatch(r'[a-f0-9]{12,64}', identifier):
                raise ServiceError('container_identity_invalid')
        except ServiceError:
            # A failed `docker run` can still create a stopped container, for
            # example when publishing its port fails. Query only this exact
            # name and recover only an identity carrying this run's owner.
            try:
                record = self._docker('inspect', '--format',
                                      '{{.Id}}|{{index .Config.Labels "' + OWNER_LABEL + '"}}', name)
                recovered, separator, owner = record.partition('|')
                if not separator or not re.fullmatch(r'[a-f0-9]{12,64}', recovered):
                    self._failed_start_cleanup_unknown = True
                elif owner == self.owner:
                    self.containers[role] = recovered
                # A different owner is an unrelated resource, never reclaimed.
            except ServiceError:
                self._failed_start_cleanup_unknown = True
            raise
        self.containers[role] = identifier
        return identifier

    def start(self, timeout: float = 240):
        if self.identity['state'] != 'not_started':
            raise ServiceError('services_already_started')
        self.root.mkdir(parents=True, exist_ok=True)
        credentials = self.root / 'explicit-local-test-credentials'
        _private_directory(credentials)
        self.identity['state'] = 'starting'
        try:
            try:
                engine = self._docker('version', '--format', '{{.Server.Version}}', timeout=8)
            except ServiceError as error:
                raise ServiceError('docker_engine_unavailable') from error
            images = {}
            self.identity.update(engine_version=engine, images=images)
            for role, image in self.images.items():
                try:
                    installed = self._docker('image', 'inspect', image)
                except ServiceError:
                    self._docker('pull', image, timeout=max(60, timeout))
                    installed = self._docker('image', 'inspect', image)
                details = json.loads(installed)[0]
                if not details.get('RepoDigests') or not details.get('Id'):
                    raise ServiceError('image_digest_unavailable')
                images[role] = {'reference': image, 'image_id': details['Id'],
                                'repo_digests': details['RepoDigests']}
            # Docker 29 does not publish container ports on --internal
            # networks. Use an owned bridge with explicit loopback publishes;
            # it is not advertised as a network-egress sandbox.
            self._docker('network', 'create', '--label',
                         f'{OWNER_LABEL}={self.owner}', self.network)
            self._network_created = True
            for role in ('database', 'bookstack'):
                name = self.owner + '-' + role + '-data'
                self._docker('volume', 'create', '--label', f'{OWNER_LABEL}={self.owner}', name)
                self.volumes.append(name)
            database_prefix = 'MYSQL' if self.images['database'].split(':')[0].rsplit('/', 1)[-1] == 'mysql' else 'MARIADB'
            database_env = self._env_file('database', {
                database_prefix + '_ROOT_PASSWORD': self._password,
                database_prefix + '_DATABASE': 'bookstack', database_prefix + '_USER': 'bookstack',
                database_prefix + '_PASSWORD': self._password})
            self._run('database', self.images['database'], '--network-alias', 'database',
                      '--env-file', str(database_env), '--mount',
                      f'type=volume,source={self.volumes[0]},target=/var/lib/mysql')
            bookstack_port = _available_loopback_port()
            self.bookstack_url = f'http://localhost:{bookstack_port}'
            bookstack_env = self._env_file('bookstack', {
                'PUID': '1000', 'PGID': '1000', 'TZ': 'Asia/Shanghai',
                'APP_KEY': 'base64:' + base64.b64encode(secrets.token_bytes(32)).decode('ascii'),
                'APP_URL': self.bookstack_url, 'DB_HOST': 'database', 'DB_PORT': '3306',
                'DB_USERNAME': 'bookstack', 'DB_PASSWORD': self._password,
                'DB_DATABASE': 'bookstack', 'MAIL_DRIVER': 'log',
                'SESSION_SECURE_COOKIE': 'false'})
            bookstack = self._run('bookstack', self.images['bookstack'], '--publish',
                                  f'127.0.0.1:{bookstack_port}:80', '--env-file', str(bookstack_env),
                                  '--mount', f'type=volume,source={self.volumes[1]},target=/config')
            mailpit = self._run('mailpit', self.images['mailpit'], '--publish', '127.0.0.1::8025')
            if self._port(bookstack, 80) != bookstack_port:
                raise ServiceError('bookstack_origin_binding_mismatch')
            self.mailpit_url = f'http://localhost:{self._port(mailpit, 8025)}'
            deadline = time.monotonic() + timeout
            while True:
                try:
                    self._provision_token()
                    result = self._http('GET', self.bookstack_url + '/api/books', authenticated=True)
                    mail = self._http('GET', self.mailpit_url + '/api/v1/messages?limit=1')
                    if not isinstance(result.get('data'), list) or 'messages' not in mail:
                        raise ServiceError('service_readiness_invalid')
                    break
                except ServiceError:
                    if time.monotonic() >= deadline:
                        raise ServiceError('services_ready_timeout')
                    time.sleep(1)
            version = self._docker('exec', bookstack, 'cat', '/app/www/version')
            self.identity.update(state='ready', engine_version=engine, images=images,
                                 containers=dict(self.containers), bookstack_version=version,
                                 bookstack_url=self.bookstack_url, mailpit_url=self.mailpit_url,
                                 smtp_relay_configured=False, network_egress_isolated=False,
                                 network_scope='owned_bridge_with_loopback_published_ports')
            return self
        except Exception as error:
            self.identity.update(state='unavailable', reason=(str(error) if isinstance(error, ServiceError)
                                                            else type(error).__name__))
            self.close()
            raise

    def _php(self, body: str) -> str:
        source = ("<?php\nrequire '/app/www/vendor/autoload.php';\n"
                  "$app = require '/app/www/bootstrap/app.php';\n"
                  "$app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap();\n" + body)
        return self._docker('exec', '-i', self.containers['bookstack'], 'php', stdin=source)

    def _provision_token(self):
        payload = base64.b64encode(json.dumps({'id': self.token_id, 'secret': self.token_secret,
                                               'password': self._password}).encode()).decode()
        result = self._php(
            "$c=json_decode(base64_decode('" + payload + "'),true);\n"
            "$u=\\BookStack\\Users\\Models\\User::query()->where('email','admin@admin.com')->firstOrFail();\n"
            "$u->password=\\Illuminate\\Support\\Facades\\Hash::make($c['password']);$u->save();\n"
            "$t=\\BookStack\\Api\\ApiToken::query()->where('token_id',$c['id'])->first() ?: new \\BookStack\\Api\\ApiToken();\n"
            "$t->forceFill(['name'=>'Transpect local fake-data experiment','token_id'=>$c['id'],"
            "'secret'=>\\Illuminate\\Support\\Facades\\Hash::make($c['secret']),'user_id'=>$u->id,"
            "'expires_at'=>\\Illuminate\\Support\\Carbon::now()->addDay()->format('Y-m-d')])->save();\n"
            "echo 'TOKEN_READY';\n")
        if not result.endswith('TOKEN_READY'):
            raise ServiceError('bookstack_token_provision_failed')

    def seed_page(self, title: str, markdown: str) -> dict:
        if self.identity['state'] != 'ready':
            raise ServiceError('services_not_ready')
        if self._book_id is None:
            book = self._http('POST', self.bookstack_url + '/api/books', authenticated=True,
                              value={'name': 'Transpect fake-data knowledge base',
                                     'description': 'Isolated local experiment; synthetic data only.'})
            self._book_id = int(book['id'])
        result = self._http('POST', self.bookstack_url + '/api/pages', authenticated=True,
                            value={'book_id': self._book_id, 'name': title, 'markdown': markdown})
        return result

    def get_page(self, page_id: int) -> dict:
        if not isinstance(page_id, int) or isinstance(page_id, bool) or page_id < 1:
            raise ValueError('invalid_page_id')
        return self._http('GET', self.bookstack_url + f'/api/pages/{page_id}', authenticated=True)

    def update_page(self, page_id: int, markdown: str) -> dict:
        if not isinstance(page_id, int) or isinstance(page_id, bool) or page_id < 1:
            raise ValueError('invalid_page_id')
        return self._http('PUT', self.bookstack_url + f'/api/pages/{page_id}', authenticated=True,
                          value={'markdown': markdown})

    def get_mail(self, message_id: str) -> dict:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', message_id):
            raise ValueError('invalid_message_id')
        return self._http('GET', self.mailpit_url + '/api/v1/message/' + message_id)

    def mail_receipts(self) -> list[dict]:
        listing = self._http('GET', self.mailpit_url + '/api/v1/messages?limit=1000')
        if not isinstance(listing.get('messages'), list):
            raise ServiceError('mailpit_listing_invalid')
        # Mailpit total is authoritative; do not silently truncate receiver
        # evidence to a first page and call the experiment complete.
        if int(listing.get('total', len(listing['messages']))) != len(listing['messages']):
            raise ServiceError('mailpit_receipt_listing_incomplete')
        receipts = []
        for summary in listing['messages']:
            message_id = summary['ID']
            message = self.get_mail(message_id)
            text = message.get('Text', '').encode('utf-8')
            html = message.get('HTML', '').encode('utf-8')
            raw = self._http('GET', self.mailpit_url + '/api/v1/message/' + message_id + '/raw', raw=True)
            receipts.append({'message_id': message_id,
                             'text_sha256': _sha(text), 'text_bytes': len(text),
                             'html_sha256': _sha(html), 'html_bytes': len(html),
                             'raw_sha256': _sha(raw), 'raw_bytes': len(raw),
                             'evidence_source': 'real_mailpit_receive_store',
                             'external_delivery': False})
        return receipts

    def get_mail_raw(self, message_id: str) -> bytes:
        """Raw receiver bytes for an explicit in-memory oracle, never audit."""
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', message_id):
            raise ValueError('invalid_message_id')
        return self._http('GET', self.mailpit_url + '/api/v1/message/' + message_id + '/raw', raw=True)

    def close(self) -> dict:
        """Remove only exact resources created by this instance; retain evidence."""
        self.cleanup_errors.clear()
        if self._failed_start_cleanup_unknown:
            self.cleanup_errors.append('failed_container_start_cleanup_unverified')
        for role, container in list(self.containers.items())[::-1]:
            try:
                owner = self._docker('inspect', '--format',
                                     '{{index .Config.Labels "' + OWNER_LABEL + '"}}', container)
                if owner != self.owner:
                    raise ServiceError('container_cleanup_owner_mismatch')
                self._docker('rm', '--force', container)
                del self.containers[role]
            except ServiceError as error:
                self.cleanup_errors.append(str(error))
        if self._network_created and not self.containers:
            try:
                owner = self._docker('network', 'inspect', '--format',
                                     '{{index .Labels "' + OWNER_LABEL + '"}}', self.network)
                if owner != self.owner:
                    raise ServiceError('network_cleanup_owner_mismatch')
                self._docker('network', 'rm', self.network)
                self._network_created = False
            except ServiceError as error:
                self.cleanup_errors.append(str(error))
        for volume in self.volumes[:]:
            if self.containers:
                break
            try:
                owner = self._docker('volume', 'inspect', '--format',
                                     '{{index .Labels "' + OWNER_LABEL + '"}}', volume)
                if owner != self.owner:
                    raise ServiceError('volume_cleanup_owner_mismatch')
                self._docker('volume', 'rm', volume)
                self.volumes.remove(volume)
            except ServiceError as error:
                self.cleanup_errors.append(str(error))
        clean = not self.containers and not self.volumes and not self._network_created and not self.cleanup_errors
        self.identity['cleanup_confirmed'] = clean
        if self.identity['state'] == 'ready':
            self.identity['state'] = 'stopped' if clean else 'cleanup_failed'
        return {'cleanup_confirmed': clean, 'errors': self.cleanup_errors.copy(),
                'owned_containers_remaining': list(self.containers),
                'owned_volumes_remaining': len(self.volumes)}
