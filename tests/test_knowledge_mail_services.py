import hashlib
import json
import subprocess

import pytest

from transpect_trace.flow.knowledge_mail import services as module
from transpect_trace.flow.knowledge_mail.services import LocalServices, ServiceError


def test_engine_failure_is_unavailable_and_does_not_create_mock_app(tmp_path, monkeypatch):
    service = LocalServices(tmp_path / 'services')
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(args)
        raise ServiceError('docker_operation_failed')
    monkeypatch.setattr(service, '_docker', unavailable)
    monkeypatch.setattr(module, '_private_directory', lambda path: path.mkdir())
    with pytest.raises(ServiceError, match='docker_engine_unavailable'):
        service.start()
    assert service.identity['state'] == 'unavailable'
    assert service.identity['reason'] == 'docker_engine_unavailable'
    assert service.identity['cleanup_confirmed'] is True
    assert service.bookstack_url == service.mailpit_url == ''
    assert calls == [('version', '--format', '{{.Server.Version}}')]


def test_docker_errors_do_not_include_secret_stderr(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(
        a[0], 1, stdout='', stderr='FAKE_CREDENTIAL_MUST_NOT_LEAK'))
    with pytest.raises(ServiceError) as raised:
        service._docker('exec', 'owned-id', 'php')
    assert str(raised.value) == 'docker_operation_failed'
    assert 'FAKE_CREDENTIAL' not in repr(raised.value)


@pytest.mark.parametrize('bindings', [
    [], [{'HostIp': '0.0.0.0', 'HostPort': '1234'}],
    [{'HostIp': '127.0.0.1', 'HostPort': '1234'}, {'HostIp': '::', 'HostPort': '1234'}],
])
def test_non_loopback_or_ambiguous_port_is_rejected(tmp_path, monkeypatch, bindings):
    service = LocalServices(tmp_path)
    monkeypatch.setattr(service, '_docker', lambda *a, **k: json.dumps({'80/tcp': bindings}))
    with pytest.raises(ServiceError, match='service_not_loopback_bound'):
        service._port('container', 80)


def test_loopback_port_is_read_from_actual_docker_binding(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    monkeypatch.setattr(service, '_docker', lambda *a, **k: json.dumps(
        {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '54321'}]}))
    assert service._port('container', 80) == 54321


def test_receipts_are_independent_per_message_and_do_not_export_body(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    service.mailpit_url = 'http://localhost:8025'
    secret = 'FAKE_ONLY_SECRET_DO_NOT_EXPORT'
    calls = []
    def request(method, url, **kwargs):
        calls.append(url)
        if '/messages?' in url:
            return {'total': 2, 'messages': [{'ID': 'one'}, {'ID': 'two'}]}
        if url.endswith('/raw'):
            return b'From: local@example.test\r\n\r\n' + secret.encode()
        return {'Text': secret, 'HTML': '', 'Subject': 'private subject'}
    monkeypatch.setattr(service, '_http', request)
    receipts = service.mail_receipts()
    assert len(receipts) == 2
    assert [r['message_id'] for r in receipts] == ['one', 'two']
    assert all(r['text_sha256'] == hashlib.sha256(secret.encode()).hexdigest() for r in receipts)
    assert all(r['text_bytes'] == len(secret) for r in receipts)
    assert secret not in json.dumps(receipts)
    assert 'private subject' not in json.dumps(receipts)
    assert all(r['external_delivery'] is False for r in receipts)


def test_incomplete_receiver_pagination_is_not_called_complete(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    monkeypatch.setattr(service, '_http', lambda *a, **k: {'total': 3, 'messages': [{'ID': 'one'}]})
    with pytest.raises(ServiceError, match='mailpit_receipt_listing_incomplete'):
        service.mail_receipts()


def test_cleanup_refuses_resources_owned_by_another_run(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    service.containers = {'bookstack': 'abc123'}
    service.volumes = ['owned-data']
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        return 'different-owner'
    monkeypatch.setattr(service, '_docker', docker)
    result = service.close()
    assert result['cleanup_confirmed'] is False
    assert result['errors'] == ['container_cleanup_owner_mismatch']
    assert not any(args[0] in {'rm', 'volume'} for args in calls)
    assert service.containers == {'bookstack': 'abc123'}


def test_cleanup_removes_only_exact_owned_ids(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    service.containers = {'bookstack': 'abc123'}
    service.volumes = ['test-data']
    service._network_created = True
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        return service.owner if 'inspect' in args else ''
    monkeypatch.setattr(service, '_docker', docker)
    result = service.close()
    assert result['cleanup_confirmed'] is True
    assert ('rm', '--force', 'abc123') in calls
    assert ('volume', 'rm', 'test-data') in calls
    assert ('network', 'rm', service.network) in calls
    assert not any('prune' in args for args in calls)


@pytest.mark.parametrize('page_id', [0, -1, True, '../secrets', '1'])
def test_page_identity_does_not_accept_path_injection(tmp_path, page_id):
    service = LocalServices(tmp_path)
    with pytest.raises(ValueError, match='invalid_page_id'):
        service.get_page(page_id)


@pytest.mark.parametrize('message_id', ['../secret', 'a/b', '', 'a?token=secret'])
def test_mail_identity_does_not_accept_path_or_query_injection(tmp_path, message_id):
    with pytest.raises(ValueError, match='invalid_message_id'):
        LocalServices(tmp_path).get_mail(message_id)


def test_php_provision_sends_secret_on_stdin_not_command_line(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    service.containers['bookstack'] = 'owned-container'
    calls = []
    def docker(*args, **kwargs):
        calls.append((args, kwargs))
        return 'TOKEN_READY'
    monkeypatch.setattr(service, '_docker', docker)
    service._provision_token()
    assert calls[0][0] == ('exec', '-i', 'owned-container', 'php')
    assert service.token_secret not in repr(calls[0][0])
    assert 'forceFill' in calls[0][1]['stdin']
    assert 'Hash::make' in calls[0][1]['stdin']
    assert service.token_secret not in json.dumps(service.identity)


def test_named_service_images_are_versioned():
    assert all(':latest' not in image for image in module.IMAGES.values())
    assert set(module.IMAGES) == {'database', 'bookstack', 'mailpit'}


@pytest.mark.parametrize('image', ['bookstack', 'bookstack:latest', 'bookstack:1 --privileged'])
def test_explicit_image_overrides_cannot_use_floating_or_argument_values(tmp_path, image):
    with pytest.raises(ValueError, match='explicit_versioned_service_images_required'):
        LocalServices(tmp_path, images={**module.IMAGES, 'bookstack': image})


def test_start_uses_owned_bridge_actual_loopback_ports_and_inspected_images(tmp_path, monkeypatch):
    service = LocalServices(tmp_path / 'services', images={**module.IMAGES, 'database': 'mysql:8.0.36'})
    calls, launches = [], []
    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == 'version':
            return '29.8.0'
        if args[:2] == ('image', 'inspect'):
            return json.dumps([{'Id': 'sha256:abc', 'RepoDigests': ['repo@sha256:def']}])
        if args[0] == 'exec':
            return 'v26.03.3'
        return ''
    def launch(role, image, *extra):
        launches.append((role, image, extra))
        service.containers[role] = 'owned-' + role
        return service.containers[role]
    monkeypatch.setattr(service, '_docker', docker)
    monkeypatch.setattr(service, '_run', launch)
    monkeypatch.setattr(module, '_private_directory', lambda path: path.mkdir())
    monkeypatch.setattr(module, '_available_loopback_port', lambda: 54321)
    monkeypatch.setattr(service, '_port', lambda container, port: 54321 if port == 80 else 54322)
    monkeypatch.setattr(service, '_provision_token', lambda: None)
    monkeypatch.setattr(service, '_http', lambda method, url, **kwargs:
                        {'data': []} if '/api/books' in url else {'messages': []})
    assert service.start() is service
    network_call = next(args for args in calls if args[:2] == ('network', 'create'))
    assert '--internal' not in network_call
    bookstack = next(row for row in launches if row[0] == 'bookstack')
    assert '127.0.0.1:54321:80' in bookstack[2]
    assert service.bookstack_url == 'http://localhost:54321'
    assert service.mailpit_url == 'http://localhost:54322'
    assert service.identity['network_egress_isolated'] is False
    assert service.identity['images']['database']['reference'] == 'mysql:8.0.36'
    assert not any(args[0] == 'pull' for args in calls)
    env_file = service.root / 'explicit-local-test-credentials' / 'database.env'
    assert 'MYSQL_DATABASE=bookstack' in env_file.read_text()
    assert 'MARIADB_' not in env_file.read_text()


def test_failed_run_recovers_only_exact_owned_container_for_cleanup(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    identifier = 'a' * 64
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == 'run':
            raise ServiceError('docker_operation_failed')
        if args[0] == 'inspect':
            return identifier + '|' + service.owner if '{{.Id}}|' in args[2] else service.owner
        return ''
    monkeypatch.setattr(service, '_docker', docker)
    with pytest.raises(ServiceError, match='docker_operation_failed'):
        service._run('bookstack', module.IMAGES['bookstack'], '--publish', '127.0.0.1:1:80')
    assert service.containers == {'bookstack': identifier}
    assert calls[1][-1] == service.owner + '-bookstack'
    assert calls[1][0] == 'inspect'
    assert not any('ps' in args or '--all' in args for args in calls)
    assert service.close()['cleanup_confirmed'] is True
    assert ('rm', '--force', identifier) in calls


def test_failed_run_does_not_adopt_container_with_another_owner(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == 'run':
            raise ServiceError('docker_operation_failed')
        return 'b' * 64 + '|another-experiment'
    monkeypatch.setattr(service, '_docker', docker)
    with pytest.raises(ServiceError, match='docker_operation_failed'):
        service._run('mailpit', module.IMAGES['mailpit'])
    assert service.containers == {}
    assert service.close()['cleanup_confirmed'] is True
    assert not any(args[0] == 'rm' for args in calls)


def test_failed_run_inspect_failure_keeps_cleanup_unverified(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    def docker(*args, **kwargs):
        raise ServiceError('docker_operation_failed')
    monkeypatch.setattr(service, '_docker', docker)
    with pytest.raises(ServiceError, match='docker_operation_failed'):
        service._run('mailpit', module.IMAGES['mailpit'])
    result = service.close()
    assert result['cleanup_confirmed'] is False
    assert result['errors'] == ['failed_container_start_cleanup_unverified']


def test_invalid_run_stdout_still_recovers_created_container(tmp_path, monkeypatch):
    service = LocalServices(tmp_path)
    def docker(*args, **kwargs):
        if args[0] == 'run':
            return 'unexpected output'
        return 'c' * 64 + '|' + service.owner
    monkeypatch.setattr(service, '_docker', docker)
    with pytest.raises(ServiceError, match='container_identity_invalid'):
        service._run('database', module.IMAGES['database'])
    assert service.containers == {'database': 'c' * 64}
