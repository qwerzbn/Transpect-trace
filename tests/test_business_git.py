"""Real Git HTTPS reception and live-quarantine component evidence.

These tests use a per-client CA, never modify OS trust, and certify no Hook/ETW.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from test_flow_origin import tls_files
from test_business_sources import request, wait_count
from transpect_trace.flow.scenarios.sources import BusinessOrigin, clean_git_environment


@pytest.fixture
def git():
    path = shutil.which('git.exe' if __import__('os').name == 'nt' else 'git')
    if not path:
        pytest.skip('real Git unavailable; this is a component integration test')
    return path


def command(git, work, *args, check=True):
    result = subprocess.run([git, '-C', str(work), '-c', 'credential.helper=', '-c', 'http.proxy=',
                             '-c', 'http.sslBackend=openssl', '-c', 'commit.gpgsign=false', *args],
                            env=clean_git_environment(), capture_output=True, timeout=35)
    if check:
        assert result.returncode == 0, (result.returncode, result.stderr.decode(errors='replace'))
    return result


def repository(git, root):
    root.mkdir()
    command(git, root, 'init', '--initial-branch=fixture')
    command(git, root, 'config', 'user.name', 'Synthetic Fixture')
    command(git, root, 'config', 'user.email', 'fixture@example.invalid')
    command(git, root, 'config', 'core.autocrlf', 'false')
    return root


def commit(git, root, text):
    (root / 'diagnostics.json').write_text(text, encoding='utf-8')
    command(git, root, 'add', 'diagnostics.json')
    command(git, root, 'commit', '-m', 'fixture update')


def push(git, root, origin, ca, check=True):
    return command(git, root, '-c', 'http.sslCAInfo=' + str(ca), '-c', 'http.version=HTTP/1.1',
                   'push', origin.git_url, 'HEAD:refs/heads/fixture', check=check)


def test_git_receives_secret_in_deleted_history_not_untracked_file(tls_files, tmp_path, git):
    ca, certificate, key = tls_files
    received = []
    origin = BusinessOrigin(certificate, key, git_root=tmp_path / 'source', git=git,
                            on_git_blob=lambda data, meta: received.append((data, meta))).start()
    work = repository(git, tmp_path / 'work')
    secret = 'FAKE_ONLY_SECRET_COMMITTED_中文'
    try:
        commit(git, work, json.dumps({'secret': secret}, ensure_ascii=False))
        command(git, work, 'rm', 'diagnostics.json')
        command(git, work, 'commit', '-m', 'fixture delete')
        (work / 'untracked.txt').write_text('FAKE_ONLY_NEVER_SENT', encoding='utf-8')
        result = push(git, work, origin, ca, check=False)
        assert result.returncode == 0, origin.git_receipts
        assert len(origin.git_receipts) == 1
        evidence = origin.git_receipts[0]
        assert evidence['quarantine_observed'] and evidence['inspection_complete']
        assert evidence['ref_update_observed'] and evidence['refs_before'] == {}
        assert len(evidence['refs_after']) == 1
        assert len([o for o in evidence['new_objects'] if o['object_type'] == 'commit']) == 2
        commits = [o for o in evidence['new_objects'] if o['object_type'] == 'commit']
        assert all('tree_object_id' in o and 'parent_object_ids' in o for o in commits)
        assert any(o.get('entries') and o['entries'][0]['name_sha256'] == hashlib.sha256(b'diagnostics.json').hexdigest()
                   for o in evidence['new_objects'] if o['object_type'] == 'tree')
        assert any(secret.encode() in data for data, _ in received)
        assert not any(b'FAKE_ONLY_NEVER_SENT' in data for data, _ in received)
        assert all(meta['attempt_id'] == evidence['attempt_id'] for _, meta in received)
        assert secret not in json.dumps(origin.git_receipts, ensure_ascii=False)
        assert 'FAKE_ONLY_NEVER_SENT' not in json.dumps(origin.receipts)
        assert command(git, work, 'ls-tree', 'HEAD').stdout == b''
        # Identical push has advertisement but no receive body / invented blob.
        old_count, old_blobs = len(origin.git_receipts), len(received)
        push(git, work, origin, ca)
        assert len(origin.git_receipts) == old_count and len(received) == old_blobs
    finally:
        origin.close()
    assert origin.errors == []


def test_ref_rejection_still_observes_actual_quarantine_secret(tls_files, tmp_path, git):
    ca, certificate, key = tls_files
    received = []
    origin = BusinessOrigin(certificate, key, git_root=tmp_path / 'source', git=git,
                            reject_refs=True, on_git_blob=lambda data, meta: received.append((data, meta))).start()
    work = repository(git, tmp_path / 'work')
    data = '{"report":"FAKE_ONLY_REJECTED_BUT_RECEIVED"}'
    try:
        commit(git, work, data)
        assert push(git, work, origin, ca, check=False).returncode != 0
        assert len(origin.git_receipts) == 1
        evidence = origin.git_receipts[0]
        assert evidence['inspection_complete'] and evidence['quarantine_observed'], evidence
        assert not evidence['ref_update_observed']
        assert evidence['refs_before'] == evidence['refs_after'] == {}
        assert any(raw == data.encode() for raw, _ in received)
        assert any(o.get('content_sha256') == hashlib.sha256(data.encode()).hexdigest() for o in evidence['new_objects'])
        assert origin.git_store.objects() == {}  # quarantine removed after rejection
        assert any(r['route'] == 'git_receive' and r['body_bytes'] > 0 for r in origin.receipts)
    finally:
        origin.close()


def test_fixture_auth_challenge_records_no_authorization(tls_files, tmp_path, git):
    ca, certificate, key = tls_files
    origin = BusinessOrigin(certificate, key, git_root=tmp_path / 'source', git=git, git_auth_challenge=True).start()
    try:
        assert request(origin, ca, 'GET', '/target.git/info/refs?service=git-receive-pack')[0] == 401
        assert request(origin, ca, 'GET', '/target.git/info/refs?service=git-receive-pack',
                       extra_headers={'Authorization': 'Basic Zml4dHVyZTpmaXh0dXJl'})[0] == 200
        wait_count(origin, 2)
        assert origin.receipts[0]['fixture_authentication'] == 'challenged'
        assert 'Authorization' not in json.dumps(origin.receipts)
        assert 'Zml4dHVyZTpmaXh0dXJl' not in json.dumps(origin.receipts)
    finally:
        origin.close()


def test_git_environment_removes_local_credentials_and_config(monkeypatch):
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', 'FAKE_ONLY_SECRET')
    monkeypatch.setenv('GIT_ASKPASS', 'untrusted.exe')
    monkeypatch.setenv('HTTPS_PROXY', 'http://secret.invalid')
    value = clean_git_environment()
    assert 'GIT_CONFIG_COUNT' not in value and 'GIT_ASKPASS' not in value
    assert 'HTTPS_PROXY' not in value and value['GIT_TERMINAL_PROMPT'] == '0'
    assert value['GIT_CONFIG_NOSYSTEM'] == '1'


def test_blob_callback_failure_preserves_receive_fact_without_ref_success(tls_files, tmp_path, git):
    ca, certificate, key = tls_files
    def fail(*_):
        raise ValueError('FAKE_ONLY_PRIVATE_CALLBACK')
    origin = BusinessOrigin(certificate, key, git_root=tmp_path / 'source', git=git, on_git_blob=fail).start()
    work = repository(git, tmp_path / 'work')
    try:
        commit(git, work, '{"report":"FAKE_ONLY_PRIVATE_CALLBACK"}')
        assert push(git, work, origin, ca, check=False).returncode != 0
        evidence = origin.git_receipts[0]
        assert evidence['quarantine_observed'] and not evidence['inspection_complete']
        assert not evidence['ref_update_observed']
        assert 'git_quarantine_inspection_failed' in evidence['limitations']
        assert evidence['inspection_phase'] == 'blob_callback'
        assert evidence['inspection_error_type'] == 'ValueError'
        assert any(o['object_type'] == 'blob' and 'content_sha256' in o for o in evidence['new_objects'])
        assert 'FAKE_ONLY_PRIVATE_CALLBACK' not in json.dumps(origin.git_receipts + origin.receipts)
    finally:
        origin.close()


def test_git_command_failure_diagnostic_contains_only_lengths_hashes_and_status(monkeypatch):
    from transpect_trace.flow.scenarios.sources import GitStore, GitCommandError
    store = object.__new__(GitStore)
    store.git, store.env = 'inert-git.exe', {}
    def fail(*_, **__):
        return subprocess.CompletedProcess([], 128, b'FAKE_ONLY_STDOUT_SECRET', b'FAKE_ONLY_STDERR_SECRET')
    monkeypatch.setattr(subprocess, 'run', fail)
    with pytest.raises(GitCommandError) as result:
        store.run(['cat-file'])
    diagnostic = result.value.diagnostic
    assert diagnostic['returncode'] == 128
    assert diagnostic['stderr_sha256'] == hashlib.sha256(b'FAKE_ONLY_STDERR_SECRET').hexdigest()
    assert 'FAKE_ONLY' not in json.dumps(diagnostic)


def test_ready_read_failure_reports_phase_without_claiming_quarantine_inspected(tls_files, tmp_path, git, monkeypatch):
    ca, certificate, key = tls_files
    origin = BusinessOrigin(certificate, key, git_root=tmp_path / 'source', git=git).start()
    work = repository(git, tmp_path / 'work')
    original = Path.read_text
    def blocked(path, *args, **kwargs):
        if path.name == 'ready.json' and 'capture-handoffs' in path.parts:
            raise PermissionError(13, 'FAKE_ONLY_PRIVATE_OS_DETAIL')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', blocked)
    try:
        commit(git, work, '{"report":"ordinary fixture"}')
        assert push(git, work, origin, ca, check=False).returncode != 0
        evidence = origin.git_receipts[0]
        assert not evidence['inspection_complete'] and not evidence['quarantine_observed']
        assert evidence['inspection_phase'] == 'read_ready_metadata'
        assert evidence['inspection_error_type'] == 'PermissionError'
        assert evidence['inspection_os_error']['errno'] == 13
        assert evidence['fixture_pre_receive_decision'] == 'reject'
        assert 'FAKE_ONLY_PRIVATE_OS_DETAIL' not in json.dumps(evidence)
    finally:
        origin.close()
