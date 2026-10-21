import hashlib
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@pytest.fixture
def trust_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    import _local_test_trust
    return _local_test_trust


class FakeStore:
    """A private list; these tests never query or change Windows trust."""
    def __init__(self, root_path):
        self.root_path = root_path
        self.roots = []
        self.commands = []
        self.import_code = 0
        self.removal_code = 0
        self.keep_on_remove = False

    def read(self):
        return list(self.roots)

    def run(self, arguments):
        self.commands.append(arguments)
        if '-addstore' in arguments:
            self.roots.append(self.root_path.read_bytes())
            return SimpleNamespace(returncode=self.import_code)
        if not self.keep_on_remove:
            self.roots.clear()
        return SimpleNamespace(returncode=self.removal_code)


def lease(module, tmp_path):
    folder = tmp_path / 'isolated-origin'
    store = FakeStore(folder / module.ROOT_NAME)
    return module.LocalTestTrust(folder, store_reader=store.read, command_runner=store.run), store


def test_prepare_has_bounded_localhost_constraints_and_no_trust_side_effect(trust_module, tmp_path):
    trust, store = lease(trust_module, tmp_path)
    trust.prepare()
    assert store.commands == [] and store.roots == []
    root = x509.load_der_x509_certificate(trust.root_der.read_bytes())
    basic = root.extensions.get_extension_for_class(x509.BasicConstraints)
    scope = root.extensions.get_extension_for_class(x509.NameConstraints)
    assert basic.critical and basic.value.ca and basic.value.path_length == 0
    assert scope.critical
    assert set(scope.value.permitted_subtrees) == {x509.DNSName('localhost'),
        x509.IPAddress(ipaddress.ip_network('127.0.0.0/8')), x509.IPAddress(ipaddress.ip_network('::1/128'))}
    assert (root.not_valid_after_utc - root.not_valid_before_utc).total_seconds() <= 24 * 3600 + 300
    root.verify_directly_issued_by(root)
    leaf = x509.load_pem_x509_certificate(trust.certificate.read_bytes())
    leaf.verify_directly_issued_by(root)
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert ExtendedKeyUsageOID.SERVER_AUTH in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert set(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) == {
        x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
        x509.IPAddress(ipaddress.ip_address('::1'))}
    private = serialization.load_pem_private_key(trust.private_key.read_bytes(), password=None)
    assert private.public_key().public_numbers() == leaf.public_key().public_numbers()
    manifest = json.loads(trust.manifest_path.read_text())
    assert not manifest['root_private_key_persisted']
    assert 'PRIVATE KEY' not in trust.manifest_path.read_text()
    assert not manifest['import_attempted']


def test_context_imports_then_removes_exact_user_root_even_on_client_error(trust_module, tmp_path):
    trust, store = lease(trust_module, tmp_path)
    with pytest.raises(RuntimeError, match='fake-client-error'):
        with trust:
            assert store.roots and trust.manifest['import_confirmed']
            assert trust.manifest['phase'] == 'trusted_before_client_start'
            raise RuntimeError('fake-client-error')
    manifest = json.loads(trust.manifest_path.read_text())
    assert manifest['cleanup_confirmed'] and manifest['phase'] == 'removed'
    assert len(store.commands) == 2
    assert store.commands[0] == ['certutil.exe', '-user', '-addstore', 'Root', str(trust.root_der)]
    assert store.commands[1] == ['certutil.exe', '-user', '-delstore', 'Root', manifest['root_thumbprint_sha1']]
    assert not store.roots


def test_existing_root_is_never_replaced_or_deleted(trust_module, tmp_path):
    trust, store = lease(trust_module, tmp_path)
    trust.prepare()
    store.roots.append(trust.root_der.read_bytes())
    with pytest.raises(ValueError, match='Preexisting'):
        trust.install()
    with pytest.raises(ValueError, match='not newly imported'):
        trust.cleanup()
    assert store.commands == []
    assert len(store.roots) == 1


def test_changed_root_cannot_be_imported_under_saved_ownership(trust_module, tmp_path):
    trust, store = lease(trust_module, tmp_path)
    trust.prepare()
    other, _ = lease(trust_module, tmp_path / 'other');other.prepare()
    trust.root_der.write_bytes(other.root_der.read_bytes())
    with pytest.raises(ValueError, match='identity mismatch'):
        trust.install()
    assert store.commands == [] and not store.roots


def test_failed_import_that_left_root_is_cleaned(trust_module, tmp_path):
    trust, store = lease(trust_module, tmp_path)
    store.import_code = 5
    with pytest.raises(RuntimeError, match='import not confirmed'):
        trust.install()
    manifest = json.loads(trust.manifest_path.read_text())
    assert manifest['import_returncode'] == 5 and manifest['cleanup_confirmed']
    assert not store.roots and len(store.commands) == 2


def test_removal_failure_remains_explicit_and_has_recovery_target(trust_module, tmp_path):
    trust, store = lease(trust_module, tmp_path)
    trust.install(); store.keep_on_remove = True; store.removal_code = 5
    with pytest.raises(RuntimeError, match='removal not confirmed'):
        trust.cleanup()
    manifest = json.loads(trust.manifest_path.read_text())
    assert not manifest['cleanup_confirmed'] and manifest['cleanup_returncode'] == 5
    assert manifest['cleanup_error_type'] == 'RuntimeError'
    assert manifest['recovery_command'][-1] == str(trust.manifest_path)
    store.keep_on_remove = False; store.removal_code = 0
    trust_module.cleanup_from_manifest(trust.manifest_path, store_reader=store.read, command_runner=store.run)
    assert not store.roots


@pytest.mark.parametrize('field,value', [('root_der_file', '../other.cer'), ('owner_id', 'not-owned'),
    ('root_der_sha256', 'a'*64), ('root_thumbprint_sha1', 'B'*40), ('store', 'LocalMachine\\Root')])
def test_recovery_refuses_identity_or_store_tampering(trust_module, tmp_path, field, value):
    trust, store = lease(trust_module, tmp_path)
    trust.prepare()
    manifest = dict(trust.manifest, import_attempted=True, preexisting_root=False)
    manifest[field] = value
    trust.manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        trust_module.cleanup_from_manifest(trust.manifest_path, store_reader=store.read, command_runner=store.run)
    assert store.commands == []


def test_recovery_handles_stale_partial_manifest_write_without_broad_deletion(trust_module, tmp_path):
    trust, store = lease(trust_module, tmp_path)
    trust.install()
    (trust.directory / 'test-trust.json.pending').write_text('interrupted write')
    trust_module.cleanup_from_manifest(trust.manifest_path, store_reader=store.read, command_runner=store.run)
    assert not store.roots
    assert (trust.directory / 'test-trust.json.pending').is_file()
    assert json.loads(trust.manifest_path.read_text())['cleanup_confirmed']
