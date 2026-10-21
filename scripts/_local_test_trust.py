"""Explicit, reversible CurrentUser Root trust for a localhost-only test origin.

Importing this module changes no trust. The context manager installs only its
new constrained test CA, before starting the client, and removes that exact CA
on exit. No verification flags, proxy, or custom-CA environment are changed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SCHEMA = 'transpect.test.localhost-trust/1.0'
MANIFEST_NAME = 'test-trust.json'
ROOT_NAME = 'test-root.cer'
PREFIX = 'Transpect Local Test Root '


def _roots():
    if os.name != 'nt':
        raise RuntimeError('Windows CurrentUser trust experiment required')
    return [data for data, encoding, _trust in ssl.enum_certificates('ROOT') if encoding == 'x509_asn']


def _command(arguments):
    return subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)


def _contains(reader, digest):
    return any(hashlib.sha256(der).hexdigest() == digest for der in reader())


def _write(path, value):
    temporary = path.with_name(path.name + '.' + uuid4().hex + '.pending')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(value, indent=2) + '\n')
            stream.flush(); os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():temporary.unlink()


def _constraints():
    return [x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_network('127.0.0.0/8')),
        x509.IPAddress(ipaddress.ip_network('::1/128'))]


def _validate_owner(manifest_path, value):
    if (value.get('schema') != SCHEMA or value.get('store') != 'CurrentUser\\Root'
            or not re.fullmatch('[0-9a-f]{32}', value.get('owner_id', ''))
            or value.get('root_der_file') != ROOT_NAME):
        raise ValueError('Invalid local test trust ownership')
    root = manifest_path.parent / ROOT_NAME
    if root.is_symlink() or not root.is_file() or root.stat().st_size > 65536:
        raise ValueError('Invalid test root artifact')
    raw = root.read_bytes()
    cert = x509.load_der_x509_certificate(raw)
    if (hashlib.sha256(raw).hexdigest() != value.get('root_der_sha256')
            or cert.fingerprint(hashes.SHA1()).hex().upper() != value.get('root_thumbprint_sha1')
            or cert.subject != cert.issuer
            or cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != PREFIX + value['owner_id']):
        raise ValueError('Test root identity mismatch')
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    permitted = cert.extensions.get_extension_for_class(x509.NameConstraints)
    if (not basic.critical or not basic.value.ca or basic.value.path_length != 0 or not permitted.critical
            or set(permitted.value.permitted_subtrees or []) != set(_constraints())
            or permitted.value.excluded_subtrees):
        raise ValueError('Test root scope mismatch')
    cert.verify_directly_issued_by(cert)
    return root


def cleanup_from_manifest(manifest_path, *, store_reader=None, command_runner=None):
    """Remove only the newly imported exact root; usable after interrupted runs."""
    path = Path(manifest_path).absolute()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('Invalid test trust manifest')
    value = json.loads(path.read_text(encoding='utf-8'))
    _validate_owner(path, value)
    reader, runner = store_reader or _roots, command_runner or _command
    digest = value['root_der_sha256']
    if not value.get('import_attempted') or value.get('preexisting_root') is not False:
        raise ValueError('Root was not newly imported by this experiment; cleanup refused')
    value['cleanup_attempted'] = True
    value['cleanup_confirmed'] = False
    value['phase'] = 'cleanup_pending'
    _write(path, value)
    try:
        if _contains(reader, digest):
            result = runner(['certutil.exe', '-user', '-delstore', 'Root', value['root_thumbprint_sha1']])
            value['cleanup_returncode'] = result.returncode
        else:
            value['cleanup_returncode'] = None
        value['cleanup_confirmed'] = not _contains(reader, digest)
        value['phase'] = 'removed' if value['cleanup_confirmed'] else 'cleanup_unconfirmed'
        if not value['cleanup_confirmed']:
            raise RuntimeError('Test root removal not confirmed')
    except Exception as error:
        value['cleanup_error_type'] = type(error).__name__
        _write(path, value)
        raise
    _write(path, value)
    return value


class LocalTestTrust:
    """One-use local-origin trust lease; generation never reuses an old root."""
    def __init__(self, directory, *, store_reader=None, command_runner=None):
        self.directory = Path(directory).resolve()
        self.manifest_path = self.directory / MANIFEST_NAME
        self.certificate = self.directory / 'localhost-cert.pem'
        self.private_key = self.directory / 'localhost-key.pem'
        self.root_der = self.directory / ROOT_NAME
        self.root_pem = self.directory / 'test-root.pem'
        self.reader = store_reader or _roots
        self.runner = command_runner or _command
        self.manifest = None

    def prepare(self):
        """Generate fake origin material only; do not import trust yet."""
        self.directory.mkdir(parents=True, exist_ok=False)
        owner = uuid4().hex
        now = datetime.now(timezone.utc)
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PREFIX + owner)])
        root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=24))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.NameConstraints(_constraints(), None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(root_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=12))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1')), x509.IPAddress(ipaddress.ip_address('::1'))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
        raw = root.public_bytes(serialization.Encoding.DER)
        self.root_der.write_bytes(raw)
        self.root_pem.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        self.certificate.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        self.private_key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.manifest = {'schema': SCHEMA, 'owner_id': owner, 'store': 'CurrentUser\\Root', 'phase': 'prepared',
            'root_der_file': ROOT_NAME, 'root_der_sha256': hashlib.sha256(raw).hexdigest(),
            'root_thumbprint_sha1': root.fingerprint(hashes.SHA1()).hex().upper(),
            'leaf_certificate_file': self.certificate.name, 'leaf_key_file': self.private_key.name,
            'leaf_certificate_sha256': hashlib.sha256(self.certificate.read_bytes()).hexdigest(),
            'root_not_after_utc': root.not_valid_after_utc.isoformat(),
            'name_constraints': ['localhost', '127.0.0.0/8', '::1/128'], 'root_private_key_persisted': False,
            'preexisting_root': None, 'import_attempted': False, 'import_confirmed': False,
            'cleanup_attempted': False, 'cleanup_confirmed': False,
            'recovery_command': [sys.executable, str(Path(__file__).resolve()), '--cleanup-manifest', str(self.manifest_path)]}
        _write(self.manifest_path, self.manifest)
        return self

    def install(self):
        if self.manifest is None:
            self.prepare()
        if self.manifest['import_attempted']:
            raise RuntimeError('Test trust lease is one-use')
        _validate_owner(self.manifest_path, self.manifest)
        self.manifest['preexisting_root'] = _contains(self.reader, self.manifest['root_der_sha256'])
        if self.manifest['preexisting_root']:
            self.manifest['phase'] = 'refused_preexisting'
            _write(self.manifest_path, self.manifest)
            raise ValueError('Preexisting root must not be replaced or removed')
        self.manifest.update(import_attempted=True, phase='import_pending')
        _write(self.manifest_path, self.manifest)
        try:
            result = self.runner(['certutil.exe', '-user', '-addstore', 'Root', str(self.root_der)])
            self.manifest['import_returncode'] = result.returncode
            self.manifest['import_confirmed'] = _contains(self.reader, self.manifest['root_der_sha256'])
            if result.returncode or not self.manifest['import_confirmed']:
                raise RuntimeError('Controlled test root import not confirmed')
            self.manifest['phase'] = 'trusted_before_client_start'
            _write(self.manifest_path, self.manifest)
        except Exception as error:
            self.manifest['import_error_type'] = type(error).__name__
            _write(self.manifest_path, self.manifest)
            try:self.cleanup()
            except Exception:pass  # Persisted manifest retains the explicit recovery target.
            raise
        return self

    def cleanup(self):
        self.manifest = cleanup_from_manifest(self.manifest_path,
            store_reader=self.reader, command_runner=self.runner)
        return self.manifest

    def __enter__(self):
        return self.install()

    def __exit__(self, _type, _value, _traceback):
        self.cleanup()
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cleanup-manifest', type=Path, required=True)
    args = parser.parse_args()
    result = cleanup_from_manifest(args.cleanup_manifest)
    print(json.dumps({key: result[key] for key in ('phase', 'store', 'root_thumbprint_sha1', 'cleanup_confirmed')}))


if __name__ == '__main__':
    main()
