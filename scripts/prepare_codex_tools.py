"""Prepare the fixed Codex CLI with exact-version official companion tools.

Only copies files. No npm installation, package scripts, client execution,
authentication changes or Windows sandbox/security changes are performed.
The fixed CLI remains byte-identical and all existing Guard checks still apply.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = '@openai/codex'
VERSION = '0.162.0-alpha.17.2-win32-x64'
ARCHIVE_URL = 'https://registry.npmjs.org/@openai/codex/-/codex-0.162.0-alpha.17.2-win32-x64.tgz'
ARCHIVE_INTEGRITY = 'sha512-k+CyefeURtw3GMK9+4EmDx5cGfpcIns9+t5fST3XA30aeMZ/LvOR6hIqa4PDjzq8MksXM8zVYw3Tq/aWyFnsog=='
FIXED_CODEX_SHA256 = 'd13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec'
PACKAGE_CODEX_SHA256 = 'f5521b058ca08e249afd3b25b4681e81100181d92e73aa6b94bb8e75c2aa487b'
HOST_SHA256 = 'ec91f7a04dcb1a36f0e2ed87885777bf78900c2ea3295e82621c5721fd5d9f41'
SCHEMA = 'transpect.codex-tools.runtime/1.0'
MANIFEST = 'runtime-manifest.json'
VENDOR_PREFIX = 'package/vendor/x86_64-pc-windows-msvc/'
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024
MAX_FILE_BYTES = 400 * 1024 * 1024
MAX_UNPACKED_BYTES = 800 * 1024 * 1024
MAX_MEMBERS = 1024
REQUIRED = {'bin/codex.exe', 'bin/codex-code-mode-host.exe',
            'codex-resources/codex-command-runner.exe',
            'codex-resources/codex-windows-sandbox-setup.exe', 'codex-path/rg.exe',
            'codex-package.json'}


def digest(path, algorithm='sha256'):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, algorithm).hexdigest()


def verify_archive(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError('archive_unavailable_or_oversized')
    actual = 'sha512-' + base64.b64encode(bytes.fromhex(digest(path, 'sha512'))).decode('ascii')
    if actual != ARCHIVE_INTEGRITY:
        raise ValueError('archive_integrity_mismatch')
    return path


def obtain_archive(*, archive=None, cache=None):
    if archive is not None:
        return verify_archive(archive)
    directory = Path(cache) if cache is not None else ROOT / '.external' / 'downloads' / 'codex-tools'
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / ('codex-' + VERSION + '.tgz')
    if target.exists() or target.is_symlink():
        return verify_archive(target)
    descriptor, temporary = tempfile.mkstemp(prefix='.codex-download-', suffix='.tgz', dir=directory)
    temporary = Path(temporary)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request(ARCHIVE_URL, headers={'User-Agent': 'transpect-codex-tools/1'})
        with os.fdopen(descriptor, 'wb') as destination, opener.open(request, timeout=60) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != 'https' or final.hostname != 'registry.npmjs.org':
                raise ValueError('archive_download_origin_mismatch')
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError('archive_download_limit')
                destination.write(chunk)
        verify_archive(temporary)
        # Hard-link publication refuses a pre-existing cache instead of
        # silently replacing it. Cache and temporary are on the same volume.
        try:
            os.link(temporary, target)
        except FileExistsError:
            verify_archive(target)
        return verify_archive(target)
    finally:
        temporary.unlink(missing_ok=True)


def safe_relative(name):
    """Use Windows-safe names even when preparing the bundle on another OS."""
    if not isinstance(name, str) or not name or '\\' in name or any(ord(char) < 32 for char in name):
        raise ValueError('unsafe_archive_path')
    cleaned = name[:-1] if name.endswith('/') else name
    parts = cleaned.split('/')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                *(f'LPT{i}' for i in range(1, 10))}
    if (not cleaned or PurePosixPath(cleaned).is_absolute()
            or any(part in {'', '.', '..'} or ':' in part or part.endswith((' ', '.'))
                   or part.split('.')[0].upper() in reserved for part in parts)):
        raise ValueError('unsafe_archive_path')
    return cleaned


def extract_vendor(archive, destination):
    """Extract ordinary files only; never let tarfile create links or devices."""
    destination = Path(destination).resolve()
    seen, selected = set(), {}
    total = 0
    with tarfile.open(archive, mode='r:gz') as bundle:
        count = 0
        metadata = None
        for member in bundle:
            count += 1
            if count > MAX_MEMBERS:
                raise ValueError('archive_member_limit')
            name = safe_relative(member.name)
            if name.casefold() in seen:
                raise ValueError('archive_duplicate_path')
            seen.add(name.casefold())
            if not name.startswith('package/') and name != 'package':
                raise ValueError('unexpected_archive_root')
            if (member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}
                    or member.sparse is not None):
                raise ValueError('archive_non_regular_member')
            if member.size < 0 or member.size > MAX_FILE_BYTES:
                raise ValueError('archive_file_limit')
            if member.isfile():
                total += member.size
                if total > MAX_UNPACKED_BYTES:
                    raise ValueError('archive_unpacked_limit')
            if name == 'package/package.json' and member.isfile():
                if member.size > 65536:
                    raise ValueError('package_metadata_limit')
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError('package_metadata_missing')
                metadata = json.loads(source.read())
            if not name.startswith(VENDOR_PREFIX):
                continue
            relative = safe_relative(name[len(VENDOR_PREFIX):])
            target = destination / relative
            if not target.resolve().is_relative_to(destination):
                raise ValueError('unsafe_archive_path')
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError('archive_member_unreadable')
            hasher, copied = hashlib.sha256(), 0
            with target.open('xb') as output:
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > member.size:
                        raise ValueError('archive_member_size_mismatch')
                    output.write(chunk)
                    hasher.update(chunk)
            if copied != member.size:
                raise ValueError('archive_member_size_mismatch')
            selected[relative] = {'sha256': hasher.hexdigest(), 'bytes': copied}
    if not isinstance(metadata, dict) or metadata.get('name') != PACKAGE or metadata.get('version') != VERSION:
        raise ValueError('package_identity_mismatch')
    if not REQUIRED <= set(selected):
        raise ValueError('companion_files_missing')
    if selected['bin/codex.exe']['sha256'] != PACKAGE_CODEX_SHA256:
        raise ValueError('package_codex_identity_mismatch')
    if selected['bin/codex-code-mode-host.exe']['sha256'] != HOST_SHA256:
        raise ValueError('package_host_identity_mismatch')
    return selected


def _publish(source, output):
    # Reserve a new output before copying, so this also refuses an empty
    # existing directory on Windows and POSIX. Files are always opened 'xb'.
    output.mkdir()
    for path in sorted(source.rglob('*')):
        target = output / path.relative_to(source)
        if path.is_dir():
            target.mkdir()
        else:
            with path.open('rb') as read, target.open('xb') as write:
                shutil.copyfileobj(read, write, 1024 * 1024)


def _remove_owned_stage(stage, parent):
    if stage.is_symlink() or stage.resolve().parent != parent.resolve() or not stage.name.startswith('.codex-stage-'):
        raise ValueError('staging_cleanup_target_mismatch')
    shutil.rmtree(stage)


def prepare(codex, output, *, archive=None, cache=None):
    codex, output = Path(codex).resolve(), Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('output_already_exists')
    if not codex.is_file() or digest(codex) != FIXED_CODEX_SHA256:
        raise ValueError('fixed_codex_identity_mismatch')
    source_archive = obtain_archive(archive=archive, cache=cache)
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.codex-stage-', dir=output.parent))
    try:
        original_files = extract_vendor(source_archive, stage)
        # This replacement is inside our new staging directory only; the
        # user's existing baseline and the downloaded package remain intact.
        with codex.open('rb') as source, (stage / 'bin/codex.exe').open('wb') as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        if digest(codex) != FIXED_CODEX_SHA256 or digest(stage / 'bin/codex.exe') != FIXED_CODEX_SHA256:
            raise ValueError('fixed_codex_changed_during_copy')
        files = {}
        for name, original in original_files.items():
            path = stage / name
            files[name] = {'sha256': digest(path), 'bytes': path.stat().st_size,
                           'package_sha256': original['sha256'], 'package_bytes': original['bytes'],
                           'origin': 'fixed_codex_copy' if name == 'bin/codex.exe' else 'pinned_official_package'}
        manifest = {'schema_version': SCHEMA, 'package': PACKAGE, 'version': VERSION,
                    'archive_url': ARCHIVE_URL, 'archive_integrity': ARCHIVE_INTEGRITY,
                    'archive_bytes': source_archive.stat().st_size,
                    'fixed_codex_sha256': FIXED_CODEX_SHA256,
                    'package_codex_sha256': PACKAGE_CODEX_SHA256, 'host_sha256': HOST_SHA256,
                    'fixed_cli_disk_mutated': False, 'package_cli_differs_from_fixed_baseline': True,
                    'client_executed': False, 'sandbox_configuration_changed': False,
                    'capability_validation': 'not_run; runtime preparation is not protection certification',
                    'files': files}
        (stage / MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        _publish(stage, output)
        check_runtime(output)
        return manifest
    finally:
        _remove_owned_stage(stage, output.parent)


def check_runtime(output):
    output = Path(output).absolute()
    if output.is_symlink() or not output.is_dir() or getattr(output, 'is_junction', lambda: False)():
        raise ValueError('runtime_directory_invalid')
    manifest_path = output / MANIFEST
    if (not manifest_path.is_file() or manifest_path.is_symlink()
            or manifest_path.stat().st_size > 1024 * 1024):
        raise ValueError('runtime_manifest_unavailable')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    pins = {'schema_version': SCHEMA, 'package': PACKAGE, 'version': VERSION,
            'archive_url': ARCHIVE_URL, 'archive_integrity': ARCHIVE_INTEGRITY,
            'fixed_codex_sha256': FIXED_CODEX_SHA256, 'package_codex_sha256': PACKAGE_CODEX_SHA256,
            'host_sha256': HOST_SHA256, 'fixed_cli_disk_mutated': False,
            'package_cli_differs_from_fixed_baseline': True}
    if any(manifest.get(key) != value for key, value in pins.items()):
        raise ValueError('runtime_manifest_identity_mismatch')
    files = manifest.get('files')
    if not isinstance(files, dict) or not REQUIRED <= set(files) or len(files) > MAX_MEMBERS:
        raise ValueError('runtime_manifest_files_invalid')
    seen = set()
    for name, row in files.items():
        if safe_relative(name) != name or name.casefold() in seen or not isinstance(row, dict):
            raise ValueError('runtime_manifest_files_invalid')
        seen.add(name.casefold())
        for field in ('sha256', 'package_sha256'):
            if not isinstance(row.get(field), str) or not re.fullmatch('[a-f0-9]{64}', row[field]):
                raise ValueError('runtime_manifest_files_invalid')
        if any(type(row.get(field)) is not int or not 0 <= row[field] <= MAX_FILE_BYTES
               for field in ('bytes', 'package_bytes')):
            raise ValueError('runtime_manifest_files_invalid')
        fixed = name == 'bin/codex.exe'
        if row.get('origin') != ('fixed_codex_copy' if fixed else 'pinned_official_package'):
            raise ValueError('runtime_manifest_files_invalid')
        if not fixed and (row['sha256'], row['bytes']) != (row['package_sha256'], row['package_bytes']):
            raise ValueError('runtime_companion_source_mismatch')
    if (files['bin/codex.exe']['sha256'] != FIXED_CODEX_SHA256
            or files['bin/codex.exe']['package_sha256'] != PACKAGE_CODEX_SHA256
            or files['bin/codex-code-mode-host.exe']['sha256'] != HOST_SHA256):
        raise ValueError('runtime_critical_file_identity_mismatch')
    observed, pending = set(), [output]
    while pending:
        parent = pending.pop()
        for item in parent.iterdir():
            if item.is_symlink() or getattr(item, 'is_junction', lambda: False)():
                raise ValueError('runtime_link_forbidden')
            if item.is_dir():
                pending.append(item)
                continue
            name = item.relative_to(output).as_posix()
            if name == MANIFEST:
                continue
            if name not in files or not item.is_file():
                raise ValueError('runtime_unregistered_file')
            row = files[name]
            if item.stat().st_size != row['bytes'] or digest(item) != row['sha256']:
                raise ValueError('runtime_file_identity_mismatch')
            observed.add(name)
    if observed != set(files):
        raise ValueError('runtime_files_missing')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex', type=Path, help='Existing unchanged d139 fixed official CLI.')
    parser.add_argument('--output', type=Path, required=True, help='New complete runtime directory.')
    parser.add_argument('--archive', type=Path, help='Optional existing exact pinned npm tarball.')
    parser.add_argument('--cache', type=Path, help='Optional download cache; its files must match the pin.')
    parser.add_argument('--check', action='store_true', help='Read-only manifest and runtime identity check.')
    args = parser.parse_args(argv)
    try:
        if args.check:
            if args.codex and digest(args.codex) != FIXED_CODEX_SHA256:
                raise ValueError('fixed_codex_identity_mismatch')
            manifest = check_runtime(args.output)
        else:
            if args.codex is None:
                parser.error('--codex is required unless --check is used')
            manifest = prepare(args.codex, args.output, archive=args.archive, cache=args.cache)
        print(json.dumps({'passed': True, 'operation': 'check' if args.check else 'prepare',
                          'output': str(args.output.resolve()), 'cli': str((args.output / 'bin/codex.exe').resolve()),
                          'version': manifest['version'], 'files': len(manifest['files']),
                          'fixed_codex_sha256': manifest['fixed_codex_sha256'],
                          'host_sha256': manifest['host_sha256'], 'client_executed': False}))
        return 0
    except Exception as error:
        # Exceptions from network libraries may contain environment-specific
        # URLs or headers. Only our fixed local codes enter default output.
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch('[a-z_]+', str(error)) else type(error).__name__
        print(json.dumps({'passed': False, 'reason': reason}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
