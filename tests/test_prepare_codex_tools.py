"""Pinned official companions never replace or relax the fixed Guard baseline."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'prepare_codex_tools.py'


def module():
    spec = importlib.util.spec_from_file_location('prepare_codex_tools', SCRIPT)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive_file(path, entries):
    with tarfile.open(path, 'w:gz') as output:
        for name, data, kind, link in entries:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kind, link
            info.size = len(data)
            output.addfile(info, io.BytesIO(data) if kind in {tarfile.REGTYPE, tarfile.AREGTYPE} else None)
    return path


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    prepare = module()
    fixed = tmp_path / 'original-codex.exe'
    fixed.write_bytes(b'FAKE_ONLY fixed original CLI')
    data = {
        'bin/codex.exe': b'FAKE_ONLY official package CLI with different identity',
        'bin/codex-code-mode-host.exe': b'FAKE_ONLY matching official host',
        'codex-resources/codex-command-runner.exe': b'FAKE_ONLY command runner',
        'codex-resources/codex-windows-sandbox-setup.exe': b'FAKE_ONLY sandbox setup',
        'codex-path/rg.exe': b'FAKE_ONLY search tool',
        'codex-package.json': b'{"version":"fake fixture"}',
        'codex-resources/voice/NOTICE.md': b'FAKE_ONLY complete vendor resource',
    }
    entries = [('package/package.json', json.dumps({'name': prepare.PACKAGE, 'version': prepare.VERSION}).encode(),
                tarfile.REGTYPE, '')]
    entries += [(prepare.VENDOR_PREFIX + name, raw, tarfile.REGTYPE, '') for name, raw in data.items()]
    archive = archive_file(tmp_path / 'official.tgz', entries)
    monkeypatch.setattr(prepare, 'FIXED_CODEX_SHA256', sha(fixed.read_bytes()))
    monkeypatch.setattr(prepare, 'PACKAGE_CODEX_SHA256', sha(data['bin/codex.exe']))
    monkeypatch.setattr(prepare, 'HOST_SHA256', sha(data['bin/codex-code-mode-host.exe']))

    def repin(path):
        integrity = 'sha512-' + base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode()
        monkeypatch.setattr(prepare, 'ARCHIVE_INTEGRITY', integrity)
    repin(archive)
    return prepare, fixed, archive, data, entries, repin


def test_official_production_pins_are_exact_and_distinguish_cli_builds():
    prepare = module()
    assert prepare.VERSION == '0.162.0-alpha.17.2-win32-x64'
    assert prepare.FIXED_CODEX_SHA256 == 'd13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec'
    assert prepare.PACKAGE_CODEX_SHA256 == 'f5521b058ca08e249afd3b25b4681e81100181d92e73aa6b94bb8e75c2aa487b'
    assert prepare.HOST_SHA256 == 'ec91f7a04dcb1a36f0e2ed87885777bf78900c2ea3295e82621c5721fd5d9f41'
    assert prepare.ARCHIVE_URL == 'https://registry.npmjs.org/@openai/codex/-/codex-0.162.0-alpha.17.2-win32-x64.tgz'
    assert prepare.ARCHIVE_INTEGRITY == 'sha512-k+CyefeURtw3GMK9+4EmDx5cGfpcIns9+t5fST3XA30aeMZ/LvOR6hIqa4PDjzq8MksXM8zVYw3Tq/aWyFnsog=='


def test_preparation_preserves_source_and_complete_companions(bundle, tmp_path):
    prepare, fixed, archive, data, *_ = bundle
    original = fixed.read_bytes()
    output = tmp_path / 'runtime'
    manifest = prepare.prepare(fixed, output, archive=archive)
    assert fixed.read_bytes() == original
    assert (output / 'bin/codex.exe').read_bytes() == original
    for name, raw in data.items():
        if name != 'bin/codex.exe':
            assert (output / name).read_bytes() == raw
    assert manifest['fixed_cli_disk_mutated'] is False
    assert manifest['package_cli_differs_from_fixed_baseline'] is True
    assert manifest['client_executed'] is False
    assert manifest['sandbox_configuration_changed'] is False
    assert manifest['files']['bin/codex.exe']['origin'] == 'fixed_codex_copy'
    assert manifest['files']['bin/codex.exe']['sha256'] != manifest['files']['bin/codex.exe']['package_sha256']
    assert prepare.check_runtime(output) == manifest
    assert not list(tmp_path.glob('.codex-stage-*'))


@pytest.mark.parametrize('empty', [False, True])
def test_existing_output_is_not_overwritten(bundle, tmp_path, empty):
    prepare, fixed, archive, *_ = bundle
    output = tmp_path / 'runtime'
    output.mkdir()
    if not empty:
        (output / 'unique-evidence.txt').write_bytes(b'preserve')
    before = sorted(str(p.relative_to(output)) for p in output.rglob('*'))
    with pytest.raises(ValueError, match='output_already_exists'):
        prepare.prepare(fixed, output, archive=archive)
    assert sorted(str(p.relative_to(output)) for p in output.rglob('*')) == before


def test_mismatched_fixed_cli_is_rejected_before_fetch(bundle, tmp_path, monkeypatch):
    prepare, fixed, archive, *_ = bundle
    fixed.write_bytes(b'changed')
    monkeypatch.setattr(prepare, 'obtain_archive', lambda **_: pytest.fail('must not download'))
    with pytest.raises(ValueError, match='fixed_codex_identity_mismatch'):
        prepare.prepare(fixed, tmp_path / 'runtime', archive=archive)


def test_corrupt_archive_and_existing_cache_are_rejected_without_replacement(bundle, tmp_path, monkeypatch):
    prepare, fixed, archive, *_ = bundle
    cache = tmp_path / 'cache'
    cache.mkdir()
    cached = cache / ('codex-' + prepare.VERSION + '.tgz')
    cached.write_bytes(b'unique corrupted cached evidence')
    monkeypatch.setattr(prepare.urllib.request, 'build_opener', lambda *_: pytest.fail('must not redownload corrupt cache'))
    with pytest.raises(ValueError, match='archive_integrity_mismatch'):
        prepare.prepare(fixed, tmp_path / 'runtime', cache=cache)
    assert cached.read_bytes() == b'unique corrupted cached evidence'
    assert not (tmp_path / 'runtime').exists()


def test_download_is_verified_and_cached_without_install_scripts(bundle, tmp_path, monkeypatch):
    prepare, fixed, archive, *_ = bundle
    raw = archive.read_bytes()
    calls = []

    class Response(io.BytesIO):
        def geturl(self):
            return prepare.ARCHIVE_URL

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            return Response(raw)

    monkeypatch.setattr(prepare.urllib.request, 'build_opener', lambda *_: Opener())
    cached = prepare.obtain_archive(cache=tmp_path / 'cache')
    assert cached.read_bytes() == raw and len(calls) == 1
    assert prepare.obtain_archive(cache=tmp_path / 'cache') == cached
    assert len(calls) == 1
    assert not list((tmp_path / 'cache').glob('.codex-download-*'))


def test_bad_download_never_becomes_a_cached_archive(bundle, tmp_path, monkeypatch):
    prepare, *_ = bundle

    class Response(io.BytesIO):
        def geturl(self):
            return prepare.ARCHIVE_URL

    class Opener:
        def open(self, *args, **kwargs):
            return Response(b'corrupted')

    monkeypatch.setattr(prepare.urllib.request, 'build_opener', lambda *_: Opener())
    with pytest.raises(ValueError, match='archive_integrity_mismatch'):
        prepare.obtain_archive(cache=tmp_path / 'cache')
    assert not list((tmp_path / 'cache').iterdir())


@pytest.mark.parametrize('name', [
    '/absolute', '../escape', 'package/../escape', 'package/vendor/../../escape',
    'package\\vendor\\evil', 'C:/escape', 'package/evil:stream', 'package/CON',
    'package/NUL.txt', 'package/a.', 'package/a ', 'package//evil', './package/evil',
    'package/evil\x00name',
])
def test_nonportable_or_escaping_archive_paths_are_rejected(name):
    with pytest.raises(ValueError, match='unsafe_archive_path'):
        module().safe_relative(name)


@pytest.mark.parametrize('kind', [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                                tarfile.CHRTYPE, tarfile.BLKTYPE])
def test_tar_links_and_special_members_are_rejected(bundle, tmp_path, kind):
    prepare, fixed, _, _, entries, repin = bundle
    attack = archive_file(tmp_path / 'attack.tgz', entries + [
        (prepare.VENDOR_PREFIX + 'evil', b'', kind, '../../outside')])
    repin(attack)
    with pytest.raises(ValueError, match='archive_non_regular_member'):
        prepare.prepare(fixed, tmp_path / 'runtime', archive=attack)
    assert not (tmp_path / 'runtime').exists()
    assert not list(tmp_path.glob('.codex-stage-*'))


@pytest.mark.parametrize('name', ['bin/codex.exe', 'bin/CODEX.exe'])
def test_duplicate_and_case_aliased_archive_paths_are_rejected(bundle, tmp_path, name):
    prepare, fixed, _, _, entries, repin = bundle
    attack = archive_file(tmp_path / 'duplicate.tgz', entries + [
        (prepare.VENDOR_PREFIX + name, b'override', tarfile.REGTYPE, '')])
    repin(attack)
    with pytest.raises(ValueError, match='archive_duplicate_path'):
        prepare.prepare(fixed, tmp_path / 'runtime', archive=attack)


def test_wrong_package_version_and_missing_companion_fail(bundle, tmp_path):
    prepare, fixed, _, _, entries, repin = bundle
    for case in ['wrong-version', 'missing-host']:
        changed = entries[:]
        if case == 'wrong-version':
            changed[0] = (changed[0][0], b'{"name":"@openai/codex","version":"wrong"}', tarfile.REGTYPE, '')
        else:
            changed = [row for row in changed if not row[0].endswith('/codex-code-mode-host.exe')]
        attack = archive_file(tmp_path / (case + '.tgz'), changed)
        repin(attack)
        with pytest.raises(ValueError, match='package_identity_mismatch|companion_files_missing'):
            prepare.prepare(fixed, tmp_path / case, archive=attack)


@pytest.mark.parametrize('name,error', [('bin/codex.exe', 'package_codex_identity_mismatch'),
                                      ('bin/codex-code-mode-host.exe', 'package_host_identity_mismatch')])
def test_critical_package_hashes_are_independent_of_archive_pin(bundle, tmp_path, name, error):
    prepare, fixed, _, _, entries, repin = bundle
    changed = [(n, b'changed critical member' if n == prepare.VENDOR_PREFIX + name else data, kind, link)
               for n, data, kind, link in entries]
    attack = archive_file(tmp_path / 'changed.tgz', changed)
    repin(attack)
    with pytest.raises(ValueError, match=error):
        prepare.prepare(fixed, tmp_path / 'runtime', archive=attack)


@pytest.mark.parametrize('mutation', ['file', 'missing', 'extra', 'manifest-version', 'manifest-path', 'manifest-critical'])
def test_check_detects_runtime_or_manifest_changes_without_writing(bundle, tmp_path, mutation):
    prepare, fixed, archive, *_ = bundle
    output = tmp_path / 'runtime'
    prepare.prepare(fixed, output, archive=archive)
    manifest_path = output / prepare.MANIFEST
    if mutation == 'file':
        (output / 'bin/codex-code-mode-host.exe').write_bytes(b'changed')
    elif mutation == 'missing':
        (output / 'bin/codex-code-mode-host.exe').unlink()
    elif mutation == 'extra':
        (output / 'unexpected.exe').write_bytes(b'unknown')
    else:
        value = json.loads(manifest_path.read_text())
        if mutation == 'manifest-version':
            value['version'] = 'newer'
        elif mutation == 'manifest-path':
            value['files']['../outside.exe'] = value['files']['codex-path/rg.exe']
        else:
            value['files']['bin/codex.exe']['sha256'] = 'f' * 64
        manifest_path.write_text(json.dumps(value))
    before = manifest_path.read_bytes()
    with pytest.raises(ValueError):
        prepare.check_runtime(output)
    assert manifest_path.read_bytes() == before


def test_cli_check_is_read_only_and_existing_prepare_fails(bundle, tmp_path, capsys):
    prepare, fixed, archive, *_ = bundle
    output = tmp_path / 'runtime'
    assert prepare.main(['--codex', str(fixed), '--output', str(output), '--archive', str(archive)]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first['client_executed'] is False and first['operation'] == 'prepare'
    before = (output / prepare.MANIFEST).read_bytes()
    assert prepare.main(['--output', str(output), '--check']) == 0
    assert json.loads(capsys.readouterr().out)['operation'] == 'check'
    assert (output / prepare.MANIFEST).read_bytes() == before
    assert prepare.main(['--codex', str(fixed), '--output', str(output), '--archive', str(archive)]) == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'output_already_exists'


def test_staging_cleanup_refuses_unowned_targets(bundle, tmp_path):
    prepare, *_ = bundle
    user_folder = tmp_path / 'valuable-evidence'
    user_folder.mkdir()
    with pytest.raises(ValueError, match='staging_cleanup_target_mismatch'):
        prepare._remove_owned_stage(user_folder, tmp_path)
    assert user_folder.exists()
