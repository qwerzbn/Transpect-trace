"""Owned browser experiment preparation, discovery and read-only reports."""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from uuid import uuid4

from .decoder import loopback_origin
from .models import BrowserRequestObservation


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def _private_directory(path):
    path.mkdir(parents=True, exist_ok=False)
    if os.name == 'nt':
        import csv
        rows = list(csv.reader(subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], encoding='utf-8').splitlines()))
        sid = rows[0][1]
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        path.chmod(0o700)


def extension_identity(manifest):
    value = hashlib.sha256(base64.b64decode(manifest['key'], validate=True)).digest()[:16].hex()
    return ''.join(chr(ord('a') + int(c, 16)) for c in value)


def _wide_literal(path):
    value = str(path)
    if any(char in value for char in ('"', '\r', '\n', '\x00')):
        raise ValueError('unsafe_launcher_path')
    return 'L"' + value.replace('\\', '\\\\') + '"'


def prepare_browser_run(output, *, origin, chrome, python=sys.executable, install=False, content_index=None):
    """Create a fresh private enrollment; does not open or operate Chrome."""
    output = Path(output).resolve()
    chrome, python = Path(chrome).resolve(), Path(python).resolve()
    normalized = loopback_origin(origin)
    if not chrome.is_file() or not python.is_file(): raise ValueError('client_unavailable')
    root = Path(__file__).resolve().parents[4]
    templates = root/'extensions/browser-observe'
    if not templates.is_dir(): raise ValueError('extension_sources_unavailable')
    source_manifest = json.loads((templates/'manifest.json').read_text(encoding='utf-8'))
    extension_id = extension_identity(source_manifest)
    run_id = uuid4().hex
    host_name = 'com.transpect.browser_' + run_id
    _private_directory(output)
    extension = output/'extension'
    extension.mkdir()
    (output/'profile').mkdir()
    for name in ('manifest.json', 'worker.js', 'core.js', 'popup.html', 'popup.js'):
        shutil.copyfile(templates/name, extension/name)
    # The Chromium permission is origin-limited again at runtime. No page
    # content or credentials are stored in this private enrollment material.
    origin_url = __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(normalized)
    permission_host = '[' + origin_url.hostname + ']' if ':' in origin_url.hostname else origin_url.hostname
    source_manifest['host_permissions'] = [f'https://{permission_host}/*']
    _write(extension/'manifest.json', source_manifest)
    enrollment = {'browser_run_id':run_id, 'origin':normalized, 'host_name':host_name,
                  'extension_id':extension_id, 'enrollment_token':secrets.token_hex(32)}
    (extension/'enrollment.js').write_text('const TTEnrollment = Object.freeze(' + json.dumps(enrollment) + ');\n', encoding='utf-8')
    config = dict(enrollment, audit_directory=str(output/'audit'), python_sha256=digest(python),
                  implementation={p.name:{'path':str(p), 'sha256':digest(p)} for p in Path(__file__).parent.glob('*.py')})
    if content_index is not None:
        from transpect_trace.protect.detection import ContentIndex
        config['content_index'] = ContentIndex.model_validate(content_index).model_dump()
    _write(output/'host-config.json', config)
    (output/'launcher_config.h').write_text('\n'.join([
        '#define TT_PYTHON ' + _wide_literal(python),
        '#define TT_CONFIG ' + _wide_literal(output/'host-config.json'),
        '#define TT_ORIGIN ' + _wide_literal(f'chrome-extension://{extension_id}/'), '']), encoding='utf-8')
    launcher = output/'browser-observe-host.exe'
    build = {'state':'unavailable', 'can_enforce':False}
    if os.name == 'nt':
        result = subprocess.run([str(python), '-m', 'ziglang', 'cc', '-target', 'x86_64-windows-gnu', '-O2',
            '-municode', '-I', str(output), str(templates/'native_host.c'), '-o', str(launcher)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if result.returncode == 0:
            build = {'state':'built', 'launcher_sha256':digest(launcher), 'source_sha256':digest(templates/'native_host.c'), 'can_enforce':False}
        else:
            build['limitation'] = 'native_launcher_build_failed'
    _write(output/'native-host.json', {'name':host_name, 'description':'Controlled localhost browser request observation',
           'path':str(launcher), 'type':'stdio', 'allowed_origins':[f'chrome-extension://{extension_id}/']})
    public = {'schema_version':'transpect.browser.experiment/1.0', 'browser_run_id':run_id,
        'origin':normalized, 'extension_id':extension_id, 'host_name':host_name,
        'chrome':{'path':str(chrome), 'sha256':digest(chrome)}, 'python':{'path':str(python), 'sha256':digest(python)},
        'extension_sources':{p.name:digest(p) for p in templates.glob('*') if p.is_file()},
        'build':build, 'state':'prepared_manual_load_required', 'can_enforce':False,
        'profile_directory':str(output/'profile'), 'extension_directory':str(extension),
        'launch_arguments':[str(chrome), '--user-data-dir='+str(output/'profile'), '--no-first-run', '--no-default-browser-check', 'chrome://extensions/'],
        'limitations':['manual_extension_load_required', 'real_site_not_certified', 'network_process_binding_unknown',
                       'eCapture_probe_not_run', 'raw_file_and_streaming_not_supported']}
    if os.name == 'nt':
        from transpect_trace.observe.windows import file_version
        public['chrome']['version'] = file_version(chrome)
    _write(output/'experiment.json', public)
    if install:
        register_native_host(output)
    return public


def register_native_host(directory):
    """Install only this new per-run HKCU name; never overwrite another host."""
    if os.name != 'nt': raise ValueError('windows_required')
    import winreg
    directory = Path(directory).resolve()
    experiment = json.loads((directory/'experiment.json').read_text(encoding='utf-8'))
    _host_identity(experiment)
    if experiment['build']['state'] != 'built' or digest(directory/'browser-observe-host.exe') != experiment['build']['launcher_sha256']:
        raise ValueError('native_host_identity_mismatch')
    path = 'Software\\Google\\Chrome\\NativeMessagingHosts\\' + experiment['host_name']
    for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | view):
                raise ValueError('native_host_registry_already_exists')
        except FileNotFoundError:
            pass
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_32KEY) as key:
        winreg.SetValueEx(key, '', 0, winreg.REG_SZ, str(directory/'native-host.json'))
    _write(directory/'registry-owner.json', {'registry_path':path, 'manifest':str(directory/'native-host.json'), 'can_enforce':False})


def unregister_native_host(directory):
    if os.name != 'nt': raise ValueError('windows_required')
    import winreg
    directory = Path(directory).resolve()
    owner = json.loads((directory/'registry-owner.json').read_text(encoding='utf-8'))
    experiment = json.loads((directory/'experiment.json').read_text(encoding='utf-8'))
    _host_identity(experiment)
    path = 'Software\\Google\\Chrome\\NativeMessagingHosts\\' + experiment['host_name']
    if owner != {'registry_path':path, 'manifest':str(directory/'native-host.json'), 'can_enforce':False}:
        raise ValueError('registry_ownership_mismatch')
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
        if winreg.QueryValueEx(key, '') != (owner['manifest'], winreg.REG_SZ) or winreg.QueryInfoKey(key)[:2] != (0, 1):
            raise ValueError('registry_contents_changed')
    winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER, path, winreg.KEY_WOW64_32KEY, 0)
    return {'removed_owned_registration':True, 'can_enforce':False}


def _host_identity(experiment):
    run_id = experiment.get('browser_run_id')
    if not isinstance(run_id, str) or not re.fullmatch('[a-f0-9]{32}', run_id) or experiment.get('host_name') != 'com.transpect.browser_' + run_id:
        raise ValueError('owned_host_name_required')


def report_browser_run(directory, *, receipts=None):
    directory = Path(directory)
    manifest = json.loads((directory/'experiment.json').read_text(encoding='utf-8'))
    observations, health, lifecycle = [], [], []
    gaps = set()
    connections = sorted((directory/'audit').glob('*')) if (directory/'audit').exists() else []
    for connection in connections:
        if not connection.is_dir(): continue
        try:
            state = json.loads((connection/'health.json').read_text(encoding='utf-8'))
            if state.get('browser_run_id') != manifest['browser_run_id'] or state.get('can_enforce') is not False:
                raise ValueError('health_identity_mismatch')
            health.append(state)
            if not state['ready'] or not state['terminal'] or state['errors'] or state['lost_events'] or state['limitations']:
                gaps.add('capture_health_incomplete')
            before = len(observations)
            for line in (connection/'requests.jsonl').read_text(encoding='utf-8').splitlines():
                row = BrowserRequestObservation.model_validate_json(line)
                if row.browser_run_id != manifest['browser_run_id'] or row.extension_session_id != state['extension_session_id']:
                    raise ValueError('request_identity_mismatch')
                observations.append(row.model_dump())
            if type(state.get('request_observations')) is not int or len(observations) - before != state['request_observations']:
                gaps.add('request_audit_count_mismatch')
            lifecycle.extend(json.loads((connection/'lifecycle.json').read_text(encoding='utf-8')))
        except (OSError, ValueError, KeyError, TypeError):
            gaps.add('audit_incomplete_or_invalid')
    if not observations: gaps.add('no_request_observation')
    if not health: gaps.add('native_host_not_observed')
    if len(health) > 1: gaps.add('multiple_host_connections_mapping_unverified')
    if any(row['completeness'] != 'complete' or row['detection_status'] == 'incomplete' for row in observations):
        gaps.add('request_content_incomplete')
    receipt_state = 'unverified'
    if receipts is not None:
        expected = Counter((row['body_sha256'], row['body_bytes']) for row in receipts)
        actual = Counter((row['body_sha256'], row['body_bytes']) for row in observations if row['completeness'] == 'complete')
        receipt_state = 'multiset_match_candidate' if expected and expected == actual else 'mismatch'
        if receipt_state == 'mismatch': gaps.add('origin_body_count_or_hash_mismatch')
    result = {'schema_version':'transpect.browser.report/1.0', 'browser_run_id':manifest['browser_run_id'],
        'status':'unavailable' if not health else 'partial' if gaps else 'complete_request_observation',
        'observations':observations, 'collector_health':health, 'lifecycle':lifecycle,
        'source_receipts':receipt_state, 'exact_attempt_mapping':False, 'ecapture_certified':False,
        'real_site_certified':False, 'network_process_binding':'unknown', 'can_enforce':False,
        'limitations':sorted(gaps | {'browser_api_not_wire_or_delivery_evidence', 'origin_hash_match_not_unique_request_mapping'})}
    return result
