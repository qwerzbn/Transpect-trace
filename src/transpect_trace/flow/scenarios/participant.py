"""Fixed fake-data workers. Control records are fixture truth, never capture evidence."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

LIMIT = 1024 * 1024


def write_json(path, value):
    temporary = path.with_suffix('.pending')
    temporary.write_text(json.dumps(value, ensure_ascii=True), encoding='utf-8')
    temporary.replace(path)


def wait(path, seconds=180):
    deadline = time.monotonic() + seconds
    while True:
        if (path.parent/'abort').is_file():
            raise RuntimeError('fixture_cancelled')
        if path.is_file():
            return
        if time.monotonic() > deadline:
            raise TimeoutError('fixture_release_unavailable')
        time.sleep(.025)


def rendezvous(directory, role, **metadata):
    write_json(directory / (role + '.ready.json'), {'pid': os.getpid(), **metadata})
    wait(directory / (role + '.release'))


def parent_map():
    class Entry(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('usage', wintypes.DWORD), ('pid', wintypes.DWORD),
                    ('heap', ctypes.c_size_t), ('module', wintypes.DWORD), ('threads', wintypes.DWORD),
                    ('parent', wintypes.DWORD), ('priority', wintypes.LONG), ('flags', wintypes.DWORD),
                    ('name', wintypes.WCHAR * 260)]
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = k.CreateToolhelp32Snapshot(2, 0)
    if handle == wintypes.HANDLE(-1).value:
        raise OSError('process_snapshot_unavailable')
    result = {}
    try:
        entry = Entry(); entry.size = ctypes.sizeof(entry)
        ok = k.Process32FirstW(handle, ctypes.byref(entry))
        while ok:
            result[entry.pid] = (entry.parent, entry.name.lower())
            ok = k.Process32NextW(handle, ctypes.byref(entry))
    finally:
        k.CloseHandle(handle)
    return result


def credential(directory):
    # Git invokes this only after a controlled 401, before the push body. The
    # parent chain is a locator; the controller independently verifies identities.
    parents = parent_map(); pid = os.getpid(); helper = None
    for _ in range(6):
        if pid not in parents: break
        parent, name = parents[pid]
        if name in {'git-remote-http.exe', 'git-remote-https.exe'}:
            helper = pid; break
        pid = parent
    if helper is None: raise ValueError('git_transport_parent_not_found')
    for line in sys.stdin:
        if line in ('\n', '\r\n'): break
    rendezvous(directory, 'git-helper-' + str(helper), helper_pid=helper)
    # Deliberately fake authentication for this local receiver only.
    sys.stdout.write('username=fixture\npassword=fixture\n\n'); sys.stdout.flush()


def git_environment():
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_') and 'PROXY' not in k.upper()}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='NUL', GIT_TERMINAL_PROMPT='0')
    return env


def transform(config, directory):
    rendezvous(directory, 'transformer')
    raw = Path(config['incident']).read_bytes()
    if len(raw) > LIMIT: raise ValueError('source_limit')
    document = json.loads(raw.decode('utf-8-sig'))
    case = config['case']; output = Path(config['generated']); workspace = output.parent
    public = {'report': 'ordinary synthetic diagnostic statistics', 'count': 1}
    content = public if case == 'public' else document
    output.write_text(json.dumps(content, ensure_ascii=False), encoding='utf-8', newline='')
    git = config['git']; env = git_environment()
    def run(*args, check=True):
        return subprocess.run([git, '-C', str(workspace), *args], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=check)
    run('init', '--initial-branch=fixture')
    run('config', 'user.name', 'Synthetic Fixture')
    run('config', 'user.email', 'fixture@example.invalid')
    run('config', 'core.autocrlf', 'false')
    run('config', 'core.hooksPath', str(directory / 'empty-hooks'))
    if case in {'untracked', 'old_commit'}:
        (workspace / 'ordinary.txt').write_text('ordinary synthetic data', encoding='utf-8')
        run('add', 'ordinary.txt')
    else:
        run('add', output.name)
    run('-c', 'commit.gpgsign=false', 'commit', '-m', 'synthetic initial data')
    if case == 'old_commit':
        run('add', output.name)
        run('-c', 'commit.gpgsign=false', 'commit', '-m', 'synthetic local-only change')
    if case == 'deleted_history':
        run('rm', output.name)
        run('-c', 'commit.gpgsign=false', 'commit', '-m', 'remove from tip')
    reference = 'HEAD~1' if case == 'old_commit' else 'HEAD'
    # This explicit helper pauses the real transport after public discovery.
    # It is not a substitute transport, TLS library, or network proxy.
    def shell_quote(value):
        return "'" + str(value).replace("'", "'\\''") + "'"
    helper = '!'+shell_quote(sys.executable.replace('\\', '/'))+' -I '+shell_quote(str(Path(__file__).resolve()).replace('\\', '/'))+' --role credential --control '+shell_quote(str(directory).replace('\\', '/'))
    options = ['-c', 'credential.helper=', '-c', 'credential.helper=' + helper,
               '-c', 'http.proxy=', '-c', 'http.version=HTTP/1.1', '-c', 'http.sslVerify=true']
    if config['git_tls_backend'] == 'schannel':
        options += ['-c', 'http.sslBackend=schannel']
    attempts = []
    for _ in range(2 if case == 'repeat' else 1):
        result = run(*options, 'push', config['url'], reference + ':refs/heads/fixture', check=False)
        attempts.append({'exit_code': result.returncode})
    write_json(directory / 'transformer.done.json', {'success': all(r['exit_code'] == 0 for r in attempts),
                'transform_success': True, 'commit_success': True,
                'expected_ref_rejection': case == 'reject_ref', 'attempts': attempts})
    wait(directory / 'transformer.finish')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=['exporter', 'transformer', 'credential'], required=True)
    parser.add_argument('--control', type=Path, required=True)
    parser.add_argument('--config', type=Path)
    parser.add_argument('credential_operation', nargs='?')
    args = parser.parse_args(); directory = args.control.resolve()
    try:
        if args.role == 'credential':
            if args.credential_operation not in (None, 'get'): return
            credential(directory); return
        config = json.loads(args.config.read_text(encoding='utf-8'))
        if args.role == 'transformer':
            transform(config, directory); return
        rendezvous(directory, 'exporter')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(config['url'], timeout=10) as response:
            body = response.read(LIMIT + 1)
        if len(body) > LIMIT: raise ValueError('ticket_limit')
        Path(config['incident']).write_bytes(body)
        write_json(directory / 'exporter.done.json', {'success': True, 'bytes': len(body)})
        wait(directory / 'exporter.finish')
    except Exception as error:
        write_json(directory / (args.role + '.error.json'), {'error_type': type(error).__name__})
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
