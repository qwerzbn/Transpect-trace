"""Fixed fake-data file boundary participants; no network or policy execution."""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import sys

LIMIT = 1024 * 1024
CUT = 65536


def api():
    if sys.platform != 'win32' or c.sizeof(c.c_void_p) != 8:
        raise RuntimeError('requires_windows_x64')
    k = c.WinDLL('kernel32', use_last_error=True)
    k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    k.CreateFileW.restype = w.HANDLE
    k.ReadFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
    k.ReadFile.restype = w.BOOL
    k.WriteFile.argtypes = k.ReadFile.argtypes
    k.WriteFile.restype = w.BOOL
    k.SetFilePointerEx.argtypes = [w.HANDLE, c.c_longlong, c.POINTER(c.c_longlong), w.DWORD]
    k.SetFilePointerEx.restype = w.BOOL
    k.FlushFileBuffers.argtypes = [w.HANDLE]
    k.FlushFileBuffers.restype = w.BOOL
    k.CloseHandle.argtypes = [w.HANDLE]
    k.CloseHandle.restype = w.BOOL
    return k


def open_file(k, path, *, write=False, create=False):
    h = k.CreateFileW(path, 0x40000000 if write else 0x80000000, 3, None, 2 if create else 3, 0x80, None)
    if h == w.HANDLE(-1).value:
        raise c.WinError(c.get_last_error())
    return h


def read_chunk(k, handle, size):
    buffer, done = c.create_string_buffer(size), w.DWORD()
    if not k.ReadFile(handle, buffer, size, c.byref(done), None):
        raise c.WinError(c.get_last_error())
    return buffer.raw[:done.value]


def read_source(k, path):
    handle = open_file(k, path)
    data = bytearray()
    try:
        while chunk := read_chunk(k, handle, CUT):
            data.extend(chunk)
            if len(data) > LIMIT:
                raise ValueError('source_limit')
        if len(data) <= CUT or not data.endswith(b'"}'):
            raise ValueError('unsupported_fake_fixture')
        json.loads(data)
        return bytes(data)
    finally:
        k.CloseHandle(handle)


def replacement(data):
    """Change only the padded suffix, preserving length and valid JSON syntax."""
    if not CUT < len(data) <= LIMIT or not data.endswith(b'"}'):
        raise ValueError('unsupported_fake_fixture')
    changed = data[:CUT] + b'B' * (len(data) - CUT - 2) + b'"}'
    json.loads(changed)
    return changed


def write_file(k, path, data, *, offset=0, create=False):
    handle = open_file(k, path, write=True, create=create)
    try:
        if offset:
            actual = c.c_longlong()
            if not k.SetFilePointerEx(handle, offset, c.byref(actual), 0) or actual.value != offset:
                raise OSError('seek_failed')
        body, done = c.create_string_buffer(data), w.DWORD()
        if not k.WriteFile(handle, body, len(data), c.byref(done), None):
            raise c.WinError(c.get_last_error())
        if done.value != len(data):
            raise ValueError('short_write')
        if not k.FlushFileBuffers(handle):
            raise c.WinError(c.get_last_error())
    finally:
        k.CloseHandle(handle)


def emit(kind, role, **fields):
    print(json.dumps({'kind': kind, 'role': role, 'evidence_origin': 'fixture_truth', **fields}), flush=True)


def command(expected):
    if sys.stdin.readline(32).strip() != expected:
        raise ValueError('unexpected_control_command')


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid_arguments')


def main(argv=None):
    role = 'unknown'
    try:
        parser = Arguments(description=__doc__)
        parser.add_argument('--fake-data-only', action='store_true', required=True)
        parser.add_argument('--role', choices=('A', 'B'), required=True)
        parser.add_argument('--scenario', choices=('stable', 'overwrite_suffix'), required=True)
        parser.add_argument('--source', required=True)
        parser.add_argument('--handoff', required=True)
        parser.add_argument('--url')
        args = parser.parse_args(argv)
        role, k = args.role, api()
        upload = None
        if args.url:
            if role != 'B':
                raise ValueError('upload_is_b_only')
            # Fixed absolute source tree under -I -S; these project imports are
            # individually hashed by the controller's experimental baseline.
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
            from transpect_trace.flow.agents import winhttp
            winhttp.endpoint(args.url)
            winhttp.preload()  # Library load only, before Native I/O/eCapture.
            upload = winhttp.upload
        emit('ready', role, pid=os.getpid(), source_access_started=False)
        command('release')
        if role == 'A':
            data = read_source(k, args.source)
            write_file(k, args.handoff, data, create=True)
            emit('initial_written', role, bytes=len(data))
            if args.scenario == 'overwrite_suffix':
                command('rewrite')
                data = replacement(data)
                write_file(k, args.handoff, data[CUT:], offset=CUT)
                emit('rewritten', role, bytes=len(data) - CUT)
        else:
            handle = open_file(k, args.handoff)
            try:
                data = bytearray(read_chunk(k, handle, CUT))
                if len(data) != CUT:
                    raise ValueError('short_first_read')
                emit('read_paused', role, bytes=len(data))
                command('continue')
                while chunk := read_chunk(k, handle, CUT):
                    data.extend(chunk)
                    if len(data) > LIMIT:
                        raise ValueError('read_limit')
                json.loads(data)
            finally:
                k.CloseHandle(handle)
            emit('read_complete', role, bytes=len(data), body_sha256=hashlib.sha256(data).hexdigest(), json_valid=True)
            if upload:
                emit('sent', role, **upload(args.url, bytes(data)))
        command('finish')
        emit('finished', role)
        return 0
    except Exception as error:
        emit('error', role, error_type=type(error).__name__, win32_error=getattr(error, 'winerror', None))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
