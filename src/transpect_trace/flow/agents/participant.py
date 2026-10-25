"""Two fixed-behavior test Agents, not an external LLM or framework adapter."""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
from uuid import uuid4

# Controlled -I execution uses the fixed interpreter, avoiding venv redirectors.
PACKAGE_ROOT = Path(__file__).resolve().parents[3]
if __package__ in (None, ''):
    sys.path.insert(0, str(PACKAGE_ROOT))

from transpect_trace.flow.participant import MAX_BYTES, PIPE_PREFIX, handoff, read_source, win32
from transpect_trace.flow.agents import protocol, winhttp


def emit(kind, *, role, **fields):
    print(json.dumps({'kind': kind, 'role': role, 'evidence_origin': 'fixture_truth', **fields}), flush=True)


def step(role, name, **identities):
    emit('agent_step', role=role, step=name,
         **{key + '_sha256': hashlib.sha256(value.encode('ascii')).hexdigest() for key, value in identities.items()})


def pipe_name(value):
    if not value.startswith(PIPE_PREFIX) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', value[len(PIPE_PREFIX):]):
        raise ValueError('invalid_local_business_pipe')
    return value


def io_api():
    api = win32()
    api.CreateNamedPipeW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.DWORD, w.DWORD, w.DWORD, w.DWORD, c.c_void_p]
    api.CreateNamedPipeW.restype = w.HANDLE
    api.ConnectNamedPipe.argtypes = [w.HANDLE, c.c_void_p]
    api.ConnectNamedPipe.restype = w.BOOL
    api.DisconnectNamedPipe.argtypes = [w.HANDLE]
    api.DisconnectNamedPipe.restype = w.BOOL
    api.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    api.OpenThread.restype = w.HANDLE
    api.GetCurrentThreadId.restype = w.DWORD
    api.CancelSynchronousIo.argtypes = [w.HANDLE]
    api.CancelSynchronousIo.restype = w.BOOL
    return api


class BoundedIO:
    """Cancel only this fixture thread's synchronous Win32 operations at deadline."""
    def __init__(self, api, seconds=15):
        self.api, self.seconds = api, seconds
        self.done, self.expired = threading.Event(), threading.Event()
        self.handle = None

    def __enter__(self):
        self.handle = self.api.OpenThread(0x1, False, self.api.GetCurrentThreadId())  # THREAD_TERMINATE
        if not self.handle:
            raise c.WinError(c.get_last_error())
        def cancel():
            if self.done.wait(self.seconds):
                return
            self.expired.set()
            while not self.done.is_set():
                self.api.CancelSynchronousIo(self.handle)
                self.done.wait(0.02)
        self.thread = threading.Thread(target=cancel, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.done.set()
        self.thread.join(1)
        self.api.CloseHandle(self.handle)
        if self.expired.is_set():
            raise TimeoutError('synchronous_io_deadline')


def receive(api, name, *, ready=None, timeout_seconds=15):
    name = pipe_name(name)
    # Local, one instance, inbound, synchronous message pipe. Its client is A.
    handle = api.CreateNamedPipeW(name, 0x1 | 0x00080000, 0x4 | 0x2 | 0x8, 1, 65536, 65536, 10000, None)
    if handle == w.HANDLE(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        with BoundedIO(api, timeout_seconds):
            if ready:
                ready()
            if not api.ConnectNamedPipe(handle, None) and c.get_last_error() != 535:
                raise c.WinError(c.get_last_error())
            body = bytearray()
            buffer = c.create_string_buffer(65536)
            while True:
                count = w.DWORD()
                ok = api.ReadFile(handle, buffer, min(len(buffer), MAX_BYTES + 1 - len(body)), c.byref(count), None)
                error = 0 if ok else c.get_last_error()
                if not ok and error != 234:  # ERROR_MORE_DATA retains actual bytes
                    raise c.WinError(error)
                body.extend(buffer.raw[:count.value])
                if len(body) > MAX_BYTES:
                    raise ValueError('message_exceeds_limit')
                if ok:
                    return bytes(body)
                if not count.value:
                    raise ValueError('incomplete_message')
    finally:
        api.DisconnectNamedPipe(handle)
        api.CloseHandle(handle)


def query_result(raw, *, public_only=False):
    return protocol.query_payload(raw, public_only=public_only)


def expect_command(command):
    if sys.stdin.readline(32).strip() != command:
        raise ValueError('controller_command_required')


def split_source(api, path):
    """Deliberate two-read fixture for an in-place source-change experiment."""
    api.GetFileSizeEx.argtypes = [w.HANDLE, c.POINTER(c.c_longlong)]
    api.GetFileSizeEx.restype = w.BOOL
    # Only this explicit negative fixture permits concurrent source writes.
    handle = api.CreateFileW(path, 0x80000000, 0x1 | 0x2, None, 3, 0x80, None)
    if handle == w.HANDLE(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        size = c.c_longlong()
        if not api.GetFileSizeEx(handle, c.byref(size)):
            raise c.WinError(c.get_last_error())
        if not 2 <= size.value <= MAX_BYTES:
            raise ValueError('split_source_size_limit')
        first_size = max(1, size.value // 2)
        first, count = c.create_string_buffer(first_size), w.DWORD()
        with BoundedIO(api):
            if not api.ReadFile(handle, first, first_size, c.byref(count), None):
                raise c.WinError(c.get_last_error())
        if count.value != first_size:
            raise ValueError('split_source_short_first_read')
        emit('source_read_part', role='A', bytes=count.value)
        expect_command('continue_read')
        second = c.create_string_buffer(MAX_BYTES + 1 - count.value)
        second_count = w.DWORD()
        with BoundedIO(api):
            if not api.ReadFile(handle, second, len(second), c.byref(second_count), None):
                raise c.WinError(c.get_last_error())
        if count.value + second_count.value > MAX_BYTES:
            raise ValueError('source_exceeds_limit')
        data = first.raw[:count.value] + second.raw[:second_count.value]
        data.decode('utf-8')
        return data
    finally:
        api.CloseHandle(handle)


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid_arguments')


def main(argv=None):
    role, stage = 'unknown', 'arguments'
    try:
        parser = Arguments(description=__doc__)
        parser.add_argument('--role', choices=['A', 'B'], required=True)
        parser.add_argument('--task-id', required=True)
        parser.add_argument('--handoff', required=True)
        parser.add_argument('--source')
        parser.add_argument('--message-id')
        parser.add_argument('--url')
        parser.add_argument('--transform', choices=['copy', 'nested', 'extractive', 'public'], default='copy')
        parser.add_argument('--handoff-public', action='store_true')
        parser.add_argument('--package-root')
        parser.add_argument('--rounds', type=int, choices=range(1, 5), default=1)
        parser.add_argument('--message-mode', choices=['unique', 'repeat', 'conflict'], default='unique')
        parser.add_argument('--attempts', type=int, choices=range(1, 4), default=1)
        parser.add_argument('--same-attempt-id', action='store_true')
        parser.add_argument('--hold-after-read', action='store_true')
        parser.add_argument('--split-read', action='store_true')
        parser.add_argument('--retry-first-error', action='store_true')
        parser.add_argument('--pause-upload', action='store_true')
        args = parser.parse_args(argv)
        role = args.role
        if not re.fullmatch(r'[0-9a-f]{32}', args.task_id):
            raise ValueError('invalid_task_id')
        pipe_name(args.handoff)
        if args.package_root and Path(args.package_root).resolve() != PACKAGE_ROOT:
            raise ValueError('unexpected_package_root')
        if role == 'A':
            if not args.source or not args.message_id or not re.fullmatch(r'[0-9a-f]{32}', args.message_id) or args.url:
                raise ValueError('invalid_agent_a_arguments')
            if args.attempts != 1 or args.same_attempt_id or args.hold_after_read or args.retry_first_error or args.pause_upload:
                raise ValueError('invalid_agent_a_experiment')
        elif not args.url or args.source or args.message_id or args.handoff_public or args.split_read or args.message_mode != 'unique':
            raise ValueError('invalid_agent_b_arguments')
        if role == 'B':
            winhttp.endpoint(args.url)
            if args.retry_first_error and args.attempts < 2:
                raise ValueError('retry_requires_multiple_attempts')
            if args.pause_upload and (args.rounds != 1 or args.attempts != 1):
                raise ValueError('pause_upload_requires_single_attempt')
        stage = 'initialization'
        api = io_api()
        winhttp.preload()
        emit('ready', role=role, pid=os.getpid(), source_access_started=False)
        expect_command('release')
        if role == 'A':
            stage = 'query'
            if args.split_read:
                raw = split_source(api, args.source)
            else:
                with BoundedIO(api):
                    raw = read_source(api, args.source)
            payload = query_result(raw, public_only=args.handoff_public)
            step(role, 'query', task_id=args.task_id)
            for iteration in range(args.rounds):
                stage = 'delegate'
                if iteration:
                    expect_command('next')
                message_id = uuid4().hex if iteration and args.message_mode == 'unique' else args.message_id
                content = protocol.transform_payload(payload, 'public') if args.message_mode == 'conflict' and iteration == 1 else payload
                body = protocol.make_message(args.task_id, message_id, content)
                if len(body) > MAX_BYTES:
                    raise ValueError('message_exceeds_limit')
                with BoundedIO(api):
                    handoff(api, args.handoff, body, 'pipe')
                step(role, 'delegate', task_id=args.task_id, message_id=message_id)
                emit('transfer_complete', role=role, bytes=len(body))
        else:
            shared_attempt_id = uuid4().hex if args.same_attempt_id else None
            for iteration in range(args.rounds):
                stage = 'receive'
                if iteration:
                    expect_command('next')
                body = receive(api, args.handoff, ready=lambda: emit('pipe_ready', role=role))
                message = protocol.parse_message(body)
                if message['task_id'] != args.task_id:
                    raise ValueError('task_identity_mismatch')
                emit('received', role=role, bytes=len(body))
                if args.hold_after_read:
                    stage = 'hold_after_read'
                    expect_command('upload')
                stage = 'transform'
                report = protocol.transform_payload(message['payload'], args.transform)
                tool_id = uuid4().hex
                step(role, 'transform', task_id=args.task_id, message_id=message['message_id'])
                for attempt in range(args.attempts):
                    attempt_id = shared_attempt_id or uuid4().hex
                    outbound = protocol.make_outbound(args.task_id, message['message_id'], tool_id, attempt_id, report)
                    stage = 'http_upload'
                    step(role, 'http_upload', task_id=args.task_id, message_id=message['message_id'],
                         tool_call_id=tool_id, attempt_id=attempt_id)
                    def checkpoint():
                        emit('upload_paused', role=role)
                        expect_command('continue_upload')
                    try:
                        result = winhttp.upload(args.url, outbound, **({'checkpoint': checkpoint} if args.pause_upload else {}))
                    except ValueError as error:
                        if args.retry_first_error and attempt == 0 and str(error) == 'unexpected_http_status':
                            emit('attempt_failed', role=role)
                            continue
                        raise
                    emit('sent', role=role, **result)
        stage = 'finish'
        expect_command('finish')
        emit('finished', role=role)
        return 0
    except Exception as error:
        emit('error', role=role, stage=stage, error_type=type(error).__name__, win32_error=getattr(error, 'winerror', None))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
