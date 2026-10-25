"""Isolated fake-data participant A. All source/handoff I/O follows stdin release.

Stdout is fixture truth (never independent observer evidence). Windows x64 only.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
import sys

MAX_BYTES = 1024 * 1024
PIPE_PREFIX = "\\\\.\\pipe\\TranspectFlowBusiness-"


def emit(kind: str, **fields):
    print(json.dumps({"kind": kind, "evidence_origin": "fixture_truth", **fields}), flush=True)


def win32():
    if sys.platform != "win32" or c.sizeof(c.c_void_p) != 8:
        raise RuntimeError("requires_windows_x64")
    k = c.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    k.CreateFileW.restype = w.HANDLE
    k.ReadFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
    k.WriteFile.argtypes = k.ReadFile.argtypes
    k.CloseHandle.argtypes = [w.HANDLE]
    k.FlushFileBuffers.argtypes = [w.HANDLE]
    k.WaitNamedPipeW.argtypes = [w.LPCWSTR, w.DWORD]
    return k


def open_handle(k, path, *, write=False, pipe=False):
    handle = k.CreateFileW(path, 0x40000000 if write else 0x80000000,
                           0 if pipe else 1, None, 3 if pipe or not write else 2,
                           0x80, None)
    if handle == w.HANDLE(-1).value:
        raise c.WinError(c.get_last_error())
    return handle


def read_source(k, path):
    handle = open_handle(k, path)
    content = bytearray()
    try:
        buffer = c.create_string_buffer(65536)
        while True:
            count = w.DWORD()
            if not k.ReadFile(handle, buffer, len(buffer), c.byref(count), None):
                raise c.WinError(c.get_last_error())
            if not count.value:
                break
            if len(content) + count.value > MAX_BYTES:
                raise ValueError("source_exceeds_limit")
            content.extend(buffer.raw[:count.value])
        bytes(content).decode("utf-8")
        return bytes(content)
    finally:
        k.CloseHandle(handle)


def handoff(k, path, data, scenario):
    pipe = scenario == "pipe"
    if pipe:
        if not path.startswith(PIPE_PREFIX) or "\\" in path[len(PIPE_PREFIX):]:
            raise ValueError("invalid_local_business_pipe")
        if not k.WaitNamedPipeW(path, 10000):
            raise c.WinError(c.get_last_error())
    handle = open_handle(k, path, write=True, pipe=pipe)
    try:
        # One write is one message for message-mode Named Pipe. File mode uses
        # bounded chunks so the experiment exercises observation segmentation.
        chunks = [data] if pipe else [data[i:i + 65536] for i in range(0, len(data), 65536)]
        for chunk in chunks:
            buffer = c.create_string_buffer(chunk)
            count = w.DWORD()
            if not k.WriteFile(handle, buffer, len(chunk), c.byref(count), None):
                raise c.WinError(c.get_last_error())
            if count.value != len(chunk):
                raise ValueError("short_write")
        # File durability is a useful fixture boundary. Pipe delivery is proven
        # by B's independent read evidence: a client flush can race B's close
        # after the completed message and incorrectly report BROKEN_PIPE.
        if not pipe and not k.FlushFileBuffers(handle):
            raise c.WinError(c.get_last_error())
    finally:
        k.CloseHandle(handle)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["file", "pipe"], required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--handoff", required=True)
    args = parser.parse_args(argv)
    try:
        k = win32()
        emit("ready", role="A", pid=os.getpid(), source_access_started=False)
        if sys.stdin.readline().strip() != "release":
            raise ValueError("release_required")
        content = read_source(k, args.source)
        handoff(k, args.handoff, content, args.scenario)
        emit("transfer_complete", bytes=len(content))
        if sys.stdin.readline().strip() != "finish":
            raise ValueError("finish_required")
        emit("finished")
        return 0
    except (OSError, ValueError, RuntimeError, UnicodeError) as error:
        # Never stringify OSError: Windows may embed a secret-bearing path.
        emit("error", error_type=type(error).__name__, win32_error=getattr(error, "winerror", None))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
