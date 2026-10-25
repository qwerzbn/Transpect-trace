"""Restricted synchronous WinHTTP uploader for controlled Agent fixtures."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import sys
import time
from urllib.parse import urlsplit

MAX_BYTES = 1024 * 1024
_libraries = []


def endpoint(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    port = 443 if parts.port is None else parts.port
    if (parts.scheme != 'https' or parts.hostname != 'localhost' or parts.path != '/upload'
            or parts.query or parts.fragment or parts.username is not None or parts.password is not None
            or not 1 <= port <= 65535 or '?' in url or '#' in url):
        raise ValueError('unsupported_local_origin')
    return 'localhost', port


def preload():
    """Load the actual TLS libraries before observers attach; perform no I/O."""
    if sys.platform != 'win32' or c.sizeof(c.c_void_p) != 8:
        raise RuntimeError('requires_windows_x64')
    if not _libraries:
        for name in ('kernel32', 'crypt32', 'secur32', 'sspicli', 'schannel', 'winhttp'):
            _libraries.append(c.WinDLL(name, use_last_error=True))
    api = _libraries[-1]
    api.WinHttpOpen.argtypes = [w.LPCWSTR, w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD]
    api.WinHttpOpen.restype = w.HANDLE
    api.WinHttpSetTimeouts.argtypes = [w.HANDLE, c.c_int, c.c_int, c.c_int, c.c_int]
    api.WinHttpSetTimeouts.restype = w.BOOL
    api.WinHttpSetOption.argtypes = [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD]
    api.WinHttpSetOption.restype = w.BOOL
    api.WinHttpConnect.argtypes = [w.HANDLE, w.LPCWSTR, w.WORD, w.DWORD]
    api.WinHttpConnect.restype = w.HANDLE
    api.WinHttpOpenRequest.argtypes = [w.HANDLE, w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.LPCWSTR,
                                       c.POINTER(w.LPCWSTR), w.DWORD]
    api.WinHttpOpenRequest.restype = w.HANDLE
    api.WinHttpSendRequest.argtypes = [w.HANDLE, w.LPCWSTR, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, c.c_size_t]
    api.WinHttpSendRequest.restype = w.BOOL
    api.WinHttpReceiveResponse.argtypes = [w.HANDLE, c.c_void_p]
    api.WinHttpReceiveResponse.restype = w.BOOL
    api.WinHttpQueryHeaders.argtypes = [w.HANDLE, w.DWORD, w.LPCWSTR, c.c_void_p, c.POINTER(w.DWORD), c.c_void_p]
    api.WinHttpQueryHeaders.restype = w.BOOL
    api.WinHttpReadData.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    api.WinHttpReadData.restype = w.BOOL
    api.WinHttpCloseHandle.argtypes = [w.HANDLE]
    api.WinHttpCloseHandle.restype = w.BOOL
    return api


def upload(url: str, body: bytes, *, timeout_seconds: float = 10, checkpoint=None) -> dict:
    host, port = endpoint(url)
    if not isinstance(body, bytes) or len(body) > MAX_BYTES:
        raise ValueError('outbound_exceeds_limit')
    if not 0 < timeout_seconds <= 30:
        raise ValueError('invalid_timeout')
    api = preload()
    handles = []

    def check(result):
        if not result:
            raise c.WinError(c.get_last_error())
        return result

    def option(handle, number, value):
        data = w.DWORD(value)
        check(api.WinHttpSetOption(handle, number, c.byref(data), c.sizeof(data)))

    try:
        session = check(api.WinHttpOpen('TranspectAgentFixture/1', 1, None, None, 0))  # NO_PROXY
        handles.append(session)
        milliseconds = max(1, int(timeout_seconds * 1000))
        check(api.WinHttpSetTimeouts(session, milliseconds, milliseconds, milliseconds, milliseconds))
        option(session, 133, 0)  # ENABLE_HTTP_PROTOCOL: no HTTP/2 or HTTP/3
        connection = check(api.WinHttpConnect(session, host, port, 0))
        handles.append(connection)
        request = check(api.WinHttpOpenRequest(connection, 'POST', '/upload', 'HTTP/1.1', None, None, 0x00800000))
        handles.append(request)
        option(request, 88, 0)  # REDIRECT_POLICY_NEVER
        option(request, 63, 0x1 | 0x4)  # DISABLE_COOKIES | DISABLE_AUTHENTICATION
        # No ignore-security flags, certificate replacement, implicit credentials,
        # proxy, redirect or response-body export. Windows trust checks stay on.
        buffer = c.create_string_buffer(body)
        first_length = max(1, len(body)//2) if checkpoint and body else len(body)
        check(api.WinHttpSendRequest(request, 'Content-Type: application/json\r\nConnection: close\r\n',
                                     0xffffffff, buffer, first_length, len(body), 0))
        if checkpoint:
            # Explicit fake-data fault experiment: a real prefix is already sent.
            # No fabricated success return or TLS buffering is involved.
            checkpoint()
            api.WinHttpWriteData.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
            api.WinHttpWriteData.restype = w.BOOL
            offset = first_length
            while offset < len(body):
                count = w.DWORD()
                check(api.WinHttpWriteData(request, c.byref(buffer,offset), len(body)-offset, c.byref(count)))
                if not count.value or count.value > len(body)-offset:
                    raise ValueError('incomplete_http_write')
                offset += count.value
        check(api.WinHttpReceiveResponse(request, None))
        status, size = w.DWORD(), w.DWORD(c.sizeof(w.DWORD))
        check(api.WinHttpQueryHeaders(request, 19 | 0x20000000, None, c.byref(status), c.byref(size), None))
        if not 200 <= status.value < 300:
            raise ValueError('unexpected_http_status')
        response = c.create_string_buffer(4096)
        total, deadline = 0, time.monotonic() + timeout_seconds
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('response_deadline')
            count = w.DWORD()
            check(api.WinHttpReadData(request, response, len(response), c.byref(count)))
            total += count.value
            if total > MAX_BYTES:
                raise ValueError('response_exceeds_limit')
            if not count.value:
                break
        return {'bytes': len(body), 'http_status': status.value}
    finally:
        for handle in reversed(handles):
            api.WinHttpCloseHandle(handle)
