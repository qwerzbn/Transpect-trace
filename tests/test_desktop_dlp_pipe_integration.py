"""Synthetic named-pipe round trip; no native Hook or network permit is involved."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

import pytest

from transpect_trace.guard.pipe import PipeServer
from transpect_trace.guard.policy import GuardRequest
from transpect_trace.guard.wire import decode_frame, encode_frame
from transpect_trace.protect.archive import EncryptedRequestArchive
from transpect_trace.protect.desktop_bridge import DesktopDLPBridge


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes and DPAPI")


def _request(request_id: str, body: dict) -> GuardRequest:
    return GuardRequest.model_validate({
        "schema": "transpect.guard.request/1.0",
        "request_id": request_id,
        "guard_session_id": "synthetic-pipe-session",
        "pid": os.getpid(),
        "tid": 1,
        "kind": "model.request",
        "protocol": "http",
        "completeness": "complete",
        "payload_utf8": json.dumps(body, ensure_ascii=False, separators=(",", ":")),
    })


def _read_exact(kernel, handle, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        buffer = ctypes.create_string_buffer(size - len(chunks))
        count = wintypes.DWORD()
        if not kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None) or not count.value:
            raise ctypes.WinError(ctypes.get_last_error())
        chunks.extend(buffer.raw[:count.value])
    return bytes(chunks)


def _round_trip(server: PipeServer, request: GuardRequest) -> dict:
    kernel = server.k
    invalid = wintypes.HANDLE(-1).value
    deadline = time.monotonic() + 3
    while True:
        handle = kernel.CreateFileW(server.name, 0xC0000000, 0, None, 3, 0, None)
        if handle != invalid:
            break
        if time.monotonic() >= deadline:
            raise ctypes.WinError(ctypes.get_last_error())
        time.sleep(0.01)
    try:
        frame = encode_frame(request.model_dump(by_alias=True))
        written = wintypes.DWORD()
        buffer = ctypes.create_string_buffer(frame)
        if not kernel.WriteFile(handle, buffer, len(frame), ctypes.byref(written), None):
            raise ctypes.WinError(ctypes.get_last_error())
        assert written.value == len(frame)
        header = _read_exact(kernel, handle, 4)
        size = struct.unpack("<I", header)[0]
        assert 0 < size < 4096
        return decode_frame(header + _read_exact(kernel, handle, size))
    finally:
        kernel.CloseHandle(handle)


def test_pipe_gate_archives_before_reply_and_denies_review_block_and_unknown_reference(
    tmp_path: Path,
) -> None:
    archive = EncryptedRequestArchive(tmp_path / "encrypted-archive")
    bridge = DesktopDLPBridge({"pid": os.getpid()}, archive)
    real_inspect = bridge.dlp.inspect_text
    inspection_results: list[str] = []

    def observe_inspection(text: str):
        verdict = real_inspect(text)
        inspection_results.append(verdict.decision)
        return verdict

    bridge.dlp.inspect_text = observe_inspection
    audit = tmp_path / "audit.jsonl"
    server = PipeServer(os.getpid(), bridge, audit, workers=1)
    server.start()
    cases = [
        ("public", {"model": "fixture", "input": "A public project note."}, "allow", "none"),
        ("secret", {"model": "fixture", "input": "password=FakeSecret12345"}, "deny", "block_request"),
        ("review", {"model": "fixture", "input": "123-45-6789"}, "deny", "block_request"),
        ("unknown-file", {"model": "fixture", "input": [
            {"type": "input_file", "file_id": "file_unknown"}
        ]}, "deny", "block_request"),
    ]
    try:
        for index, (request_id, body, expected_decision, expected_action) in enumerate(cases, 1):
            request = _request(request_id, body)
            response = _round_trip(server, request)
            assert response["request_id"] == request_id
            assert (response["decision"], response["action"]) == (
                expected_decision, expected_action,
            )
            rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            row = rows[-1]
            assert len(rows) == index
            assert row["request_id"] == request_id
            assert row["body_sha256"] == hashlib.sha256(request.payload_utf8.encode()).hexdigest()
            assert row["archive_record_id"]
            receipt, archived_body = archive.read(row["archive_record_id"])
            assert receipt.kind == "model_request"
            assert archived_body == request.payload_utf8.encode("utf-8")
        assert inspection_results == ["ALLOW", "BLOCK", "REVIEW"]
        audit_text = audit.read_text(encoding="utf-8")
        assert "FakeSecret12345" not in audit_text
        assert "123-45-6789" not in audit_text
        assert len(list(archive.directory.glob("*.enc"))) == len(cases)
        assert server.errors == []
    finally:
        server.close()
