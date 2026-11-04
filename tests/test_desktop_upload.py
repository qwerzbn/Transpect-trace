"""The desktop upload pipe must decide on exact bytes, not a filename or path."""
import hashlib
import json
import os
import struct
import time
import ctypes as c
from ctypes import wintypes as w

import pytest

from transpect_trace.guard.desktop_upload import (
    MAX_UPLOAD_BYTES, SCHEMA, DesktopUploadPipe, _configure_upload_winapi,
    decide_upload_event, parse_upload_header,
)


SUBJECT = {"pid": 42, "creation_filetime": 123456789}


def header(payload: bytes, *, kind="upload.bytes") -> dict:
    return {"schema": SCHEMA, "request_id": "r1", "kind": kind,
            "pid": SUBJECT["pid"], "creation_filetime": SUBJECT["creation_filetime"],
            "filename": "sample.docx", "body_bytes": len(payload),
            "body_sha256": hashlib.sha256(payload).hexdigest()}


def parse(value: dict) -> dict:
    return parse_upload_header(json.dumps(value).encode(), subject=SUBJECT)


def test_exact_complete_bytes_are_scanned_before_allow():
    body = b"benign office fixture"
    class Approval:
        decision = "ALLOW"
        approval_id = "approval-1"
        rule_ids = ()
    class Bridge:
        seen = None
        def evaluate_attachment(self, filename, data):
            self.seen = filename, data
            return Approval()
    bridge = Bridge()
    result = decide_upload_event(parse(header(body)), body, bridge)
    assert bridge.seen == ("sample.docx", body)
    assert result["decision"] == "allow" and result["approval_id"] == "approval-1"


def test_hash_mismatch_and_incomplete_body_never_scan_or_allow():
    body = b"sensitive fixture"
    class Bridge:
        def evaluate_attachment(self, filename, data):
            raise AssertionError("bridge must not see mismatched bytes")
    request = parse(header(body))
    assert decide_upload_event(request, body[:-1], Bridge())["decision"] == "deny"
    assert decide_upload_event(request, b"different bytesXXXXX", Bridge())["decision"] == "deny"


def test_review_is_a_denial_and_no_approval_id_is_returned():
    body = b"unknown format"
    class Approval:
        decision = "REVIEW"
        approval_id = "must-not-release"
        rule_ids = ("UNINSPECTABLE_FILE",)
    class Bridge:
        def evaluate_attachment(self, filename, data): return Approval()
    result = decide_upload_event(parse(header(body)), body, Bridge())
    assert result["decision"] == "deny" and result["approval_id"] is None


def test_file_reference_binding_uses_original_approval_and_hash():
    body = b"already approved"
    request = header(b"") | {"kind": "upload.reference", "approval_id": "approval_1",
                             "reference_id": "file_1", "body_sha256": hashlib.sha256(body).hexdigest()}
    class Bridge:
        bound = None
        def bind_reference(self, approval_id, reference_id, filename, body_sha256):
            self.bound = approval_id, reference_id, filename, body_sha256
    bridge = Bridge()
    result = decide_upload_event(parse(request), b"", bridge)
    assert result["decision"] == "allow"
    assert bridge.bound == ("approval_1", "file_1", "sample.docx", hashlib.sha256(body).hexdigest())


def test_ready_event_has_no_payload_and_cannot_be_mixed_with_file_fields():
    ready = {"schema": SCHEMA, "request_id": "r0", "kind": "upload.ready",
             "pid": 42, "creation_filetime": 123456789}
    assert decide_upload_event(parse(ready), b"", object())["decision"] == "allow"
    with pytest.raises(ValueError, match="shape"):
        parse(ready | {"filename": "sneaked.txt"})


def test_size_identity_and_unknown_metadata_fail_closed():
    body = b"one"
    with pytest.raises(ValueError, match="identity"):
        parse(header(body) | {"pid": 43})
    with pytest.raises(ValueError, match="identity"):
        parse(header(body) | {"pid": True})
    with pytest.raises(ValueError, match="shape"):
        parse(header(body) | {"file_path": "C:\\secret.txt"})
    with pytest.raises(ValueError, match="inspection limit"):
        parse(header(body) | {"body_bytes": MAX_UPLOAD_BYTES + 1})


def test_duplicate_upload_header_key_is_rejected_before_scanning():
    encoded = json.dumps(header(b"bytes")).encode("utf-8")
    encoded = encoded[:-1] + b',"filename":"different.txt"}'
    with pytest.raises(ValueError, match="duplicate"):
        parse_upload_header(encoded, subject=SUBJECT)


def test_upload_winapi_declarations_preserve_64_bit_handles():
    class Function:
        argtypes = None
        restype = None
    class Kernel:
        pass
    kernel = Kernel()
    for name in ("OpenProcess", "WaitForSingleObject", "WaitForMultipleObjects",
                 "CreateEventW", "GetOverlappedResult", "CancelIoEx"):
        setattr(kernel, name, Function())
    _configure_upload_winapi(kernel)
    assert kernel.OpenProcess.restype is w.HANDLE
    assert kernel.CreateEventW.restype is w.HANDLE
    assert kernel.WaitForSingleObject.restype is w.DWORD
    assert kernel.WaitForMultipleObjects.restype is w.DWORD


def test_upload_process_wait_failure_is_not_treated_as_alive():
    pipe = object.__new__(DesktopUploadPipe)
    pipe.process = 2**40
    class Kernel:
        result = 258
        def WaitForSingleObject(self, handle, timeout):
            assert handle == pipe.process and timeout == 0
            return self.result
    pipe.k = Kernel()
    assert pipe._alive()
    pipe.k.result = 0xFFFFFFFF
    assert not pipe._alive()
    pipe.k.result = 0
    assert not pipe._alive()


def test_upload_pipe_failure_notifies_controller_to_revoke_leases():
    pipe = object.__new__(DesktopUploadPipe)
    pipe.errors = []
    notified = []
    pipe.on_failure = lambda: notified.append(True)
    pipe._record_failure("deadline")
    assert pipe.errors == ["deadline"] and notified == [True]


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe loopback")
def test_upload_pipe_loopback_waits_for_complete_bytes(tmp_path, monkeypatch):
    from transpect_trace.guard.desktop import current_user_sid
    from transpect_trace.guard.pipe import windows_api
    monkeypatch.setattr("transpect_trace.guard.desktop_upload.verify_live_upload_subject",
                        lambda subject, adapter: None)
    subject = {"pid": os.getpid(), "creation_filetime": 123456789,
               "user_sid": current_user_sid(), "image_sha256": "a" * 64}
    class Approval:
        decision = "ALLOW"
        approval_id = "approved"
        rule_ids = ()
    class Bridge:
        data = None
        def evaluate_attachment(self, filename, data):
            self.data = filename, data
            return Approval()
    bridge = Bridge()
    pipe = DesktopUploadPipe(subject, {}, bridge, tmp_path / "audit.jsonl",
                             upload_dll=tmp_path / "not-loaded.dll")
    pipe.start()
    k = windows_api()
    try:
        for event, body in (({"schema": SCHEMA, "request_id": "ready", "kind": "upload.ready",
                             "pid": subject["pid"], "creation_filetime": subject["creation_filetime"]}, b""),
                            (header(b"benign bytes") | {"request_id": "file", "pid": subject["pid"]},
                             b"benign bytes")):
            until = time.monotonic() + 1
            while True:
                client = k.CreateFileW(pipe.name, 0xc0000000, 0, None, 3, 0, None)
                if client != w.HANDLE(-1).value or c.get_last_error() not in (2, 231) or time.monotonic() >= until:
                    break
                time.sleep(0.005)
            assert client != w.HANDLE(-1).value, (event["kind"], c.get_last_error(), pipe.errors)
            try:
                encoded = json.dumps(event).encode("utf-8")
                frame = struct.pack("<I", len(encoded)) + encoded + body
                sent = w.DWORD()
                assert k.WriteFile(client, frame, len(frame), c.byref(sent), None)
                assert sent.value == len(frame)
                def read_exact(size):
                    data = bytearray()
                    while len(data) < size:
                        buffer = c.create_string_buffer(size - len(data))
                        count = w.DWORD()
                        assert k.ReadFile(client, buffer, len(buffer), c.byref(count), None), (event["kind"], c.get_last_error(), pipe.errors)
                        assert count.value
                        data.extend(buffer.raw[:count.value])
                    return bytes(data)
                response_size = struct.unpack("<I", read_exact(4))[0]
                response = json.loads(read_exact(response_size))
                assert response["decision"] == "allow"
                ack = w.DWORD()
                assert k.WriteFile(client, b"\x06", 1, c.byref(ack), None)
                assert ack.value == 1
            finally:
                k.CloseHandle(client)
        assert bridge.data == ("sample.docx", b"benign bytes")
        assert not pipe.errors
    finally:
        pipe.close()
