"""ECW2 structured frames. Only the explicitly enhanced build uses this parser."""
from __future__ import annotations

import base64
import struct
from .models import CaptureEvent

HEADER = struct.Struct("<4s7I10Q")
PROTOCOL = "ECW2"


def read_exact(stream, count):
    data = bytearray()
    while len(data) < count:
        part = stream.read(count-len(data))
        if not part:
            raise EOFError("incomplete_structured_capture")
        data.extend(part)
    return bytes(data)


class StructuredCapture:
    def __init__(self, subject, application, pipeline):
        self.subject, self.application, self.pipeline = subject, application, pipeline
        self.session = None
        self.ready = False
        self.terminal = False
        self.lost = 0
        self.frequency = None

    def read(self, stream):
        raw = read_exact(stream, HEADER.size)
        length = HEADER.unpack(raw)[1]
        if length > 65536:
            raise ValueError("structured_frame_limit")
        return self.consume(raw, read_exact(stream, length))

    def consume(self, raw, data):
        (magic, length, pid, tid, kind, direction, flags, reserved,
         birth, session_lo, session_hi, low, high, generation, sequence, qpc, frequency, lost) = HEADER.unpack(raw)
        if (magic != b"ECW2" or length != len(data) or length > 65536 or pid != self.subject['pid'] or
            birth != self.subject['creation_filetime'] or kind not in {0,1,2,3} or direction not in {0,1} or
            flags & ~768 or reserved or frequency <= 0 or qpc <= 0 or not (session_lo or session_hi) or self.terminal):
            raise ValueError("invalid_structured_capture")
        session = (session_lo, session_hi)
        if self.session is None:
            if kind != 1: raise ValueError("capture_ready_required")
            self.session, self.frequency = session, frequency
        if session != self.session or frequency != self.frequency or lost < self.lost:
            raise ValueError("capture_session_or_counter_changed")
        if kind in {1,3} and (data or low or high or generation or sequence or flags):
            raise ValueError("invalid_control_frame")
        if kind==2 and data:raise ValueError('closed_frame_contains_data')
        self.lost = lost
        if kind == 1:
            if self.ready: raise ValueError("duplicate_capture_ready")
            self.ready = True
            self.health('ready')
            return None
        if kind == 3:
            self.terminal = True
            self.health('terminal')
            if lost: self.gap("terminal_capture_loss")
            return None
        if not generation or not sequence:
            raise ValueError("capture_context_identity_missing")
        connection = f"{session_lo:016x}{session_hi:016x}-{generation:x}-{low:x}-{high:x}"
        event = CaptureEvent(provider="ecapture-windows", capture_point="tls", pid=pid, tid=tid,
            creation_filetime=birth, connection_id=connection, direction="send" if direction == 0 else "recv",
            sequence=sequence, captured_qpc=qpc, qpc_frequency=frequency,
            data_b64=base64.b64encode(data).decode(), truncated=bool(flags&256),
            lost_events=lost+bool(flags&512), connection_identity="stable",
            event="closed" if kind == 2 else "data", application=self.application,
            image_sha256=self.subject.get("image_sha256"))
        self.pipeline.consume(event)
        return event

    def health(self, kind):
        self.pipeline.write('collector-health.jsonl',{'protocol':'ECW2','kind':kind,
            'pid':self.subject['pid'],'creation_filetime':self.subject['creation_filetime'],
            'session':f'{self.session[0]:016x}{self.session[1]:016x}','lost':self.lost,'can_enforce':False})

    def gap(self, reason):
        self.pipeline.gap(CaptureEvent(provider="ecapture-windows", capture_point="tls",
            pid=self.subject['pid'], creation_filetime=self.subject['creation_filetime'], tid=0,
            connection_id="collector-health", direction="send", sequence=1, captured_qpc=0,
            qpc_frequency=1, application=self.application), reason)
