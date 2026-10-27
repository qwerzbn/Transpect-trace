"""Chrome Native Messaging host. stdout is exclusively length-framed IPC."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

from transpect_trace.protect.detection import ContentIndex
from .decoder import BrowserDecoder
from .models import WIRE_LIMIT


def _exact(stream, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.read(size - len(chunks))
        if not part:
            raise EOFError('incomplete_frame')
        chunks.extend(part)
    return bytes(chunks)


def read_frame(stream):
    prefix = stream.read(4)
    if prefix == b'': return None
    if len(prefix) != 4: prefix += _exact(stream, 4 - len(prefix))
    size = struct.unpack('<I', prefix)[0]
    if not 0 < size <= WIRE_LIMIT:
        raise ValueError('invalid_frame_length')
    return json.loads(_exact(stream, size).decode('utf-8', errors='strict'))


def write_frame(stream, frame):
    data = json.dumps(frame, separators=(',', ':')).encode('utf-8')
    if len(data) > 4096: raise ValueError('host_reply_limit')
    stream.write(struct.pack('<I', len(data)) + data)
    stream.flush()


def _atomic(path, value):
    temporary = path.with_suffix('.pending')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def serve(config, caller_origin, incoming, outgoing):
    if caller_origin != f"chrome-extension://{config['extension_id']}/":
        raise ValueError('caller_not_enrolled')
    output = Path(config['audit_directory']).resolve()
    output.mkdir(parents=True, exist_ok=True)
    index = ContentIndex.model_validate(config['content_index']) if config.get('content_index') else None
    decoder = BrowserDecoder(config, index)
    # Each native connection writes a separate directory. A worker restart
    # cannot overwrite the previous missing terminal or its sequence history.
    from uuid import uuid4
    connection = output / uuid4().hex
    connection.mkdir()
    _atomic(connection/'health.json', decoder.health())
    try:
        with (connection/'requests.jsonl').open('x', encoding='utf-8') as records:
            while not decoder.terminal:
                frame = read_frame(incoming)
                if frame is None:
                    break
                record = decoder.consume(frame)
                if record is not None:
                    records.write(record.model_dump_json() + '\n')
                    records.flush()
                _atomic(connection/'health.json', decoder.health())
                write_frame(outgoing, {'protocol':'BWO1', 'ack':decoder.sequence, 'can_enforce':False})
    except (ValueError, EOFError, UnicodeError, OSError, KeyError, TypeError, RecursionError):
        decoder.errors += 1
        decoder.gaps.add('native_host_stream_invalid_or_lost')
    finally:
        _atomic(connection/'health.json', decoder.health())
        _atomic(connection/'lifecycle.json', decoder.lifecycle)
    return decoder.health()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('caller_origin')
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding='utf-8'))
        if config.get('python_sha256') != hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest():
            raise ValueError('python_identity_changed')
        for item in config.get('implementation', {}).values():
            if hashlib.sha256(Path(item['path']).read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('implementation_identity_changed')
        if os.name == 'nt':
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        serve(config, args.caller_origin, sys.stdin.buffer, sys.stdout.buffer)
    except (ValueError, OSError, KeyError, TypeError):
        # No traceback, supplied URL, token or raw message is ever logged.
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
