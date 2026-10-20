"""Bounded metadata collector; collection failure never changes Native Guard decisions."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path

from .index import BehaviorIndex
from .models import ProcessIdentity


def verify_collector(path: Path):
    manifest = json.loads((path.parent / 'build-manifest.json').read_text(encoding='utf-8'))
    expected = manifest['artifacts_sha256'].get(path.name)
    if not expected or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError('ETW collector manifest/hash mismatch')


class CodexBehaviorCollector:
    def __init__(self, identity, executable, output, *, duration=30):
        from transpect_trace.guard import BINARY_SHA256
        baseline = identity.get('baseline', {})
        image_hash = baseline.get('sha256')
        if image_hash != BINARY_SHA256 or not baseline.get('supported'):
            raise ValueError('Behavior scope requires the fixed Codex baseline')
        if not 1 <= duration <= 300:
            raise ValueError('Duration must be 1..300 seconds')
        from transpect_trace.observe.windows import identity as resolve_identity
        root = ProcessIdentity(pid=identity['pid'], creation_filetime=identity['creation_filetime'], image_sha256=image_hash,image_name='codex.exe')
        self.index = BehaviorIndex(root, root.key, resolver=resolve_identity)
        self.controller_identity = resolve_identity(os.getpid())
        self.output, self.executable, self.duration = Path(output), Path(executable), duration
        self.process = None
        self.ready = threading.Event()
        self.lock = threading.RLock()
        self.thread = None

    def persist_status(self):
        status = dict(schema='transpect.codex.behavior.status/1.0', root=self.index.root.model_dump(),
                      run_id=self.index.run_id, health=self.index.health(),
                      status_at_unix_ns=time.time_ns(), snapshot_only=True,
                      decoder_fields=self.index.decoder_fields,
                      controller_identity=self.controller_identity,
                      llm_gate_status='independent_not_attested_here', egress_control='not_installed')
        temporary = self.output / 'status.tmp'
        temporary.write_text(json.dumps(status, indent=2) + '\n', encoding='utf-8')
        temporary.replace(self.output / 'status.json')

    def start(self):
        verify_collector(self.executable)
        self.output.mkdir(parents=True, exist_ok=False)
        (self.output/'collector-build.json').write_bytes((self.executable.parent/'build-manifest.json').read_bytes())
        self.persist_status()
        self.process = subprocess.Popen([str(self.executable), str(self.duration),str(self.index.root.pid)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=0x08000000)

        def read():
            try:
                with (self.output / 'events.jsonl').open('w', encoding='utf-8') as out:
                    out.write(self.index.events[0].model_dump_json() + '\n')
                    while True:
                        line = self.process.stdout.readline(65537)
                        if not line:
                            break
                        with self.lock:
                            if len(line) > 65536:
                                self.index.gaps.add('oversized_collector_record')
                                # Drain this record, bounded memory, without parsing a suffix.
                                while line and not line.endswith(b'\n'):
                                    line = self.process.stdout.readline(65537)
                                continue
                            try:
                                row = json.loads(line)
                                event = self.index.consume(row)
                            except (ValueError, TypeError, KeyError, AttributeError):
                                self.index.gaps.add('malformed_collector_record')
                                continue
                            if event:
                                out.write(event.model_dump_json() + '\n'); out.flush()
                            if row.get('kind') in ('etw.ready', 'etw.unavailable'):
                                self.ready.set()
                            if row.get('kind') != 'etw.event':
                                self.persist_status()
            finally:
                code = self.process.wait()
                with self.lock:
                    self.index.eof(code)
                    self.persist_status()
                    self.ready.set()
        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()
        if not self.ready.wait(8):
            with self.lock:
                self.index.gaps.add('collector_not_ready')
                self.persist_status()
        return self.index.health()

    def wait(self):
        self.thread.join(self.duration + 15)
        if self.thread.is_alive():
            # Never terminate the protected process. Only our timed collector.
            self.process.terminate()
            self.thread.join(5)
            with self.lock:
                self.index.gaps.add('collector_watchdog_expired')
                self.persist_status()
        return self.index.health()
