"""Explicit independent process membership over the existing metadata decoder.

This adapter does not alter Codex baseline checks or infer membership from ancestry.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import threading

from transpect_trace.behavior.index import BehaviorIndex
from transpect_trace.behavior.models import ProcessIdentity
from transpect_trace.guard.etw import number


def verify_flow_etw(executable, manifest_path):
    executable, manifest_path = Path(executable), Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("protocol") != "FIO1" or manifest.get("can_enforce") is not False:
        raise ValueError("flow ETW requires observation-only FIO1 build")
    if executable.name != "flow_etw.exe":
        raise ValueError("flow ETW requires explicit-member collector artifact")
    expected = manifest.get("artifacts", {}).get(executable.name, {}).get("sha256")
    if not expected or hashlib.sha256(executable.read_bytes()).hexdigest() != expected:
        raise ValueError("flow ETW build identity mismatch")
    return manifest


class MultiApplicationIndex:
    def __init__(self, members, run_id, *, limit=100_000):
        self.members = [m if isinstance(m, ProcessIdentity) else ProcessIdentity.model_validate(m) for m in members]
        if not self.members or len(self.members) > 16 or len({m.pid for m in self.members}) != len(self.members):
            raise ValueError("flow ETW requires 1..16 distinct live member PIDs")
        self.indices = {m.pid: BehaviorIndex(m, f"{run_id}:{m.key}", limit=limit) for m in self.members}
        for index in self.indices.values():
            index.events[0].evidence_method = "explicit_member_registration_not_etw_event"
        self.gaps = set()
        self.ready = False
        self.terminal = False
        self.unavailable = False

    @property
    def events(self):
        return [event for index in self.indices.values() for event in index.events]

    def consume(self, row):
        if not isinstance(row, dict):
            raise ValueError("ETW record must be an object")
        kind = row.get("kind")
        if kind != "etw.event":
            if kind == "etw.ready":
                if row.get("scope") != "explicit_members" or row.get("member_count") != len(self.members):
                    self.gaps.add("collector_scope_mismatch")
                else:
                    self.ready = True
            elif kind == "etw.stopped":
                self.terminal = True
            elif kind == "etw.unavailable":
                self.unavailable = True
            for index in self.indices.values():
                index.consume(row)
            return None
        props = row.get("properties", {})
        if not isinstance(props, dict):
            raise ValueError("invalid ETW properties")
        pid = number(props.get("ProcessID", props.get("ProcessId", props.get("PID", row.get("header_pid")))))
        index = self.indices.get(pid)
        if index is None:
            return None
        # Even process-start rows are sent only to their explicitly enrolled
        # index. A parent reference cannot enroll a third process.
        result = index.consume(row)
        if result and result.subject.key != index.root.key:
            self.gaps.add("unregistered_identity_rejected")
            return None
        return result

    def eof(self, code):
        for index in self.indices.values():
            index.eof(code)

    def health(self):
        states = [index.health() for index in self.indices.values()]
        gaps = self.gaps | {gap for state in states for gap in state["gaps"]}
        lost = max((state["events_lost"] for state in states), default=0)
        state = "unavailable" if self.unavailable else "unknown" if not self.ready else "degraded" if gaps or lost else "stopped" if self.terminal else "ready"
        return {"state": state, "ready_observed": self.ready, "terminal_observed": self.terminal,
                "events_lost": lost, "gaps": sorted(gaps), "scope": "explicit_members", "can_enforce": False}


def summarize_coverage(index, subjects, scenario, *, destination_port=None):
    """Readiness/loss counters cannot substitute for real per-member events.

    Operation counts assert ETW observations only, not completed I/O or bytes sent.
    """
    if scenario not in {"file", "pipe"}:
        raise ValueError("unknown flow ETW coverage scenario")
    roles = {role: (subject["pid"], subject["creation_filetime"]) for role, subject in subjects.items()}
    counts = {role: {kind: 0 for kind in ("file.read", "file.write", "file.access", "network.activity", "process.start", "process.exit")}
              for role in roles}
    event_ids = {role: [] for role in roles}
    registrations = actual = target_network = 0
    for event in index.events:
        if event.evidence_method == "explicit_member_registration_not_etw_event":
            registrations += 1
            continue
        if not event.evidence_method.startswith("etw_"):
            continue
        key = (event.subject.pid, event.subject.creation_filetime)
        for role, identity in roles.items():
            if key == identity and event.kind in counts[role]:
                counts[role][event.kind] += 1
                event_ids[role].append(event.event_id)
                actual += 1
                if (role == "B" and event.kind == "network.activity" and event.protocol == "tcp"
                        and event.destination_address == "127.0.0.1" and event.destination_port == destination_port):
                    target_network += 1
    required = [("A", "file.read"), ("B", "network.activity")]
    if scenario == "file":
        required += [("A", "file.write"), ("B", "file.read")]
    gaps = [f"etw_{role}_{kind.replace('.', '_')}_not_observed"
            for role, kind in required if not counts.get(role, {}).get(kind, 0)]
    if actual == 0:
        gaps.append("etw_no_real_events")
    if destination_port is not None and not target_network:
        gaps.append("etw_B_controlled_destination_not_observed")
    return {"registration_count": registrations, "actual_event_count": actual, "per_member": counts,
            "controlled_destination_event_count": target_network, "evidence_event_ids": event_ids, "gaps": gaps, "can_enforce": False,
            "limitations": ["ETW access is not I/O completion; network activity is not payload-send proof"]}


class MultiApplicationETWCollector:
    def __init__(self, members, executable, output, *, run_id, duration=30, manifest=None):
        if not 1 <= duration <= 300:
            raise ValueError("duration must be 1..300 seconds")
        self.index = MultiApplicationIndex(members, run_id)
        self.executable, self.output = Path(executable), Path(output)
        self.manifest = Path(manifest) if manifest else self.executable.parent / "native-build.json"
        self.duration = duration
        self.process = self.thread = None
        self.ready = threading.Event()
        self.lock = threading.RLock()

    def persist(self):
        row = {"schema_version": "transpect.flow.etw-status/1.0", "members": [m.model_dump() for m in self.index.members],
               "health": self.index.health(), "can_enforce": False}
        temporary = self.output / "status.tmp"
        temporary.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.output / "status.json")

    def start(self):
        manifest = verify_flow_etw(self.executable, self.manifest)
        from transpect_trace.observe.windows import identity
        for member in self.index.members:
            current = identity(member.pid)
            if (current["creation_filetime"] != member.creation_filetime or not member.image_sha256
                    or current["image_sha256"] != member.image_sha256):
                raise ValueError("flow ETW member identity mismatch")
        self.output.mkdir(parents=True, exist_ok=False)
        (self.output / "collector-build.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        self.persist()
        arguments = [str(self.executable), str(self.duration), *[f"{m.pid}:{m.creation_filetime}" for m in self.index.members]]
        self.process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, creationflags=0x08000000)

        def read():
            try:
                with (self.output / "events.jsonl").open("w", encoding="utf-8") as out:
                    for event in self.index.events:
                        out.write(self.event_json(event) + "\n")
                    while line := self.process.stdout.readline(65537):
                        with self.lock:
                            if len(line) > 65536:
                                self.index.gaps.add("oversized_collector_record")
                                while line and not line.endswith(b"\n"):
                                    line = self.process.stdout.readline(65537)
                                continue
                            try:
                                row = json.loads(line)
                                event = self.index.consume(row)
                            except (ValueError, TypeError, KeyError, AttributeError):
                                self.index.gaps.add("malformed_collector_record")
                                continue
                            if event:
                                out.write(self.event_json(event) + "\n")
                                out.flush()
                            if row.get("kind") != "etw.event":
                                self.persist()
                            if row.get("kind") in ("etw.ready", "etw.unavailable"):
                                self.ready.set()
            finally:
                code = self.process.wait()
                with self.lock:
                    self.index.eof(code)
                    self.persist()
                    self.ready.set()
        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()
        if not self.ready.wait(8):
            with self.lock:
                self.index.gaps.add("collector_not_ready")
                self.persist()
        return self.index.health()

    @staticmethod
    def event_json(event):
        row = event.model_dump()
        row["schema_version"] = "transpect.flow.system-event/1.0"
        row["membership_basis"] = "explicit_registration"
        return json.dumps(row, ensure_ascii=True)

    def stop(self):
        if self.process and self.process.poll() is None:
            try:
                self.process.stdin.write(b"stop\n")
                self.process.stdin.flush()
            except (OSError, ValueError):
                with self.lock:
                    self.index.gaps.add("collector_stop_ipc_failed")
        return self.wait()

    def wait(self):
        if self.thread:
            self.thread.join(self.duration + 15)
            if self.thread.is_alive():
                self.process.terminate()
                self.thread.join(5)
                with self.lock:
                    self.index.gaps.add("collector_watchdog_expired")
                    self.persist()
        return self.index.health()
