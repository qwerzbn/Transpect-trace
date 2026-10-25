from transpect_trace.behavior.models import ProcessIdentity
from transpect_trace.flow.etw import MultiApplicationETWCollector, MultiApplicationIndex, verify_flow_etw, summarize_coverage
from transpect_trace.guard.etw import FILE, PROCESS, NETWORK


def member(pid, birth):
    return ProcessIdentity(pid=pid, creation_filetime=birth, image_sha256="a" * 64)


def event(pid, tick=20, provider=FILE, **props):
    return dict(kind="etw.event", header_pid=pid, timestamp_qpc=tick, provider=provider,
                task="read", opcode=0, properties=props)


def ready(index):
    index.consume(dict(kind="etw.ready", scope="explicit_members", member_count=2,
                       qpc_frequency=10, clock_qpc=1, clock_filetime=1))


def test_independent_members_no_invented_parent_and_no_descendant_expansion():
    index = MultiApplicationIndex([member(10, 100), member(20, 200)], "session")
    ready(index)
    assert all(e.evidence_method == "explicit_member_registration_not_etw_event" for e in index.events)
    for pid in (10, 20):
        observed = index.consume(event(pid, FileName=r"C:\fake\input.txt", FileObject=pid))
        assert observed.subject.pid == pid
        assert observed.parent_identity is None
    foreign = event(30, provider=PROCESS, ProcessID=30, ParentProcessID=10, CreateTime=300)
    foreign.update(task="process", opcode=1)
    assert index.consume(foreign) is None
    assert index.consume(event(30)) is None
    assert len(index.events) == 4
    assert index.health()["state"] == "ready"


def test_pid_reuse_retires_old_identity():
    index = MultiApplicationIndex([member(10, 100), member(20, 200)], "session")
    ready(index)
    assert index.consume(event(20, 20))
    changed = event(20, 30, PROCESS, ProcessID=20, ParentProcessID=999, CreateTime=201)
    changed.update(task="process", opcode=1)
    assert index.consume(changed) is None
    assert index.consume(event(20, 31)) is None
    assert index.consume(event(10, 32)).subject.creation_filetime == 100


def test_thread_start_does_not_retire_enrolled_process():
    index = MultiApplicationIndex([member(10, 100), member(20, 200)], "session")
    ready(index)
    started = event(20, 25, PROCESS, ProcessID=20, ThreadID=201)
    started.update(task="ThreadStart", opcode=1)
    assert index.consume(started) is None
    observed = index.consume(event(20, 26))
    assert observed.subject.creation_filetime == 200
    assert not index.health()["gaps"]


def test_loss_is_not_multiplied_by_number_of_members_and_no_terminal_is_gap():
    index = MultiApplicationIndex([member(10, 100), member(20, 200)], "session")
    ready(index)
    index.consume(dict(kind="etw.stopped", status=0, events_lost=3, buffers_lost=2,
                       decode_errors=1, counters_verified=True))
    assert index.health()["events_lost"] == 6
    assert index.health()["state"] == "degraded"
    other = MultiApplicationIndex([member(10, 100), member(20, 200)], "other")
    ready(other)
    other.eof(0)
    assert "collector_exit_without_terminal" in other.health()["gaps"]


def test_scope_and_unverified_terminal_cannot_be_healthy():
    index = MultiApplicationIndex([member(10, 100), member(20, 200)], "session")
    index.consume(dict(kind="etw.ready", scope="descendants", member_count=2))
    assert index.health()["state"] != "ready"
    assert "collector_scope_mismatch" in index.health()["gaps"]
    ready(index)
    index.consume(dict(kind="etw.stopped", status=0, events_lost=0, buffers_lost=0, decode_errors=0))
    assert "terminal_counters_not_verified" in index.health()["gaps"]


def test_export_is_flow_metadata_not_codex_process_lineage():
    import json
    index = MultiApplicationIndex([member(10, 100)], "session")
    row = json.loads(MultiApplicationETWCollector.event_json(index.events[0]))
    assert row["schema_version"] == "transpect.flow.system-event/1.0"
    assert row["membership_basis"] == "explicit_registration"
    assert row["parent_identity"] is None


def test_collector_pins_fio1_identity_and_observation_mode(tmp_path):
    import hashlib
    import json
    import pytest
    artifact = tmp_path / "flow_etw.exe"
    artifact.write_bytes(b"test-only-collector")
    path = tmp_path / "native-build.json"
    manifest = dict(protocol="FIO1", can_enforce=False,
                    artifacts={artifact.name: {"sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}})
    path.write_text(json.dumps(manifest))
    assert verify_flow_etw(artifact, path) == manifest
    artifact.write_bytes(b"modified")
    with pytest.raises(ValueError, match="identity"):
        verify_flow_etw(artifact, path)
    manifest["can_enforce"] = True
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="observation-only"):
        verify_flow_etw(artifact, path)
    manifest.update(protocol="unknown", can_enforce=False)
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="FIO1"):
        verify_flow_etw(artifact, path)


def test_ready_and_registration_only_cannot_pass_actual_etw_coverage():
    index = MultiApplicationIndex([member(10, 100), member(20, 200)], "session")
    ready(index)
    subjects = {"A": {"pid": 10, "creation_filetime": 100}, "B": {"pid": 20, "creation_filetime": 200}}
    coverage = summarize_coverage(index, subjects, "file")
    assert coverage["actual_event_count"] == 0
    assert coverage["registration_count"] == 2
    assert "etw_no_real_events" in coverage["gaps"]
    index.consume(event(10))
    written = event(10)
    written["task"] = "write"
    index.consume(written)
    index.consume(event(20))
    connected = event(20, provider=NETWORK, PID=20, daddr="127.0.0.1", dport=12345)
    connected["task"] = "tcpip"
    index.consume(connected)
    coverage = summarize_coverage(index, subjects, "file")
    assert coverage["actual_event_count"] == 4
    assert not coverage["gaps"]
    coverage = summarize_coverage(index, subjects, "file", destination_port=23456)
    assert "etw_B_controlled_destination_not_observed" in coverage["gaps"]
    coverage = summarize_coverage(index, subjects, "file", destination_port=12345)
    assert coverage["controlled_destination_event_count"] == 1
    assert not coverage["gaps"]
