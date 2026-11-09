"""Desktop ETW observation stays independent of model and tool gating."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json

import pytest

from transpect_trace.behavior.collector import CodexBehaviorCollector
from transpect_trace.behavior.desktop_identity import (
    BACKEND_IMAGE_SHA256, BACKEND_VERSION, DESKTOP_IMAGE_SHA256,
    PACKAGE_FULL_NAME, PACKAGE_PUBLISHER, same_desktop_observation_subject,
    validate_desktop_observation_identity,
)
from transpect_trace.behavior.index import BehaviorIndex
from transpect_trace.behavior.models import ProcessIdentity
from transpect_trace.behavior.report import build_report
from transpect_trace.guard.etw import FILE, NETWORK, PROCESS


def identity_facts():
    install = rf"C:\Program Files\WindowsApps\{PACKAGE_FULL_NAME}"
    backend = {
        'pid': 100, 'creation_filetime': 123,
        'image_path': r'C:\Users\test\AppData\Local\OpenAI\Codex\bin\pin\codex.exe',
        'image_sha256': BACKEND_IMAGE_SHA256,
        'version': BACKEND_VERSION, 'mode': 'app-server',
    }
    backend_process = {'ParentProcessId': 200, 'UserSid': 'S-1-5-21-100-200-300-1001',
                       'CommandLine': 'SECRET_COMMAND_LINE_MUST_NOT_PERSIST'}
    desktop = {'pid': 200, 'creation_filetime': 120,
               'image_path': install + r'\app\ChatGPT.exe',
               'image_sha256': DESKTOP_IMAGE_SHA256}
    desktop_process = {'UserSid': backend_process['UserSid']}
    package = {'PackageFullName': PACKAGE_FULL_NAME, 'Publisher': PACKAGE_PUBLISHER,
               'InstallLocation': install}
    return [backend, backend_process, desktop, desktop_process, package]


def observation_subject():
    return validate_desktop_observation_identity(*identity_facts())


def test_valid_observation_identity_contains_only_pinned_metadata():
    subject = observation_subject()
    assert subject['channel'] == 'desktop'
    assert subject['observation_only'] is True
    assert subject['baseline']['sha256'] == BACKEND_IMAGE_SHA256
    assert 'SECRET_COMMAND_LINE' not in json.dumps(subject)
    assert same_desktop_observation_subject(subject, deepcopy(subject))


@pytest.mark.parametrize('part,key,value', [
    (0, 'mode', 'exec-server'),
    (0, 'image_sha256', 'a' * 64),
    (0, 'version', 'codex-cli 0.168.0'),
    (0, 'creation_filetime', 0),
    (1, 'ParentProcessId', 201),
    (1, 'UserSid', 'S-1-5-21-999'),
    (2, 'image_sha256', 'b' * 64),
    (2, 'image_path', r'C:\other\ChatGPT.exe'),
    (3, 'UserSid', 'S-1-5-21-888'),
    (4, 'PackageFullName', 'OpenAI.Codex_26.1201.0.0_x64__2p2nqsd0c76g0'),
    (4, 'Publisher', 'CN=other'),
])
def test_observation_identity_rejects_wrong_role_or_pin(part, key, value):
    facts = identity_facts()
    facts[part][key] = value
    with pytest.raises(ValueError):
        validate_desktop_observation_identity(*facts)


def test_generation_recheck_detects_backend_or_parent_replacement():
    expected = observation_subject()
    for key in ('creation_filetime', 'desktop_creation_filetime', 'desktop_pid'):
        changed = deepcopy(expected)
        changed[key] += 1
        assert not same_desktop_observation_subject(expected, changed)


def test_resolver_accepts_only_app_server(monkeypatch):
    import transpect_trace.behavior.desktop_identity as module
    facts = identity_facts()
    monkeypatch.setattr(module, '_cim_process', lambda pid: deepcopy(facts[1] if pid == 100 else facts[3]))
    monkeypatch.setattr(module, 'image_identity', lambda pid: deepcopy(facts[0] if pid == 100 else facts[2]))
    monkeypatch.setattr(module, '_package_metadata', lambda: deepcopy(facts[4]))
    monkeypatch.setattr(module, '_backend_version', lambda path: BACKEND_VERSION)
    monkeypatch.setattr(module, 'command_arguments', lambda line: ['codex.exe', line])
    facts[1]['CommandLine'] = 'app-server'
    assert module.collect_desktop_observation_identity(100)['mode'] == 'app-server'
    facts[1]['CommandLine'] = 'exec-server'
    with pytest.raises(ValueError, match='app-server'):
        module.collect_desktop_observation_identity(100)


def test_desktop_collector_rechecks_before_output_and_keeps_cli_pin(tmp_path, monkeypatch):
    import transpect_trace.observe.windows as windows
    from transpect_trace.guard import BINARY_SHA256
    monkeypatch.setattr(windows, 'identity', lambda pid: {
        'pid': pid, 'creation_filetime': 50, 'image_sha256': BINARY_SHA256,
    })
    subject = observation_subject()
    executable = tmp_path / 'etw.exe'
    executable.write_bytes(b'fake collector')
    (tmp_path / 'build-manifest.json').write_text(json.dumps({
        'artifacts_sha256': {'etw.exe': hashlib.sha256(executable.read_bytes()).hexdigest()},
    }))
    with pytest.raises(ValueError, match='recheck'):
        CodexBehaviorCollector(subject, executable, tmp_path / 'none')
    changed = deepcopy(subject)
    changed['creation_filetime'] += 1
    collector = CodexBehaviorCollector(subject, executable, tmp_path / 'audit',
                                       identity_recheck=lambda: changed)
    with pytest.raises(ValueError, match='generation changed'):
        collector.start()
    assert not (tmp_path / 'audit').exists()
    with pytest.raises(ValueError, match='fixed Codex baseline'):
        CodexBehaviorCollector({'pid': 100, 'creation_filetime': 123,
                                'baseline': subject['baseline']}, executable, tmp_path / 'cli')


def _saved_report(tmp_path, *, events='normal', clock=True):
    root = ProcessIdentity(pid=100, creation_filetime=123, image_sha256=BACKEND_IMAGE_SHA256)
    index = BehaviorIndex(root, root.key)
    anchor = {'qpc_frequency': 1_000_000, 'clock_qpc': 10,
              'clock_filetime': 116_444_736_000_000_000}
    if events == 'unavailable':
        index.consume({'kind': 'etw.unavailable'})
    else:
        index.consume({'kind': 'etw.ready', **anchor})
        if events == 'normal':
            index.consume({'kind': 'etw.event', 'provider': PROCESS, 'task': 'Process',
                           'opcode': 1, 'timestamp_qpc': 20, 'header_pid': 101,
                           'properties': {'ProcessID': 101, 'ParentProcessID': 100,
                                          'CreateTime': 130}})
            index.consume({'kind': 'etw.event', 'provider': NETWORK, 'task': 'TcpIp',
                           'opcode': 1, 'timestamp_qpc': 40, 'header_pid': 101,
                           'properties': {'ProcessID': 101, 'daddr': '127.0.0.1',
                                          'dport': 9000}})
            index.consume({'kind': 'etw.event', 'provider': FILE, 'task': 'Read',
                           'opcode': 1, 'timestamp_qpc': 30, 'header_pid': 101,
                           'properties': {'ProcessID': 101, 'FileObject': 1,
                                          'FileName': r'C:\synthetic.txt'}})
        index.consume({'kind': 'etw.stopped', 'status': 0, 'counters_verified': True,
                       'events_lost': 1 if events == 'lost' else 0})
    directory = tmp_path / 'behavior'
    directory.mkdir()
    (directory / 'status.json').write_text(json.dumps({
        'root': root.model_dump(), 'run_id': root.key, 'health': index.health(),
        'channel': 'desktop', 'clock': anchor if clock and events != 'unavailable' else None,
        'model_egress_status': 'MODEL_EGRESS_NOT_COVERED',
    }), encoding='utf-8')
    (directory / 'events.jsonl').write_text(
        ''.join(event.model_dump_json() + '\n' for event in index.events), encoding='utf-8',
    )
    return directory


def test_desktop_report_has_metadata_timeline_without_guard_binding(tmp_path):
    directory = _saved_report(tmp_path)
    status_path = directory / 'status.json'
    status = json.loads(status_path.read_text(encoding='utf-8'))
    status['model_egress_status'] = 'COVERED'  # A saved status cannot promote an unvalidated adapter.
    status_path.write_text(json.dumps(status), encoding='utf-8')
    report = build_report(directory)
    assert report['health']['state'] == 'stopped'
    assert report['llm_audit_binding'] == 'no_guard_audit'
    assert report['model_egress_status'] == 'MODEL_EGRESS_NOT_COVERED'
    assert report['model_request_mapping'] == 'unvalidated'
    assert report['tool_execution_mapping'] == 'unvalidated_no_native_audit'
    assert report['agent_tool_egress_covered'] is False
    timeline = report['behavior_timeline']
    assert [row['timestamp_qpc'] for row in timeline] == [0, 20, 30, 40]
    assert timeline[2]['lineage'] == ['100-123', '101-130']
    assert timeline[2]['path'] == r'c:\synthetic.txt'
    assert timeline[3]['timestamp_utc'].startswith('1970-01-01T00:00:00.')
    assert 'payload' not in json.dumps(timeline)
    with pytest.raises(ValueError, match='unvalidated Guard audit'):
        build_report(directory, guard_directory=tmp_path)


@pytest.mark.parametrize('events,clock,expected', [
    ('zero', True, 'stopped'),
    ('lost', True, 'degraded'),
    ('unavailable', False, 'unavailable'),
    ('zero', False, 'degraded'),
])
def test_desktop_report_preserves_zero_event_loss_and_unavailable(tmp_path, events, clock, expected):
    report = build_report(_saved_report(tmp_path, events=events, clock=clock))
    assert report['health']['state'] == expected
    assert len(report['behavior_timeline']) == 1
    assert report['model_egress_status'] == 'MODEL_EGRESS_NOT_COVERED'
    assert report['agent_tool_egress_covered'] is False


def test_unavailable_collector_persists_status_and_report(tmp_path, monkeypatch):
    import transpect_trace.behavior.collector as module
    import transpect_trace.behavior.desktop_identity as desktop_identity
    import transpect_trace.observe.windows as windows
    from transpect_trace.behavior.cli import app
    from typer.testing import CliRunner
    monkeypatch.setattr(windows, 'identity', lambda pid: {
        'pid': pid, 'creation_filetime': 50, 'image_sha256': BACKEND_IMAGE_SHA256,
    })
    executable = tmp_path / 'etw.exe'
    executable.write_bytes(b'fake collector')
    (tmp_path / 'build-manifest.json').write_text(json.dumps({
        'artifacts_sha256': {'etw.exe': hashlib.sha256(executable.read_bytes()).hexdigest()},
    }))

    class Process:
        def __init__(self, args, **kwargs):
            self.stdout = io.BytesIO(b'{"kind":"etw.unavailable","win32_error":5}\n')

        def wait(self):
            return 2

    monkeypatch.setattr(module.subprocess, 'Popen', Process)
    subject = observation_subject()
    output = tmp_path / 'audit'
    collector = CodexBehaviorCollector(subject, executable, output,
                                       identity_recheck=lambda: deepcopy(subject), duration=1)
    collector.start()
    collector.wait()
    status = json.loads((output / 'status.json').read_text(encoding='utf-8'))
    report = build_report(output)
    assert status['health']['state'] == 'unavailable'
    assert status['model_egress_status'] == 'MODEL_EGRESS_NOT_COVERED'
    assert report['health']['state'] == 'unavailable'
    assert report['llm_audit_binding'] == 'no_guard_audit'
    monkeypatch.setattr(desktop_identity, 'collect_desktop_observation_identity',
                        lambda pid: deepcopy(subject))
    cli_output = tmp_path / 'audit-cli'
    result = CliRunner().invoke(app, ['attach', '--channel', 'desktop', '--pid', '100',
                                      '--output', str(cli_output), '--collector', str(executable),
                                      '--duration', '1'])
    assert result.exit_code == 2
    assert (cli_output / 'status.json').is_file()
    assert build_report(cli_output)['health']['state'] == 'unavailable'
