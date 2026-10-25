"""Failure-path orchestration tests using doubles, not Windows collection proof."""
import json
from types import SimpleNamespace

import pytest


def harness(tmp_path, monkeypatch, *, failure=None, cleanup_failure=False):
    from transpect_trace.flow import runtime, native, etw, origin
    from transpect_trace.observe import ecapture, windows
    from transpect_trace.protect.detection import ContentIndex

    paths = {name: tmp_path / name for name in ('python', 'participant', 'uploader', 'observer', 'etw', 'native_manifest',
                                                'ecapture', 'ecapture_manifest', 'source', 'content_index', 'certificate', 'private_key')}
    paths['content_index'].write_text(ContentIndex(version='mock-empty').model_dump_json())
    manifest = SimpleNamespace(scenario='file', content_type='text', ordinary_body=False, timeout_seconds=10,
                               export_fake_bodies=False, **{name: SimpleNamespace(sha256='a' * 64 if name == 'python' else 'b' * 64)
                                                          for name in paths})
    output = tmp_path / 'audit'
    monkeypatch.setattr(runtime, 'load', lambda _: (manifest, paths, output))
    monkeypatch.setattr(runtime.sys, 'platform', 'win32')
    commands, fixtures, origins = [], [], []

    class FakeProcess:
        def __init__(self, role):
            self.pid = 101 if role == 'A' else 202
            self.code = None
        def poll(self): return self.code

    class FakeFixture:
        def __init__(self, command, directory, role):
            self.role, self.process, self.events = role, FakeProcess(role), []
            fixtures.append(self)
        def wait(self, kind, timeout=15, check=None):
            if check: check()
            if kind == 'ready': return {'kind': kind, 'pid': self.process.pid}
            return {'kind': kind, 'bytes': 1, 'http_status': 200}
        def send(self, command): commands.append((self.role, command))
        def close(self):
            self.process.code = 0
            if cleanup_failure and self.role == 'A': raise RuntimeError('SECRET-DO-NOT-LOG')

    class FakeOrigin:
        def __init__(self, *args):
            self.receipts, self.errors = [], []
            self.url, self.server = 'https://localhost:12345/upload', SimpleNamespace(server_port=12345)
            self.closed = False
            origins.append(self)
        def start(self): return self
        def close(self):
            self.closed = True
            if failure == 'origin_close': raise OSError('SECRET-DO-NOT-LOG')

    class FakeNative:
        def __init__(self, subject, *args, **kwargs): self.started = self.terminal = False
        def start(self):
            if failure == 'native': raise RuntimeError('SECRET-DO-NOT-LOG')
            self.started = True
        def close(self): self.terminal = True
        def status(self):
            return {'ready': self.started, 'terminal': self.terminal, 'lost_events': 0, 'errors': []}

    class FakeETW:
        def __init__(self, *args, **kwargs):
            self.started = self.terminal = False
            self.process = SimpleNamespace(poll=lambda: None)
            self.index = SimpleNamespace(health=self.health, events=[])
        def health(self):
            return {'state': 'ready' if self.started and not self.terminal else 'stopped' if self.terminal else 'unavailable',
                    'ready_observed': self.started, 'terminal_observed': self.terminal, 'events_lost': 0, 'gaps': []}
        def start(self):
            self.started = failure != 'etw'
            return self.health()
        def stop(self):
            self.terminal = True
            return self.health()

    class FakeECapture:
        def __init__(self, *args, **kwargs):
            self.errors = []
            self.structured = SimpleNamespace(ready=False, terminal=False, lost=0)
        def start(self):
            if failure == 'ecapture': raise ValueError('SECRET-DO-NOT-LOG')
            self.structured.ready = True
        def check_health(self):
            if failure == 'ecapture_health': raise RuntimeError('SECRET-DO-NOT-LOG')
        def close(self): self.structured.terminal = True

    def identity(pid):
        if pid == runtime.os.getpid():
            return {'pid': pid, 'creation_filetime': pid * 10, 'image_sha256': 'd' * 64,
                    'image_path': str(tmp_path / 'controller.exe')}
        if pid not in {101, 202}:
            raise OSError('unknown_mock_process')
        return {'pid': pid, 'creation_filetime': pid * 10, 'image_sha256': 'c' * 64 if failure == 'identity' else ('a' if pid == 101 else 'b') * 64,
                'image_path': str(tmp_path / ('python.exe' if pid == 101 else 'uploader.exe'))}

    monkeypatch.setattr(runtime, 'Fixture', FakeFixture)
    monkeypatch.setattr(origin, 'Origin', FakeOrigin)
    monkeypatch.setattr(native, 'NativeIOCollector', FakeNative)
    monkeypatch.setattr(etw, 'MultiApplicationETWCollector', FakeETW)
    monkeypatch.setattr(etw, 'summarize_coverage', lambda *a, **kw: {'actual_event_count': 0, 'gaps': ['etw_no_real_events']})
    monkeypatch.setattr(ecapture, 'ECaptureCollector', FakeECapture)
    def verify(_):
        if failure == 'ecapture_build': raise ValueError('SECRET-DO-NOT-LOG')
        if failure == 'ecapture_stock': return {'variant': 'upstream', 'protocol': 'preview'}
        return {'variant': 'enhanced', 'protocol': 'ECW2'}
    monkeypatch.setattr(ecapture, 'verify_build', verify)
    monkeypatch.setattr(windows, 'identity', identity)
    return runtime, output, commands, fixtures, origins


@pytest.mark.parametrize('failure', ['identity', 'native', 'etw', 'ecapture', 'ecapture_health'])
def test_readiness_failure_never_releases_any_participant(tmp_path, monkeypatch, failure):
    runtime, output, commands, fixtures, origins = harness(tmp_path, monkeypatch, failure=failure)
    result = runtime.run(tmp_path / 'mock.manifest.json')
    assert result['state'] == 'unavailable'
    assert not result['data_released'] and not result['certified']
    assert all(command != 'release' for _, command in commands)
    assert all(f.process.poll() == 0 for f in fixtures)
    assert origins[0].closed
    assert not list(tmp_path.glob('synthetic-work-*'))
    for file in output.rglob('*.json'):
        assert 'SECRET-DO-NOT-LOG' not in file.read_text()


def test_zero_events_cannot_turn_green_readiness_into_complete(tmp_path, monkeypatch):
    runtime, output, commands, _, _ = harness(tmp_path, monkeypatch)
    result = runtime.run(tmp_path / 'mock.manifest.json')
    assert commands == [('A', 'release'), ('B', 'release')]
    assert result['data_released'] and result['state'] == 'partial'
    assert 'etw_no_real_events' in result['coverage_gaps']
    saved = json.loads((output / 'flow-evidence.json').read_text())
    assert not saved['collection_coverage']['complete']
    assert not result['certified']


def test_fixture_cleanup_failure_is_recorded_without_exception_text(tmp_path, monkeypatch):
    runtime, output, _, _, _ = harness(tmp_path, monkeypatch, cleanup_failure=True)
    result = runtime.run(tmp_path / 'mock.manifest.json')
    assert result['state'] == 'partial'
    assert 'fixture_A_cleanup_failed' in result['gaps']
    assert 'SECRET-DO-NOT-LOG' not in (output / 'runtime.json').read_text()


def test_origin_cleanup_failure_does_not_skip_evidence_or_work_cleanup(tmp_path, monkeypatch):
    runtime, output, _, _, _ = harness(tmp_path, monkeypatch, failure='origin_close')
    result = runtime.run(tmp_path / 'mock.manifest.json')
    assert result['state'] == 'partial'
    assert 'origin_close_failed' in result['gaps']
    assert (output / 'flow-evidence.json').is_file()
    assert not list(tmp_path.glob('synthetic-work-*'))
    assert 'SECRET-DO-NOT-LOG' not in (output / 'runtime.json').read_text()


@pytest.mark.parametrize('failure', ['ecapture_build', 'ecapture_stock'])
def test_invalid_ecapture_identity_stops_before_starting_apps(tmp_path, monkeypatch, failure):
    runtime, output, commands, fixtures, origins = harness(tmp_path, monkeypatch, failure=failure)
    result = runtime.run(tmp_path / 'mock.manifest.json')
    assert result['state'] == 'unavailable' and not result['data_released']
    assert not commands and not fixtures and not origins
    assert result['failure_phase'] == 'ecapture_baseline'
    assert 'SECRET-DO-NOT-LOG' not in (output / 'runtime.json').read_text()


@pytest.mark.parametrize('message', [
    {'kind': 'SECRET-DO-NOT-LOG'},
    {'kind': 'ready', 'pid': 'SECRET-DO-NOT-LOG'},
    {'kind': 'received', 'bytes': 'SECRET-DO-NOT-LOG'},
    {'kind': 'ready', 'source_access_started': 'SECRET-DO-NOT-LOG'},
    ['SECRET-DO-NOT-LOG'],
])
def test_fixture_truth_protocol_rejects_secret_values_in_metadata_fields(message):
    import io
    import queue
    from transpect_trace.flow.runtime import Fixture
    fixture = Fixture.__new__(Fixture)
    fixture.role, fixture.events, fixture.queue = 'A', [], queue.Queue(maxsize=128)
    fixture.process = SimpleNamespace(stdout=io.BytesIO((json.dumps(message) + '\n').encode()))
    fixture._read()
    assert fixture.events == []
    assert fixture.queue.get_nowait()['kind'] == 'error'


@pytest.mark.parametrize('failure', ['exited', 'birth_changed', 'image_changed', 'missing_identity'])
def test_status_does_not_show_observing_after_controller_loss(tmp_path, monkeypatch, failure):
    from transpect_trace.flow.cli import read_status
    from transpect_trace.observe import windows
    controller = {'pid': 123, 'creation_filetime': 456, 'image_sha256': 'a' * 64}
    state = {'state': 'observing', 'can_enforce': False, 'gaps': [], 'controller': controller}
    if failure == 'missing_identity': state.pop('controller')
    original = json.dumps(state)
    (tmp_path / 'runtime.json').write_text(original)
    def identity(_):
        if failure == 'exited': raise OSError('gone')
        return {**controller, **({'creation_filetime': 999} if failure == 'birth_changed' else
                                {'image_sha256': 'b' * 64} if failure == 'image_changed' else {})}
    monkeypatch.setattr(windows, 'identity', identity)
    result = read_status(tmp_path)
    assert result['state'] == 'unavailable' and not result['controller_live']
    assert result['recorded_state'] == 'observing'
    assert 'controller_identity_unavailable' in result['gaps']
    assert (tmp_path / 'runtime.json').read_text() == original


def test_status_verifies_active_controller_and_preserves_completed_history(tmp_path, monkeypatch):
    from transpect_trace.flow.cli import read_status
    from transpect_trace.observe import windows
    controller = {'pid': 123, 'creation_filetime': 456, 'image_sha256': 'a' * 64}
    (tmp_path / 'runtime.json').write_text(json.dumps({'state': 'initializing', 'controller': controller}))
    monkeypatch.setattr(windows, 'identity', lambda _: dict(controller))
    assert read_status(tmp_path)['controller_live']
    (tmp_path / 'runtime.json').write_text(json.dumps({'state': 'complete', 'controller': controller, 'can_enforce': False}))
    def unexpected(_): raise AssertionError('completed history must not require a live controller')
    monkeypatch.setattr(windows, 'identity', unexpected)
    assert read_status(tmp_path)['state'] == 'complete'
