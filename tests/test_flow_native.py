"""Wire checks do not stand in for the Windows Hook runtime probes."""
import hashlib
import json

import pytest

from transpect_trace.flow.native import FIELDS, HEADER, LIMIT, decode_frame, validate_build


SUBJECT = {'pid': 42, 'creation_filetime': 12345}
SCOPES = [{'role': 'source', 'path': 'C:\\fake\\source'},
          {'role': 'pipe', 'path': '\\\\.\\pipe\\TranspectFlowBusiness-test'}]


def frame(kind=4, data=b'fake', **updates):
    values = dict.fromkeys(FIELDS, 0)
    values.update(pid=42, creation_filetime=12345, sequence=2, qpc=100,
                  completed_qpc=101, requested_length=len(data), completed_length=len(data),
                  length=len(data), flags=1 | 8 | 128 | 256, volume=7, file_id=8)
    values.update(updates)
    return HEADER.pack(b'FIO1', kind, *(values[name] for name in FIELDS)), data


def decode(raw_and_data):
    return decode_frame(*raw_and_data, subject=SUBJECT, scopes=SCOPES, frequency=1000)


def test_completed_read_preserves_range_and_identity():
    event = decode(frame(offset=65536, open_generation=2))
    assert event['data'] == b'fake'
    assert event['file_identity'] == '00000007:0000000000000008'
    assert event['offset'] == 65536 and event['open_generation'] == 2
    assert event['completed_qpc'] == 101
    assert event['path_role'] == 'source' and event['can_enforce'] is False


def test_pipe_more_data_is_completed_fragment_not_message_boundary():
    event = decode(frame(scope=1, flags=16 | 2, win32_error=234,
                         peer_pid=99, peer_creation_filetime=888, connection_generation=3))
    assert event['more_data'] and not event['success']
    assert not event['message_complete']
    assert event['data'] == b'fake' and event['offset'] is None
    assert event['peer_pid'] == 99 and event['peer_creation_filetime'] == 888


def test_final_message_and_reused_connection_are_explicit():
    event = decode(frame(scope=1, flags=16 | 1 | 64, connection_generation=4))
    assert event['message_complete'] and event['connection_generation'] == 4
    assert event['file_identity'] is None


@pytest.mark.parametrize('updates', [
    {'pid': 43}, {'creation_filetime': 12346}, {'scope': 9},
    {'length': LIMIT + 1}, {'completed_length': 5},
    {'requested_length': 5, 'completed_length': 5}, {'completed_qpc': 99},
])
def test_reject_mismatched_or_inconsistent_frames(updates):
    with pytest.raises(ValueError):
        decode(frame(**updates))


def test_async_and_oversize_have_no_complete_snapshot():
    event = decode(frame(data=b'', requested_length=100, completed_length=0,
                         flags=8 | 4 | 32 | 512, reason=2))
    assert event['unsupported'] == ['overlapped_io']
    assert event['capture_gap'] and event['data_truncated']


def test_non_io_events_cannot_smuggle_a_payload():
    with pytest.raises(ValueError, match='unexpected_payload'):
        decode(frame(kind=10))


def test_build_hash_and_observation_only_contract(tmp_path):
    dll = tmp_path / 'ttrace-flow-io.dll'
    dll.write_bytes(b'test fixture only')
    manifest = tmp_path / 'native-build.json'
    data = {'protocol': 'FIO1', 'can_enforce': False,
            'artifacts': {dll.name: {'sha256': hashlib.sha256(dll.read_bytes()).hexdigest()}}}
    manifest.write_text(json.dumps(data))
    assert validate_build(dll, manifest)['can_enforce'] is False
    dll.write_bytes(b'changed fixture')
    with pytest.raises(ValueError, match='hash_mismatch'):
        validate_build(dll, manifest)
    data['can_enforce'] = True
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='protocol_mismatch'):
        validate_build(dll, manifest)


@pytest.mark.parametrize('stage,key', [('before', 'creation_filetime'), ('after', 'creation_filetime'),
                                     ('before', 'image_sha256'), ('after', 'image_sha256')])
def test_restricted_audit_pipe_rejects_changed_target_before_acl_creation(tmp_path, monkeypatch, stage, key):
    from transpect_trace.flow import native
    from transpect_trace.guard import pipe
    from transpect_trace.observe import windows
    from transpect_trace.behavior import native_egress
    subject = {'pid': 42, 'creation_filetime': 12345, 'image_sha256': 'a' * 64}
    identities = [dict(subject), dict(subject)]
    identities[0 if stage == 'before' else 1][key] = 12346 if key == 'creation_filetime' else 'b' * 64
    values = iter(identities)
    monkeypatch.setattr(native, 'validate_build', lambda *args: {'audit_transport': 'FIO1-ACK1'})
    monkeypatch.setattr(pipe, 'windows_api', lambda: object())
    monkeypatch.setattr(windows, 'identity', lambda pid: next(values))
    monkeypatch.setattr(native_egress, 'restricted_process_sids', lambda pid: ['S-1-5-12'])
    monkeypatch.setattr(native_egress, 'descendant_pipe_security', lambda *args: pytest.fail('changed target received audit ACL'))
    monkeypatch.setattr(pipe, 'pipe_security', lambda *args: pytest.fail('restricted path silently fell back'))
    with pytest.raises(ValueError, match='native_io_restricted_subject_changed'):
        native.NativeIOCollector(subject, tmp_path / 'observer.dll', tmp_path / 'build.json', lambda row: None,
                                  scopes=[{'role': 'source', 'path': str(tmp_path / 'source.json')}],
                                  allow_restricted_subject=True)


def test_default_native_audit_pipe_does_not_enable_restricted_subject_access(tmp_path, monkeypatch):
    from transpect_trace.flow import native
    from transpect_trace.guard import pipe
    from transpect_trace.behavior import native_egress
    subject = {'pid': 42, 'creation_filetime': 12345, 'image_sha256': 'a' * 64}
    monkeypatch.setattr(native, 'validate_build', lambda *args: {'audit_transport': 'FIO1-ACK1'})
    monkeypatch.setattr(pipe, 'windows_api', lambda: object())
    monkeypatch.setattr(native_egress, 'restricted_process_sids', lambda *args: pytest.fail('default unexpectedly inspected restricted token'))

    def ordinary_security(_):
        raise RuntimeError('ordinary_current_user_acl_selected')

    monkeypatch.setattr(pipe, 'pipe_security', ordinary_security)
    with pytest.raises(RuntimeError, match='ordinary_current_user_acl_selected'):
        native.NativeIOCollector(subject, tmp_path / 'observer.dll', tmp_path / 'build.json', lambda row: None,
                                  scopes=[{'role': 'source', 'path': str(tmp_path / 'source.json')}])
