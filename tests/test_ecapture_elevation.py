import struct
from types import SimpleNamespace

import pytest

from transpect_trace.observe.elevation import BoundedStream, elevation_error, validate_relay_header
from transpect_trace.observe.ecapture_enhanced import read_exact


@pytest.mark.parametrize('raw', [b'', b'D\x00\x00\x00\x00', b'Z\x01\x00\x00\x00',
    b'D'+struct.pack('<I',65649), b'E'+struct.pack('<I',513), b'X'+struct.pack('<I',3)])
def test_relay_rejects_unknown_or_unbounded_frames(raw):
    with pytest.raises(ValueError): validate_relay_header(raw)


def test_binary_relay_preserves_bytes_and_reports_overflow():
    stream=BoundedStream(4096)
    raw=bytes(range(256))*16
    stream.feed(raw)
    with pytest.raises(OSError,match='buffer_limit'):stream.feed(b'x')
    assert read_exact(stream,4096)==raw
    stream.feed(b'partial');stream.finish()
    with pytest.raises(EOFError):read_exact(stream,8)
    stream.close()
    with pytest.raises(OSError):stream.feed(b'late')


def test_diagnostics_are_separate_and_line_bounded():
    stream=BoundedStream(64);stream.feed(b'first\nsecond\ntruncated');stream.finish()
    assert stream.readline(64)==b'first\n'
    assert stream.readline(4)==b'seco'
    assert stream.readline(64)==b'nd\n'
    assert stream.readline(64)==b'truncated'
    assert stream.readline(64)==b''


@pytest.mark.parametrize('code,reason',[(1223,'elevation_cancelled'),(5,'elevation_access_denied'),(2,'elevation_launch_failed')])
def test_uac_failures_have_fixed_non_secret_reasons(code,reason):
    assert elevation_error(code)==reason


def test_medium_controller_fails_before_launch_without_explicit_elevation(monkeypatch):
    from transpect_trace.observe import ecapture,windows,elevation
    subject={'pid':12,'creation_filetime':100,'image_sha256':'0'*64}
    monkeypatch.setattr(windows,'identity',lambda pid:subject)
    monkeypatch.setattr(ecapture,'verify_build',lambda exe:{'variant':'enhanced'})
    monkeypatch.setattr(elevation,'is_elevated',lambda:False)
    monkeypatch.setattr(ecapture.subprocess,'Popen',lambda *a,**kw:pytest.fail('must not launch'))
    collector=ecapture.ECaptureCollector(subject,SimpleNamespace(mode='schannel'),None,None)
    with pytest.raises(RuntimeError,match='elevate-ecapture'):collector.start()
    collector.close()
    assert collector.elevation_state=='required'
    assert collector.errors==['administrator_privileges_required']


def test_upstream_cannot_use_enhanced_elevation_protocol(monkeypatch):
    from transpect_trace.observe import ecapture,windows
    subject={'pid':12,'creation_filetime':100,'image_sha256':'0'*64}
    monkeypatch.setattr(windows,'identity',lambda pid:subject)
    monkeypatch.setattr(ecapture,'verify_build',lambda exe:{'variant':'upstream'})
    collector=ecapture.ECaptureCollector(subject,SimpleNamespace(mode='schannel'),None,None,elevate=True)
    with pytest.raises(ValueError,match='verified enhanced'):collector.start()
    assert collector.process is None
