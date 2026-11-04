import pytest

from transpect_trace.guard.pipe import _pipe_sddl


def test_desktop_pipe_grants_only_specific_client_sid():
    result = _pipe_sddl("S-1-5-21-10", "S-1-5-21-20")
    assert "(A;;GA;;;S-1-5-21-10)" in result
    assert "(A;;GRGW;;;S-1-5-21-20)" in result
    assert "WD" not in result


def test_desktop_pipe_rejects_sddl_injection():
    with pytest.raises(ValueError):
        _pipe_sddl("S-1-5-21-10", "S-1-5-21-20)(A;;GA;;;WD")
