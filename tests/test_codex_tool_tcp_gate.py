"""The opt-in launcher must never enroll a reused PID or an unrelated image."""
import importlib.util
from pathlib import Path
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('codex_tool_tcp_gate_cli', SCRIPTS / 'codex_tool_tcp_gate.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def test_opt_in_subject_requires_exact_lifetime_and_supported_codex(monkeypatch):
    subject = {'pid': 12, 'creation_filetime': 34, 'image_name': 'codex.exe', 'image_sha256': 'a' * 64}
    monkeypatch.setattr(cli, 'inspect_process', lambda pid: dict(subject))
    monkeypatch.setattr(cli, 'load_pins', lambda *a: {'a' * 64: {}})
    assert cli.checked_subject(12, 34) == subject
    with pytest.raises(ValueError, match='lifetime mismatch'):
        cli.checked_subject(12, 35)
    subject['image_name'] = 'powershell.exe'
    with pytest.raises(ValueError, match='Codex backend'):
        cli.checked_subject(12, 34)
    subject['image_name'] = 'codex.exe'
    subject['image_sha256'] = 'b' * 64
    with pytest.raises(ValueError, match='UNSUPPORTED_VERSION'):
        cli.checked_subject(12, 34)


@pytest.mark.parametrize('pid,birth', [(0, 1), (1, 0), (-1, 1)])
def test_opt_in_rejects_missing_instance_identity(pid, birth):
    with pytest.raises(ValueError, match='positive'):
        cli.checked_subject(pid, birth)


def test_proxy_exception_is_only_the_explicit_loopback_tcp_port():
    from transpect_trace.behavior.native_egress import normalize_policy, destination_decision
    policy = normalize_policy(cli.deny_policy(8765))
    assert destination_decision(policy, '127.0.0.1', 8765, 'tcp') == 'allow'
    assert destination_decision(policy, '::1', 8765, 'tcp') == 'allow'
    assert destination_decision(policy, '127.0.0.1', 8765, 'udp') == 'block'
    assert destination_decision(policy, '127.0.0.2', 8765, 'tcp') == 'block'
    assert destination_decision(policy, '127.0.0.1', 8766, 'tcp') == 'block'
    assert cli.deny_policy() == {'default_action': 'block', 'targets': []}
    with pytest.raises(ValueError):
        cli.deny_policy(0)
