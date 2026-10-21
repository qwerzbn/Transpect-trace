import os
import threading
import time
from pathlib import Path

import pytest

from transpect_trace.guard.terminal import TerminalProcess


def test_chunked_terminal_input_preserves_split_utf8_without_exposing_unready_input():
    terminal=object.__new__(TerminalProcess);captured=[];terminal.write=captured.append
    text='a'*4095+'中文🙂'
    raw=text.encode('utf-8')
    terminal.forward_chunks([raw[:4096],raw[4096:4099],raw[4099:]])
    assert ''.join(captured)==text


def test_interactive_input_failure_is_reported_without_logging_input():
    terminal=object.__new__(TerminalProcess);terminal.errors=[];terminal.input_ready=threading.Event();terminal.input_ready.set()
    def fail():raise OSError('fake-private-input')
    terminal._forward_input=fail;terminal.forward_input()
    assert terminal.errors==['terminal_input_invalid_or_unavailable']


@pytest.mark.skipif(os.name != 'nt', reason='Windows ConPTY integration')
def test_owned_terminal_holds_user_input_until_ready():
    seen = bytearray(); event = threading.Event()
    def output(data):
        seen.extend(data)
        if b'AFTER_GATE_READY' in seen: event.set()
    terminal = TerminalProcess([str(Path(os.environ['SystemRoot'])/'System32/cmd.exe'), '/D', '/Q'], output=output)
    try:
        with pytest.raises(RuntimeError, match='held'):
            terminal.write(b'echo BEFORE_READY\r')
        terminal.mark_gate_ready()
        terminal.write(b'echo AFTER_GATE_READY\r')
        assert event.wait(5)
        assert b'BEFORE_READY' not in seen
        terminal.write(b'exit\r')
        assert terminal.wait(5) == 0
    finally:
        terminal.close()
