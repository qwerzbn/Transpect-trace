"""Owned native Windows ConPTY with a separate Native-readiness input gate."""
from __future__ import annotations
import os
import sys
import time
import threading
import subprocess
import codecs

class TerminalProcess:
    def __init__(self, argv, *, cwd=None, env=None, output=None):
        if os.name != "nt": raise RuntimeError("Windows ConPTY required")
        try:
            from winpty import PTY,Backend
        except ImportError as error:
            raise RuntimeError("Install the locked tui extra for controlled TUI startup") from error
        self.pty = PTY(120,40,backend=Backend.ConPTY)
        environment='\0'.join(f'{k}={v}' for k,v in env.items())+'\0' if env else None
        command=' '+subprocess.list2cmdline([str(x) for x in argv[1:]]) if len(argv)>1 else None
        if not self.pty.spawn(str(argv[0]),cwd=str(cwd) if cwd else None,env=environment,cmdline=command):
            raise RuntimeError('ConPTY process startup failed')
        self.pid = self.pty.pid; self.input_ready = threading.Event(); self.output = output
        self.closed = False; self.errors = []; self.output_bytes = 0; self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._drain,daemon=True); self.thread.start()

    def mark_gate_ready(self): self.input_ready.set()

    def _write(self,data):
        with self.lock:
            self.pty.write(data.decode("utf-8") if isinstance(data,bytes) else data)

    def forward_chunks(self,chunks):
        decoder=codecs.getincrementaldecoder('utf-8')('strict')
        for data in chunks:
            text=decoder.decode(data)
            if text:self.write(text)
        tail=decoder.decode(b'',final=True)
        if tail:self.write(tail)

    def write(self,data):
        if not self.input_ready.is_set(): raise RuntimeError("User input held: Native gate is not ready")
        self._write(data)

    def _drain(self):
        pending = b""
        try:
            while not self.closed:
                data=self.pty.read(blocking=False).encode("utf-8")
                if not data:
                    if not self.pty.isalive():break
                    time.sleep(.01);continue
                self.output_bytes+=len(data)
                pending=(pending+data)[-32768:]
                for query,reply in ((b"\x1b[6n",b"\x1b[1;1R"),(b"\x1b[c",b"\x1b[?1;2c")):
                    while query in pending:
                        pending=pending.replace(query,b"",1);self._write(reply)
                if self.output:self.output(data)
        except EOFError:pass
        except (OSError,ValueError):
            if not self.closed:self.errors.append("terminal_output_unavailable")

    def poll(self):
        return self.pty.get_exitstatus() if not self.pty.isalive() else None

    def wait(self,timeout=None):
        until=time.monotonic()+timeout if timeout is not None else None
        while self.poll() is None:
            if until is not None and time.monotonic()>=until:raise subprocess.TimeoutExpired("owned ConPTY process",timeout)
            time.sleep(.05)
        return self.poll()

    def forward_input(self):
        if not self.input_ready.is_set():raise RuntimeError("Gate not ready")
        try:self._forward_input()
        except (UnicodeError,OSError):self.errors.append('terminal_input_invalid_or_unavailable')

    def _forward_input(self):
        import msvcrt
        if sys.stdin.isatty():
            while self.poll() is None:
                if not msvcrt.kbhit():time.sleep(.02);continue
                key=msvcrt.getwch()
                if key in ("\x00","\xe0"):
                    key={"H":"\x1b[A","P":"\x1b[B","K":"\x1b[D","M":"\x1b[C"}.get(msvcrt.getwch(),"")
                if key:self.write(key)
        else:
            def chunks():
                while self.poll() is None:
                    data=sys.stdin.buffer.read1(4096)
                    if not data:break
                    yield data
            self.forward_chunks(chunks())

    def close(self):
        if self.closed:return
        self.closed=True
        self.pty.cancel_io()
        self.thread.join(2)
