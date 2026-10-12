from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CALL_RE = re.compile(r"^(?P<timestamp>\d+\.\d+)\s+(?P<call>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$")
EXIT_RE = re.compile(r"^(?P<timestamp>\d+\.\d+)\s+\+\+\+ exited with (?P<code>\d+) \+\+\+$")
PID_RE = re.compile(r"(?:^|\.)(?P<pid>\d+)$")
QUOTED_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
FD_RE = re.compile(r"^(?P<fd>-?\d+)(?:<(?P<target>[^>]*)>)?")


def _wall(timestamp: str) -> str:
    value = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _quoted(args: str) -> list[str]:
    values: list[str] = []
    for match in QUOTED_RE.finditer(args):
        try:
            values.append(json.loads(match.group(0)))
        except json.JSONDecodeError:
            values.append(match.group(0)[1:-1])
    return values


def _result_int(result: str) -> int | None:
    match = re.match(r"-?\d+", result.strip())
    return int(match.group(0)) if match else None


def _fd(value: str) -> tuple[int | None, str | None]:
    match = FD_RE.match(value.strip())
    if not match:
        return None, None
    return int(match.group("fd")), match.group("target")


def _first_arg(args: str) -> str:
    return args.split(",", 1)[0].strip()


def _operation(call: str, args: str, result: str) -> tuple[str, str, str | None, int | None]:
    result_value = _result_int(result)
    fd, annotated = _fd(_first_arg(args))
    quoted = _quoted(args)
    if call in {"execve", "execveat"}:
        return "system.process.started", "execute", quoted[0] if quoted else None, None
    if call in {"clone", "clone3", "fork", "vfork"}:
        return "system.process.forked", call, str(result_value) if result_value and result_value > 0 else None, None
    if call in {"open", "openat", "openat2", "creat"}:
        path_index = 0 if call in {"open", "creat"} else 0
        target = quoted[path_index] if len(quoted) > path_index else None
        opened_fd, result_target = _fd(result)
        return "system.file.opened", call, result_target or target, opened_fd
    if call in {"read", "pread64", "readv", "preadv"}:
        is_socket = bool(annotated and ("TCP" in annotated or "UDP" in annotated or "socket" in annotated))
        return ("system.network.received" if is_socket else "system.file.read"), call, annotated, fd
    if call in {"write", "pwrite64", "writev", "pwritev"}:
        is_socket = bool(annotated and ("TCP" in annotated or "UDP" in annotated or "socket" in annotated))
        return ("system.network.sent" if is_socket else "system.file.write"), call, annotated, fd
    if call in {"socket", "socketpair"}:
        opened_fd, result_target = _fd(result)
        return "system.network.socket", call, result_target, opened_fd
    if call in {"connect", "bind", "listen", "accept", "accept4"}:
        target = annotated
        if "sin_port=" in args:
            target = args[args.find("sin_port=") :][:500]
        return f"system.network.{call}", call, target, fd
    if call in {"sendto", "sendmsg", "sendmmsg"}:
        return "system.network.sent", call, annotated, fd
    if call in {"recvfrom", "recvmsg", "recvmmsg"}:
        return "system.network.received", call, annotated, fd
    if call in {"close", "dup", "dup2", "dup3", "pipe", "pipe2"}:
        return f"system.fd.{call}", call, annotated, fd
    if call in {"rename", "renameat", "renameat2"}:
        return "system.file.renamed", call, " -> ".join(quoted[:2]) or None, fd
    if call in {"unlink", "unlinkat", "rmdir"}:
        return "system.file.deleted", call, quoted[0] if quoted else None, fd
    if call in {"mmap", "mmap2"}:
        return "system.file.mapped", call, annotated, fd
    if call in {"stat", "lstat", "newfstatat", "access", "readlink", "readlinkat"}:
        return "system.file.metadata", call, quoted[0] if quoted else annotated, fd
    return "system.unknown", call, annotated, fd


def iter_strace_rows(system_dir: Path) -> Iterable[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    parent_by_pid: dict[tuple[str, int], int] = {}
    for path in sorted(system_dir.glob("*strace*")):
        if not path.is_file():
            continue
        match_pid = PID_RE.search(path.name)
        pid = int(match_pid.group("pid")) if match_pid else None
        scope = "gateway" if path.name.startswith("gateway-") else "agent"
        pending: tuple[int, str] | None = None
        for line_number, raw_line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            line = raw_line.strip()
            if line.endswith("<unfinished ...>"):
                pending = (line_number, line.removesuffix("<unfinished ...>"))
                continue
            resumed = re.match(r"^\d+\.\d+\s+<\.\.\. \w+ resumed>(.*)$", line)
            if resumed:
                if pending is None:
                    continue
                line_number, prefix = pending
                line = prefix + resumed.group(1)
                pending = None
            exit_match = EXIT_RE.match(line)
            if exit_match:
                records.append(
                    {
                        "timestamp": float(exit_match.group("timestamp")),
                        "wall": _wall(exit_match.group("timestamp")),
                        "pid": pid,
                        "ppid": None,
                        "process_scope": scope,
                        "kind": "system.process.exited",
                        "operation": "exit",
                        "target": None,
                        "fd": None,
                        "result": int(exit_match.group("code")),
                        "syscall": "exit",
                        "args": "",
                        "source_file": path.name,
                        "source_line": line_number,
                    }
                )
                continue
            match = CALL_RE.match(line)
            if not match:
                continue
            call = match.group("call")
            args = match.group("args")
            result = match.group("result")
            kind, operation, target, fd = _operation(call, args, result)
            result_value = _result_int(result)
            if call in {"clone", "clone3", "fork", "vfork"} and pid is not None and result_value and result_value > 0:
                parent_by_pid[(scope, result_value)] = pid
            records.append(
                {
                    "timestamp": float(match.group("timestamp")),
                    "wall": _wall(match.group("timestamp")),
                    "pid": pid,
                    "ppid": None,
                    "process_scope": scope,
                    "kind": kind,
                    "operation": operation,
                    "target": target,
                    "fd": fd,
                    "result": result_value,
                    "raw_result": result[:1000],
                    "syscall": call,
                    "args": args[:4096],
                    "source_file": path.name,
                    "source_line": line_number,
                }
            )
    records.sort(key=lambda row: (row["timestamp"], row["source_file"], row["source_line"]))
    # Files are enumerated by name, not by fork order. Resolve parents only
    # after all fork records have been collected (including resumed calls).
    for row in records:
        row["ppid"] = parent_by_pid.get((row["process_scope"], row["pid"]))
        yield row
