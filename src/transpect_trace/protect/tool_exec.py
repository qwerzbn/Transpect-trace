"""Pre-execution decision for a process the Codex backend is about to create.

The desktop guard DLL reports every CreateProcessW of the backend (shell
commands, MCP servers, helpers) before the process exists. A command is denied
when it carries a secret itself, or when it would send data out of the process
while touching a sensitive path or a file whose content the DLP engine flags.
Everything else runs. This is a pre-execution command/file check, not a socket
boundary: computed payloads, later file changes and unobserved descendants can
bypass it. The model-request gate separately inspects what reaches the model.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import ntpath
from pathlib import Path
import re
import time

from .tool_upload import upload_references

SCHEMA = "transpect.desktop-guard.tool-exec/1.0"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_FILES = 16
_TOKEN = re.compile(r"""[^\s"'`;|&(){}<>,]+""")
_SKIP_SUFFIXES = {".exe", ".dll", ".sys", ".msi", ".com", ".bat", ".cmd"}


def _unescaped(text: str) -> str:
    return re.sub(r"\\([\"'\\])", r"\1", text)


# Programs that run their arguments as a command or move data over the network.
_COMMAND_PROGRAMS = {
    "pwsh", "powershell", "powershell_ise", "cmd", "bash", "sh", "zsh", "dash", "wsl",
    "python", "python3", "pythonw", "py", "node", "deno", "bun", "ruby", "perl", "php",
    "cscript", "wscript", "mshta", "rundll32", "regsvr32", "msiexec",
    "curl", "wget", "scp", "sftp", "ftp", "tftp", "ssh", "rsync", "git", "nc", "ncat",
    "netcat", "telnet", "socat", "certutil", "bitsadmin", "robocopy", "xcopy", "copy",
}


def is_command_program(program: str) -> bool:
    name = ntpath.basename(program).lower()
    for suffix in (".exe", ".com", ".bat", ".cmd"):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    return name in _COMMAND_PROGRAMS or re.fullmatch(r"python[\d.]*", name) is not None


def _program(command: str) -> str:
    """First argument of a Windows command line, honouring a quoted path."""
    command = command.lstrip()
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else command[1:]
    return command.split(maxsplit=1)[0] if command else ""


def parse_payload(payload: str) -> dict:
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("tool.exec payload must be an object")
    return {key: value.get(key) if isinstance(value.get(key), str) else ""
            for key in ("application", "command_line", "cwd")}


def referenced_files(command: str, cwd: str) -> list[Path]:
    """Existing local files a command names, e.g. `@file/x`, `-InFile x`, `a=@x`."""
    found: list[Path] = []
    total = 0
    for raw in _TOKEN.findall(_unescaped(command)):
        token = raw.split("=@", 1)[1] if "=@" in raw else raw
        token = token.lstrip("@")
        if len(token) < 3 or token.startswith("-") or "://" in token:
            continue
        if token.startswith(("\\\\", "//")) or cwd.startswith(("\\\\", "//")):
            continue  # Never resolve UNC operands from the controller.
        if ntpath.isabs(token):
            path = Path(token)
        elif cwd:
            path = Path(cwd) / token
        else:
            continue
        try:
            if (path.suffix.lower() in _SKIP_SUFFIXES or not path.is_file()
                    or path in found):
                continue
            size = path.stat().st_size
        except (OSError, ValueError):
            continue
        if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
            continue
        found.append(path)
        total += size
        if len(found) >= MAX_FILES:
            break
    return found


def decide(gate, payload: str) -> dict:
    """Inspect one process creation; return the audit row with the decision."""
    began = time.perf_counter()
    request = parse_payload(payload)
    command = request["command_line"] or request["application"]
    program = ntpath.basename(request["application"] or _program(command))
    archive, engine = gate._prepare()
    command_verdict = engine.inspect_text(_unescaped(command))
    # Only a shell, interpreter or network tool executes its arguments as a
    # command. Any other program (e.g. a Codex helper handed a JSON summary
    # that quotes an earlier command) gets the inline-secret check alone.
    executes = is_command_program(program)
    findings = gate.policy.inspect("shell_command", [command]) if executes else []
    sensitive_paths = sorted({rule for category, rule, _ in findings
                              if category == "SENSITIVE_PATH"})
    egress_rules = sorted({rule for category, rule, _ in findings
                           if category == "NETWORK_EGRESS"})
    explicit = upload_references(_unescaped(command), request["cwd"]) if executes else []
    transfer = executes and (gate.policy.transfer_intent(command) or bool(explicit))
    sensitive_files, file_rules, file_checks = [], set(), []
    uninspectable = [ref.error for ref in explicit if ref.error]
    required = {ref.path for ref in explicit if ref.path is not None}
    candidates = list(dict.fromkeys([ref.path for ref in explicit if ref.path is not None]
                                   + (referenced_files(command, request["cwd"]) if executes else [])))
    total_bytes = 0
    for index, path in enumerate(candidates):
        check = {"file": path.name, "required_upload_source": path in required}
        try:
            if index >= MAX_FILES:
                raise ValueError("UPLOAD_FILE_COUNT_EXCEEDED")
            budget = min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total_bytes)
            # A bounded read also catches a file growing after stat(), without
            # loading arbitrarily large tool operands into the controller.
            with path.open("rb") as stream:
                content = stream.read(budget + 1)
            if len(content) > budget:
                raise ValueError("UPLOAD_SCAN_LIMIT_EXCEEDED")
            total_bytes += len(content)
            verdict = engine.inspect_file_bytes(path.name, content)
        except (OSError, ValueError) as error:
            reason = (str(error) if str(error) in {"UPLOAD_FILE_COUNT_EXCEEDED", "UPLOAD_SCAN_LIMIT_EXCEEDED"}
                      else "UPLOAD_SOURCE_UNREADABLE" if isinstance(error, OSError) else "UPLOAD_SCAN_FAILED")
            check.update(status="uninspectable", reason=reason)
            file_checks.append(check)
            if transfer:
                uninspectable.append(reason)
            continue
        except Exception:
            check.update(status="uninspectable", reason="UPLOAD_SCAN_FAILED")
            file_checks.append(check)
            if transfer:
                uninspectable.append("UPLOAD_SCAN_FAILED")
            continue
        check.update(status="inspected", bytes=len(content))
        file_checks.append(check)
        if gate.actionable(verdict, ()) != "ALLOW":
            sensitive_files.append(path.name)
            file_rules.update(verdict.rule_ids)
    if gate.actionable(command_verdict, ()) != "ALLOW":
        allowed, reason = False, "SECRET_IN_COMMAND"
    elif transfer and (sensitive_paths or sensitive_files):
        allowed, reason = False, "SENSITIVE_DATA_EGRESS"
    elif transfer and uninspectable:
        allowed, reason = False, "UPLOAD_CONTENT_UNINSPECTABLE"
    else:
        allowed, reason = True, "TOOL_EXEC_ALLOWED"
    rules = sorted(set(command_verdict.rule_ids) | set(sensitive_paths) | set(egress_rules)
                   | file_rules | set(uninspectable)) if not allowed else sorted(set(sensitive_paths) | set(egress_rules))
    encoded = payload.encode("utf-8", "surrogatepass")
    receipt = archive.save("tool_command", encoded)
    return {"schema": SCHEMA, "decision": "allow" if allowed else "deny", "reason": reason,
            "rules": rules, "transfer_intent": transfer,
            "application": program, "executes_command": executes,
            "command_bytes": len(encoded),
            "command_sha256": hashlib.sha256(encoded).hexdigest(),
            "sensitive_files": sensitive_files,
            "file_checks": file_checks,
            "scope": "pre_execution_command_and_named_files",
            "network_boundary_enforced": False,
            "archive_record_id": receipt.record_id if receipt else None,
            "elapsed_ms": round((time.perf_counter() - began) * 1000, 3),
            "collected_at": datetime.now(timezone.utc).isoformat()}
