"""Codex-callable read/send tools with controlled Native startup for mail."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
from uuid import uuid4

from .tools import LIMIT, NATIVE_OWNER, KnowledgeMailTools, ToolError, encode_draft, strict_json


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def bounded_json(path):
    with Path(path).open('rb') as source:
        return strict_json(source.read(LIMIT + 1))


def public_worker_result(value):
    """Persist only the fixed worker protocol, never arbitrary extra output."""
    if not isinstance(value, dict) or value.get('kind') not in {
            'mail_sent', 'mail_blocked', 'tool_failed'}:
        raise ValueError('mail_worker_result_invalid')
    result = {'kind': value['kind']}
    for name in ('tool_attempt_id', 'body_sha256'):
        if name in value:
            size = 32 if name == 'tool_attempt_id' else 64
            if not isinstance(value[name], str) or not re.fullmatch(r'[a-f0-9]{' + str(size) + '}', value[name]):
                raise ValueError('mail_worker_result_invalid')
            result[name] = value[name]
    if 'body_bytes' in value:
        if type(value['body_bytes']) is not int or not 0 < value['body_bytes'] <= LIMIT:
            raise ValueError('mail_worker_result_invalid')
        result['body_bytes'] = value['body_bytes']
    if 'reason' in value:
        reason = value['reason']
        if not isinstance(reason, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,126}', reason):
            raise ValueError('mail_worker_result_invalid')
        result['reason'] = reason
    if value['kind'] == 'mail_sent':
        if type(value.get('status_code')) is not int or value['status_code'] not in {200, 201, 202}:
            raise ValueError('mail_worker_result_invalid')
        if value.get('delivery_scope') != 'local_mailpit_acceptance':
            raise ValueError('mail_worker_result_invalid')
        result.update(status_code=value['status_code'], delivery_scope='local_mailpit_acceptance',
                      receipt_verified=False)
    return result


def verify_execution(subject, raw, captures, executions, result):
    """Require the same complete body, process and Native attempt/action."""
    if not isinstance(subject, dict) or len(captures) != 1 or len(executions) != 1:
        return False
    capture, execution = captures[0], executions[0]
    digest = hashlib.sha256(raw).hexdigest()
    if (capture.get('pid') != subject.get('pid')
            or capture.get('creation_filetime') != subject.get('creation_filetime')
            or capture.get('body_sha256') != digest or capture.get('body_bytes') != len(raw)
            or capture.get('completeness') != 'complete' or capture.get('source') != NATIVE_OWNER
            or execution.get('pid') != subject.get('pid')
            or not capture.get('attempt_id') or execution.get('attempt_id') != capture['attempt_id']
            or result.get('body_sha256') != digest or result.get('body_bytes') != len(raw)):
        return False
    decision = capture.get('decision')
    if decision == 'ALLOW':
        return (result.get('kind') == 'mail_sent' and execution.get('action') == 'none'
                and execution.get('result') == 'transport_authorized')
    if decision in {'BLOCK', 'REVIEW', 'UNKNOWN'}:
        return (result.get('kind') == 'mail_blocked' and execution.get('action') == 'block_request'
                and execution.get('result') == 'native_rejection')
    return False


class ControlOutput:
    """Bounded worker control messages, excluding raw stderr and payloads."""
    def __init__(self, process):
        self.records = queue.Queue(maxsize=8)

        def read():
            try:
                while True:
                    line = process.stdout.readline(16385)
                    if not line:
                        self.records.put_nowait({'kind': 'worker_exited'})
                        return
                    if len(line) > 16384:
                        raise ValueError('control_record_limit')
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError('control_record_invalid')
                    self.records.put_nowait(record)
            except Exception:
                try:
                    self.records.put_nowait({'kind': 'invalid_control'})
                except queue.Full:
                    pass

        threading.Thread(target=read, daemon=True).start()

    def get(self, timeout=30):
        return self.records.get(timeout=timeout)


def send_protected(config_path: Path, draft_path: Path):
    from transpect_trace.observe.windows import identity
    from transpect_trace.behavior.native_egress import inspect_process
    from transpect_trace.protect.detection import ContentIndex
    from transpect_trace.protect.pipe import ProtectionServer
    from .policy import MailPolicyEngine

    config = bounded_json(config_path)
    raw = encode_draft(bounded_json(draft_path))
    identifier = uuid4().hex
    audit = Path(config['gate_audit_directory']) / identifier
    audit.mkdir(parents=True, exist_ok=False)
    index = ContentIndex.model_validate_json(Path(config['content_index']).read_bytes())
    engine = MailPolicyEngine(index, allowed_sender='codex@transpect.test',
                              allowed_recipients=['partner@example.test'])
    process = gate = None
    result = {'kind': 'tool_failed', 'reason': 'MAIL_GATE_NOT_STARTED'}
    subject = None
    errors = []
    cleanup_kill = False
    ready = False
    try:
        process = subprocess.Popen([sys.executable, '-m', 'transpect_trace.protect.python_runner'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL,
                                   creationflags=0x08000000 if os.name == 'nt' else 0)
        output = ControlOutput(process)
        start = {'dll': config['gate_dll'], 'manifest': config['gate_manifest'],
                 'server_pid': os.getpid(), 'run_id': config['run_id'],
                 'script': str(Path(__file__).with_name('worker.py').resolve()),
                 'arguments': [str(Path(config_path).resolve()), str(Path(draft_path).resolve())],
                 'mode': 'outbound-json'}
        process.stdin.write(json.dumps(start).encode('utf-8') + b'\n')
        process.stdin.flush()
        response = output.get(20)
        if (response.get('kind') != 'protect.ready' or response.get('gate_ready') is not True
                or response.get('adapter_id') != NATIVE_OWNER or response.get('mode') != 'outbound-json'
                or type(response.get('pid')) is not int or response['pid'] <= 0):
            raise ValueError('native_gate_not_ready')
        subject = identity(response['pid'])
        if response['pid'] != process.pid and inspect_process(response['pid'])['parent_pid'] != process.pid:
            raise ValueError('worker_process_identity_mismatch')
        gate = ProtectionServer(subject, engine, audit / 'policy.jsonl')
        gate.start()
        ready = True
        # LF is part of the existing runner protocol, including on Windows.
        process.stdin.write(b'RUN\n')
        process.stdin.flush()
        result = public_worker_result(output.get(35))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            attempts = {x['attempt_id'] for x in engine.captures}
            if attempts and attempts <= {x['attempt_id'] for x in gate.execution_records}:
                break
            time.sleep(.02)
    except Exception as error:
        errors.append(type(error).__name__)
        if isinstance(error, ValueError) and error.args and error.args[0] in {
                'native_gate_not_ready', 'worker_process_identity_mismatch', 'mail_worker_result_invalid'}:
            errors.append(error.args[0])
        result = {'kind': 'tool_failed', 'reason': 'MAIL_GATE_UNAVAILABLE'}
    finally:
        if process:
            try:
                process.stdin.write(b'FINISH\n')
                process.stdin.flush()
                process.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cleanup_kill = True
                process.terminate()
                process.wait(timeout=5)
        if gate:
            gate.close()
    executions = list(gate.execution_records) if gate else []
    captures = list(engine.captures)
    certified = (ready and not errors and not cleanup_kill and process is not None
                 and process.returncode == 0 and gate is not None and not gate.errors
                 and verify_execution(subject, raw, captures, executions, result))
    record = {'schema_version': 'transpect.knowledge-mail.send/1.0', 'run_id': config['run_id'],
              'tool_invocation': identifier, 'subject': subject, 'native_ready': ready,
              'client_result': result, 'captures': captures, 'executions': executions,
              'execution_verified': bool(certified), 'receiver_verified': False,
              'cleanup_kill': cleanup_kill, 'worker_exit_code': process.returncode if process else None,
              'errors': errors + (gate.errors if gate else []),
              'body_sha256': hashlib.sha256(raw).hexdigest(), 'body_bytes': len(raw),
              'control_scope': 'registered HTTPX 0.28.1 text-mail process only'}
    save(audit / 'summary.json', record)
    return {'kind': result['kind'] if certified else 'tool_failed', 'execution_verified': bool(certified),
            'tool_invocation': identifier, 'audit_directory': str(audit),
            'reason': result.get('reason') if certified else 'MAIL_EXECUTION_UNVERIFIED',
            'delivery_scope': result.get('delivery_scope') if certified else None}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    commands = parser.add_subparsers(dest='command', required=True)
    read = commands.add_parser('read-page')
    read.add_argument('page_id', type=int)
    send = commands.add_parser('send-mail')
    send.add_argument('--draft', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'read-page':
            result = KnowledgeMailTools(strict_json(args.config.read_bytes())).read_page(args.page_id)
        else:
            result = send_protected(args.config, args.draft)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0 if result.get('kind') in {'bookstack_page', 'mail_sent', 'mail_blocked'} else 2
    except Exception as error:
        print(json.dumps({'kind': 'tool_failed', 'reason': str(error) if isinstance(error, ToolError)
                          else 'KNOWLEDGE_MAIL_TOOL_FAILED'}), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
