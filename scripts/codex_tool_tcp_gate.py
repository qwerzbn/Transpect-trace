"""Opt-in standard socket API gate for ONE explicit Codex backend instance.

This does not install a system firewall, discover/attach other backends, or
provide a DLP forwarding proxy. All new TCP connections from registered tool
descendants, UDP sends and inherited TCP writes are denied; local tools continue. Stopping this controller leaves
the injected gate fail-closed: restart that Codex backend to remove it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from _build_support import ROOT, enter_repository
from transpect_trace.behavior.native_egress import (
    EgressController, inspect_process, process_lifetime_ended,
)
from transpect_trace.guard.desktop_service import PIN_DIR, STATE_DIR, load_pins


def checked_subject(pid: int, creation_filetime: int) -> dict:
    if pid <= 0 or creation_filetime <= 0:
        raise ValueError('PID and creation FILETIME must be positive')
    subject = inspect_process(pid)
    if subject['creation_filetime'] != creation_filetime:
        raise ValueError('process lifetime mismatch; refusing a reused PID')
    if subject['image_name'].casefold() != 'codex.exe':
        raise ValueError('only an explicit Codex backend is accepted')
    pins = load_pins(PIN_DIR, STATE_DIR / 'pins')
    if subject['image_sha256'] not in pins:
        raise ValueError('UNSUPPORTED_VERSION: backend SHA-256 has no supported local pin')
    return subject


def deny_policy(proxy_port: int | None = None) -> dict:
    if proxy_port is not None and (type(proxy_port) is not int or not 1 <= proxy_port <= 65535):
        raise ValueError('local inspection proxy port must be 1..65535')
    return {'default_action': 'block', 'targets': [] if proxy_port is None else [
        {'address': address, 'port': proxy_port, 'protocol': 'tcp', 'action': 'allow'}
        for address in ('127.0.0.1', '::1')]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--creation-filetime', type=int, required=True,
                        help='Exact creation FILETIME, not a PID alone.')
    parser.add_argument('--native-dir', type=Path, required=True,
                        help='Host-verified DLL build directory from build_egress_native.py.')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-loopback-proxy-port', type=int,
                        help='Permit only TCP to this explicit loopback port; does not configure or certify a proxy.')
    args = parser.parse_args()
    enter_repository()
    policy = deny_policy(args.allow_loopback_proxy_port)
    subject = checked_subject(args.pid, args.creation_filetime)
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    controller = EgressController(subject, args.native_dir.resolve() / 'ttrace-egress.dll',
        policy, directory)
    try:
        controller.start()
        print(json.dumps({'state': 'SOCKET_API_LIMITED', 'pid': subject['pid'],
            'creation_filetime': subject['creation_filetime'],
            'scope': 'registered_descendants_standard_socket_send_apis',
            'full_tool_protection': False, 'restart_backend_to_detach': True,
            'uncovered': controller.state['uncovered']}, ensure_ascii=False), flush=True)
        while not process_lifetime_ended(subject['pid'], subject['creation_filetime']):
            if not controller.state['can_enforce']:
                raise RuntimeError('TCP gate degraded; backend restart is required')
            time.sleep(.5)
    except KeyboardInterrupt:
        print('Controller stopping; the injected gate remains fail-closed until this backend is restarted.', flush=True)
    finally:
        controller.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
