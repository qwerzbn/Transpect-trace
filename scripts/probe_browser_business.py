"""Prepare and inspect a controlled, observe-only Chrome experiment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from _build_support import enter_repository


def main():
    enter_repository()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    prepare = sub.add_parser('prepare')
    prepare.add_argument('--output', required=True, type=Path)
    prepare.add_argument('--origin', required=True)
    prepare.add_argument('--chrome', required=True, type=Path)
    prepare.add_argument('--python', default=sys.executable, type=Path)
    prepare.add_argument('--install-host', action='store_true')
    prepare.add_argument('--content-index', type=Path)
    serve = sub.add_parser('serve')
    serve.add_argument('--output', required=True, type=Path)
    serve.add_argument('--certificate', required=True, type=Path)
    serve.add_argument('--private-key', required=True, type=Path)
    serve.add_argument('--port', type=int, default=0)
    serve.add_argument('--seconds', type=int, default=300)
    for name in ('status', 'report', 'install-host', 'uninstall-host', 'discover', 'ecapture'):
        command = sub.add_parser(name)
        command.add_argument('--output', required=True, type=Path)
        if name in {'discover', 'ecapture'}:
            command.add_argument('--browser-pid', type=int, required=True)
        if name == 'ecapture':
            command.add_argument('--network-pid', type=int, required=True)
            command.add_argument('--ecapture', type=Path, required=True)
            command.add_argument('--seconds', type=int, default=15)
            command.add_argument('--elevate-ecapture', action='store_true')
        if name == 'report': command.add_argument('--receipts', type=Path)
    args = parser.parse_args()
    from transpect_trace.flow.browser.runtime import (prepare_browser_run, report_browser_run,
                                                      register_native_host, unregister_native_host)
    try:
        if args.mode == 'prepare':
            index = json.loads(args.content_index.read_text(encoding='utf-8')) if args.content_index else None
            result = prepare_browser_run(args.output, origin=args.origin, chrome=args.chrome, python=args.python,
                                         install=args.install_host, content_index=index)
        elif args.mode == 'serve':
            from transpect_trace.flow.browser.origin import BrowserOrigin
            if not 1 <= args.seconds <= 1800: raise ValueError('duration_out_of_bounds')
            args.output.mkdir(parents=True, exist_ok=False)
            source = BrowserOrigin(args.certificate, args.private_key, port=args.port).start()
            (args.output/'ready.json').write_text(json.dumps({'origin':source.url, 'ready':True, 'can_enforce':False}), encoding='utf-8')
            print(json.dumps({'origin':source.url, 'ready':True, 'can_enforce':False}), flush=True)
            try:
                deadline = time.monotonic() + args.seconds
                while time.monotonic() < deadline:
                    with source.lock: current = list(source.receipts)
                    temporary = args.output/'receipts.pending'
                    temporary.write_text(json.dumps(current, indent=2), encoding='utf-8')
                    temporary.replace(args.output/'receipts.json')
                    time.sleep(0.2)
            finally:
                source.close()
                (args.output/'receipts.json').write_text(json.dumps(source.receipts, indent=2), encoding='utf-8')
            result = {'origin':source.url, 'terminal':True, 'receipts':source.receipts,
                      'errors':source.errors, 'can_enforce':False}
        elif args.mode == 'install-host':
            register_native_host(args.output)
            result = {'registered':True, 'can_enforce':False}
        elif args.mode == 'uninstall-host': result = unregister_native_host(args.output)
        elif args.mode == 'discover':
            from transpect_trace.flow.browser.probe import discover_browser
            result = discover_browser(args.output, args.browser_pid)
        elif args.mode == 'ecapture':
            from transpect_trace.flow.browser.probe import probe_ecapture
            result = probe_ecapture(args.output, root_pid=args.browser_pid, network_pid=args.network_pid,
                ecapture=args.ecapture, duration=args.seconds, elevate=args.elevate_ecapture)
        else:
            receipts = json.loads(args.receipts.read_text(encoding='utf-8')) if getattr(args, 'receipts', None) else None
            result = report_browser_run(args.output, receipts=receipts)
    except (OSError, ValueError, RuntimeError):
        result = {'status':'unavailable', 'limitations':['preparation_or_probe_failed'], 'can_enforce':False}
        print(json.dumps(result))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
