"""Codex -> shell -> Python/curl/Git, fake data to a nonforwarding loopback origin."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import sys
import threading

from _build_support import ROOT
from probe_guard_native import experiment
from transpect_trace.guard import BINARY_SHA256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--elevate', action='store_true')
    args = parser.parse_args()
    if hashlib.sha256(args.codex.read_bytes()).hexdigest() != BINARY_SHA256:
        parser.error('fixed baseline mismatch')
    root = args.output.resolve(); root.mkdir(parents=True, exist_ok=False)
    receipts = []
    class Source(BaseHTTPRequestHandler):
        def do_GET(self):
            # Record only known synthetic paths, no query or headers.
            route = self.path.split('?', 1)[0]
            receipts.append(dict(route=route if route in ('/python', '/curl', '/git/info/refs') else 'other', body_bytes=0))
            self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
        def log_message(self, *_): pass
    source = ThreadingHTTPServer(('127.0.0.1', 0), Source)
    thread = threading.Thread(target=source.serve_forever, daemon=True); thread.start()
    base = f'http://127.0.0.1:{source.server_port}'
    python = Path(sys.base_prefix) / 'python.exe'
    curl, git = shutil.which('curl.exe'), shutil.which('git.exe')
    def quote(value): return "'" + str(value).replace("'", "''") + "'"
    command = f"& {quote(python)} -I -c {quote('import urllib.request; urllib.request.urlopen('+repr(base+'/python')+', timeout=3).read()')}; "
    if curl: command += f"& {quote(curl)} --noproxy '*' --max-time 3 --silent {quote(base+'/curl')}; "
    if git:
        command += f"$env:GIT_CONFIG_NOSYSTEM='1'; $env:GIT_CONFIG_GLOBAL='NUL'; $env:GIT_TERMINAL_PROMPT='0'; & {quote(git)} -c credential.helper= -c http.proxy= ls-remote {quote(base+'/git')}; "
    command += "Write-Output 'synthetic network task completed'"
    try:
        result = experiment(args.codex.resolve(), ROOT/'build/guard/ttrace-guard.dll', root/'http', 'http', 'observe',
            scenario='tool_network', behavior_compare=True, elevate_behavior=args.elevate, tool_command=command)
    finally:
        source.shutdown(); source.server_close(); thread.join(3)
    report_path = root/'http/behavior/report.json'
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    networks = [r for r in report.get('network_observations', []) if r['event']['destination_port'] == source.server_port]
    summary = dict(synthetic_only=True, target='loopback_nonforwarding_http', source_receipts=receipts,
                   target_port=source.server_port, descendant_network_events=networks,
                   behavior_health=result.get('behavior_comparison'),
                   native_ready=result['native_ready'], client_returncode=result['returncode'],
                   can_enforce=False, limitations=['HTTP GET connectivity test, not proof of secret upload',
                       'Git source is not a Git server; protocol error after connection is expected'])
    (root/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(dict(output=str(root), receipts=len(receipts), network_events=len(networks), can_enforce=False)))


if __name__ == '__main__': main()
