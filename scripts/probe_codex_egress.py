"""Opt-in UAC experiment: synthetic client, temporary local-only WFP filter."""
import argparse
import json
from pathlib import Path
import queue
import socket
import subprocess
import threading
import time

from _build_support import ROOT
from _behavior_probe import ElevatedProcess
from transpect_trace.behavior.collector import verify_collector
from transpect_trace.observe.windows import identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--elevate', action='store_true')
    args = parser.parse_args(); output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    client_exe, controller = ROOT / 'build/behavior/egress_client.exe', ROOT / 'build/behavior/wfp_lease.exe'
    for p in (client_exe, controller):
        verify_collector(p)
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.2)
    stop = threading.Event(); received = []; lock = threading.Lock()
    def source():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2)
                count = 0
                try:
                    while data := conn.recv(4096): count += len(data)
                except (OSError, socket.timeout):
                    pass
                with lock: received.append(count)
    thread = threading.Thread(target=source, daemon=True); thread.start()
    client = subprocess.Popen([str(client_exe), str(listener.getsockname()[1])], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    replies = queue.Queue()
    def read():
        for line in client.stdout: replies.put(json.loads(line))
    threading.Thread(target=read, daemon=True).start()
    def request():
        before = sum(received); client.stdin.write('send\n'); client.stdin.flush()
        result = replies.get(timeout=5); time.sleep(.3)
        result['source_bytes_delta'] = sum(received) - before
        return result
    lease = None
    result = dict(scope='synthetic_client_only', pid_exact_filter=False, can_enforce_for_codex_descendants=False,
                  protocol='ipv4_tcp_loopback', persistent_filter=False)
    try:
        subject = identity(client.pid)
        result['subject'] = subject
        result['before'] = request()
        argv = [str(client.pid), str(subject['creation_filetime']), subject['image_sha256'],
                str(listener.getsockname()[1]), '8', str(output / 'filter.jsonl')]
        lease = ElevatedProcess(controller, argv, ROOT) if args.elevate else subprocess.Popen([str(controller), *argv], creationflags=0x08000000)
        until = time.monotonic() + 8
        records = []
        while time.monotonic() < until:
            path = output / 'filter.jsonl'
            if path.exists(): records = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
            if records or lease.poll() is not None: break
            time.sleep(.05)
        installed = any(r['kind'] == 'filter.installed' for r in records)
        if installed:
            result['during'] = request()
        result['lease_exit_code'] = lease.wait(timeout=15)
        result['after'] = request()
        result['filter_records'] = [json.loads(x) for x in (output / 'filter.jsonl').read_text().splitlines()] if (output / 'filter.jsonl').exists() else []
        result['passed'] = (installed and result['lease_exit_code'] == 0 and result['before']['source_bytes_delta'] > 0
            and result['during']['connect_error'] == 10013 and result['during']['source_bytes_delta'] == 0
            and result['after']['source_bytes_delta'] > 0)
    except (OSError, queue.Empty, subprocess.TimeoutExpired) as error:
        result.update(passed=False, status='unavailable', error_type=type(error).__name__, win32_error=getattr(error, 'winerror', None))
    finally:
        if lease and isinstance(lease, ElevatedProcess):
            lease.wait(timeout=15); lease.close()
        client.stdin.write('quit\n'); client.stdin.flush(); client.wait(timeout=5)
        stop.set(); listener.close(); thread.join(3)
        (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    if not result.get('passed'): raise SystemExit(2)


if __name__ == '__main__': main()
