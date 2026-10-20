"""Local-only WFP lifecycle/scope experiment; explicit UAC, no global firewall edits."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
import time

from _build_support import ROOT
from _behavior_probe import ElevatedProcess
from transpect_trace.behavior.collector import verify_collector
from transpect_trace.behavior.egress_status import FILTER_NOT_FOUND, lease_status
from transpect_trace.observe.windows import identity


class Source:
    def __init__(self, port=0, *, ipv6=False, udp=False):
        self.udp = udp
        self.socket = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,
                                    socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        if ipv6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            self.socket.bind(('::1' if ipv6 else '127.0.0.1', port))
        except OSError:
            self.socket.close()
            raise
        self.port = self.socket.getsockname()[1]
        if not udp:
            self.socket.listen()
        self.socket.settimeout(.1)
        self.total = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.connections = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def read(self, conn):
        with conn:
            conn.settimeout(.1)
            while not self.stop.is_set():
                try:
                    data = conn.recv(4096)
                    if not data:
                        return
                    with self.lock:
                        self.total += len(data)
                except socket.timeout:
                    continue
                except OSError:
                    return

    def run(self):
        while not self.stop.is_set():
            try:
                if self.udp:
                    data, _ = self.socket.recvfrom(4096)
                    with self.lock:
                        self.total += len(data)
                else:
                    conn, _ = self.socket.accept()
                    thread = threading.Thread(target=self.read, args=(conn,), daemon=True)
                    self.connections.append(thread)
                    thread.start()
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(2)
        for thread in self.connections:
            thread.join(2)


class Client:
    def __init__(self, binary, source, mode=None):
        self.source = source
        self.process = subprocess.Popen([str(binary), str(source.port), *([mode] if mode else [])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.subject = identity(self.process.pid)
        self.replies = queue.Queue()
        def read():
            for line in self.process.stdout:
                self.replies.put(json.loads(line))
        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()

    def request(self):
        before = self.source.total
        self.process.stdin.write('send\n')
        self.process.stdin.flush()
        value = self.replies.get(timeout=5)
        time.sleep(.2)
        return value | dict(source_bytes_delta=self.source.total - before, subject=self.subject)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write('quit\n')
            self.process.stdin.flush()
            self.process.wait(5)
        self.thread.join(2)


class Lease:
    def __init__(self, binary, client, path, fault=None, owner=None):
        self.binary, self.path = binary, path
        who = client.subject
        owner_args = ['--owner',str(owner['pid']),str(owner['creation_filetime']),owner['image_sha256']] if owner else []
        self.process = subprocess.Popen([str(binary), str(who['pid']), str(who['creation_filetime']),
            who['image_sha256'], str(client.source.port), '30', str(path), *([fault] if fault else []), *owner_args],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.controller = identity(self.process.pid)
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if any(r['kind'] == 'filter.installed' for r in self.records()) or self.process.poll() is not None:
                break
            time.sleep(.02)
        self.installed = next((r for r in self.records() if r['kind'] == 'filter.installed'), None)
        self.id = self.installed['filter_id'] if self.installed else None

    def records(self):
        if not self.path.exists():
            return []
        # A concurrently written last line may be partial; never count it as ready.
        values = []
        for line in self.path.read_text().splitlines():
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return values

    def query(self):
        if not self.id:
            return dict(query_error=None, open_error=None)
        result = subprocess.run([str(self.binary), '--query', str(self.id)], capture_output=True, text=True, timeout=5)
        return json.loads(result.stdout)

    def state(self, cleanup=False):
        result = self.query()
        actual = None
        if self.process.poll() is None:
            try:
                actual = identity(self.process.pid)
            except OSError:
                pass
        tick = ctypes.windll.kernel32.GetTickCount64()
        return lease_status(controller_identity_matches=actual == self.controller,
            filter_id=self.id, query_error=result['query_error'], query_tick_ms=tick,
            now_tick_ms=tick, cleanup_requested=cleanup)

    def finish(self, crash=False):
        if self.process.poll() is None:
            if crash:
                self.process.terminate()  # Own controller only; never an enforcement action on target.
            else:
                self.process.stdin.write(b'revoke\n')
                self.process.stdin.flush()
        code = self.process.wait(5)
        end = time.monotonic() + 5
        result = self.query()
        while self.id and result['query_error'] != FILTER_NOT_FOUND and time.monotonic() < end:
            time.sleep(.05)
            result = self.query()
        return dict(exit_code=code, bfe=result, records=self.records(),
                    state=self.state(cleanup=True), controller=self.controller)


def blocked(value):
    return value['connect_error'] == 10013 and value['failure_stage'] == 'connect' and value['source_bytes_delta'] == 0


def delivered(value):
    return value['connect_error'] == 0 and value['sent_bytes'] == value['source_bytes_delta'] > 0


def worker(output, native):
    clients, leases, sources = [], [], []
    result = dict(scope='synthetic_image_path_loopback_only', tests={}, passed=False,
                  elevated_synthetic_clients=True, real_codex_sessions_tested=False,
                  process_tree_inheritance=False, pid_isolation=False)
    def source(**kw):
        obj = Source(**kw); sources.append(obj); return obj
    def client(src, mode=None):
        obj = Client(native/'egress_client.exe', src, mode); clients.append(obj); return obj
    def lease(name, target, fault=None):
        obj = Lease(native/'wfp_lease.exe', target, output/(name+'.jsonl'), fault); leases.append(obj); return obj
    try:
        for name in ('egress_client.exe', 'wfp_lease.exe'):
            verify_collector(native/name)
        result['artifacts_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in native.glob('*.exe')}
        # Reserve all three local source endpoints before testing any filter.
        # Windows TCP/UDP exclusions can differ; a bind failure is not WFP evidence.
        result['fixture_bind_failures'] = []
        for attempt in range(10):
            created = []
            try:
                tcp = Source(); created.append(tcp)
                tcp6 = Source(port=tcp.port, ipv6=True); created.append(tcp6)
                udp4 = Source(port=tcp.port, udp=True); created.append(udp4)
                sources.extend(created)
                break
            except OSError as error:
                result['fixture_bind_failures'].append(dict(winerror=getattr(error,'winerror',None)))
                for obj in created:
                    obj.close()
        else:
            raise RuntimeError('No common local TCP/UDP/IPv6 fixture port')
        main = client(tcp); persistent = client(tcp, '--persistent')
        before = main.request(); established_before = persistent.request()
        # Deliberately release a descendant-like fixture before installing its path rule.
        late = client(tcp); before_ready = late.request()
        rule = lease('normal', main)
        if not rule.installed:
            raise RuntimeError('WFP rule unavailable; inspect native records')
        ready = rule.state(); during = main.request()
        newborn = client(tcp); first_after_ready = newborn.request()
        unrelated = client(tcp); unrelated_result = unrelated.request()
        existing_during = persistent.request()
        ipv6 = client(tcp6, '--ipv6').request()
        udp = client(udp4, '--udp').request()
        normal_end = rule.finish(); after = main.request()
        result['tests']['normal_and_scope'] = dict(before=before, ready=ready, during=during,
            after=after, finish=normal_end, established_before=established_before,
            established_during=existing_during, ipv6_tcp=ipv6, ipv4_udp=udp,
            unrelated_same_path=unrelated_result,
            passed=delivered(before) and ready['protected'] and blocked(during) and
                blocked(unrelated_result) and normal_end['state']['cleanup_confirmed'] and delivered(after))
        result['tests']['first_connection'] = dict(before_rule_ready=before_ready,
            installed=rule.installed, first_after_ready=first_after_ready,
            reactive_unprotected_window_demonstrated=delivered(before_ready),
            general_descendant_race_free=False,
            passed=delivered(before_ready) and blocked(first_after_ready) and
                first_after_ready['tick_ms'] >= rule.installed['tick_ms'])
        # Controller crash: BFE absence + recovered communication, without trusting terminal logs.
        crash = lease('controller-crash', main)
        crash_before = main.request(); crash_end = crash.finish(crash=True)
        result['tests']['controller_crash'] = dict(before=crash_before, finish=crash_end,
            status=crash.state(), after=main.request())
        row = result['tests']['controller_crash']
        row['passed'] = blocked(crash_before) and crash_end['state']['cleanup_confirmed'] and delivered(row['after']) and not row['status']['protected']
        # Target death: its lease ends, despite other same-path instances remaining alive.
        victim = client(tcp); death = lease('target-death', victim)
        victim.process.terminate(); victim.process.wait(5)
        death.process.wait(5); death_end = death.finish()
        result['tests']['target_death'] = dict(finish=death_end, after=main.request())
        row = result['tests']['target_death']; row['passed'] = death_end['state']['cleanup_confirmed'] and delivered(row['after'])
        # Independent destinations, independent dynamic sessions.
        second = client(source()); a = lease('parallel-a', main); b = lease('parallel-b', second)
        both = [main.request(), second.request()]; end_a = a.finish()
        isolated = [main.request(), second.request()]; end_b = b.finish(); restored = second.request()
        result['tests']['parallel_distinct_ports'] = dict(both=both, after_a_removed=isolated,
            finish_a=end_a, finish_b=end_b, restored=restored,
            passed=all(map(blocked,both)) and delivered(isolated[0]) and blocked(isolated[1]) and delivered(restored))
        # Same-path/same-target filters overlap, not session/PID isolation.
        a = lease('overlap-a', main); b = lease('overlap-b', main)
        a.finish(); overlap = main.request(); end_b = b.finish(); restored = main.request()
        result['tests']['overlapping_sessions'] = dict(after_one_removed=overlap, finish=end_b,
            after_both_removed=restored, passed=blocked(overlap) and delivered(restored))
        failed = lease('install-failure', main, '--fault-install'); failed_end = failed.finish()
        final = failed_end['records'][-1]
        result['tests']['install_failure'] = dict(finish=failed_end, after=main.request(),
            fault_injection='nonexistent_layer', passed=bool(final['install_error']) and failed.id is None and failed_end['exit_code'] != 0)
        failed = lease('remove-failure', main, '--fault-remove'); denied = main.request()
        failed_end = failed.finish(); recovered = main.request()
        final = failed_end['records'][-1]
        result['tests']['remove_failure'] = dict(finish=failed_end, during=denied, after=recovered,
            fault_injection='wrong_session_delete_own_test_filter',
            passed=blocked(denied) and bool(final['remove_error']) and failed_end['exit_code'] != 0 and
                failed_end['state']['cleanup_confirmed'] and delivered(recovered))
        result['passed'] = all(row['passed'] for row in result['tests'].values())
    except Exception as error:
        result['failure'] = dict(type=type(error).__name__, winerror=getattr(error,'winerror',None))
    finally:
        result['cleanup'] = []
        for obj in leases:
            try:
                record = obj.finish()
                result['cleanup'].append(dict(filter_id=obj.id, bfe=record['bfe'], state=record['state']))
            except Exception as error:
                result['cleanup'].append(dict(error_type=type(error).__name__))
                result['passed'] = False
        for obj in clients:
            obj.close()
        for obj in sources:
            obj.close()
        if any(r.get('filter_id') and not r.get('state',{}).get('cleanup_confirmed') for r in result['cleanup']):
            result['passed'] = False
        (output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-dir', type=Path, required=True)
    parser.add_argument('--elevate', action='store_true')
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args(); output = args.output.resolve(); native = args.native_dir.resolve()
    ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
    if args.worker:
        result = worker(output, native)
    else:
        output.mkdir(parents=True,exist_ok=False)
        if args.elevate:
            child = ElevatedProcess(sys.executable,[str(Path(__file__).resolve()), '--worker', '--output',str(output), '--native-dir',str(native)], ROOT)
            try:
                code = child.wait(timeout=120)
            finally:
                child.close()
            result = json.loads((output/'summary.json').read_text()) if (output/'summary.json').exists() else dict(passed=False, worker_exit_code=code, status='unavailable_or_pending')
        else:
            result = worker(output, native)
        print(json.dumps(dict(passed=result['passed'], cases={k:v['passed'] for k,v in result.get('tests',{}).items()}, failure=result.get('failure'))))
    if not result['passed']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
