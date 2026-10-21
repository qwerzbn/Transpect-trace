"""Run isolated descendant-gate checks against a non-forwarding loopback listener."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading
import time

from _build_support import ROOT, enter_repository
from transpect_trace.behavior.native_egress import CONNECT, MAGIC, RESPONSE, EgressController, inspect_process


class FaultReplyController(EgressController):
    fault = None

    def response_frame(self, values, allowed, reason):
        if values[2] == CONNECT:
            if self.fault == 'timeout':
                # Deliberately late ALLOW: the Native exchange must fail closed
                # before this response, rather than execute the original connect.
                time.sleep(2.25)
            if self.fault == 'sequence':
                return RESPONSE.pack(MAGIC, 1, 1, 0, values[-1] + 1)
            if self.fault == 'version':
                return RESPONSE.pack(MAGIC, 2, 1, 0, values[-1])
        return super().response_frame(values, allowed, reason)

    def receipt_confirmation(self, values):
        return b'\x00' if values[2] == CONNECT and self.fault == 'ack' else super().receipt_confirmation(values)


def cleanup_fixture_children(controller,fixture,cleanup_records):
    """Explicit cleanup of exact synthetic lifetimes, never enforcement proof."""
    pending={(m['pid'],m['creation_filetime']):m for m in controller.members.values() if not m.get('root')}
    for row in controller.records:
        if row['kind']=='process.held':
            pending[(row['child_pid'],row['creation_filetime'])]={'pid':row['child_pid'],'creation_filetime':row['creation_filetime']}
    already={(row['pid'],row['creation_filetime']) for row in cleanup_records if row['cleanup_confirmed']}
    expected_fixture=hashlib.sha256(fixture.read_bytes()).hexdigest()
    for key,member in pending.items():
        if key in already:continue
        try:identity=inspect_process(member['pid'])
        except OSError:continue
        if (identity['creation_filetime'],identity['image_sha256'])!=(member['creation_filetime'],expected_fixture):continue
        from transpect_trace.guard.native import api
        import ctypes
        from ctypes import wintypes
        k=api();k.TerminateProcess.argtypes=[ctypes.c_void_p,ctypes.c_uint32]
        handle=k.OpenProcess(1|0x1000|0x100000,False,member['pid'])
        if not handle:continue
        try:
            times=[wintypes.FILETIME() for _ in range(4)]
            if k.GetProcessTimes(handle,*(ctypes.byref(t) for t in times)) and (times[0].dwLowDateTime|(times[0].dwHighDateTime<<32))==member['creation_filetime']:
                cleaned=bool(k.TerminateProcess(handle,99) and k.WaitForSingleObject(handle,5000)==0)
                cleanup_records.append({'pid':member['pid'],'creation_filetime':member['creation_filetime'],
                    'fixture_image_sha256':identity['image_sha256'],'cleanup_confirmed':cleaned,
                    'method':'explicit_identity_checked_test_fixture_cleanup','enforcement_evidence':False})
        finally:k.CloseHandle(handle)


def run_case(fixture, dll, output, family, method, action, *, lost=False, mapped=False, double=False, fault=None, deny_enrollment=False):
    listener = socket.socket(socket.AF_INET6 if family == 6 and not mapped else socket.AF_INET)
    address = "::ffff:127.0.0.1" if mapped else "::1" if family == 6 else "127.0.0.1"
    policy_address = "127.0.0.1" if mapped else address
    listener.bind((policy_address, 0))
    listener.listen()
    listener.settimeout(.2)
    port = listener.getsockname()[1]
    receipts = []
    stop = threading.Event()
    def receive():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(2)
                receipts.append(connection.recv(1024))
    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    child = subprocess.list2cmdline([str(fixture), str(family), address, str(port), method, "2500" if lost else "0"])
    process = subprocess.Popen([str(fixture), "root", child], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    policy = {"targets": [{"address": policy_address, "port": port, "action": action}]}
    if deny_enrollment:
        policy['allowed_image_hashes']=['0'*64]
    controller = FaultReplyController(inspect_process(process.pid), dll, policy, output)
    controller.fault = fault
    cleanup_records=[];result_row=None;held_targets=[];held_valid=False;receipts_before_cleanup=None
    try:
        controller.start()
        unrelated = subprocess.run([str(fixture), str(family), address, str(port), method], capture_output=True, timeout=8)
        time.sleep(.05)
        unrelated_receipts = len(receipts)
        scope_ok = unrelated.returncode == 0 and unrelated_receipts == 1
        double_rejected = None
        if double:
            second = EgressController(inspect_process(process.pid), dll, {}, output / "double-owner")
            try:
                second.start()
            except RuntimeError:
                double_rejected = True
            else:
                double_rejected = False
            finally:
                second.close()
        process.stdin.write(b"\n")
        process.stdin.flush()
        prefix=[]
        if lost:
            entered=threading.Event()
            def read_started():
                while True:
                    line=process.stdout.readline()
                    if not line:return
                    prefix.append(line)
                    if b'child_main_started' in line:
                        entered.set();return
            reader=threading.Thread(target=read_started,daemon=True);reader.start()
            # READY is sent before initialization returns. Prove the synthetic
            # main thread actually started before deliberately losing control.
            if not entered.wait(10):
                raise RuntimeError("child main did not start before controller-loss test")
            reader.join(1)
            controller.close()
        if deny_enrollment:
            # The held child inherits the fixture's stdout/stderr handles. Root
            # exit does not imply pipe EOF: validate the Native HELD outcome,
            # then clean up this exact test child before draining those pipes.
            process.wait(timeout=25)
            held_records=[r for r in controller.records if r['kind']=='process.held']
            held_targets=list(controller.state.get('held_processes',[]))
            expected_fixture=hashlib.sha256(fixture.read_bytes()).hexdigest()
            held_valid=bool(held_records and held_targets and process.returncode==50)
            for target in held_targets:
                actual=inspect_process(target['pid'])
                held_valid=held_valid and (actual['creation_filetime'],actual['image_sha256'])==(target['creation_filetime'],expected_fixture)
                held_valid=held_valid and target['enrollment']=='not_registered' and target['pid'] not in controller.members
                held_valid=held_valid and any((row['child_pid'],row['creation_filetime'])==(target['pid'],target['creation_filetime']) for row in held_records)
            (output/'held-before-cleanup.json').write_text(json.dumps(controller.state,indent=2)+'\n')
            time.sleep(.15)
            receipts_before_cleanup=list(receipts[unrelated_receipts:])
            cleanup_fixture_children(controller,fixture,cleanup_records)
        stdout, stderr = process.communicate(timeout=25)
        stdout=b''.join(prefix)+stdout
        time.sleep(.15)
        protected_receipts = receipts_before_cleanup if deny_enrollment else receipts[unrelated_receipts:]
        blocked = action == "block" or lost or fault or deny_enrollment
        native_rejections = [r for r in controller.records if r["kind"] == "connection.rejected"]
        passed = scope_ok and process.returncode == (50 if deny_enrollment else 13 if blocked else 0) and (not protected_receipts if blocked else b"synthetic-egress" in b"".join(protected_receipts))
        if double:
            passed = passed and double_rejected
        if blocked and not lost and not fault and not deny_enrollment:
            passed = passed and bool(native_rejections)
        if deny_enrollment:
            passed=passed and held_valid and b'create_failed=5' in stdout and b'child_main_started' not in stdout
        result_row={"family": family, "ipv4_mapped": mapped, "entry": method, "policy": action, "controller_loss": lost, "reply_fault": fault, "passed": passed, "same_path_unrelated_allowed": scope_ok, "double_owner_rejected": double_rejected, "client_returncode": process.returncode, "client_evidence": stdout.decode("utf-8", errors="replace").strip(), "source_bytes": sum(map(len, protected_receipts)), "source_connections": len(protected_receipts), "native_rejections": len(native_rejections), "members": len(controller.members), "stderr_bytes": len(stderr)}
        if deny_enrollment:
            result_row.update(enrollment_denied=True,held_targets=held_targets,
                child_native_main_started=False,execution='process_creation_rejected_child_held_not_network_block',
                fixture_cleanup=cleanup_records,fixture_cleanup_is_enforcement_evidence=False,
                source_receipt_window='before_test_fixture_cleanup',held_state_evidence='held-before-cleanup.json')
        return result_row
    finally:
        controller.close()
        if process.poll() is None:
            process.kill()  # explicit cleanup of this isolated test subject only
            process.wait()
        cleanup_fixture_children(controller,fixture,cleanup_records)
        if deny_enrollment and result_row is not None:
            result_row['fixture_cleanup_confirmed']=bool(held_targets) and all(any(
                (target['pid'],target['creation_filetime'])==(row['pid'],row['creation_filetime']) and row['cleanup_confirmed']
                for row in cleanup_records) for target in held_targets)
            result_row['passed']=result_row['passed'] and result_row['fixture_cleanup_confirmed']
        stop.set()
        listener.close()
        thread.join(timeout=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-dir", type=Path, default=ROOT / "build/egress")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    enter_repository()
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = (args.native_dir / "egress-fixture.exe").resolve()
    dll = (args.native_dir / "ttrace-egress.dll").resolve()
    cases = []
    combinations = [(4, "connect", "block")] if args.quick else [(family, method, action) for family in (4, 6) for method in ("connect", "wsaconnect", "connectex") for action in ("allow", "block")]
    for family, method, action in combinations:
        name = f"ipv{family}-{method}-{action}"
        try:
            row = run_case(fixture, dll, args.output / name, family, method, action)
        except Exception as exc:
            row = {"passed": False, "error": type(exc).__name__, "reason": str(exc)}
        row["case"] = name
        cases.append(row)
        print(json.dumps(row), flush=True)
    if not args.quick:
        cases.append(dict(run_case(fixture, dll, args.output / "controller-loss", 4, "connect", "allow", lost=True), case="controller-loss"))
        cases.append(dict(run_case(fixture, dll, args.output / "mapped-ipv4-block", 6, "connect", "block", mapped=True), case="mapped-ipv4-block"))
        cases.append(dict(run_case(fixture, dll, args.output / "double-owner", 4, "connect", "block", double=True), case="double-owner"))
        for fault in ['sequence', 'version', 'ack', 'timeout']:
            cases.append(dict(run_case(fixture, dll, args.output / f"bad-reply-{fault}", 4, "connect", "allow", fault=fault), case=f"bad-reply-{fault}"))
        cases.append(dict(run_case(fixture, dll, args.output / 'denied-enrollment', 4, 'connect', 'allow', deny_enrollment=True),case='denied-enrollment'))
    summary = {"schema": "transpect.egress.probe/1.0", "scope": "isolated_synthetic_descendants_loopback_tcp", "passed": all(row["passed"] for row in cases), "dll_sha256": hashlib.sha256(dll.read_bytes()).hexdigest(), "cases": cases, "limitations": ["Synthetic root only; real Codex and tools require separate certification", "No kernel enforcement or full-system bypass resistance", "Private Windows process entry only verified on the current host"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
