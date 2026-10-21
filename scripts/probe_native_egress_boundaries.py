"""Characterize excluded paths; excluded traffic arriving is never protection success.

The synthetic root establishes TCP before attachment, then inherits the connected
socket into a Native-ready child. The same child tries a new denied TCP connect,
sends on the inherited connection, and sends an unconnected UDP datagram. No
proxy, firewall edit, UAC, live Codex session or external network is involved.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import queue
import socket
import subprocess
import threading
import time

from _build_support import ROOT,enter_repository
from transpect_trace.behavior.native_egress import EgressController,inspect_process

BEFORE=b'boundary-existing-before-ready'
AFTER=b'boundary-existing-after-ready'
DATAGRAM=b'boundary-unconnected-udp'


class Source:
    def __init__(self,udp=False):
        self.udp=udp;self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1',0));self.port=self.socket.getsockname()[1]
        if not udp:self.socket.listen()
        self.socket.settimeout(.1);self.stop=threading.Event();self.lock=threading.Lock();self.data=bytearray();self.connections=0;self.readers=[]
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()

    def payload(self):
        with self.lock:return bytes(self.data)

    def drain(self,connection):
        with connection:
            connection.settimeout(.1)
            while not self.stop.is_set():
                try:
                    data=connection.recv(4096)
                    if not data:return
                    with self.lock:self.data.extend(data)
                except socket.timeout:continue
                except OSError:return

    def run(self):
        while not self.stop.is_set():
            try:
                if self.udp:
                    data,_=self.socket.recvfrom(4096)
                    with self.lock:self.data.extend(data);self.connections+=1
                else:
                    connection,_=self.socket.accept()
                    with self.lock:self.connections+=1
                    thread=threading.Thread(target=self.drain,args=(connection,),daemon=True);self.readers.append(thread);thread.start()
            except socket.timeout:continue
            except OSError:return

    def close(self):
        self.stop.set();self.socket.close();self.thread.join(2)
        for thread in self.readers:thread.join(2)


def assess(rows,records,members,*,tcp_before,tcp_after,tcp_connections,udp_payload,exit_code):
    """Keep fixture validity, protected new connects and excluded sends separate."""
    by_kind={row.get('kind'):row for row in rows}
    child=by_kind.get('fixture.child_main_started',{})
    registered=[m for m in members if not m.get('root') and m.get('pid')==child.get('pid') and m.get('ready')]
    new=by_kind.get('boundary.new_tcp',{});existing=by_kind.get('boundary.existing_tcp',{});udp=by_kind.get('boundary.udp_sendto',{})
    denied_attempts={r.get('attempt_id') for r in records if r.get('kind')=='connection.decision' and r.get('pid')==child.get('pid') and r.get('decision')=='block'}
    executed={r.get('attempt_id') for r in records if r.get('kind')=='connection.rejected' and r.get('pid')==child.get('pid') and r.get('native_result')==-1 and r.get('winsock_error')==10013}
    valid=bool(exit_code==0 and registered and tcp_before==BEFORE and by_kind.get('fixture.preexisting_ready',{}).get('socket_inheritable'))
    new_blocked=bool(valid and new.get('result')==-1 and new.get('error')==10013 and denied_attempts&executed and tcp_connections==1)
    existing_observed=bool(valid and existing.get('peer_matches') and existing.get('sent_bytes')==len(AFTER) and existing.get('error')==0 and tcp_after==BEFORE+AFTER)
    udp_observed=bool(valid and udp.get('sent_bytes')==len(DATAGRAM) and udp.get('error')==0 and udp_payload==DATAGRAM)
    udp_connect=by_kind.get('boundary.udp_connect',{})
    udp_connect_passthrough=bool(valid and udp_connect.get('result')==0 and udp_connect.get('error')==0)
    return {'experiment_valid':valid,'boundary_characterization_passed':new_blocked and existing_observed and udp_observed and udp_connect_passthrough,
        'new_tcp':{'protected':new_blocked,'native_failure_and_source_connection_count_match':new_blocked},
        'existing_tcp':{'protected':False,'coverage':'excluded','send_after_native_ready_observed':existing_observed},
        'udp_sendto':{'protected':False,'coverage':'excluded','datagram_after_native_ready_observed':udp_observed},
        'udp_connect':{'protected':False,'coverage':'excluded','native_client_result':udp_connect,
            'original_api_passthrough_succeeded':udp_connect_passthrough,
            'limitation':'UDP connect is passed through unchanged; UDP sendto and QUIC remain uncovered'},
        'loader_tls_callbacks':{'protected':False,'coverage':'not_certified','tested':False},
        'this_is_not_a_protection_pass_for_excluded_paths':True}


def confirmed_exit_keys(rows,members):
    """Accept owned-handle exit receipts only for an enrolled child lifetime."""
    expected={(m.get('pid'),m.get('creation_filetime')) for m in members if not m.get('root')}
    confirmed=set()
    for row in rows:
        if (row.get('kind')!='fixture.child_exited' or row.get('handle_wait_confirmed') is not True or
                row.get('identity_from_process_handle') is not True):continue
        pid,birth,code=row.get('pid'),row.get('creation_filetime'),row.get('exit_code')
        if (type(pid) is not int or type(birth) is not int or type(code) is not int or
                pid<=0 or birth<=0 or not 0<=code<=0xffffffff):continue
        if (pid,birth) in expected:confirmed.add((pid,birth))
    return confirmed


def cleanup_children(controller,fixture,exit_receipts=()):
    """Explicit test cleanup of this file's verified synthetic children only."""
    import ctypes
    from ctypes import wintypes
    from transpect_trace.guard.native import api
    cleaned=[];expected=hashlib.sha256(fixture.read_bytes()).hexdigest();k=None
    exited=confirmed_exit_keys(exit_receipts,list(controller.members.values()))
    for member in controller.members.values():
        if member.get('root'):continue
        if (member['pid'],member['creation_filetime']) in exited:continue
        try:current=inspect_process(member['pid'])
        except OSError as error:
            if getattr(error,'winerror',None)!=87:cleaned.append({'pid':member['pid'],'state':'identity_unavailable'})
            continue
        if (current['creation_filetime'],current['image_sha256'])!=(member['creation_filetime'],expected):continue
        if k is None:
            k=api();k.TerminateProcess.argtypes=[ctypes.c_void_p,ctypes.c_uint32]
        handle=k.OpenProcess(0x1000|0x100000|1,False,member['pid'])
        if not handle:cleaned.append({'pid':member['pid'],'state':'cleanup_unavailable'});continue
        try:
            times=[wintypes.FILETIME() for _ in range(4)]
            birth_ok=k.GetProcessTimes(handle,*(ctypes.byref(t) for t in times)) and (times[0].dwLowDateTime|(times[0].dwHighDateTime<<32))==member['creation_filetime']
            if birth_ok:
                confirmed=bool(k.TerminateProcess(handle,99) and k.WaitForSingleObject(handle,5000)==0)
                cleaned.append({'pid':member['pid'],'creation_filetime':member['creation_filetime'],
                    'state':'explicit_fixture_cleanup' if confirmed else 'cleanup_unavailable','enforcement_evidence':False})
        finally:k.CloseHandle(handle)
    return cleaned


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-dir',type=Path,default=ROOT/'build/egress')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();enter_repository();root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    native=args.native_dir.resolve();fixture=native/'egress-boundary-fixture.exe';dll=native/'ttrace-egress.dll'
    manifest=json.loads((native/'build-manifest.json').read_text(encoding='utf-8'))
    for path in (fixture,dll):
        if hashlib.sha256(path.read_bytes()).hexdigest()!=manifest['artifacts_sha256'].get(path.name):raise ValueError('Boundary fixture or DLL manifest mismatch')
    tcp=Source();udp=Source(udp=True);controller=None;process=None;rows=[];errors=[];messages=queue.Queue();reader=None
    result={'experiment_valid':False,'boundary_characterization_passed':False,'scope':'synthetic_ipv4_loopback_only','actual_codex_certified':False}
    try:
        process=subprocess.Popen([str(fixture),'root',str(tcp.port),str(udp.port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        def read():
            for raw in process.stdout:
                try:row=json.loads(raw)
                except (ValueError,UnicodeError):errors.append('malformed_fixture_record');continue
                rows.append(row);messages.put(row)
        reader=threading.Thread(target=read,daemon=True);reader.start()
        if messages.get(timeout=8).get('kind')!='fixture.preexisting_ready':raise RuntimeError('Preexisting TCP fixture was not ready')
        deadline=time.monotonic()+3
        while tcp.payload()!=BEFORE and time.monotonic()<deadline:time.sleep(.02)
        before=tcp.payload()
        policy={'targets':[{'address':'127.0.0.1','port':port,'action':'block'} for port in sorted({tcp.port,udp.port})]}
        controller=EgressController(inspect_process(process.pid),dll,policy,root/'controller');controller.start()
        # Root Native initializer has returned successfully before its input is
        # released. The inherited child attests readiness before main resumes.
        process.stdin.write(b'\n');process.stdin.flush();process.stdin.close()
        code=process.wait(25);reader.join(3);time.sleep(.3)
        result.update(assess(rows,controller.records,list(controller.members.values()),tcp_before=before,
            tcp_after=tcp.payload(),tcp_connections=tcp.connections,udp_payload=udp.payload(),exit_code=code))
        result.update(protected_since_unix_ns=controller.state.get('protected_since_unix_ns'),
            root_protection_boundary='Native initializer returned before stdin release; no claim for loader callbacks',
            child_protection_boundary='Parent resumes main only after Native initialization; ready record alone is earlier than return',
            source_receipts={'tcp':{'connections':tcp.connections,'bytes':len(tcp.payload()),'sha256':hashlib.sha256(tcp.payload()).hexdigest()},
                'udp':{'datagrams':udp.connections,'bytes':len(udp.payload()),'sha256':hashlib.sha256(udp.payload()).hexdigest()}},
            fixture_rows=rows,controller_errors=list(controller.errors),fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
            dll_sha256=hashlib.sha256(dll.read_bytes()).hexdigest())
        if errors or controller.errors:result['experiment_valid']=result['boundary_characterization_passed']=False
    except (OSError,RuntimeError,ValueError,queue.Empty,subprocess.SubprocessError) as error:
        result.update(error_type=type(error).__name__,winerror=getattr(error,'winerror',None))
    finally:
        if controller:controller.close()
        if process and process.poll() is None:
            process.kill();process.wait(5)  # Own isolated fixture cleanup, never enforcement.
            result['fixture_forced_cleanup']=True
        else:result['fixture_forced_cleanup']=False
        result['fixture_confirmed_exits']=[{'pid':pid,'creation_filetime':birth,'proof':'owned_child_handle_wait_and_exit_code'}
            for pid,birth in sorted(confirmed_exit_keys(rows,list(controller.members.values())))] if controller else []
        result['fixture_child_cleanup']=cleanup_children(controller,fixture,rows) if controller else []
        if result['fixture_forced_cleanup'] or result['fixture_child_cleanup']:
            result['experiment_valid']=result['boundary_characterization_passed']=False
        if reader:reader.join(2)
        tcp.close();udp.close()
        result['errors']=errors
        with (root/'summary.json').open('x',encoding='utf-8') as output:json.dump(result,output,indent=2);output.write('\n')
    print(json.dumps(result,indent=2))
    if not result['boundary_characterization_passed']:raise SystemExit(2)


if __name__=='__main__':main()
