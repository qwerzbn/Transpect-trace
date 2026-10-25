"""Real Windows audit-pipe transport tests, distinct from full Hook certification."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

import pytest

from transpect_trace.flow.native import NativeIOCollector, validate_build


CLIENT = r'''
import ctypes as c, json, struct, sys, time
from ctypes import wintypes as w
k=c.WinDLL('kernel32',use_last_error=True)
k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
k.WriteFile.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p]
k.ReadFile.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p]
k.CloseHandle.argtypes=[w.HANDLE]
print('ready',flush=True)
cfg=json.loads(sys.stdin.readline())
for seq in range(1,cfg['count']+1):
    deadline=time.monotonic()+5
    while True:
        h=k.CreateFileW(cfg['name'],0xc0000000,0,None,3,0,None)
        if h!=w.HANDLE(-1).value:break
        if time.monotonic()>deadline:raise RuntimeError('pipe_timeout')
        time.sleep(.002)
    kind=10 if cfg.get('terminal') and seq==cfg['count'] else 3
    # FIO1 header remains unchanged. Only its transport adds a receipt.
    fields=[cfg['pid']+cfg.get('wrong_pid',0),1,cfg['birth'],seq,100,77,1,0,1,2,0,0,0,0,1|8|128|256,0,0,0,0,0,0,100]
    raw=struct.pack('<4sI22Q',b'FIO1',kind,*fields)
    n=w.DWORD()
    assert k.WriteFile(h,raw,len(raw),c.byref(n),None) and n.value==len(raw)
    print('written',flush=True)
    if cfg['ack']:
        buf=c.create_string_buffer(1);n=w.DWORD()
        ok=k.ReadFile(h,buf,1,c.byref(n),None)
        print('ack' if ok and n.value==1 and buf.raw==b'\x06' else 'no-ack',flush=True)
    k.CloseHandle(h)
print('done',flush=True)
sys.stdin.readline() # Keep identity inspectable until the test finishes.
'''


def make_manifest(tmp_path, transport):
    dll=tmp_path/'not-loaded.dll';dll.write_bytes(b'pipe-server-fixture-only')
    manifest=tmp_path/'native-build.json'
    value={'protocol':'FIO1','can_enforce':False,
           'artifacts':{dll.name:{'sha256':hashlib.sha256(dll.read_bytes()).hexdigest()}}}
    if transport is not None:value['audit_transport']=transport
    manifest.write_text(json.dumps(value),encoding='utf-8')
    return dll,manifest


@pytest.mark.parametrize('transport',[None,'FIO1-legacy','FIO1-ACK1'])
def test_manifest_declares_receipt_transport_without_changing_frame(tmp_path,transport):
    dll,manifest=make_manifest(tmp_path,transport)
    assert validate_build(dll,manifest).get('audit_transport','FIO1-legacy')==(transport or 'FIO1-legacy')


@pytest.mark.parametrize('transport',['unknown',None,False])
def test_explicit_unknown_transport_fails_closed(tmp_path,transport):
    dll,manifest=make_manifest(tmp_path,'FIO1-ACK1')
    value=json.loads(manifest.read_bytes());value['audit_transport']=transport
    manifest.write_text(json.dumps(value),encoding='utf-8')
    with pytest.raises(ValueError,match='transport_unsupported'):validate_build(dll,manifest)


@pytest.fixture
def audit_pair(tmp_path):
    if sys.platform!='win32':pytest.skip('Windows Named Pipe transport')
    from transpect_trace.observe.windows import identity
    active=[]
    def start(callback, *, transport='FIO1-ACK1', before_accept=None, count=1, ack=True, **flags):
        process=subprocess.Popen([getattr(sys,'_base_executable',sys.executable),'-I','-c',CLIENT],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        assert process.stdout.readline().strip()==b'ready'
        subject=identity(process.pid)
        folder=tmp_path/str(process.pid);folder.mkdir()
        dll,manifest=make_manifest(folder,transport)
        collector=NativeIOCollector(subject,dll,manifest,callback,
            scopes=[{'role':'source','path':str(folder/'fake-source')}])
        if before_accept:
            original=collector.k.ConnectNamedPipe
            def connect(handle,overlapped):
                assert before_accept.wait(5)
                return original(handle,overlapped)
            collector.k.ConnectNamedPipe=connect
        active.append((process,collector))
        collector.thread=threading.Thread(target=collector._serve,daemon=True);collector.thread.start()
        assert collector.listening.wait(3)
        config={'name':collector.name,'pid':process.pid,'birth':subject['creation_filetime'],'count':count,'ack':ack,**flags}
        process.stdin.write((json.dumps(config)+'\n').encode());process.stdin.flush()
        lines=queue.Queue()
        def reader():
            for line in process.stdout:lines.put(line.strip())
        threading.Thread(target=reader,daemon=True).start()
        return collector,lines
    yield start
    for process,collector in active:
        collector.close()
        if process.poll() is None:
            process.stdin.write(b'finish\n');process.stdin.flush()
            process.wait(timeout=5)
        assert not collector.thread.is_alive()


def test_real_early_close_reproduces_connect_232_and_records_gap(audit_pair):
    gate=threading.Event();rows=[]
    collector,lines=audit_pair(rows.append,transport=None,before_accept=gate,ack=False)
    assert lines.get(timeout=3)==b'written'
    assert lines.get(timeout=3)==b'done' # Client closed before server accept.
    gate.set()
    deadline=time.monotonic()+3
    while not collector.errors and time.monotonic()<deadline:time.sleep(.01)
    assert 'native_io_peer_closed_before_accept' in collector.errors
    assert rows==[] and collector.sequence==0
    assert not collector.status()['terminal_health']


def test_ack_keeps_peer_open_until_full_frame_and_callback(audit_pair):
    gate=threading.Event();in_callback=threading.Event();release=threading.Event();rows=[]
    def consume(row):
        rows.append(row);in_callback.set();assert release.wait(3)
    collector,lines=audit_pair(consume,before_accept=gate)
    assert lines.get(timeout=3)==b'written'
    gate.set();assert in_callback.wait(3)
    with pytest.raises(queue.Empty):lines.get(timeout=.1)
    release.set()
    assert lines.get(timeout=3)==b'ack' and lines.get(timeout=3)==b'done'
    assert len(rows)==1 and rows[0]['sequence']==1 and not collector.errors
    assert collector.status()['audit_transport']=='FIO1-ACK1'


def test_ack_preserves_many_distinct_frames_and_terminal(audit_pair):
    rows=[];collector,lines=audit_pair(rows.append,count=160,terminal=True)
    for _ in range(160):
        assert lines.get(timeout=5)==b'written'
        assert lines.get(timeout=5)==b'ack'
    assert lines.get(timeout=3)==b'done'
    assert collector.terminal.wait(3)
    assert [r['sequence'] for r in rows]==list(range(1,161))
    assert not collector.errors and collector.lost_events==0


@pytest.mark.parametrize('failure',['identity','callback'])
def test_invalid_or_unconsumed_frame_never_acknowledged(audit_pair,failure):
    rows=[]
    def callback(row):
        if failure=='callback':raise RuntimeError('test consumer unavailable')
        rows.append(row)
    collector,lines=audit_pair(callback,wrong_pid=1 if failure=='identity' else 0)
    assert lines.get(timeout=3)==b'written'
    assert lines.get(timeout=3)==b'no-ack' and lines.get(timeout=3)==b'done'
    assert rows==[] and collector.errors
    assert not collector.ready.is_set() and not collector.terminal.is_set()


NATIVE_CLIENT=r'''
import ctypes as c,sys
from ctypes import wintypes as w
k=c.WinDLL('kernel32',use_last_error=True)
k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
k.ReadFile.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p];k.CloseHandle.argtypes=[w.HANDLE]
print('ready',flush=True)
for command in sys.stdin:
    if command.strip()=='quit':break
    path,count=command.strip().rsplit('|',1)
    for _ in range(int(count)):
        h=k.CreateFileW(path,0x80000000,1,None,3,0,None)
        assert h!=w.HANDLE(-1).value
        buf=c.create_string_buffer(4096);n=w.DWORD()
        assert k.ReadFile(h,buf,len(buf),c.byref(n),None) and n.value==4096
        assert k.CloseHandle(h)
    print('done',flush=True)
'''


@pytest.mark.parametrize('mode',['stress','missing_ack','wrong_ack'])
def test_injected_worker_receipt_and_bounded_failure(tmp_path,mode):
    """Actual scoped I/O using the separate ACK build, never an AI-client claim."""
    if sys.platform!='win32':pytest.skip('Windows Native injection')
    build=Path(__file__).resolve().parents[1]/'build/flow-linkage'
    if not (build/'native-build.json').is_file():
        pytest.skip('Build Native ACK target: uv run python scripts/build_flow_native.py --output build/flow-linkage')
    if json.loads((build/'native-build.json').read_bytes()).get('audit_transport')!='FIO1-ACK1':
        pytest.fail('The separate flow-linkage build must declare FIO1-ACK1')
    from transpect_trace.observe.windows import identity
    source=tmp_path/'synthetic-source';source.write_bytes(b'x'*4096)
    process=subprocess.Popen([getattr(sys,'_base_executable',sys.executable),'-I','-c',NATIVE_CLIENT],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    collector=None;rows=[]
    try:
        assert process.stdout.readline().strip()==b'ready'
        collector=NativeIOCollector(identity(process.pid),build/'ttrace-flow-io.dll',build/'native-build.json',
            lambda row:rows.append({key:value for key,value in row.items() if key!='data'}),
            scopes=[{'role':'source','path':str(source)}])
        collector.start()
        if mode!='stress':
            original=collector.k.WriteFile;faults=[]
            def write(handle,data,size,written,overlapped):
                if size==1 and data==b'\x06' and not faults:
                    faults.append(True)
                    if mode=='missing_ack':
                        c.cast(written,c.POINTER(w.DWORD))[0]=1
                        return 1
                    return original(handle,b'\x15',size,written,overlapped)
                return original(handle,data,size,written,overlapped)
            collector.k.WriteFile=write
        started=time.monotonic()
        iterations=24 if mode=='stress' else 1
        process.stdin.write((str(source)+'|'+str(iterations)+'\n').encode());process.stdin.flush()
        assert process.stdout.readline().strip()==b'done'
        application_elapsed=time.monotonic()-started
        deadline=time.monotonic()+8
        while len(rows)<1+iterations*3 and time.monotonic()<deadline:time.sleep(.02)
        collector.close();health=collector.status()
        assert health['audit_transport']=='FIO1-ACK1' and health['can_enforce'] is False
        assert [r['sequence'] for r in rows]==list(range(1,len(rows)+1))
        if mode=='stress':
            assert len(rows)==2+iterations*3 and health['terminal_health']
            assert health['lost_events']==0 and not health['errors']
        else:
            assert health['lost_events']>=1 and health['state']=='degraded'
            assert not health['terminal_health']
            # The 2-second worker receipt deadline must not block application I/O.
            assert application_elapsed<1
    finally:
        if collector and not collector._closed:collector.close()
        if process.poll() is None:
            process.stdin.write(b'quit\n');process.stdin.flush();process.wait(timeout=5)
