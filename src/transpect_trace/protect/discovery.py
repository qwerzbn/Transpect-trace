"""Windows snapshot evidence. Command lines are used only for role selection."""
from __future__ import annotations
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import struct
import subprocess
import uuid
import socket
from transpect_trace.observe.windows import identity, modules, digest
from transpect_trace.guard.native import api


def debug_identity(path):
    """Read PE/CodeView RSDS without loading the target image."""
    with Path(path).open('rb') as f:
        header=f.read(64); pe=struct.unpack_from('<I',header,60)[0]
        f.seek(pe); head=f.read(264)
        if head[:4]!=b'PE\0\0' or struct.unpack_from('<H',head,24)[0]!=0x20b:
            raise ValueError('requires PE32+')
        count=struct.unpack_from('<H',head,6)[0]; optional=struct.unpack_from('<H',head,20)[0]
        debug_rva,debug_size=struct.unpack_from('<II',head,24+112+6*8)
        f.seek(pe+24+optional);sections=[struct.unpack('<8sIIIIIIHHI',f.read(40)) for _ in range(count)]
        offset=next((s[4]+debug_rva-s[2] for s in sections if s[2]<=debug_rva<s[2]+max(s[1],s[3])),None)
        if offset is None:return None
        f.seek(offset);entries=f.read(min(debug_size,65536))
        for pos in range(0,len(entries)-27,28):
            _,_,_,_,kind,size,_,pointer=struct.unpack_from('<IIHHIIII',entries,pos)
            if kind!=2 or not 24<=size<=4096:continue
            f.seek(pointer);data=f.read(size)
            if data[:4]!=b'RSDS':continue
            guid=uuid.UUID(bytes_le=data[4:20]);age=struct.unpack_from('<I',data,20)[0]
            name=Path(data[24:].split(b'\0')[0].decode('utf-8',errors='replace').replace('\\','/')).name
            key=guid.hex.upper()+format(age,'X')
            return {'pdb':name,'guid':str(guid),'age':age,'symbol_key':key,
                    'symbol_url':f'https://chromium-browser-symsrv.commondatastorage.googleapis.com/{name}/{key}/{name}'}
    return None


def mitigations(pid):
    k=api();k.GetProcessMitigationPolicy.argtypes=[w.HANDLE,c.c_int,c.c_void_p,c.c_size_t]
    k.GetProcessMitigationPolicy.restype=w.BOOL
    h=k.OpenProcess(0x1000,False,pid)
    if not h:raise c.WinError(c.get_last_error())
    result={}
    try:
        for name,index in {'dynamic_code':2,'extension_points':6,'cfg':7,'signature':8,'image_load':10}.items():
            flags=w.DWORD()
            result[name]={'flags':flags.value,'available':True} if k.GetProcessMitigationPolicy(h,index,c.byref(flags),4) else {'available':False,'error':c.get_last_error()}
            if result[name]['available']:result[name]['flags']=flags.value
    finally:k.CloseHandle(h)
    return result


def tcp_snapshot(subjects):
    ip=c.WinDLL('iphlpapi',use_last_error=True)
    ip.GetExtendedTcpTable.argtypes=[c.c_void_p,c.POINTER(w.ULONG),w.BOOL,w.ULONG,c.c_int,w.ULONG]
    ip.GetExtendedTcpTable.restype=w.DWORD
    rows=[]
    for family,row_size in [(2,24),(23,56)]:
        size=w.ULONG();result=ip.GetExtendedTcpTable(None,c.byref(size),False,family,5,0)
        if result not in {0,122}:continue
        buffer=c.create_string_buffer(size.value)
        if ip.GetExtendedTcpTable(buffer,c.byref(size),False,family,5,0):continue
        raw=buffer.raw;count=struct.unpack_from('<I',raw)[0]
        if 4+count*row_size>len(raw):continue
        for index in range(count):
            entry=raw[4+index*row_size:4+(index+1)*row_size]
            if family==2:
                state,_,local_port,_,remote_port,pid=struct.unpack('<6I',entry)
                local=socket.inet_ntop(socket.AF_INET,entry[4:8]);remote=socket.inet_ntop(socket.AF_INET,entry[12:16])
            else:
                local=socket.inet_ntop(socket.AF_INET6,entry[:16]);remote=socket.inet_ntop(socket.AF_INET6,entry[24:40])
                local_port=struct.unpack_from('<I',entry,20)[0];remote_port,state,pid=struct.unpack_from('<3I',entry,44)
            subject=subjects.get(pid,{}).get('identity')
            if subject:
                rows.append({'pid':pid,'creation_filetime':subject['creation_filetime'],'local_address':local,
                    'local_port':socket.ntohs(local_port&65535),'remote_address':remote,'remote_port':socket.ntohs(remote_port&65535),
                    'tcp_state':state,'method':'GetExtendedTcpTable','connection_identity':'endpoint_tuple_snapshot_only'})
    return rows

def snapshot(root_pid,*,include_modules=True,include_network=True):
    query='Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress'
    rows=json.loads(subprocess.check_output(['powershell','-NoProfile','-Command',query],encoding='utf-8',timeout=20) or '[]')
    if isinstance(rows,dict):rows=[rows]
    scope={root_pid}
    while True:
        before=len(scope);scope.update(int(r['ProcessId']) for r in rows if int(r['ParentProcessId']) in scope)
        if before==len(scope):break
    # Read identities twice to avoid attributing evidence across PID reuse.
    subjects={}
    for r in rows:
        pid=int(r['ProcessId'])
        if pid not in scope:continue
        try:
            subject=identity(pid);command=r.get('CommandLine') or ''
            role='network-service' if 'network.mojom.NetworkService' in command else 'renderer' if '--type=renderer' in command else 'extension-host' if 'extensionHost' in command else 'app-server' if 'app-server' in command else 'process'
            item={'identity':subject,'parent_pid':int(r['ParentProcessId']),'role':role,'mitigations':mitigations(pid)}
            if include_modules:
                loaded=modules(pid);relevant=[m for m in loaded if Path(m['path']).name.lower() in {'chrome.dll','python312.dll','libssl-3.dll','schannel.dll','node.dll'}]
                item['modules']=[{'path':m['path'],'sha256':digest(m['path']),'base':m['base'],'size':m['size']} for m in relevant]
                item['tls_backend_evidence']=[Path(m['path']).name for m in relevant]
            if identity(pid)!=subject:raise ValueError('identity changed during snapshot')
            subjects[pid]=item
        except (OSError,ValueError) as e:
            subjects[pid]={'pid':pid,'unavailable':type(e).__name__}
    for item in subjects.values():
        parent=subjects.get(item.get('parent_pid'),{}).get('identity')
        item['parent_identity']=parent
        item['parent_relation']='snapshot_only_not_process_start_event' if parent else 'unknown'
    network=tcp_snapshot(subjects) if include_network else []
    valid=[]
    for row in network:
        try:
            if identity(row['pid'])['creation_filetime']==row['creation_filetime']:valid.append(row)
        except (OSError,ValueError):pass
    return {'schema_version':'transpect.protect.discovery/1.0','snapshot_only':True,'processes':list(subjects.values()),
            'network_evidence':valid,'limitations':['polling_is_not_event_stream','module_presence_is_not_proof_of_TLS_use','request_to_connection_relation_unverified']}
