"""Explicit-process Windows observation, with independently pinned profiles."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
from typing import Literal
from pydantic import Field
from .models import Record
from transpect_trace.guard.native import api,ModuleEntry

# Observation only. The extension package has identical .text/.rdata to the
# original CLI, but a different complete-file identity. Guard v1 is unchanged.
SEMANTIC_IMAGES={
    'd13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec',
    'f5521b058ca08e249afd3b25b4681e81100181d92e73aa6b94bb8e75c2aa487b',
}


def identity(pid):
    k=api();handle=k.OpenProcess(0x1000|0x100000,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    try:
        if k.WaitForSingleObject(handle,0)==0:raise ValueError("target exited")
        image=c.create_unicode_buffer(32768);length=w.DWORD(len(image));times=[w.FILETIME() for _ in range(4)]
        if not k.QueryFullProcessImageNameW(handle,0,image,c.byref(length)) or not k.GetProcessTimes(handle,*(c.byref(t) for t in times)):
            raise c.WinError(c.get_last_error())
        path=Path(image.value);birth=times[0].dwLowDateTime+(times[0].dwHighDateTime<<32)
        with path.open('rb') as image_file:
            head=image_file.read(64);pe=struct.unpack_from('<I',head,60)[0];image_file.seek(pe);coff=image_file.read(6)
        if coff[:4]!=b'PE\0\0' or struct.unpack_from('<H',coff,4)[0]!=0x8664:
            raise ValueError('observation requires a Windows x64 target')
        return {"pid":pid,"creation_filetime":birth,"image_path":str(path),"image_sha256":digest(path)}
    finally:k.CloseHandle(handle)


def digest(path):
    with Path(path).open("rb") as file:return hashlib.file_digest(file,"sha256").hexdigest()


def file_version(path):
    version=c.WinDLL('version',use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes=[w.LPCWSTR,c.c_void_p];version.GetFileVersionInfoSizeW.restype=w.DWORD
    version.GetFileVersionInfoW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p]
    version.VerQueryValueW.argtypes=[c.c_void_p,w.LPCWSTR,c.POINTER(c.c_void_p),c.POINTER(w.UINT)]
    size=version.GetFileVersionInfoSizeW(str(path),None)
    if not size:return None
    buffer=c.create_string_buffer(size);pointer=c.c_void_p();length=w.UINT()
    if not version.GetFileVersionInfoW(str(path),0,size,buffer) or not version.VerQueryValueW(buffer,'\\',c.byref(pointer),c.byref(length)):return None
    fixed=c.cast(pointer,c.POINTER(w.DWORD));ms,ls=fixed[2],fixed[3]
    return f'{ms>>16}.{ms&65535}.{ls>>16}.{ls&65535}'


def modules(pid):
    k=api();snapshot=k.CreateToolhelp32Snapshot(0x8|0x10,pid);out=[]
    if snapshot==w.HANDLE(-1).value:raise c.WinError(c.get_last_error())
    try:
        entry=ModuleEntry();entry.size=c.sizeof(entry);ok=k.Module32FirstW(snapshot,c.byref(entry))
        while ok:
            out.append({"path":entry.path,"base":entry.base,"size":entry.bytes})
            ok=k.Module32NextW(snapshot,c.byref(entry))
    finally:k.CloseHandle(snapshot)
    return out


def exports(path):
    data=Path(path).read_bytes();pe=struct.unpack_from("<I",data,60)[0];opt=pe+24
    if data[pe:pe+4]!=b"PE\0\0" or struct.unpack_from("<H",data,pe+4)[0]!=0x8664:raise ValueError("requires Windows x64 PE")
    count=struct.unpack_from("<H",data,pe+6)[0];size=struct.unpack_from("<H",data,pe+20)[0]
    sections=[struct.unpack_from("<IIII",data,opt+size+i*40+8) for i in range(count)]
    def off(rva):
        for virtual_size,base,raw_size,raw in sections:
            if base<=rva<base+raw_size:return raw+rva-base
        raise ValueError("PE RVA outside file")
    rva,table_size=struct.unpack_from("<II",data,opt+112)
    if not rva:return {}
    table=off(rva);n=struct.unpack_from("<I",data,table+24)[0]
    if n>100000:raise ValueError("export count limit")
    functions,names,ordinals=struct.unpack_from("<III",data,table+28);result={}
    for i in range(n):
        nameoff=off(struct.unpack_from("<I",data,off(names)+i*4)[0]);end=data.find(b"\0",nameoff,nameoff+1024)
        name=data[nameoff:end].decode("ascii",errors="replace")
        ordinal=struct.unpack_from("<H",data,off(ordinals)+i*2)[0]
        address=struct.unpack_from("<I",data,off(functions)+ordinal*4)[0]
        if not rva<=address<rva+table_size:result[name]=address
    return result


class Profile(Record):
    schema_version: Literal["transpect.observe.profile/1.0"] = "transpect.observe.profile/1.0"
    image_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    application: str
    mode: Literal['openssl','schannel','codex-json']
    module_path: str | None = None
    module_sha256: str | None = None
    rvas: dict[str,int] = Field(default_factory=dict)
    can_enforce: Literal[False] = False

    def configuration(self,subject):
        if self.can_enforce or subject["image_sha256"]!=self.image_sha256:raise ValueError("profile identity or observation-only constraint mismatch")
        modes={"openssl":1,"schannel":2,"codex-json":3}
        if self.mode not in modes:raise ValueError("unsupported observation mode")
        addresses=[0]*10
        if self.mode!="schannel":
            match=next((m for m in modules(subject["pid"]) if Path(m["path"]).resolve()==Path(self.module_path or "").resolve()),None)
            if match is None or digest(match["path"])!=self.module_sha256:raise ValueError("loaded module hash mismatch")
            names=["SSL_write","SSL_write_ex","SSL_read","SSL_read_ex","SSL_free"] if self.mode=="openssl" else ["http_json","wss_json"]
            if self.mode=="openssl":
                available=exports(match["path"])
                if any(self.rvas.get(name,0)!=available.get(name,0) for name in names):raise ValueError("OpenSSL export profile mismatch")
            else:
                if self.module_sha256 not in SEMANTIC_IMAGES or self.rvas!={"http_json":0x09d96b10,"wss_json":0x03d6daa0}:
                    raise ValueError("unverified semantic observer profile")
            for i,name in enumerate(names):
                rva=self.rvas.get(name,0)
                if not 0<=rva<match["size"]:raise ValueError("profile RVA outside module")
                addresses[i]=match["base"]+rva if rva else 0
        return struct.pack("<4sIQ10Q",b"TTC1",modes[self.mode],subject["creation_filetime"],*addresses)


def discover_profile(pid,application="unknown",mode=None):
    subject=identity(pid);loaded=modules(pid)
    if mode=="schannel":return subject,Profile(image_sha256=subject["image_sha256"],application=application,mode="schannel")
    candidates=[]
    for module in loaded:
        if "ssl" not in Path(module["path"]).name.lower():continue
        symbols=exports(module["path"])
        if "SSL_free" in symbols and ("SSL_write" in symbols or "SSL_write_ex" in symbols):
            candidates.append((module,symbols))
    if len(candidates)==1:
        module,symbols=candidates[0]
        names=["SSL_write","SSL_write_ex","SSL_read","SSL_read_ex","SSL_free"]
        return subject,Profile(image_sha256=subject["image_sha256"],application=application,mode="openssl",
            module_path=module["path"],module_sha256=digest(module["path"]),rvas={n:symbols.get(n,0) for n in names})
    if subject["image_sha256"] in SEMANTIC_IMAGES:
        return subject,Profile(image_sha256=subject["image_sha256"],application=application,mode="codex-json",
            module_path=subject["image_path"],module_sha256=subject["image_sha256"],rvas={"http_json":0x09d96b10,"wss_json":0x03d6daa0})
    raise ValueError("no verified TLS exports or semantic profile; capture unsupported (not evidence of no egress)")


def inject(pid,dll,subject):
    if pid==__import__('os').getpid():raise ValueError("refuse controller instrumentation")
    current=identity(pid)
    if current["creation_filetime"]!=subject["creation_filetime"] or current["image_sha256"]!=subject["image_sha256"]:
        raise ValueError("target identity changed")
    k=api();loaded=modules(pid)
    if any(Path(m["path"]).name.lower() in {"ttrace-observe.dll","schannel_hook.dll"} for m in loaded):
        raise ValueError("observer hook owner already resident")
    local=k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"),b"LoadLibraryW");owner=w.HMODULE()
    if not k.GetModuleHandleExW(6,c.cast(local,w.LPCWSTR),c.byref(owner)):raise c.WinError(c.get_last_error())
    path=c.create_unicode_buffer(32768);k.GetModuleFileNameW(owner,path,len(path))
    remote=next(m for m in loaded if Path(m["path"]).name.lower()==Path(path.value).name.lower())
    loader=remote["base"]+local-owner.value
    handle=k.OpenProcess(0x2|0x8|0x10|0x20|0x400|0x100000,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    allocation=None;thread=None;completed=False
    try:
        data=(str(dll.resolve())+"\0").encode("utf-16-le");allocation=k.VirtualAllocEx(handle,None,len(data),0x3000,4)
        written=c.c_size_t()
        if not allocation or not k.WriteProcessMemory(handle,allocation,data,len(data),c.byref(written)) or written.value!=len(data):raise c.WinError(c.get_last_error())
        thread=k.CreateRemoteThread(handle,None,0,loader,allocation,0,None)
        if not thread:raise c.WinError(c.get_last_error())
        if k.WaitForSingleObject(thread,15000)!=0:raise TimeoutError("observer loader timed out")
        completed=True
    finally:
        if thread:k.CloseHandle(thread)
        if allocation and (not thread or completed):k.VirtualFreeEx(handle,allocation,0,0x8000)
        k.CloseHandle(handle)


def inventory():
    candidates={"python-api":Path(sys.executable),"chrome-web":Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
                "vscode":Path("D:/Microsoft VS Code/Code.exe"),"schannel-curl":Path("C:/Windows/System32/curl.exe")}
    code=shutil.which("code")
    if code:candidates["vscode"]=Path(code).parent.parent/"Code.exe"
    rows=[]
    for name,path in candidates.items():
        rows.append({"application":name,"path":str(path),"installed":path.is_file(),
                     "sha256":digest(path) if path.is_file() else None,"version":file_version(path) if path.is_file() else None,
                     "tls_backend":"requires_process_module_validation"})
    extension_root=Path.home()/".vscode/extensions"
    roots=[extension_root,Path('.external/observe-vscode-extensions')]
    extensions=[]
    for folder in roots:
        for p in folder.glob('openai.chatgpt-*'):
            if p.is_dir():
                package=json.loads((p/'package.json').read_text(encoding='utf-8'))
                extensions.append({'path':str(p.resolve()),'version':package['version'],
                                   'backends':[{'path':str(b.resolve()),'sha256':digest(b)} for b in p.rglob('codex.exe')]})
    from .ecapture import PIN
    return {"schema_version":"transpect.observe.inventory/1.0","platform":"windows-x64",
            "elevated":bool(c.windll.shell32.IsUserAnAdmin()),"clients":rows,"vscode_codex_extensions":extensions,
            "ecapture_pin":PIN,"can_enforce":False}
