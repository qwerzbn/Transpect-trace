"""Explicit-PID native injection. Disk images and TLS configuration are untouched."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess

from .baseline import inspect_binary


class ModuleEntry(c.Structure):
    _fields_=[("size",w.DWORD),("module_id",w.DWORD),("pid",w.DWORD),("global_usage",w.DWORD),
              ("process_usage",w.DWORD),("base",c.c_void_p),("bytes",w.DWORD),("module",w.HANDLE),
              ("name",w.WCHAR*256),("path",w.WCHAR*260)]


def api():
    if os.name!="nt" or c.sizeof(c.c_void_p)!=8:
        raise RuntimeError("Native guard requires Windows x64")
    k=c.WinDLL("kernel32",use_last_error=True)
    signatures={
        "OpenProcess":([w.DWORD,w.BOOL,w.DWORD],w.HANDLE),
        "CloseHandle":([w.HANDLE],w.BOOL),
        "LocalFree":([c.c_void_p],c.c_void_p),
        "GetModuleHandleW":([w.LPCWSTR],w.HMODULE),
        "OpenEventW":([w.DWORD,w.BOOL,w.LPCWSTR],w.HANDLE),
        "GetProcAddress":([w.HMODULE,c.c_char_p],c.c_void_p),
        "GetModuleHandleExW":([w.DWORD,w.LPCWSTR,c.POINTER(w.HMODULE)],w.BOOL),
        "GetModuleFileNameW":([w.HMODULE,w.LPWSTR,w.DWORD],w.DWORD),
        "CreateToolhelp32Snapshot":([w.DWORD,w.DWORD],w.HANDLE),
        "Module32FirstW":([w.HANDLE,c.POINTER(ModuleEntry)],w.BOOL),
        "Module32NextW":([w.HANDLE,c.POINTER(ModuleEntry)],w.BOOL),
        "VirtualAllocEx":([w.HANDLE,c.c_void_p,c.c_size_t,w.DWORD,w.DWORD],c.c_void_p),
        "VirtualFreeEx":([w.HANDLE,c.c_void_p,c.c_size_t,w.DWORD],w.BOOL),
        "WriteProcessMemory":([w.HANDLE,c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)],w.BOOL),
        "CreateRemoteThread":([w.HANDLE,c.c_void_p,c.c_size_t,c.c_void_p,c.c_void_p,w.DWORD,c.c_void_p],w.HANDLE),
        "WaitForSingleObject":([w.HANDLE,w.DWORD],w.DWORD),
        "GetProcessTimes":([w.HANDLE,c.POINTER(w.FILETIME),c.POINTER(w.FILETIME),c.POINTER(w.FILETIME),c.POINTER(w.FILETIME)],w.BOOL),
        "QueryFullProcessImageNameW":([w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)],w.BOOL),
    }
    for name,(args,result) in signatures.items():
        fn=getattr(k,name);fn.argtypes=args;fn.restype=result
    return k


def cli_mode(arguments:list[str]) -> str:
    values={"-c","--config","-m","--model","-p","--profile","-C","--cd","--add-dir","--enable","--disable",
            '-s','--sandbox','-a','--ask-for-approval','--image','-i'}
    skip=False;command=None
    for index,token in enumerate(arguments[1:],1):
        if skip:skip=False;continue
        if token in values:skip=True;continue
        if token=="--":
            if index+1<len(arguments):command='positional_after_separator'
            break
        if token.startswith("-"):continue
        command=token;break
    if command=="exec":return "exec"
    if command is None and "--no-daemon" in arguments:return "tui_no_daemon"
    return "unsupported"


def command_arguments(command_line:str) -> list[str]:
    shell=c.WinDLL("shell32",use_last_error=True)
    shell.CommandLineToArgvW.argtypes=[w.LPCWSTR,c.POINTER(c.c_int)]
    shell.CommandLineToArgvW.restype=c.POINTER(w.LPWSTR)
    count=c.c_int();pointer=shell.CommandLineToArgvW(command_line,c.byref(count))
    if not pointer:raise c.WinError(c.get_last_error())
    try:return [pointer[i] for i in range(count.value)]
    finally:api().LocalFree(pointer)


def process_identity(pid:int,*,launched_cli:bool=False) -> dict:
    if pid==os.getpid():raise ValueError("Cannot instrument the guard controller")
    # Resolve scope before injection. Do not persist the command line or prompt.
    command=f"Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}' | Select-Object ExecutablePath,CommandLine | ConvertTo-Json -Compress"
    result=subprocess.run(["powershell","-NoProfile","-Command",command],stdin=subprocess.DEVNULL,
                          capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=15)
    row=json.loads(result.stdout or "null")
    command_line=(row or {}).get("CommandLine") or ""
    if not command_line and not launched_cli:raise ValueError("Cannot establish CLI scope for existing process")
    mode=cli_mode(command_arguments(command_line)) if command_line else "exec" if launched_cli else "unsupported"
    if mode=="unsupported":
        raise ValueError("Only exec or --no-daemon TUI is verified; desktop, daemon and app-server processes are out of scope")
    k=api();handle=k.OpenProcess(0x1000,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    times=[w.FILETIME() for _ in range(4)]
    image=c.create_unicode_buffer(32768);size=w.DWORD(len(image))
    try:
        if not k.QueryFullProcessImageNameW(handle,0,image,c.byref(size)):raise c.WinError(c.get_last_error())
        if not k.GetProcessTimes(handle,*(c.byref(t) for t in times)):raise c.WinError(c.get_last_error())
    finally:k.CloseHandle(handle)
    created=times[0].dwLowDateTime+(times[0].dwHighDateTime<<32)
    baseline=inspect_binary(Path(image.value))
    if not baseline["supported"]:raise ValueError("Target does not match fixed official Codex baseline")
    return {"pid":pid,"creation_filetime":created,"guard_session_id":f"{pid}-{created}","baseline":baseline,"cli_mode":mode}


def inject(pid:int,dll:Path,expected_identity:dict|None=None,*,launched_cli:bool=False):
    identity=process_identity(pid,launched_cli=launched_cli)
    if expected_identity and identity["creation_filetime"]!=expected_identity["creation_filetime"]:
        raise ValueError("PID was reused before injection")
    k=api();handle=k.OpenProcess(0x2|0x8|0x10|0x20|0x400|0x100000,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    allocation=None;thread=None;completed=False
    try:
        local=k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"),b"LoadLibraryW")
        owner=w.HMODULE()
        if not k.GetModuleHandleExW(6,c.cast(local,w.LPCWSTR),c.byref(owner)):raise c.WinError(c.get_last_error())
        owner_path=c.create_unicode_buffer(32768);k.GetModuleFileNameW(owner,owner_path,len(owner_path))
        snapshot=k.CreateToolhelp32Snapshot(0x8|0x10,pid)
        remote_base=None;resident=False
        try:
            entry=ModuleEntry();entry.size=c.sizeof(entry)
            ok=k.Module32FirstW(snapshot,c.byref(entry))
            while ok:
                if entry.name.lower()==Path(owner_path.value).name.lower():remote_base=entry.base
                if Path(entry.path).resolve()==Path(identity["baseline"]["path"]).resolve():
                    identity["module_base"]=hex(entry.base)
                if Path(entry.path).resolve()==dll.resolve():resident=True
                ok=k.Module32NextW(snapshot,c.byref(entry))
        finally:k.CloseHandle(snapshot)
        if remote_base is None:raise RuntimeError("Remote loader module not found")
        if resident:raise RuntimeError("Native guard already resident; do not install a second controller on this PID")
        loader=remote_base+local-owner.value
        data=(str(dll.resolve())+"\0").encode("utf-16-le")
        allocation=k.VirtualAllocEx(handle,None,len(data),0x3000,4)
        if not allocation:raise c.WinError(c.get_last_error())
        written=c.c_size_t()
        if not k.WriteProcessMemory(handle,allocation,data,len(data),c.byref(written)) or written.value!=len(data):
            raise c.WinError(c.get_last_error())
        thread=k.CreateRemoteThread(handle,None,0,loader,allocation,0,None)
        if not thread:raise c.WinError(c.get_last_error())
        if k.WaitForSingleObject(thread,15000)!=0:raise TimeoutError("Native loader did not complete")
        completed=True
    finally:
        if thread:k.CloseHandle(thread)
        if allocation and (thread is None or completed):k.VirtualFreeEx(handle,allocation,0,0x8000)
        k.CloseHandle(handle)
    return identity


def resume(pid:int):
    k=api();handle=k.OpenProcess(0x800,False,pid)
    if not handle:raise c.WinError(c.get_last_error())
    try:
        n=c.WinDLL("ntdll");n.NtResumeProcess.argtypes=[w.HANDLE];n.NtResumeProcess.restype=c.c_long
        if n.NtResumeProcess(handle)!=0:raise RuntimeError("Could not resume guarded process")
    finally:k.CloseHandle(handle)


def wait_ready(identity:dict,timeout:float=15) -> bool:
    import time
    k=api();deadline=time.monotonic()+timeout
    name="Local\\ttrace-guard-ready-"+identity["guard_session_id"]
    while time.monotonic()<deadline:
        handle=k.OpenEventW(0x100000,False,name)
        if handle:
            try:return k.WaitForSingleObject(handle,1000)==0
            finally:k.CloseHandle(handle)
        time.sleep(0.05)
    return False
