"""Authorized HTTPX 0.28.1 startup bridge; Native code makes the gate decision.

Restored from the original working copy, SHA-256 before this extension:
91d0df64a5bedeb0b7fb95a4ab139d8d5fe61a67bc09bb28b909d83867b24fce.
Only standard HTTPX transports in this controlled process are supported.
``outbound-json`` additionally admits bounded raw JSON file bodies, never
multipart, arbitrary uploads, hostile monkeypatches or sibling processes.
"""
from __future__ import annotations
import asyncio,base64,hashlib,importlib.util,json,os,sys
from pathlib import Path
from uuid import uuid4
from transpect_trace.observe.windows import identity,digest
from .models import SemanticCaptureEvent

def _load_native(dll):
    spec=importlib.util.spec_from_file_location('_ttrace_native_gate',dll)
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    return native


def install(dll,server_pid,run_id,manifest,*,mode='llm'):
    if mode not in {'llm','outbound-json'}:raise ValueError('unsupported HTTPX gate mode')
    import httpx
    if httpx.__version__!='0.28.1':raise RuntimeError('unsupported HTTPX version')
    if getattr(httpx.HTTPTransport,'_ttrace_owner',None):raise RuntimeError('HTTPX gate owner already installed')
    dll=Path(dll).resolve();build=json.loads(Path(manifest).read_text(encoding='utf-8'))
    if build.get('schema_version')!='transpect.protect.native-build/1.0':raise ValueError('Native manifest schema mismatch')
    if digest(dll)!=build['artifacts'].get(dll.name):raise ValueError('Native build identity mismatch')
    subject=identity(os.getpid())
    for path,wanted in build['runtime_files'].items():
        if digest(path)!=wanted:raise ValueError('CPython runtime identity mismatch')
    if subject['image_sha256'] not in build['runtime_files'].values():raise ValueError('unregistered interpreter')
    if sys.version_info[:2]!=(3,12):raise ValueError('unsupported CPython ABI')
    native=_load_native(dll)
    native.configure(server_pid)
    original_sync=httpx.HTTPTransport.handle_request;original_async=httpx.AsyncHTTPTransport.handle_async_request
    adapter='python-httpx-outbound-native/1' if mode=='outbound-json' else 'python-httpx-native/1'
    limit=1024*1024 if mode=='outbound-json' else 16*1024*1024

    def bounded(parts):
        total=0;chunks=[]
        for part in parts:
            if not isinstance(part,(bytes,bytearray,memoryview)):raise PermissionError('PROTECT_STREAM_TYPE_UNSUPPORTED')
            total+=len(part)
            if total>limit:raise PermissionError('PROTECT_BODY_LIMIT')
            chunks.append(bytes(part))
        return b''.join(chunks)

    def envelope(request,raw):
        if len(raw)>limit:raise PermissionError('PROTECT_BODY_LIMIT')
        encoding=request.headers.get('content-encoding','identity').strip().lower()
        if encoding not in {'identity','gzip','deflate','zstd'}:raise PermissionError('PROTECT_ENCODING_UNSUPPORTED')
        if request.headers.get('content-type','').split(';')[0].strip().lower()!='application/json':raise PermissionError('PROTECT_CONTENT_TYPE_UNSUPPORTED')
        path=request.url.path.rstrip('/');route='/chat/completions' if path.endswith('/chat/completions') else '/responses' if path.endswith('/responses') else 'unknown'
        if mode=='outbound-json':
            if request.method not in {'POST','PUT'}:raise PermissionError('PROTECT_METHOD_UNSUPPORTED')
            if encoding not in {'','identity'}:raise PermissionError('PROTECT_ENCODING_UNSUPPORTED')
            try:json.loads(raw.decode('utf-8'))
            except (ValueError,UnicodeError,RecursionError):raise PermissionError('PROTECT_JSON_UNINSPECTABLE') from None
            route='unknown';encoding='identity'
        event=SemanticCaptureEvent(run_id=run_id,adapter_id=adapter,application='python-outbound' if mode=='outbound-json' else 'python-api',channel='api',
            pid=subject['pid'],creation_filetime=subject['creation_filetime'],image_sha256=subject['image_sha256'],protocol='httpx',
            destination_host=request.url.host,api_path=route,method=request.method,completeness='complete',
            content_encoding=encoding,encoding_state='identity' if encoding=='identity' else 'compressed',
            body_sha256=hashlib.sha256(raw).hexdigest(),body_bytes=len(raw),body=raw,gate_owner=adapter)
        wire={'schema_version':'transpect.protect.request/1.0','event':event.model_dump(),'body_b64':base64.b64encode(raw).decode('ascii')}
        return event.attempt_id,json.dumps(wire,separators=(',',':')).encode()

    def prepared(request,raw):
        # No code can append to the inspected stream after this snapshot.
        headers=request.headers.copy();headers.pop('transfer-encoding',None);headers['Content-Length']=str(len(raw))
        return httpx.Request(request.method,request.url,headers=headers,content=raw,extensions=request.extensions.copy())

    def sync(self,request):
        raw=bounded(request.stream);attempt,payload=envelope(request,raw);snapshot=prepared(request,raw)
        native.authorize(payload,attempt)
        return original_sync(self,snapshot)

    async def async_(self,request):
        total=0;chunks=[]
        async for part in request.stream:
            if not isinstance(part,(bytes,bytearray,memoryview)):raise PermissionError('PROTECT_STREAM_TYPE_UNSUPPORTED')
            total+=len(part)
            if total>limit:raise PermissionError('PROTECT_BODY_LIMIT')
            chunks.append(bytes(part))
        raw=b''.join(chunks);attempt,payload=envelope(request,raw);snapshot=prepared(request,raw)
        # Native IPC has its own deadline; cancellation cannot delegate sending.
        await asyncio.to_thread(native.authorize,payload,attempt)
        return await original_async(self,snapshot)

    httpx.HTTPTransport.handle_request=sync;httpx.AsyncHTTPTransport.handle_async_request=async_
    httpx.HTTPTransport._ttrace_owner=adapter;httpx.AsyncHTTPTransport._ttrace_owner=adapter
    return {'observation_ready':True,'gate_ready':True,'adapter_id':adapter,'mode':mode,
            'scope':'standard HTTPX transports; controlled startup only; JSON <=1MiB' if mode=='outbound-json' else 'standard HTTPX transports; controlled startup only'}
