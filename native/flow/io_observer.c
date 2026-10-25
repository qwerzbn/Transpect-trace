/* Observation only. Synchronous, explicitly scoped Win32 I/O; never changes an
 * application result. Buffers leave the target only through its restricted pipe. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "protocol.h"
#include "../guard/third_party/minhook/include/MinHook.h"

typedef HANDLE (WINAPI *OpenFn)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef HANDLE (WINAPI *PipeFn)(LPCWSTR,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,LPSECURITY_ATTRIBUTES);
typedef BOOL (WINAPI *ReadFn)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL (WINAPI *WriteFn)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL (WINAPI *CloseFn)(HANDLE);
typedef BOOL (WINAPI *ConnectFn)(HANDLE,LPOVERLAPPED);
typedef BOOL (WINAPI *DisconnectFn)(HANDLE);
static OpenFn real_open;static PipeFn real_pipe;static ReadFn real_read;static WriteFn real_write;
static CloseFn real_close;static ConnectFn real_connect;static DisconnectFn real_disconnect;
typedef struct { HANDLE handle; uint64_t generation,connection,scope,flags,volume,file_id; unsigned busy; } Track;
typedef struct Node { struct Node *next; size_t capacity; FlowHeader h; unsigned char data[]; } Node;
static Track tracks[128];static FlowConfig config;
static CRITICAL_SECTION lock;static HANDLE wake,finished;static Node *first,*last;
static size_t queued;static uint64_t generation,connection,birth,sequence;static unsigned running_ops;
static _Thread_local int internal;
static wchar_t audit_name[160];
__declspec(dllexport) volatile LONG flow_io_status;
__declspec(dllexport) volatile LONG flow_io_dropped;
__declspec(dllexport) volatile LONG flow_io_open_calls;
__declspec(dllexport) volatile LONG flow_io_scope_hits;
static volatile LONG active,stopping;

static uint64_t creation(DWORD pid){
    HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);FILETIME a,b,c,d;uint64_t result=0;
    if(p){if(GetProcessTimes(p,&a,&b,&c,&d))result=((uint64_t)a.dwHighDateTime<<32)|a.dwLowDateTime;CloseHandle(p);}return result;
}
static FlowHeader head(unsigned kind){
    FlowHeader h={0};memcpy(h.magic,"FIO1",4);h.kind=kind;h.pid=GetCurrentProcessId();h.tid=GetCurrentThreadId();h.birth=birth;
    LARGE_INTEGER t;QueryPerformanceCounter(&t);h.qpc=t.QuadPart;h.completed_qpc=h.qpc;h.offset=UINT64_MAX;return h;
}
static void loss(void){InterlockedIncrement(&flow_io_dropped);}
static void completed(FlowHeader*h){LARGE_INTEGER t;QueryPerformanceCounter(&t);h->completed_qpc=t.QuadPart;}
static void emit(FlowHeader h,const void *data,size_t size){
    if(!h.completed_qpc)completed(&h);
    if(size>FLOW_LIMIT){h.flags|=F_DATA_GAP;h.reason=R_SIZE;size=0;}
    EnterCriticalSection(&lock);h.dropped=flow_io_dropped;
    if(queued+sizeof(Node)+size>FLOW_QUEUE_LIMIT){loss();LeaveCriticalSection(&lock);return;}
    queued+=sizeof(Node)+size;LeaveCriticalSection(&lock);
    Node *n=HeapAlloc(GetProcessHeap(),0,sizeof(Node)+size);
    if(!n){EnterCriticalSection(&lock);queued-=sizeof(Node)+size;LeaveCriticalSection(&lock);loss();return;}
    n->next=NULL;n->capacity=size;n->h=h;n->h.length=size;
    if(size){SIZE_T done=0;if(!ReadProcessMemory(GetCurrentProcess(),data,n->data,size,&done)||done!=size){SecureZeroMemory(n->data,size);n->h.length=0;n->h.flags|=F_DATA_GAP;n->h.reason=R_SNAPSHOT;}}
    /* Queue accounting includes reserved bytes even when a snapshot failed. */
    EnterCriticalSection(&lock);n->h.sequence=++sequence;
    if(last)last->next=n;else first=n;last=n;LeaveCriticalSection(&lock);SetEvent(wake);
}
static BOOL write_all(HANDLE p,const void *data,DWORD size){
    DWORD done=0;while(done<size){DWORD n=0;if(!WriteFile(p,(const char*)data+done,size-done,&n,NULL)||!n)return FALSE;done+=n;}return TRUE;
}
/* Worker-only, bounded asynchronous output. Return -1 if cancellation could
 * not complete: its node/OVERLAPPED storage is retained until process exit,
 * never freed while Windows may still reference it. */
static int write_bounded(HANDLE p,const void*data,DWORD size){
    DWORD offset=0;
    while(offset<size){
        OVERLAPPED*ov=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*ov));
        if(!ov)return 0;ov->hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
        if(!ov->hEvent){HeapFree(GetProcessHeap(),0,ov);return 0;}
        DWORD done=0;BOOL ok=WriteFile(p,(const char*)data+offset,size-offset,&done,ov);
        if(!ok&&GetLastError()==ERROR_IO_PENDING){
            DWORD wait=WaitForSingleObject(ov->hEvent,2000);
            if(wait!=WAIT_OBJECT_0){CancelIoEx(p,ov);
                if(WaitForSingleObject(ov->hEvent,1000)!=WAIT_OBJECT_0)return -1;
                ok=FALSE;
            }else ok=GetOverlappedResult(p,ov,&done,FALSE);
        }
        CloseHandle(ov->hEvent);HeapFree(GetProcessHeap(),0,ov);
        if(!ok||!done)return 0;offset+=done;
    }
    return 1;
}
/* FIO1-ACK1: a completed WriteFile only proves that Windows buffered bytes.
 * Keep the pipe connected until the identity-checked collector has consumed
 * the complete frame and its callback returned. Without this receipt a quick
 * close can make ConnectNamedPipe fail with ERROR_NO_DATA and discard a frame.
 * This wait is worker-only, not on an application I/O thread. */
static int acknowledge_bounded(HANDLE p){
    typedef struct { OVERLAPPED ov; unsigned char ack; } Receipt;
    Receipt*r=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*r));
    if(!r)return 0;r->ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!r->ov.hEvent){HeapFree(GetProcessHeap(),0,r);return 0;}
    DWORD done=0;BOOL ok=ReadFile(p,&r->ack,1,&done,&r->ov);
    if(!ok&&GetLastError()==ERROR_IO_PENDING){
        DWORD wait=WaitForSingleObject(r->ov.hEvent,2000);
        if(wait!=WAIT_OBJECT_0){CancelIoEx(p,&r->ov);
            /* Retain both OVERLAPPED and its byte if cancellation is pending. */
            if(WaitForSingleObject(r->ov.hEvent,1000)!=WAIT_OBJECT_0)return -1;
            ok=FALSE;
        }else ok=GetOverlappedResult(p,&r->ov,&done,FALSE);
    }
    int accepted=ok&&done==1&&r->ack==6;
    CloseHandle(r->ov.hEvent);HeapFree(GetProcessHeap(),0,r);return accepted;
}
static DWORD WINAPI worker(void *unused){
    (void)unused;internal=1;
    for(;;){WaitForSingleObject(wake,1000);
        for(;;){EnterCriticalSection(&lock);Node*n=first;if(n){first=n->next;if(!first)last=NULL;}LeaveCriticalSection(&lock);if(!n)break;
            HANDLE p=INVALID_HANDLE_VALUE;ULONGLONG deadline=GetTickCount64()+1500;
            do{p=CreateFileW(audit_name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
                if(p!=INVALID_HANDLE_VALUE)break;DWORD e=GetLastError();if(e!=ERROR_PIPE_BUSY&&e!=ERROR_FILE_NOT_FOUND)break;WaitNamedPipeW(audit_name,20);Sleep(1);
            }while(GetTickCount64()<deadline);
            n->h.dropped=flow_io_dropped;
            int sent=p!=INVALID_HANDLE_VALUE?write_bounded(p,&n->h,sizeof(n->h)):0;
            if(sent==1)sent=write_bounded(p,n->data,(DWORD)n->h.length);
            if(sent==1)sent=acknowledge_bounded(p);
            if(p!=INVALID_HANDLE_VALUE)CloseHandle(p);
            if(sent!=1){loss();InterlockedExchange(&active,0);flow_io_status=-10;}
            if(sent<0){SetEvent(finished);return 1;}
            int terminal=n->h.kind==F_TERMINAL;
            EnterCriticalSection(&lock);queued-=sizeof(Node)+n->capacity;LeaveCriticalSection(&lock);
            SecureZeroMemory(n->data,n->capacity);HeapFree(GetProcessHeap(),0,n);
            if(terminal){SetEvent(finished);return 0;}
        }
    }
}
static int scope_of(LPCWSTR path){
    if(!path)return -1;
    for(unsigned i=0;i<config.count;i++)if(CompareStringOrdinal(path,-1,config.paths[i],-1,TRUE)==CSTR_EQUAL)return (int)i;
    return -1;
}
static FlowHeader from_track(Track t,unsigned kind){
    FlowHeader h=head(kind);h.handle=(uintptr_t)t.handle;h.open_generation=t.generation;h.connection_generation=t.connection;
    h.scope=t.scope;h.flags=t.flags;h.volume=t.volume;h.file_id=t.file_id;
    if(t.flags&F_PIPE){ULONG pid=0;BOOL ok=(t.flags&F_SERVER)?GetNamedPipeClientProcessId(t.handle,&pid):GetNamedPipeServerProcessId(t.handle,&pid);
        if(ok){h.peer_pid=pid;h.peer_birth=creation(pid);}DWORD info=0;
        if(!GetNamedPipeInfo(t.handle,&info,NULL,NULL,NULL)||!(info&PIPE_TYPE_MESSAGE)){h.flags|=F_UNSUPPORTED;h.reason=R_PIPE_MODE;}
    }else{LARGE_INTEGER zero={0},pos;if(SetFilePointerEx(t.handle,zero,&pos,FILE_CURRENT)){h.offset=(uint64_t)pos.QuadPart;h.flags|=F_OFFSET;}}
    return h;
}
static void register_handle(HANDLE handle,int scope,DWORD attrs,int server){
    if(handle==INVALID_HANDLE_VALUE)return;
    Track t={0};t.handle=handle;t.scope=scope;
    DWORD type=GetFileType(handle);t.flags=type==FILE_TYPE_DISK?F_FILE:type==FILE_TYPE_PIPE?F_PIPE:F_UNSUPPORTED;
    if(attrs&FILE_FLAG_OVERLAPPED)t.flags|=F_OVERLAPPED|F_UNSUPPORTED;
    if(server)t.flags|=F_SERVER;
    BY_HANDLE_FILE_INFORMATION info;
    if((t.flags&F_FILE)&&GetFileInformationByHandle(handle,&info)){t.volume=info.dwVolumeSerialNumber;t.file_id=((uint64_t)info.nFileIndexHigh<<32)|info.nFileIndexLow;t.flags|=F_ID;}
    EnterCriticalSection(&lock);int slot=-1;for(unsigned i=0;i<128;i++)if(!tracks[i].handle){slot=i;break;}
    t.generation=++generation;if(t.flags&F_PIPE)t.connection=++connection;
    if(slot>=0)tracks[slot]=t;LeaveCriticalSection(&lock);
    FlowHeader h=from_track(t,slot<0?F_GAP:F_OPEN);h.flags|=F_SUCCESS;if(slot<0)h.reason=R_HANDLE_CAP;emit(h,NULL,0);
}
static int begin(HANDLE handle,Track*out,int *concurrent){
    int found=0;EnterCriticalSection(&lock);
    if(active)for(unsigned i=0;i<128;i++)if(tracks[i].handle==handle){*concurrent=tracks[i].busy!=0;tracks[i].busy++;*out=tracks[i];running_ops++;found=1;break;}
    LeaveCriticalSection(&lock);return found;
}
static int begin_open(void){
    EnterCriticalSection(&lock);int accepted=active!=0;if(accepted)running_ops++;LeaveCriticalSection(&lock);return accepted;
}
static void end_open(void){EnterCriticalSection(&lock);if(running_ops)running_ops--;LeaveCriticalSection(&lock);}
static void end(Track t,int remove){
    EnterCriticalSection(&lock);for(unsigned i=0;i<128;i++)if(tracks[i].handle==t.handle&&tracks[i].generation==t.generation){if(remove)memset(&tracks[i],0,sizeof(Track));else if(tracks[i].busy)tracks[i].busy--;break;}
    if(running_ops)running_ops--;LeaveCriticalSection(&lock);
}
static HANDLE WINAPI on_open(LPCWSTR path,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES sa,DWORD disposition,DWORD attrs,HANDLE template){
    InterlockedIncrement(&flow_io_open_calls);
    if(internal||!active)return real_open(path,access,share,sa,disposition,attrs,template);
    DWORD before=GetLastError();internal=1;int scope=scope_of(path);if(scope>=0)InterlockedIncrement(&flow_io_scope_hits);SetLastError(before);
    int accepted=scope>=0&&begin_open();SetLastError(before);
    HANDLE h=real_open(path,access,share,sa,disposition,attrs,template);DWORD error=GetLastError();
    if(accepted){if(h!=INVALID_HANDLE_VALUE)register_handle(h,scope,attrs,0);else{FlowHeader e=head(F_OPEN);e.scope=scope;e.error=error;emit(e,NULL,0);}end_open();}
    internal=0;SetLastError(error);return h;
}
static HANDLE WINAPI on_pipe(LPCWSTR path,DWORD mode,DWORD pm,DWORD count,DWORD out,DWORD in,DWORD timeout,LPSECURITY_ATTRIBUTES sa){
    if(internal||!active)return real_pipe(path,mode,pm,count,out,in,timeout,sa);
    DWORD before=GetLastError();internal=1;int scope=scope_of(path);SetLastError(before);
    int accepted=scope>=0&&begin_open();SetLastError(before);
    HANDLE h=real_pipe(path,mode,pm,count,out,in,timeout,sa);DWORD error=GetLastError();
    if(accepted){if(h!=INVALID_HANDLE_VALUE)register_handle(h,scope,mode,1);else{FlowHeader e=head(F_OPEN);e.scope=scope;e.error=error;emit(e,NULL,0);}end_open();}
    internal=0;SetLastError(error);return h;
}
static BOOL WINAPI on_read(HANDLE handle,LPVOID data,DWORD size,LPDWORD done,LPOVERLAPPED ov){
    if(internal||!active)return real_read(handle,data,size,done,ov);
    DWORD before=GetLastError();internal=1;Track t;int concurrent=0;
    if(!begin(handle,&t,&concurrent)){internal=0;SetLastError(before);return real_read(handle,data,size,done,ov);}
    FlowHeader h=from_track(t,F_READ);h.requested=size;SetLastError(before);
    BOOL ok=real_read(handle,data,size,done,ov);DWORD error=GetLastError();completed(&h);h.error=ok?0:error;
    if(ok)h.flags|=F_SUCCESS;if(!ok&&error==ERROR_MORE_DATA)h.flags|=F_MORE;
    if(ov||t.flags&F_OVERLAPPED){h.flags|=F_UNSUPPORTED|F_DATA_GAP;h.reason=R_ASYNC;}
    else if(concurrent){h.flags|=F_UNSUPPORTED|F_DATA_GAP;h.reason=R_CONCURRENT;}
    else if(done&&(ok||error==ERROR_MORE_DATA)){h.completed=*done;
        if(h.completed>size||h.completed>FLOW_LIMIT){h.flags|=F_DATA_GAP;h.reason=R_SIZE;}
        else{if((t.flags&F_PIPE)&&ok)h.flags|=F_MESSAGE;}}
    else if(ok){h.flags|=F_DATA_GAP;h.reason=R_SNAPSHOT;}
    emit(h,h.flags&F_DATA_GAP?NULL:data,h.flags&F_DATA_GAP?0:(size_t)h.completed);end(t,0);internal=0;SetLastError(error);return ok;
}
static BOOL WINAPI on_write(HANDLE handle,LPCVOID data,DWORD size,LPDWORD done,LPOVERLAPPED ov){
    if(internal||!active)return real_write(handle,data,size,done,ov);
    DWORD before=GetLastError();internal=1;Track t;int concurrent=0;
    if(!begin(handle,&t,&concurrent)){internal=0;SetLastError(before);return real_write(handle,data,size,done,ov);}
    FlowHeader h=from_track(t,F_WRITE);h.requested=size;unsigned char*copy=NULL;
    if(ov||t.flags&F_OVERLAPPED){h.flags|=F_UNSUPPORTED|F_DATA_GAP;h.reason=R_ASYNC;}
    else if(concurrent){h.flags|=F_UNSUPPORTED|F_DATA_GAP;h.reason=R_CONCURRENT;}
    else if(size>FLOW_LIMIT){h.flags|=F_DATA_GAP;h.reason=R_SIZE;}
    else if(size){copy=HeapAlloc(GetProcessHeap(),0,size);SIZE_T n=0;if(!copy||!ReadProcessMemory(GetCurrentProcess(),data,copy,size,&n)||n!=size){h.flags|=F_DATA_GAP;h.reason=R_SNAPSHOT;}}
    SetLastError(before);BOOL ok=real_write(handle,data,size,done,ov);DWORD error=GetLastError();completed(&h);h.error=ok?0:error;
    if(ok)h.flags|=F_SUCCESS;
    if(!ov&&!(t.flags&F_OVERLAPPED)&&done&&ok){h.completed=*done;if(h.completed>size){h.flags|=F_DATA_GAP;h.reason=R_SIZE;}}
    else if(ok){h.flags|=F_DATA_GAP;h.reason=R_SNAPSHOT;}
    if((t.flags&F_PIPE)&&ok&&h.completed==size)h.flags|=F_MESSAGE;
    emit(h,copy,h.flags&F_DATA_GAP?0:(size_t)h.completed);
    if(copy){SecureZeroMemory(copy,size);HeapFree(GetProcessHeap(),0,copy);}end(t,0);internal=0;SetLastError(error);return ok;
}
static BOOL WINAPI on_close(HANDLE handle){
    if(internal||!active)return real_close(handle);DWORD before=GetLastError();internal=1;Track t;int concurrent=0;
    if(!begin(handle,&t,&concurrent)){internal=0;SetLastError(before);return real_close(handle);}
    FlowHeader h=from_track(t,F_CLOSE);SetLastError(before);BOOL ok=real_close(handle);DWORD error=GetLastError();completed(&h);h.error=ok?0:error;if(ok)h.flags|=F_SUCCESS;
    if(concurrent){h.flags|=F_UNSUPPORTED;h.reason=R_CONCURRENT;}emit(h,NULL,0);end(t,ok);internal=0;SetLastError(error);return ok;
}
static BOOL WINAPI on_connect(HANDLE handle,LPOVERLAPPED ov){
    if(internal||!active)return real_connect(handle,ov);DWORD before=GetLastError();internal=1;Track t;int concurrent=0;
    if(!begin(handle,&t,&concurrent)){internal=0;SetLastError(before);return real_connect(handle,ov);}
    SetLastError(before);BOOL ok=real_connect(handle,ov);DWORD error=GetLastError();FlowHeader h=from_track(t,F_CONNECT);h.error=ok?0:error;
    if(ok||error==ERROR_PIPE_CONNECTED)h.flags|=F_SUCCESS;if(ov||t.flags&F_OVERLAPPED){h.flags|=F_UNSUPPORTED;h.reason=R_ASYNC;}
    if(concurrent){h.flags|=F_UNSUPPORTED;h.reason=R_CONCURRENT;}
    emit(h,NULL,0);end(t,0);internal=0;SetLastError(error);return ok;
}
static BOOL WINAPI on_disconnect(HANDLE handle){
    if(internal||!active)return real_disconnect(handle);DWORD before=GetLastError();internal=1;Track t;int concurrent=0;
    if(!begin(handle,&t,&concurrent)){internal=0;SetLastError(before);return real_disconnect(handle);}
    FlowHeader h=from_track(t,F_DISCONNECT);SetLastError(before);BOOL ok=real_disconnect(handle);DWORD error=GetLastError();completed(&h);h.error=ok?0:error;if(ok)h.flags|=F_SUCCESS;
    if(concurrent){h.flags|=F_UNSUPPORTED;h.reason=R_CONCURRENT;}
    emit(h,NULL,0);if(ok){EnterCriticalSection(&lock);for(int i=0;i<128;i++)if(tracks[i].handle==handle&&tracks[i].generation==t.generation)tracks[i].connection=++connection;LeaveCriticalSection(&lock);}
    end(t,0);internal=0;SetLastError(error);return ok;
}
static int install(const char*name,void*fn,void**original){
    /* Kernel32 exports on this platform are import thunks. Instrument the
     * actual KernelBase implementations, never rewrite the import thunks. */
    void*p=(void*)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"),name);MEMORY_BASIC_INFORMATION m;
    if(!p||!VirtualQuery(p,&m,sizeof(m))||m.Type!=MEM_IMAGE)return 0;
    BYTE*b=p;/* Existing external detours are not ours to replace. */
    if(b[0]==0xe9||(b[0]==0xff&&b[1]==0x25))return 0;
    return MH_CreateHook(p,fn,original)==MH_OK;
}
__declspec(dllexport) DWORD WINAPI flow_io_stop(void*unused){
    (void)unused;if(InterlockedExchange(&stopping,1))return 1;internal=1;InterlockedExchange(&active,0);
    ULONGLONG until=GetTickCount64()+2000;unsigned busy;
    do{EnterCriticalSection(&lock);busy=running_ops;LeaveCriticalSection(&lock);if(!busy)break;Sleep(1);}while(GetTickCount64()<until);
    FlowHeader h=head(F_TERMINAL);if(busy){h.flags|=F_DATA_GAP;h.reason=R_STOP_BUSY;loss();}
    emit(h,NULL,0);DWORD r=WaitForSingleObject(finished,6000);if(r==WAIT_OBJECT_0&&flow_io_status>=0)flow_io_status=0;else flow_io_status=-11;
    internal=0;return r==WAIT_OBJECT_0?0:1;
}
static DWORD WINAPI initialize(void*unused){
    (void)unused;internal=1;flow_io_status=1;InitializeCriticalSection(&lock);
    wake=CreateEventW(NULL,FALSE,FALSE,NULL);finished=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!wake||!finished){flow_io_status=-1;return 1;}birth=creation(GetCurrentProcessId());
    swprintf(audit_name,160,L"\\\\.\\pipe\\ttrace-flow-io-%lu-%llu",GetCurrentProcessId(),(unsigned long long)birth);
    HANDLE p=CreateFileW(audit_name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);DWORD n=0;FlowHeader h=head(F_INIT);
    BOOL ok=p!=INVALID_HANDLE_VALUE&&write_all(p,&h,sizeof(h))&&ReadFile(p,&config,sizeof(config),&n,NULL)&&n==sizeof(config);
    if(p!=INVALID_HANDLE_VALUE)CloseHandle(p);
    if(!ok||memcmp(config.magic,"FIC1",4)||config.birth!=birth||config.count>FLOW_MAX_SCOPES||!config.count){flow_io_status=-2;return 2;}
    for(unsigned i=0;i<config.count;i++)if(!config.paths[i][0]||config.paths[i][1023]){flow_io_status=-2;return 2;}
    wchar_t owner[160];swprintf(owner,160,L"Local\\ttrace-flow-io-owner-%lu-%llu",GetCurrentProcessId(),(unsigned long long)birth);
    HANDLE mutex=CreateMutexW(NULL,FALSE,owner);if(!mutex||GetLastError()==ERROR_ALREADY_EXISTS){flow_io_status=-3;return 3;}
    if(MH_Initialize()!=MH_OK){flow_io_status=-4;return 4;}
    ok=install("CreateFileW",on_open,(void**)&real_open)&&install("CreateNamedPipeW",on_pipe,(void**)&real_pipe)&&
        install("ReadFile",on_read,(void**)&real_read)&&install("WriteFile",on_write,(void**)&real_write)&&install("CloseHandle",on_close,(void**)&real_close)&&
        install("ConnectNamedPipe",on_connect,(void**)&real_connect)&&install("DisconnectNamedPipe",on_disconnect,(void**)&real_disconnect);
    if(!ok||MH_EnableHook(MH_ALL_HOOKS)!=MH_OK){MH_Uninitialize();flow_io_status=-5;return 5;}
    HANDLE thread=CreateThread(NULL,0,worker,NULL,0,NULL);if(!thread){flow_io_status=-6;return 6;}CloseHandle(thread);
    active=1;flow_io_status=2;emit(head(F_READY),NULL,0);internal=0;return 0;
}
BOOL WINAPI DllMain(HINSTANCE dll,DWORD why,LPVOID reserved){
    (void)reserved;if(why==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(dll);HANDLE t=CreateThread(NULL,0,initialize,NULL,0,NULL);if(t)CloseHandle(t);}return TRUE;
}
