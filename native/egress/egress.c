/* Explicitly enrolled Windows x64 descendants only. No forwarding or TLS changes. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <string.h>
#include "../guard/third_party/minhook/include/MinHook.h"
#include "protocol.h"

typedef BOOL (WINAPI *CreateInternal)(HANDLE,LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION,PHANDLE);
static CreateInternal original_create;
static int (WSAAPI *original_connect)(SOCKET,const struct sockaddr *,int);
static int (WSAAPI *original_wsaconnect)(SOCKET,const struct sockaddr *,int,LPWSABUF,LPWSABUF,LPQOS,LPQOS);
static LPFN_CONNECTEX original_connectex;
static EgressConfig config;
static HMODULE module;
static volatile LONG initialized, healthy;
static _Thread_local DWORD injection_stage, injection_error;
static volatile LONG64 sequence;
static _Thread_local DWORD ipc_error;
static HANDLE queue_event;
static CRITICAL_SECTION queue_lock;
typedef struct Job {
    EgressRequest request;
    EgressResponse response;
    int exchange_valid;
    HANDLE done;
    volatile LONG refs;
    struct Job *next;
} Job;
static Job *queue_head, *queue_tail;
static unsigned int queue_count;

static uint64_t creation_time(HANDLE process) {
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(process,&created,&exited,&kernel,&user)) return 0;
    return ((uint64_t)created.dwHighDateTime<<32)|created.dwLowDateTime;
}
static void release_job(Job *job) {
    if (!InterlockedDecrement(&job->refs)) { CloseHandle(job->done); HeapFree(GetProcessHeap(),0,job); }
}
static int transfer(HANDLE pipe, void *data, DWORD bytes, int write, ULONGLONG deadline) {
    DWORD offset=0;
    while (offset<bytes) {
        OVERLAPPED ov={0}; ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
        if (!ov.hEvent) return 0;
        DWORD count=0;
        BOOL ok=write?WriteFile(pipe,(char*)data+offset,bytes-offset,&count,&ov):ReadFile(pipe,(char*)data+offset,bytes-offset,&count,&ov);
        if (!ok && GetLastError()==ERROR_IO_PENDING) {
            ULONGLONG now=GetTickCount64(); DWORD remaining=now<deadline?(DWORD)(deadline-now):0;
            if (WaitForSingleObject(ov.hEvent,remaining)==WAIT_OBJECT_0) ok=GetOverlappedResult(pipe,&ov,&count,FALSE);
            else { CancelIoEx(pipe,&ov); GetOverlappedResult(pipe,&ov,&count,TRUE); ok=FALSE; }
        }
        CloseHandle(ov.hEvent);
        if (!ok || !count) return 0;
        offset+=count;
    }
    return 1;
}
static int exchange(EgressRequest *request,EgressResponse *response) {
    ULONGLONG deadline=GetTickCount64()+1500;
    HANDLE pipe=INVALID_HANDLE_VALUE;
    do {
        pipe=CreateFileW(config.pipe_name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
        if (pipe!=INVALID_HANDLE_VALUE) break;
        DWORD error=GetLastError();
        if (error!=ERROR_PIPE_BUSY && error!=ERROR_FILE_NOT_FOUND) break;
        /* A one-client child pipe has a small disconnect/recreate interval.
           Retry only these transient availability states within the deadline. */
        WaitNamedPipeW(config.pipe_name,50); Sleep(2);
    } while (GetTickCount64()<deadline);
    if (pipe==INVALID_HANDLE_VALUE) { ipc_error=1000+GetLastError(); return 0; }
    ULONG server=0;
    int ok=GetNamedPipeServerProcessId(pipe,&server) && server==config.controller_pid;
    if (!ok) ipc_error=2000+GetLastError();
    if (ok) ok=transfer(pipe,request,sizeof(*request),1,deadline) && transfer(pipe,response,sizeof(*response),0,deadline);
    if (ok) {
        unsigned char received=0xa5,confirmed=0,finished=0xa6;
        ok=transfer(pipe,&received,1,1,deadline) && transfer(pipe,&confirmed,1,0,deadline) && confirmed==0x5a;
        /* Let the server retire this connection only after confirmation was
           consumed. DisconnectNamedPipe would otherwise discard unread bytes. */
        if (ok) ok=transfer(pipe,&finished,1,1,deadline);
    }
    if (!ok && !ipc_error) ipc_error=3000+GetLastError();
    CloseHandle(pipe);
    return ok && response->magic==EGRESS_MAGIC && response->version==EGRESS_VERSION && response->sequence==request->sequence;
}
static EgressRequest request_for(uint32_t kind) {
    EgressRequest request={0}; request.magic=EGRESS_MAGIC; request.version=EGRESS_VERSION;
    request.kind=kind; request.pid=GetCurrentProcessId(); request.creation=config.creation;
    memcpy(request.token,config.token,32); request.sequence=(uint64_t)InterlockedIncrement64(&sequence);
    return request;
}
static DWORD WINAPI policy_worker(void *unused) {
    (void)unused;
    for (;;) {
        WaitForSingleObject(queue_event,1000);
        for (;;) {
            EnterCriticalSection(&queue_lock);
            Job *job=queue_head;
            if (job) { queue_head=job->next; if (!queue_head) queue_tail=NULL; queue_count--; }
            LeaveCriticalSection(&queue_lock);
            if (!job) break;
            job->exchange_valid=exchange(&job->request,&job->response);
            if (!job->exchange_valid) { job->response.allow=0; InterlockedExchange(&healthy,0); }
            SetEvent(job->done); release_job(job);
        }
        EgressRequest heartbeat=request_for(EGRESS_HEARTBEAT); EgressResponse response={0};
        heartbeat.reserved=InterlockedCompareExchange(&healthy,0,0)?1:0;
        if (!exchange(&heartbeat,&response) || !response.allow) InterlockedExchange(&healthy,0);
    }
}
static int decide(EgressRequest request) {
    if (!InterlockedCompareExchange(&healthy,0,0)) return 0;
    Job *job=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*job));
    if (!job) return 0;
    job->done=CreateEventW(NULL,TRUE,FALSE,NULL); job->refs=2; job->request=request;
    if (!job->done) { HeapFree(GetProcessHeap(),0,job); return 0; }
    EnterCriticalSection(&queue_lock);
    if (queue_count>=32) { LeaveCriticalSection(&queue_lock); release_job(job); release_job(job); return 0; }
    if (queue_tail) queue_tail->next=job; else queue_head=job;
    queue_tail=job; queue_count++;
    LeaveCriticalSection(&queue_lock); SetEvent(queue_event);
    DWORD wait=WaitForSingleObject(job->done,2000);
    int allowed=0;
    if (wait==WAIT_OBJECT_0) {
        /* The completion event publishes the worker's response. Never inspect
           it while a timed-out caller can race the worker writing the frame. */
        allowed=job->exchange_valid && job->response.allow==1;
        if (!job->exchange_valid || !job->response.magic) InterlockedExchange(&healthy,0);
    } else InterlockedExchange(&healthy,0);
    release_job(job); return allowed;
}
static int check_destination(SOCKET socket,const struct sockaddr *address,int length,uint64_t *attempt) {
    if (config.root) return 1; /* LLM transport belongs to Native Guard. */
    EgressRequest request=request_for(EGRESS_CONNECT); *attempt=request.sequence;
    int type=0, bytes=sizeof(type);
    if (getsockopt(socket,SOL_SOCKET,SO_TYPE,(char*)&type,&bytes)==SOCKET_ERROR) return 0;
    /* This adapter authorizes TCP connection attempts only. Preserve the
       original API for other socket types; in particular, denying UDP connect
       does not protect sendto and would silently broaden a TCP-only policy. */
    if (type!=SOCK_STREAM) return 1;
    if (!address || length<(int)sizeof(struct sockaddr)) return 0;
    if (address->sa_family==AF_INET && length>=(int)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *a=(const struct sockaddr_in*)address;
        request.family=4; request.port=ntohs(a->sin_port); memcpy(request.address,&a->sin_addr,4);
    } else if (address->sa_family==AF_INET6 && length>=(int)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *a=(const struct sockaddr_in6*)address;
        request.family=6; request.port=ntohs(a->sin6_port); memcpy(request.address,&a->sin6_addr,16);
    } else return 0;
    return decide(request);
}
static void blocked_result(uint64_t attempt) {
    EgressRequest result=request_for(EGRESS_RESULT); result.child_creation=attempt;
    result.result=SOCKET_ERROR; result.error=WSAEACCES; decide(result); WSASetLastError(WSAEACCES);
}
static int WSAAPI hook_connect(SOCKET socket,const struct sockaddr *address,int length) {
    uint64_t attempt=0;
    if (!check_destination(socket,address,length,&attempt)) { blocked_result(attempt); return SOCKET_ERROR; }
    return original_connect(socket,address,length);
}
static int WSAAPI hook_wsaconnect(SOCKET socket,const struct sockaddr *address,int length,LPWSABUF caller,LPWSABUF callee,LPQOS send,LPQOS receive) {
    uint64_t attempt=0;
    if (!check_destination(socket,address,length,&attempt)) { blocked_result(attempt); return SOCKET_ERROR; }
    return original_wsaconnect(socket,address,length,caller,callee,send,receive);
}
static BOOL PASCAL hook_connectex(SOCKET socket,const struct sockaddr *address,int length,PVOID data,DWORD size,LPDWORD sent,LPOVERLAPPED overlapped) {
    uint64_t attempt=0;
    if (!check_destination(socket,address,length,&attempt)) { blocked_result(attempt); return FALSE; }
    return original_connectex(socket,address,length,data,size,sent,overlapped);
}
static int remote_call(HANDLE process,void *function,void *argument,DWORD *result) {
    HANDLE thread=CreateRemoteThread(process,NULL,0,(LPTHREAD_START_ROUTINE)function,argument,0,NULL);
    if (!thread) return 0;
    int ok=WaitForSingleObject(thread,10000)==WAIT_OBJECT_0 && GetExitCodeThread(thread,result);
    CloseHandle(thread); return ok;
}
static void *module_base(DWORD pid,const wchar_t *name) {
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if (snapshot==INVALID_HANDLE_VALUE) return NULL;
    MODULEENTRY32W entry={0}; entry.dwSize=sizeof(entry); void *base=NULL;
    if (Module32FirstW(snapshot,&entry)) do {
        if (!_wcsicmp(entry.szModule,name)) { base=entry.modBaseAddr; break; }
    } while (Module32NextW(snapshot,&entry));
    CloseHandle(snapshot); return base;
}
static void *remote_export(DWORD pid,HMODULE local,void *function) {
    wchar_t path[32768]; if (!GetModuleFileNameW(local,path,32768)) return NULL;
    wchar_t *name=wcsrchr(path,L'\\'); name=name?name+1:path;
    void *base=module_base(pid,name); return base?(char*)base+((char*)function-(char*)local):NULL;
}
static void *remote_loader(DWORD pid) {
    void *load=(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW");
    HMODULE owner=NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCWSTR)load,&owner)) return NULL;
    return remote_export(pid,owner,load);
}
static int inject_child(PROCESS_INFORMATION *pi) {
    injection_stage=1; injection_error=0;
    EgressConfig child=config; child.root=0; child.creation=creation_time(pi->hProcess);
    wchar_t base_pipe[128]; wcscpy(base_pipe,config.pipe_name);
    if (!config.root) { wchar_t *suffix=wcsrchr(base_pipe,L'-'); if (!suffix) return 0; *suffix=0; }
    if (swprintf(child.pipe_name,128,L"%ls-%lu",base_pipe,pi->dwProcessId)<0) return 0;
    if (!child.creation) return 0;
    EgressRequest register_child=request_for(EGRESS_CHILD); register_child.child_pid=pi->dwProcessId; register_child.child_creation=child.creation;
    if (!decide(register_child)) return 0;
    injection_stage=2;
    void *loader=remote_loader(pi->dwProcessId);
    if (!loader) {
        /* A CREATE_SUSPENDED process can have only ntdll mapped. Bootstrap the
           Windows loader on a worker, never the application's main thread.
           Validate the actual remote mapping and bytes instead of assuming
           that system DLL ASLR bases are equal. Custom loader/TLS callbacks
           are outside this fixed-tool prototype's certified scope. */
        HMODULE nt=GetModuleHandleW(L"ntdll.dll");
        void *yield=(void*)GetProcAddress(nt,"NtYieldExecution");
        MEMORY_BASIC_INFORMATION info={0}; unsigned char bytes[16]; SIZE_T read=0;
        DWORD ignored=0;
        if (!yield || !VirtualQueryEx(pi->hProcess,yield,&info,sizeof(info)) || info.AllocationBase!=(void*)nt || info.Type!=MEM_IMAGE ||
            !ReadProcessMemory(pi->hProcess,yield,bytes,sizeof(bytes),&read) || read!=sizeof(bytes) || memcmp(bytes,yield,sizeof(bytes)) ||
            !remote_call(pi->hProcess,yield,NULL,&ignored)) { injection_error=GetLastError(); return 0; }
        loader=remote_loader(pi->dwProcessId);
    }
    if (!loader) return 0;
    injection_stage=3;
    SIZE_T path_bytes=(wcslen(child.dll_path)+1)*sizeof(wchar_t), written=0;
    void *memory=VirtualAllocEx(pi->hProcess,NULL,sizeof(child),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!memory) return 0;
    DWORD result=0; int completed=0;
    int ok=WriteProcessMemory(pi->hProcess,memory,child.dll_path,path_bytes,&written) && written==path_bytes;
    if (ok) { ok=remote_call(pi->hProcess,loader,memory,&result); completed=ok; }
    injection_stage=4; injection_error=GetLastError();
    wchar_t *name=wcsrchr(child.dll_path,L'\\'); name=name?name+1:child.dll_path;
    void *base=ok?module_base(pi->dwProcessId,name):NULL;
    void *entry=(void*)GetProcAddress(module,"EgressInitialize");
    if (!base || !entry) ok=0;
    if (!ok) { injection_stage=4; goto finish; }
    injection_stage=5;
    if (ok) ok=WriteProcessMemory(pi->hProcess,memory,&child,sizeof(child),&written) && written==sizeof(child);
    if (ok) { ok=remote_call(pi->hProcess,(char*)base+((char*)entry-(char*)module),memory,&result); completed=ok; }
    injection_error=result;
finish:
    if (completed) VirtualFreeEx(pi->hProcess,memory,0,MEM_RELEASE);
    return ok && result==EGRESS_MAGIC;
}
static BOOL WINAPI hook_create(HANDLE token,LPCWSTR application,LPWSTR command,LPSECURITY_ATTRIBUTES process_security,LPSECURITY_ATTRIBUTES thread_security,BOOL inherit,DWORD flags,LPVOID environment,LPCWSTR directory,LPSTARTUPINFOW startup,LPPROCESS_INFORMATION pi,PHANDLE new_token) {
    if (!InterlockedCompareExchange(&healthy,0,0)) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    BOOL ok=original_create(token,application,command,process_security,thread_security,inherit,flags|CREATE_SUSPENDED,environment,directory,startup,pi,new_token);
    if (!ok) return FALSE;
    if (!inject_child(pi)) {
        EgressRequest held=request_for(EGRESS_HELD); held.child_pid=pi->dwProcessId; held.child_creation=creation_time(pi->hProcess); held.result=injection_stage; held.error=injection_error; decide(held);
        /* Never run an unenrolled child. Keep it suspended; report the PID for explicit cleanup. */
        CloseHandle(pi->hThread); CloseHandle(pi->hProcess); memset(pi,0,sizeof(*pi)); SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    if (!(flags&CREATE_SUSPENDED) && ResumeThread(pi->hThread)==(DWORD)-1) {
        EgressRequest held=request_for(EGRESS_HELD); held.child_pid=pi->dwProcessId; held.child_creation=creation_time(pi->hProcess); decide(held);
        CloseHandle(pi->hThread); CloseHandle(pi->hProcess); memset(pi,0,sizeof(*pi)); SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    return TRUE;
}
static int own_hook(void *target,void *replacement,void **original) {
    if (!target) return 0;
    MEMORY_BASIC_INFORMATION information;
    if (!VirtualQuery(target,&information,sizeof(information)) || !(information.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) return 0;
    unsigned char first=*(unsigned char*)target;
    if (first==0xe9 || first==0xeb || first==0xcc || (first==0xff && ((unsigned char*)target)[1]==0x25)) return 0;
    return MH_CreateHook(target,replacement,original)==MH_OK && MH_EnableHook(target)==MH_OK;
}
__declspec(dllexport) DWORD WINAPI EgressInitialize(void *argument) {
    if (InterlockedCompareExchange(&initialized,1,0)) return 0;
    EgressConfig *provided=(EgressConfig*)argument;
    if (!provided || provided->magic!=EGRESS_MAGIC || provided->version!=EGRESS_VERSION || provided->creation!=creation_time(GetCurrentProcess()) || !provided->pipe_name[0] || !provided->dll_path[0]) return 0;
    memcpy(&config,provided,sizeof(config));
    if (config.pipe_name[127] || config.dll_path[1023]) return 0;
    EgressRequest request=request_for(EGRESS_REGISTER); EgressResponse response={0};
    if (!exchange(&request,&response) || !response.allow) return ipc_error?ipc_error:110;
    InitializeCriticalSection(&queue_lock); queue_event=CreateEventW(NULL,FALSE,FALSE,NULL);
    if (!queue_event || MH_Initialize()!=MH_OK) return 0;
    InterlockedExchange(&healthy,1);
    HANDLE worker=CreateThread(NULL,0,policy_worker,NULL,0,NULL);
    if (!worker) { InterlockedExchange(&healthy,0); return 0; } CloseHandle(worker);
    WSADATA data; if (WSAStartup(MAKEWORD(2,2),&data)) return 0;
    void *create=(void*)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"),"CreateProcessInternalW");
    if (!create || (uint64_t)((char*)create-(char*)GetModuleHandleW(L"kernelbase.dll"))!=config.create_rva || memcmp(create,config.create_prologue,16)) return 120;
    if (!own_hook(create,hook_create,(void**)&original_create)) return 0;
    HMODULE winsock=GetModuleHandleW(L"ws2_32.dll");
    if (!own_hook((void*)GetProcAddress(winsock,"connect"),hook_connect,(void**)&original_connect)) return 0;
    if (!own_hook((void*)GetProcAddress(winsock,"WSAConnect"),hook_wsaconnect,(void**)&original_wsaconnect)) return 0;
    SOCKET socket=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,0); DWORD bytes=0;
    GUID guid=WSAID_CONNECTEX; LPFN_CONNECTEX connectex=NULL;
    int got=socket!=INVALID_SOCKET && WSAIoctl(socket,SIO_GET_EXTENSION_FUNCTION_POINTER,&guid,sizeof(guid),&connectex,sizeof(connectex),&bytes,NULL,NULL)==0;
    if (socket!=INVALID_SOCKET) closesocket(socket);
    if (!got || !own_hook((void*)connectex,hook_connectex,(void**)&original_connectex)) return 0;
    EgressRequest ready=request_for(EGRESS_READY); ready.reserved=0x0f;
    if (!decide(ready)) return 0;
    return EGRESS_MAGIC;
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved) {
    (void)reserved;
    if (reason==DLL_PROCESS_ATTACH) { module=instance; DisableThreadLibraryCalls(instance); }
    return TRUE;
}
