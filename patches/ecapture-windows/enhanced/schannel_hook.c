/* eCapture Windows research companion, ECW2. Passive SSPI only.
 * Uses the project's checksum-pinned MinHook; never replaces TLS or decisions.
 */
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "MinHook.h"

#define CAP 65536
#define QUEUE_CAP (8*1024*1024)
/* Same byte layout as Python <4s7I10Q and Go's explicit little-endian fields. */
typedef struct {
    char magic[4]; uint32_t length,pid,tid,kind,direction,flags,reserved;
    uint64_t birth,session_lo,session_hi,low,high,generation,sequence,qpc,frequency,lost;
} Header;
_Static_assert(sizeof(Header)==112,"ECW2 header");
typedef struct Node {struct Node *next; Header h; BYTE data[];} Node;
typedef struct {uint64_t low,high,epoch,seq[2]; int used,busy[2],uncertain;} Context;
typedef SECURITY_STATUS(WINAPI *Enc)(PCtxtHandle,ULONG,PSecBufferDesc,ULONG);
typedef SECURITY_STATUS(WINAPI *Dec)(PCtxtHandle,PSecBufferDesc,ULONG,PULONG);
typedef SECURITY_STATUS(WINAPI *Del)(PCtxtHandle);
static Enc original_enc; static Dec original_dec; static Del original_del;
static CRITICAL_SECTION lock;
static HANDLE wake,pipe_handle;
static Node *first,*last; static size_t queued;
static Context contexts[128]; static uint64_t epoch,birth,session_lo,session_hi,frequency;
static volatile LONG active,callbacks;
static volatile LONG64 dropped;
__declspec(dllexport) volatile LONG ecapture_status;
/* Fixed-stage diagnostics only. Never expose captured application buffers. */
__declspec(dllexport) volatile DWORD ecapture_winerror;

static Header header(unsigned kind){
    Header h={0};LARGE_INTEGER tick;QueryPerformanceCounter(&tick);
    memcpy(h.magic,"ECW2",4);h.pid=GetCurrentProcessId();h.tid=GetCurrentThreadId();h.kind=kind;
    h.birth=birth;h.session_lo=session_lo;h.session_hi=session_hi;h.qpc=tick.QuadPart;h.frequency=frequency;
    h.lost=(uint64_t)InterlockedCompareExchange64(&dropped,0,0);return h;
}
static void lose(void){InterlockedIncrement64(&dropped);}
static Context *context(PCtxtHandle ctx){
    if(!ctx)return NULL;
    for(int i=0;i<128;i++)if(contexts[i].used&&contexts[i].low==ctx->dwLower&&contexts[i].high==ctx->dwUpper)return &contexts[i];
    for(int i=0;i<128;i++)if(!contexts[i].used){Context *c=&contexts[i];memset(c,0,sizeof(*c));c->used=1;c->low=ctx->dwLower;c->high=ctx->dwUpper;c->epoch=++epoch;return c;}
    return NULL;
}
static Context *begin(PCtxtHandle ctx,unsigned dir,Header *h){
    if(!TryEnterCriticalSection(&lock)){lose();return NULL;}
    Context *c=context(ctx);
    if(c){
        if(c->busy[dir])c->uncertain=1;
        c->busy[dir]++;h->low=c->low;h->high=c->high;h->generation=c->epoch;h->direction=dir;
    }else lose();
    LeaveCriticalSection(&lock);return c;
}
static void finish(Context *c,Header h,const BYTE *data,size_t n,int emit,int closed){
    if(n>CAP){n=CAP;h.flags|=256;}
    Node *node=emit?HeapAlloc(GetProcessHeap(),0,sizeof(Node)+n):NULL;
    if(emit&&!node)lose();
    EnterCriticalSection(&lock);
    if(c->uncertain||c->busy[0]>1||c->busy[1]>1)h.flags|=512;
    if(emit)h.sequence=++c->seq[h.direction];
    c->busy[h.direction]--;if(closed){if(c->busy[0]||c->busy[1])h.flags|=512;c->used=0;}
    if(!node){LeaveCriticalSection(&lock);return;}
    h.length=(uint32_t)n;h.lost=(uint64_t)InterlockedCompareExchange64(&dropped,0,0);
    node->h=h;node->next=NULL;if(n)memcpy(node->data,data,n);
    if(queued+sizeof(Node)+n>QUEUE_CAP){LeaveCriticalSection(&lock);SecureZeroMemory(node->data,n);HeapFree(GetProcessHeap(),0,node);lose();return;}
    if(last)last->next=node;else first=node;last=node;queued+=sizeof(Node)+n;
    LeaveCriticalSection(&lock);SetEvent(wake);
}
static size_t copy_data(PSecBufferDesc msg,BYTE *copy,unsigned *flags){
    size_t n=0;
    if(!msg||!msg->pBuffers||msg->cBuffers>64){*flags|=512;return 0;}
    for(ULONG i=0;i<msg->cBuffers;i++){
        SecBuffer *b=&msg->pBuffers[i];if((b->BufferType&0x0fffffff)!=SECBUFFER_DATA||!b->pvBuffer)continue;
        size_t take=b->cbBuffer;if(take>CAP-n){take=CAP-n;*flags|=256;}
        memcpy(copy+n,b->pvBuffer,take);n+=take;
    }
    return n;
}
static SECURITY_STATUS WINAPI encrypt_hook(PCtxtHandle ctx,ULONG qop,PSecBufferDesc msg,ULONG seq){
    if(qop&SECQOP_WRAP_OOB_DATA)return original_enc(ctx,qop,msg,seq);
    DWORD before=GetLastError();InterlockedIncrement(&callbacks);
    if(!InterlockedCompareExchange(&active,0,0)){InterlockedDecrement(&callbacks);SetLastError(before);return original_enc(ctx,qop,msg,seq);}
    Header h=header(0);Context *c=begin(ctx,0,&h);BYTE *copy=c?HeapAlloc(GetProcessHeap(),0,CAP):NULL;
    if(c&&!copy)lose();size_t n=copy?copy_data(msg,copy,&h.flags):0;
    SetLastError(before);SECURITY_STATUS result=original_enc(ctx,qop,msg,seq);DWORD error=GetLastError();
    if(c){finish(c,h,copy,n,result==SEC_E_OK&&copy&&(n||h.flags),0);if(result!=SEC_E_OK)lose();}
    if(copy){SecureZeroMemory(copy,n);HeapFree(GetProcessHeap(),0,copy);}InterlockedDecrement(&callbacks);SetLastError(error);return result;
}
static SECURITY_STATUS WINAPI decrypt_hook(PCtxtHandle ctx,PSecBufferDesc msg,ULONG seq,PULONG qop){
    DWORD before=GetLastError();InterlockedIncrement(&callbacks);
    if(!InterlockedCompareExchange(&active,0,0)){InterlockedDecrement(&callbacks);SetLastError(before);return original_dec(ctx,msg,seq,qop);}
    Header h=header(0);Context *c=begin(ctx,1,&h);
    SetLastError(before);SECURITY_STATUS result=original_dec(ctx,msg,seq,qop);DWORD error=GetLastError();
    BYTE *copy=NULL;size_t n=0;
    if(c&&result==SEC_E_OK){copy=HeapAlloc(GetProcessHeap(),0,CAP);if(copy)n=copy_data(msg,copy,&h.flags);else lose();}
    if(c)finish(c,h,copy,n,copy&&(n||h.flags),0);
    /* Incomplete records and close_notify return no application bytes and do
     * not consume the capture sequence. Other decrypt errors are explicit gaps. */
    if(c&&result!=SEC_E_OK&&result!=SEC_E_INCOMPLETE_MESSAGE&&result!=SEC_I_CONTEXT_EXPIRED&&result!=SEC_I_RENEGOTIATE)lose();
    if(copy){SecureZeroMemory(copy,n);HeapFree(GetProcessHeap(),0,copy);}InterlockedDecrement(&callbacks);SetLastError(error);return result;
}
static SECURITY_STATUS WINAPI delete_hook(PCtxtHandle ctx){
    DWORD before=GetLastError();InterlockedIncrement(&callbacks);Header h=header(2);Context *c=NULL;
    if(InterlockedCompareExchange(&active,0,0))c=begin(ctx,0,&h);
    if(c)finish(c,h,NULL,0,1,1);
    SetLastError(before);SECURITY_STATUS result=original_del(ctx);DWORD error=GetLastError();InterlockedDecrement(&callbacks);SetLastError(error);return result;
}
static int write_bounded(const void *data,DWORD n){
    const BYTE *p=data;
    while(n){
        OVERLAPPED ov={0};ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);if(!ov.hEvent)return 0;
        DWORD done=0;BOOL ok=WriteFile(pipe_handle,p,n,&done,&ov);
        if(!ok&&GetLastError()==ERROR_IO_PENDING){
            DWORD wait=WaitForSingleObject(ov.hEvent,500);
            if(wait!=WAIT_OBJECT_0)CancelIoEx(pipe_handle,&ov);
            ok=GetOverlappedResult(pipe_handle,&ov,&done,TRUE)&&wait==WAIT_OBJECT_0;
        }
        CloseHandle(ov.hEvent);if(!ok||!done)return 0;p+=done;n-=done;
    }return 1;
}
static DWORD WINAPI drain(void *unused){
    (void)unused;int stopping=0;ULONGLONG deadline=0;
    Header ready=header(1);if(!write_bounded(&ready,sizeof(ready)))goto failed;
    for(;;){
        DWORD available=0;
        if(!PeekNamedPipe(pipe_handle,NULL,0,NULL,&available,NULL))goto failed;
        if(available>=4){
            char command[4];OVERLAPPED ov={0};DWORD got=0;ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
            BOOL ok=ReadFile(pipe_handle,command,4,&got,&ov);
            if(!ok&&GetLastError()==ERROR_IO_PENDING){WaitForSingleObject(ov.hEvent,500);ok=GetOverlappedResult(pipe_handle,&ov,&got,TRUE);}
            CloseHandle(ov.hEvent);if(!ok||got!=4||memcmp(command,"STOP",4))goto failed;
            InterlockedExchange(&active,0);stopping=1;deadline=GetTickCount64()+3000;
        }
        EnterCriticalSection(&lock);Node *node=first;
        if(node){first=node->next;if(!first)last=NULL;queued-=sizeof(Node)+node->h.length;}
        LeaveCriticalSection(&lock);
        if(node){
            int ok=write_bounded(&node->h,sizeof(Header))&&write_bounded(node->data,node->h.length);
            SecureZeroMemory(node->data,node->h.length);HeapFree(GetProcessHeap(),0,node);if(!ok)goto failed;
        }else if(stopping){
            if(!InterlockedCompareExchange(&callbacks,0,0)){
                Header health=header(3);write_bounded(&health,sizeof(health));ecapture_status=0;CloseHandle(pipe_handle);return 0;
            }
            if(GetTickCount64()>deadline)goto failed;
        }else WaitForSingleObject(wake,10);
    }
failed:
    lose();InterlockedExchange(&active,0);ecapture_status=-9;
    EnterCriticalSection(&lock);Node *node=first;first=last=NULL;queued=0;
    while(node){Node *next=node->next;SecureZeroMemory(node->data,node->h.length);HeapFree(GetProcessHeap(),0,node);lose();node=next;}
    LeaveCriticalSection(&lock);CloseHandle(pipe_handle);return 1;
}
static int install(void *address,void *detour,void **original){
    if(!address)return 0;MEMORY_BASIC_INFORMATION image;
    if(!VirtualQuery(address,&image,sizeof(image))||image.Type!=MEM_IMAGE)return 0;
    for(int i=0;i<8;i++){
        BYTE *p=address;if(p[0]!=0xe9)break;int32_t d;memcpy(&d,p+1,4);void *next=p+5+d;
        MEMORY_BASIC_INFORMATION target;if(!VirtualQuery(next,&target,sizeof(target))||target.Type!=MEM_IMAGE||target.AllocationBase!=image.AllocationBase)return 0;address=next;
    }
    BYTE *p=address;if(p[0]==0xe9||(p[0]==0xff&&p[1]==0x25))return 0;
    return MH_CreateHook(address,detour,original)==MH_OK;
}
static DWORD WINAPI initialize(void *unused){
    (void)unused;ecapture_status=1;FILETIME ft,a,b,c;ULARGE_INTEGER t;LARGE_INTEGER freq;
    if(!GetProcessTimes(GetCurrentProcess(),&ft,&a,&b,&c)||!QueryPerformanceFrequency(&freq)){ecapture_winerror=GetLastError();ecapture_status=-1;return 1;}
    t.LowPart=ft.dwLowDateTime;t.HighPart=ft.dwHighDateTime;birth=t.QuadPart;frequency=freq.QuadPart;
    /* The owner is the SSPI function family, not every observation in a
     * process. A Codex request-body hook can coexist with SSPI observation.
     * install() still rejects existing detours on these actual entries. */
    wchar_t name[160];swprintf(name,160,L"Local\\ttrace-sspi-owner-%lu-%llu",GetCurrentProcessId(),(unsigned long long)birth);
    SetLastError(ERROR_SUCCESS);HANDLE owner=CreateMutexW(NULL,FALSE,name);DWORD owner_error=GetLastError();
    if(!owner||owner_error==ERROR_ALREADY_EXISTS){ecapture_winerror=owner_error;ecapture_status=-2;if(owner)CloseHandle(owner);return 2;}
    swprintf(name,160,L"\\\\.\\pipe\\ecapture-enhanced-%lu-%llu",GetCurrentProcessId(),(unsigned long long)birth);
    pipe_handle=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
    if(pipe_handle==INVALID_HANDLE_VALUE){ecapture_winerror=GetLastError();ecapture_status=-3;return 3;}
    Header config={0};OVERLAPPED ov={0};ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);DWORD got=0;
    BOOL ok=ReadFile(pipe_handle,&config,sizeof(config),&got,&ov);
    if(!ok&&GetLastError()==ERROR_IO_PENDING){DWORD wait=WaitForSingleObject(ov.hEvent,3000);if(wait!=WAIT_OBJECT_0)CancelIoEx(pipe_handle,&ov);ok=GetOverlappedResult(pipe_handle,&ov,&got,TRUE)&&wait==WAIT_OBJECT_0;}
    CloseHandle(ov.hEvent);
    if(!ok||got!=sizeof(config)||memcmp(config.magic,"ECW2",4)||config.kind!=5||config.birth!=birth||config.pid!=GetCurrentProcessId()){ecapture_status=-4;CloseHandle(pipe_handle);return 4;}
    session_lo=config.session_lo;session_hi=config.session_hi;
    InitializeCriticalSection(&lock);wake=CreateEventW(NULL,FALSE,FALSE,NULL);
    HMODULE lib=LoadLibraryW(L"secur32.dll");
    if(!wake||!lib||MH_Initialize()!=MH_OK){ecapture_status=-5;CloseHandle(pipe_handle);return 5;}
    ok=install((void*)GetProcAddress(lib,"EncryptMessage"),encrypt_hook,(void**)&original_enc)&&
       install((void*)GetProcAddress(lib,"DecryptMessage"),decrypt_hook,(void**)&original_dec)&&
       install((void*)GetProcAddress(lib,"DeleteSecurityContext"),delete_hook,(void**)&original_del);
    if(!ok||MH_EnableHook(MH_ALL_HOOKS)!=MH_OK){ecapture_status=-6;MH_Uninitialize();CloseHandle(pipe_handle);return 6;}
    InterlockedExchange(&active,1);HANDLE worker=CreateThread(NULL,0,drain,NULL,0,NULL);
    if(!worker){InterlockedExchange(&active,0);ecapture_status=-7;CloseHandle(pipe_handle);return 7;}CloseHandle(worker);ecapture_status=2;return 0;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){
    (void)reserved;if(reason==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(module);HANDLE t=CreateThread(NULL,0,initialize,NULL,0,NULL);if(t)CloseHandle(t);}return TRUE;
}
