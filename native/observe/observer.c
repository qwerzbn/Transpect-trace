/* Passive, bounded plaintext observation. Never modifies a TLS return value. */
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../guard/third_party/minhook/include/MinHook.h"

#define CAP 65536
#define QUEUE_CAP (8*1024*1024)
typedef struct { char magic[4]; uint32_t pid,tid,direction; uint64_t sequence,low,high,epoch,qpc; uint32_t length,flags; } Header;
typedef struct { char magic[4]; uint32_t mode; uint64_t birth,addresses[10]; } Config;
typedef struct Node { struct Node *next; Header header; unsigned char bytes[]; } Node;
typedef struct { uint64_t low,high,epoch,sequence[2]; int used; } Conn;
_Static_assert(sizeof(Header)==64,"capture header layout");
_Static_assert(sizeof(Config)==96,"configuration layout");
static CRITICAL_SECTION lock;
static HANDLE wake;
static Node *first,*last;
static size_t queued;
static Conn connections[128];
static uint64_t epoch;
static unsigned lost;
static wchar_t pipe_name[128];
static _Thread_local int nested;
__declspec(dllexport) volatile LONG observe_status;
__declspec(dllexport) volatile LONG observe_dropped;
static volatile LONG active;

static Header header(unsigned flags) {
    Header h={0};memcpy(h.magic,"TTO1",4);h.pid=GetCurrentProcessId();h.tid=GetCurrentThreadId();h.flags=flags;
    LARGE_INTEGER tick;QueryPerformanceCounter(&tick);h.qpc=tick.QuadPart;return h;
}
static void emit(uint64_t low,uint64_t high,unsigned dir,const void *data,size_t n,unsigned flags) {
    if(!InterlockedCompareExchange(&active,0,0))return;
    size_t take=n>CAP?CAP:n;
    Node *node=HeapAlloc(GetProcessHeap(),0,sizeof(Node)+take);
    EnterCriticalSection(&lock);
    if(!InterlockedCompareExchange(&active,0,0)){if(node)HeapFree(GetProcessHeap(),0,node);LeaveCriticalSection(&lock);return;}
    Conn *c=NULL;
    for(int i=0;i<128;i++)if(connections[i].used&&connections[i].low==low&&connections[i].high==high){c=&connections[i];break;}
    if(!c)for(int i=0;i<128;i++)if(!connections[i].used){c=&connections[i];memset(c,0,sizeof(*c));c->used=1;c->low=low;c->high=high;c->epoch=++epoch;break;}
    uint64_t seq=c?++c->sequence[dir]:1;
    if(!node||!c||queued+sizeof(Node)+take>QUEUE_CAP){lost++;InterlockedIncrement(&observe_dropped);if(node)HeapFree(GetProcessHeap(),0,node);LeaveCriticalSection(&lock);return;}
    node->next=NULL;node->header=header(flags|(n>take?256:0)|((lost>65535?65535:lost)<<16));lost=0;
    node->header.low=low;node->header.high=high;node->header.epoch=c->epoch;
    node->header.direction=dir;node->header.sequence=seq;node->header.length=(uint32_t)take;
    if(take)memcpy(node->bytes,data,take);
    if(last)last->next=node;else first=node;last=node;queued+=sizeof(Node)+take;
    if((flags&255)==2)c->used=0;
    LeaveCriticalSection(&lock);SetEvent(wake);
}
static int write_all(HANDLE pipe,const void *data,DWORD n) {
    DWORD done=0;
    while(done<n){DWORD bytes=0;if(!WriteFile(pipe,(char*)data+done,n-done,&bytes,NULL)||!bytes)return 0;done+=bytes;}
    return 1;
}
static DWORD WINAPI drain(void *unused) {
    (void)unused;
    for(;;){
        WaitForSingleObject(wake,1000);
        for(;;){
            EnterCriticalSection(&lock);Node *node=first;
            if(node){first=node->next;if(!first)last=NULL;queued-=sizeof(Node)+node->header.length;}
            LeaveCriticalSection(&lock);if(!node)break;
            HANDLE pipe=INVALID_HANDLE_VALUE;ULONGLONG deadline=GetTickCount64()+1000;
            do {
                pipe=CreateFileW(pipe_name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
                if(pipe!=INVALID_HANDLE_VALUE)break;
                DWORD error=GetLastError();if(error!=ERROR_PIPE_BUSY&&error!=ERROR_FILE_NOT_FOUND)break;
                WaitNamedPipeW(pipe_name,20);Sleep(1);
            } while(GetTickCount64()<deadline);
            int ok=pipe!=INVALID_HANDLE_VALUE&&write_all(pipe,&node->header,sizeof(Header))&&write_all(pipe,node->bytes,node->header.length);
            if(ok)ok=FlushFileBuffers(pipe);
            if(pipe!=INVALID_HANDLE_VALUE)CloseHandle(pipe);
            if(!ok){InterlockedExchange(&active,0);EnterCriticalSection(&lock);lost++;InterlockedIncrement(&observe_dropped);LeaveCriticalSection(&lock);}
            SecureZeroMemory(node->bytes,node->header.length);HeapFree(GetProcessHeap(),0,node);
        }
    }
}
__declspec(dllexport) DWORD WINAPI observe_disable(void *unused) {
    (void)unused;InterlockedExchange(&active,0);observe_status=0;
    EnterCriticalSection(&lock);
    Node *node=first;first=last=NULL;queued=0;
    while(node){Node *next=node->next;InterlockedIncrement(&observe_dropped);SecureZeroMemory(node->bytes,node->header.length);HeapFree(GetProcessHeap(),0,node);node=next;}
    LeaveCriticalSection(&lock);return 0;
}
typedef int (*WriteFn)(void*,const void*,int);
typedef int (*WriteExFn)(void*,const void*,size_t,size_t*);
typedef int (*ReadFn)(void*,void*,int);
typedef int (*ReadExFn)(void*,void*,size_t,size_t*);
typedef void (*FreeFn)(void*);
static WriteFn ow;static WriteExFn owe;static ReadFn or;static ReadExFn ore;static FreeFn ofree;
static int ssl_write(void *ssl,const void *data,int n){int outer=!nested++;int r=ow(ssl,data,n);DWORD error=GetLastError();nested--;if(outer&&r>0)emit((uintptr_t)ssl,0,0,data,(size_t)r,0);SetLastError(error);return r;}
static int ssl_write_ex(void *ssl,const void *data,size_t n,size_t *done){int outer=!nested++;int r=owe(ssl,data,n,done);DWORD error=GetLastError();nested--;if(outer&&r==1&&done&&*done)emit((uintptr_t)ssl,0,0,data,*done,0);SetLastError(error);return r;}
static int ssl_read(void *ssl,void *data,int n){int outer=!nested++;int r=or(ssl,data,n);DWORD error=GetLastError();nested--;if(outer&&r>0)emit((uintptr_t)ssl,0,1,data,(size_t)r,0);SetLastError(error);return r;}
static int ssl_read_ex(void *ssl,void *data,size_t n,size_t *done){int outer=!nested++;int r=ore(ssl,data,n,done);DWORD error=GetLastError();nested--;if(outer&&r==1&&done&&*done)emit((uintptr_t)ssl,0,1,data,*done,0);SetLastError(error);return r;}
static void ssl_free(void *ssl){DWORD error=GetLastError();emit((uintptr_t)ssl,0,0,NULL,0,2);SetLastError(error);ofree(ssl);}
typedef SECURITY_STATUS (WINAPI *EncryptFn)(PCtxtHandle,ULONG,PSecBufferDesc,ULONG);
typedef SECURITY_STATUS (WINAPI *DecryptFn)(PCtxtHandle,PSecBufferDesc,ULONG,PULONG);
typedef SECURITY_STATUS (WINAPI *DeleteFn)(PCtxtHandle);
static EncryptFn oe;static DecryptFn od;static DeleteFn ox;
static SECURITY_STATUS WINAPI encrypt(PCtxtHandle ctx,ULONG qop,PSecBufferDesc msg,ULONG seq){
    /* SECQOP_WRAP_OOB_DATA carries TLS alerts (e.g. close_notify), not HTTP. */
    if((qop&SECQOP_WRAP_OOB_DATA)||!InterlockedCompareExchange(&active,0,0))return oe(ctx,qop,msg,seq);
    DWORD before=GetLastError();
    unsigned char *copy=HeapAlloc(GetProcessHeap(),0,CAP);size_t n=0,total=0;
    if(!copy){EnterCriticalSection(&lock);lost++;InterlockedIncrement(&observe_dropped);LeaveCriticalSection(&lock);}
    uint64_t low=ctx->dwLower,high=ctx->dwUpper;
    if(copy&&msg&&msg->cBuffers<64)for(ULONG i=0;i<msg->cBuffers;i++){
        SecBuffer *b=&msg->pBuffers[i];if((b->BufferType&0xfffffff)!=SECBUFFER_DATA||!b->pvBuffer)continue;
        size_t take=b->cbBuffer;if(take>CAP-n)take=CAP-n;memcpy(copy+n,b->pvBuffer,take);n+=take;total+=b->cbBuffer;
    }
    SetLastError(before);SECURITY_STATUS r=oe(ctx,qop,msg,seq);DWORD error=GetLastError();if(r==SEC_E_OK&&n)emit(low,high,0,copy,n,total>n?256:0);
    if(copy){SecureZeroMemory(copy,n);HeapFree(GetProcessHeap(),0,copy);}SetLastError(error);return r;
}
static SECURITY_STATUS WINAPI decrypt(PCtxtHandle ctx,PSecBufferDesc msg,ULONG seq,PULONG qop){
    SECURITY_STATUS r=od(ctx,msg,seq,qop);DWORD error=GetLastError();
    if(r==SEC_E_OK&&msg&&msg->cBuffers<64)for(ULONG i=0;i<msg->cBuffers;i++){
        SecBuffer *b=&msg->pBuffers[i];if((b->BufferType&0xfffffff)==SECBUFFER_DATA&&b->pvBuffer&&b->cbBuffer)emit(ctx->dwLower,ctx->dwUpper,1,b->pvBuffer,b->cbBuffer,0);
    }
    SetLastError(error);return r;
}
static SECURITY_STATUS WINAPI delctx(PCtxtHandle ctx){DWORD error=GetLastError();emit(ctx->dwLower,ctx->dwUpper,0,NULL,0,2);SetLastError(error);return ox(ctx);}
typedef void *(*HttpFn)(void*,void*,void*,void*);
typedef void *(*WssFn)(void*,void*);
static HttpFn oh;static WssFn os;
static void *http_json(void *out,void *req,void *headers,void *body){
    uintptr_t *b=body;if(b[2]&&b[2]<=16*1024*1024)emit(GetCurrentThreadId(),1,0,(void*)b[1],b[2],16);
    return oh(out,req,headers,body);
}
static void *wss_json(void *out,void *req){void *r=os(out,req);uintptr_t *v=out;if(v[0]==0x1c&&v[3]&&v[3]<=16*1024*1024)emit(GetCurrentThreadId(),2,0,(void*)v[2],v[3],32);return r;}

static int hook(void *address,void *detour,void **original) {
    if(!address)return 1;
    MEMORY_BASIC_INFORMATION m;
    if(!VirtualQuery(address,&m,sizeof(m))||m.Type!=MEM_IMAGE)return 0;
    /* MSVC exports may be legitimate E9 import thunks. Follow only jumps
     * inside the same pinned image; MinHook relays live in private memory. */
    for(int i=0;i<8;i++){
        BYTE *p=address;if(p[0]!=0xe9)break;
        int32_t displacement;memcpy(&displacement,p+1,4);void *next=p+5+displacement;
        MEMORY_BASIC_INFORMATION target;
        if(!VirtualQuery(next,&target,sizeof(target))||target.Type!=MEM_IMAGE||target.AllocationBase!=m.AllocationBase)return 0;
        address=next;
    }
    BYTE *p=address;if(p[0]==0xe9||(p[0]==0xff&&p[1]==0x25))return 0;
    return MH_CreateHook(address,detour,original)==MH_OK;
}
static DWORD WINAPI initialize(void *unused){
    (void)unused;observe_status=1;InitializeCriticalSection(&lock);wake=CreateEventW(NULL,FALSE,FALSE,NULL);
    if(!wake){observe_status=-1;return 1;}
    swprintf(pipe_name,128,L"\\\\.\\pipe\\ttrace-observe-%lu",GetCurrentProcessId());
    HANDLE pipe=CreateFileW(pipe_name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if(pipe==INVALID_HANDLE_VALUE)return 1;
    Header init=header(4);Config config={0};DWORD got=0;
    int ok=write_all(pipe,&init,sizeof(init))&&ReadFile(pipe,&config,sizeof(config),&got,NULL)&&got==sizeof(config);
    CloseHandle(pipe);
    FILETIME birth,a,b,c;ULARGE_INTEGER t;
    if(!ok||memcmp(config.magic,"TTC1",4)||!GetProcessTimes(GetCurrentProcess(),&birth,&a,&b,&c)){observe_status=-2;return 2;}
    observe_status=2;
    t.LowPart=birth.dwLowDateTime;t.HighPart=birth.dwHighDateTime;if(t.QuadPart!=config.birth)return 3;
    wchar_t owner[160];swprintf(owner,160,L"Local\\ttrace-observe-owner-%lu-%llu",GetCurrentProcessId(),(unsigned long long)t.QuadPart);
    HANDLE mutex=CreateMutexW(NULL,FALSE,owner);if(!mutex||GetLastError()==ERROR_ALREADY_EXISTS)return 4;
    if(MH_Initialize()!=MH_OK){observe_status=-5;return 5;}
    observe_status=3;
    if(config.mode==1){
        ok=hook((void*)config.addresses[0],ssl_write,(void**)&ow)&&hook((void*)config.addresses[1],ssl_write_ex,(void**)&owe)&&
           hook((void*)config.addresses[2],ssl_read,(void**)&or)&&hook((void*)config.addresses[3],ssl_read_ex,(void**)&ore)&&hook((void*)config.addresses[4],ssl_free,(void**)&ofree);
        ok=ok&&(ow||owe)&&(or||ore)&&ofree;
    }else if(config.mode==2){
        HMODULE lib=LoadLibraryW(L"secur32.dll");
        ok=lib&&hook((void*)GetProcAddress(lib,"EncryptMessage"),encrypt,(void**)&oe)&&
           hook((void*)GetProcAddress(lib,"DecryptMessage"),decrypt,(void**)&od)&&hook((void*)GetProcAddress(lib,"DeleteSecurityContext"),delctx,(void**)&ox);
        ok=ok&&oe&&od&&ox;
    }else if(config.mode==3){
        ok=hook((void*)config.addresses[0],http_json,(void**)&oh)&&hook((void*)config.addresses[1],wss_json,(void**)&os)&&oh&&os;
    }else ok=0;
    if(!ok||MH_EnableHook(MH_ALL_HOOKS)!=MH_OK){observe_status=-6;MH_Uninitialize();return 6;}
    observe_status=4;
    InterlockedExchange(&active,1);
    HANDLE worker=CreateThread(NULL,0,drain,NULL,0,NULL);if(!worker){InterlockedExchange(&active,0);observe_status=-7;return 7;}CloseHandle(worker);
    emit(0,0,0,NULL,0,1);observe_status=5;return 0;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){
    (void)reserved;if(reason==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(module);HANDLE thread=CreateThread(NULL,0,initialize,NULL,0,NULL);if(thread)CloseHandle(thread);}return TRUE;
}
