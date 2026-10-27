/* CPython 3.12 runtime bridge. No TLS interception or disk image modification. */
#define PY_SSIZE_T_CLEAN
#define WIN32_LEAN_AND_MEAN
#include <Python.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#define JSMN_STRICT
#define JSMN_PARENT_LINKS
#include "../guard/third_party/jsmn/jsmn.h"
#define MAX_REQUEST (24u*1024u*1024u)
static HANDLE server_process;
static DWORD server_pid;
static volatile LONG session_blocked;
static volatile LONG pending_reports;
static wchar_t pipe_name[96];

static int transfer(HANDLE pipe,void *buffer,DWORD size,int writing,ULONGLONG deadline) {
    DWORD offset=0;
    while(offset<size) {
        ULONGLONG now=GetTickCount64();if(now>=deadline)return 0;
        OVERLAPPED ov={0};ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);if(!ov.hEvent)return 0;
        DWORD count=0;BOOL ok=writing?WriteFile(pipe,(char*)buffer+offset,size-offset,&count,&ov):ReadFile(pipe,(char*)buffer+offset,size-offset,&count,&ov);
        if(!ok&&GetLastError()==ERROR_IO_PENDING) {
            now=GetTickCount64();DWORD remaining=now<deadline?(DWORD)(deadline-now):0;
            if(WaitForSingleObject(ov.hEvent,remaining)==WAIT_OBJECT_0)ok=GetOverlappedResult(pipe,&ov,&count,FALSE);
            else {CancelIoEx(pipe,&ov);GetOverlappedResult(pipe,&ov,&count,TRUE);ok=FALSE;}
        }
        CloseHandle(ov.hEvent);if(!ok||!count)return 0;offset+=count;
    }
    return 1;
}
static int field(const char*j,jsmntok_t*t,int n,const char*key,char*out,size_t cap) {
    int found=0;
    for(int i=1;i+1<n;i++)if(t[i].parent==0&&t[i].type==JSMN_STRING&&t[i].end-t[i].start==(int)strlen(key)&&!memcmp(j+t[i].start,key,strlen(key))) {
        if(found++||t[i+1].type!=JSMN_STRING)return 0;
        int len=t[i+1].end-t[i+1].start;if(len<0||(size_t)len>=cap)return 0;
        memcpy(out,j+t[i+1].start,len);out[len]=0;
    }
    return found==1;
}
static int space(char x){return x==' '||x=='\n'||x=='\r'||x=='\t';}
static int shape(const char*j,size_t bytes,jsmntok_t*t,int n) {
    if(n!=13||t[0].type!=JSMN_OBJECT)return 0;
    size_t p=0;while(p<bytes&&space(j[p]))p++;if(p!=(size_t)t[0].start||j[p++]!='{')return 0;
    for(int i=1;i<n;i+=2) {
        if(t[i].parent!=0||t[i].type!=JSMN_STRING||t[i+1].parent!=i||t[i+1].type!=JSMN_STRING)return 0;
        while(p<bytes&&space(j[p]))p++;if(p!=(size_t)t[i].start-1||j[p]!='"')return 0;p=t[i].end+1;
        while(p<bytes&&space(j[p]))p++;if(p>=bytes||j[p++]!=':')return 0;
        while(p<bytes&&space(j[p]))p++;if(p!=(size_t)t[i+1].start-1||j[p]!='"')return 0;p=t[i+1].end+1;
        while(p<bytes&&space(j[p]))p++;if(i+2<n&&(p>=bytes||j[p++]!=','))return 0;
    }
    if(p>=bytes||j[p++]!='}'||p!=(size_t)t[0].end)return 0;while(p<bytes&&space(j[p]))p++;return p==bytes;
}
static int check(char *request,DWORD length,const char *id) {
    if(InterlockedCompareExchange(&session_blocked,0,0))return 2;
    if(!server_process||WaitForSingleObject(server_process,0)!=WAIT_TIMEOUT)return 0;
    ULONGLONG deadline=GetTickCount64()+2000;HANDLE pipe=INVALID_HANDLE_VALUE;
    do {
        pipe=CreateFileW(pipe_name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
        if(pipe!=INVALID_HANDLE_VALUE||GetLastError()!=ERROR_PIPE_BUSY)break;
        ULONGLONG now=GetTickCount64();if(now>=deadline||!WaitNamedPipeW(pipe_name,(DWORD)(deadline-now)))break;
    }while(GetTickCount64()<deadline);
    if(pipe==INVALID_HANDLE_VALUE)return 0;
    ULONG peer=0;int result=0;DWORD size=0;char reply[8193];
    if(GetNamedPipeServerProcessId(pipe,&peer)&&peer==server_pid&&transfer(pipe,&length,4,1,deadline)&&transfer(pipe,request,length,1,deadline)&&transfer(pipe,&size,4,0,deadline)&&size&&size<=8192&&transfer(pipe,reply,size,0,deadline)&&GetTickCount64()<deadline) {
        reply[size]=0;jsmn_parser p;jsmntok_t t[64];jsmn_init(&p);int n=jsmn_parse(&p,reply,size,t,64);
        char schema[64],matched[65],decision[16],action[32],reason[128],version[128];
        if(shape(reply,size,t,n)&&field(reply,t,n,"schema_version",schema,sizeof(schema))&&!strcmp(schema,"transpect.protect.reply/1.0")&&
           field(reply,t,n,"attempt_id",matched,sizeof(matched))&&!strcmp(id,matched)&&field(reply,t,n,"decision",decision,sizeof(decision))&&
           field(reply,t,n,"action",action,sizeof(action))&&field(reply,t,n,"reason",reason,sizeof(reason))&&field(reply,t,n,"policy_version",version,sizeof(version))) {
            if(!strcmp(decision,"ALLOW")&&!strcmp(action,"none"))result=1;
            else if(!strcmp(decision,"BLOCK")&&!strcmp(action,"block_session")){InterlockedExchange(&session_blocked,1);result=2;}
            else if(!strcmp(decision,"BLOCK")&&!strcmp(action,"terminate_process"))TerminateProcess(GetCurrentProcess(),76);
        }
    }
    CloseHandle(pipe);return InterlockedCompareExchange(&session_blocked,0,0)?2:result;
}
typedef struct {char id[65];int result;} Execution;
static DWORD WINAPI report_execution(void *parameter) {
    Execution*event=parameter;char json[512];LARGE_INTEGER qpc;QueryPerformanceCounter(&qpc);
    int length=snprintf(json,sizeof(json),"{\"schema_version\":\"transpect.protect.execution/1.0\",\"attempt_id\":\"%s\",\"pid\":%lu,\"action\":\"%s\",\"result\":\"%s\",\"qpc\":%lld}",
        event->id,GetCurrentProcessId(),event->result==1?"none":event->result==2?"block_session":"block_request",event->result==1?"transport_authorized":"native_rejection",qpc.QuadPart);
    ULONGLONG deadline=GetTickCount64()+500;HANDLE pipe=INVALID_HANDLE_VALUE;
    do {
        pipe=CreateFileW(pipe_name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);
        if(pipe!=INVALID_HANDLE_VALUE||GetLastError()!=ERROR_PIPE_BUSY)break;
        ULONGLONG now=GetTickCount64();if(now>=deadline||!WaitNamedPipeW(pipe_name,(DWORD)(deadline-now)))break;
    }while(GetTickCount64()<deadline);
    if(pipe!=INVALID_HANDLE_VALUE) {
        ULONG peer;DWORD size=(DWORD)length,reply_size=0;char reply[8192];
        if(GetNamedPipeServerProcessId(pipe,&peer)&&peer==server_pid&&transfer(pipe,&size,4,1,deadline)&&transfer(pipe,json,size,1,deadline)&&
           transfer(pipe,&reply_size,4,0,deadline)&&reply_size&&reply_size<=sizeof(reply))transfer(pipe,reply,reply_size,0,deadline);
        CloseHandle(pipe);
    }
    HeapFree(GetProcessHeap(),0,event);InterlockedDecrement(&pending_reports);return 0;
}
static void report(const char*id,int result) {
    if(InterlockedIncrement(&pending_reports)>64){InterlockedDecrement(&pending_reports);return;}
    Execution*event=HeapAlloc(GetProcessHeap(),0,sizeof(Execution));
    if(!event){InterlockedDecrement(&pending_reports);return;}
    strcpy(event->id,id);event->result=result;
    if(!QueueUserWorkItem(report_execution,event,WT_EXECUTEDEFAULT)){HeapFree(GetProcessHeap(),0,event);InterlockedDecrement(&pending_reports);}
}
static PyObject *configure(PyObject*self,PyObject*args) {
    unsigned long pid;if(!PyArg_ParseTuple(args,"k",&pid))return NULL;
    if(server_process){PyErr_SetString(PyExc_RuntimeError,"Native gate already configured");return NULL;}
    server_process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!server_process)return PyErr_SetFromWindowsErr(0);
    server_pid=pid;swprintf(pipe_name,96,L"\\\\.\\pipe\\ttrace-protect-%lu",GetCurrentProcessId());Py_RETURN_NONE;
}
static PyObject *authorize(PyObject*self,PyObject*args) {
    const char*input,*id;Py_ssize_t size;
    if(!PyArg_ParseTuple(args,"y#s",&input,&size,&id))return NULL;
    if(size<=0||size>MAX_REQUEST||strlen(id)>64){PyErr_SetString(PyExc_PermissionError,"PROTECT_INVALID_SNAPSHOT");return NULL;}
    char*copy=HeapAlloc(GetProcessHeap(),0,size);if(!copy)return PyErr_NoMemory();memcpy(copy,input,size);
    int ok;Py_BEGIN_ALLOW_THREADS
    ok=check(copy,(DWORD)size,id);SecureZeroMemory(copy,size);HeapFree(GetProcessHeap(),0,copy);
    Py_END_ALLOW_THREADS
    if(ok!=1){PyErr_SetString(PyExc_PermissionError,"PROTECT_REQUEST_DENIED");report(id,ok);return NULL;}
    report(id,ok);
    Py_RETURN_NONE;
}
static PyMethodDef methods[]={{"configure",configure,METH_VARARGS,NULL},{"authorize",authorize,METH_VARARGS,NULL},{NULL,NULL,0,NULL}};
static struct PyModuleDef definition={PyModuleDef_HEAD_INIT,"_ttrace_native_gate",NULL,-1,methods};
PyMODINIT_FUNC PyInit__ttrace_native_gate(void){return PyModule_Create(&definition);}
