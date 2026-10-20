/* ETW observation only. Emits TDH-decoded metadata, never request bodies. */
#define WIN32_LEAN_AND_MEAN
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef ULONG (WINAPI *FormatPropertyFn)(PTRACE_EVENT_INFO,PEVENT_MAP_INFO,ULONG,USHORT,USHORT,
                                        USHORT,USHORT,PBYTE,PULONG,PWCHAR,PUSHORT);
static FormatPropertyFn format_property;
static const GUID system_trace={0x9e814aad,0x3204,0x11d2,{0x9a,0x82,0x00,0x60,0x08,0xa8,0x69,0x39}};
static const GUID providers[]={
    {0x22fb2cd6,0x0e7b,0x422b,{0xa0,0xc7,0x2f,0xad,0x1f,0xd0,0xe7,0x16}},
    {0xedd08927,0x9cc4,0x4e65,{0xb9,0x70,0xc2,0x56,0x0f,0xb5,0xc2,0x89}},
    {0x7dd42a49,0x5329,0x4832,{0x8d,0xfd,0x43,0xd9,0x79,0x15,0x3a,0x88}}
};
static TRACEHANDLE controller,consumer;
static EVENT_TRACE_PROPERTIES *properties;
static wchar_t session[128];
static unsigned long long sequence;
static unsigned long decode_errors;
static int metadata_property(const wchar_t *name) {
#ifdef TTRACE_BEHAVIOR_ETW
    /* Kernel-File Create uses OpenPath. Only the independent behavior build
     * enables this additional metadata field; fixed Guard builds are unchanged. */
    if(!_wcsicmp(name,L"OpenPath")||!_wcsicmp(name,L"IssuingThreadId"))return 1;
#endif
    const wchar_t *allowed[]={L"ProcessID",L"ProcessId",L"ParentProcessID",L"ParentProcessId",
        L"ThreadID",L"ThreadId",L"TTID",L"CreateTime",L"FileObject",L"FileKey",L"FileName",
        L"FilePath",L"IoSize",L"ByteOffset",L"saddr",L"daddr",L"sport",L"dport",L"size",
        L"PID",L"TID",L"ImageName",L"ImageFileName"};
    for(size_t i=0;i<sizeof(allowed)/sizeof(allowed[0]);i++)
        if(!_wcsicmp(name,allowed[i]))return 1;
    return 0;
}
static void quote(const wchar_t *value) {
    int bytes=WideCharToMultiByte(CP_UTF8,0,value,-1,NULL,0,NULL,NULL);
    char *text=malloc(bytes?bytes:1);
    if(bytes)WideCharToMultiByte(CP_UTF8,0,value,-1,text,bytes,NULL,NULL);else text[0]=0;
    putchar('"');
    for(char *p=text;*p;p++) {
        unsigned char x=(unsigned char)*p;
        if(x=='"'||x=='\\')printf("\\%c",x);
        else if(x<32)printf("\\u%04x",x);
        else putchar(x);
    }
    putchar('"');free(text);
}
static void WINAPI event(PEVENT_RECORD record) {
    DWORD size=0;
    if(TdhGetEventInformation(record,0,NULL,NULL,&size)!=ERROR_INSUFFICIENT_BUFFER){decode_errors++;return;}
    TRACE_EVENT_INFO *info=malloc(size);
    if(!info||TdhGetEventInformation(record,0,NULL,info,&size)!=ERROR_SUCCESS){decode_errors++;free(info);return;}
    GUID *g=&record->EventHeader.ProviderId;wchar_t guid[64];
    swprintf(guid,64,L"{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
             g->Data1,g->Data2,g->Data3,g->Data4[0],g->Data4[1],g->Data4[2],g->Data4[3],
             g->Data4[4],g->Data4[5],g->Data4[6],g->Data4[7]);
    printf("{\"kind\":\"etw.event\",\"sequence\":%llu,\"header_pid\":%lu,\"header_tid\":%lu,\"timestamp_qpc\":%lld,\"opcode\":%u,\"provider\":",
           ++sequence,record->EventHeader.ProcessId,record->EventHeader.ThreadId,
           (long long)record->EventHeader.TimeStamp.QuadPart,record->EventHeader.EventDescriptor.Opcode);
    quote(guid);printf(",\"task\":");quote(info->TaskNameOffset?(wchar_t*)((char*)info+info->TaskNameOffset):L"");
    printf(",\"properties\":{");int first=1;
    for(DWORD i=0;i<info->TopLevelPropertyCount;i++) {
        EVENT_PROPERTY_INFO *item=&info->EventPropertyInfoArray[i];
        if(item->Flags&PropertyStruct)continue;
        wchar_t *name=(wchar_t*)((char*)info+item->NameOffset);
        /* Process command lines and arbitrary payload properties may contain
         * credentials. Persist only the declared evidence metadata. */
        if(!metadata_property(name))continue;
        PROPERTY_DATA_DESCRIPTOR property={(ULONGLONG)(uintptr_t)name,ULONG_MAX,0};
        ULONG n=0;
        if(TdhGetPropertySize(record,0,NULL,1,&property,&n)!=ERROR_SUCCESS||n>65536)continue;
        BYTE *data=malloc(n?n:1);
        if(!data||TdhGetProperty(record,0,NULL,1,&property,n,data)!=ERROR_SUCCESS){free(data);continue;}
#ifdef TTRACE_BEHAVIOR_ETW
        /* TDH InType 1 is a UTF-16 null-terminated string. TdhGetProperty already
         * returns its bytes. Passing byte length as TdhFormatProperty's string
         * length can drop these fields; bound and terminate the returned bytes. */
        if(item->nonStructType.InType==1 && n%sizeof(wchar_t)==0) {
            wchar_t *value=calloc(1,n+sizeof(wchar_t));
            if(value){memcpy(value,data,n);if(!first)putchar(',');first=0;quote(name);putchar(':');quote(value);free(value);}
            else decode_errors++;
            free(data);continue;
        }
#endif
        if(!_wcsicmp(name,L"CreateTime") && n==8) {
            unsigned long long created;memcpy(&created,data,8);
            if(!first)putchar(',');first=0;quote(name);printf(":\"%llu\"",created);
            free(data);continue;
        }
        ULONG output_bytes=0;USHORT consumed=0;
        ULONG status=format_property(info,NULL,(record->EventHeader.Flags&EVENT_HEADER_FLAG_32_BIT_HEADER)?4:8,
             item->nonStructType.InType,item->nonStructType.OutType,(USHORT)n,(USHORT)n,data,&output_bytes,NULL,&consumed);
        wchar_t *output=status==ERROR_INSUFFICIENT_BUFFER?malloc(output_bytes):NULL;
        if(output&&format_property(info,NULL,(record->EventHeader.Flags&EVENT_HEADER_FLAG_32_BIT_HEADER)?4:8,
             item->nonStructType.InType,item->nonStructType.OutType,(USHORT)n,(USHORT)n,data,&output_bytes,output,&consumed)==ERROR_SUCCESS) {
            if(!first)putchar(',');first=0;quote(name);putchar(':');quote(output);
        }
        free(output);free(data);
    }
    printf("},\"byte_level_taint_proof\":false}\n");fflush(stdout);free(info);
}
static BOOL WINAPI stop(DWORD reason) {
    (void)reason;
    if(controller)ControlTraceW(controller,session,properties,EVENT_TRACE_CONTROL_STOP);
    if(consumer!=(TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE)CloseTrace(consumer);
    return TRUE;
}
int main(void) {
    format_property=(FormatPropertyFn)GetProcAddress(LoadLibraryW(L"tdh.dll"),"TdhFormatProperty");
    if(!format_property){printf("{\"kind\":\"etw.unavailable\",\"reason\":\"TDH formatter unavailable\"}\n");return 2;}
    consumer=(TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE;
    swprintf(session,128,L"TranspectGuard-%lu",GetCurrentProcessId());
    size_t n=sizeof(EVENT_TRACE_PROPERTIES)+sizeof(session);
    properties=calloc(1,n);properties->Wnode.BufferSize=(ULONG)n;
    properties->Wnode.Flags=WNODE_FLAG_TRACED_GUID;properties->Wnode.ClientContext=1;
    properties->LogFileMode=EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset=sizeof(EVENT_TRACE_PROPERTIES);
    ULONG status=StartTraceW(&controller,session,properties);
    if(status!=ERROR_SUCCESS) {
        printf("{\"kind\":\"etw.unavailable\",\"win32_error\":%lu,\"requires_elevated_kernel_trace_privilege\":true,\"byte_level_taint_proof\":false}\n",status);
        free(properties);return 2;
    }
    for(int i=0;i<3;i++) {
        ULONG enabled=EnableTraceEx2(controller,&providers[i],EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                     TRACE_LEVEL_VERBOSE,~0ULL,0,0,NULL);
        if(enabled!=ERROR_SUCCESS) {
            printf("{\"kind\":\"etw.unavailable\",\"win32_error\":%lu,\"provider_index\":%d,\"byte_level_taint_proof\":false}\n",enabled,i);
            ControlTraceW(controller,session,properties,EVENT_TRACE_CONTROL_STOP);free(properties);return 2;
        }
    }
    SetConsoleCtrlHandler(stop,TRUE);
    EVENT_TRACE_LOGFILEW log={0};log.LoggerName=session;
    log.ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD|PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback=event;
    consumer=OpenTraceW(&log);
    if(consumer==(TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE){stop(0);return 3;}
    LARGE_INTEGER frequency,tick;FILETIME wall;ULARGE_INTEGER filetime;
    QueryPerformanceFrequency(&frequency);QueryPerformanceCounter(&tick);GetSystemTimeAsFileTime(&wall);
    filetime.LowPart=wall.dwLowDateTime;filetime.HighPart=wall.dwHighDateTime;
    printf("{\"kind\":\"etw.ready\",\"collector_pid\":%lu,\"qpc_frequency\":%lld,\"clock_qpc\":%lld,\"clock_filetime\":%llu,\"byte_level_taint_proof\":false}\n",
           GetCurrentProcessId(),frequency.QuadPart,tick.QuadPart,filetime.QuadPart);fflush(stdout);
    status=ProcessTrace(&consumer,1,NULL,NULL);
    ControlTraceW(controller,session,properties,EVENT_TRACE_CONTROL_QUERY);
    printf("{\"kind\":\"etw.stopped\",\"status\":%lu,\"events_lost\":%lu,\"buffers_lost\":%lu,\"decode_errors\":%lu,\"byte_level_taint_proof\":false}\n",
           status,properties->EventsLost,properties->RealTimeBuffersLost,decode_errors);
    stop(0);free(properties);return status==ERROR_SUCCESS?0:4;
}
