/* Independent, finite-duration multi-application ETW collector. Does not change
 * the fixed Codex collector, and never expands membership through parent PID. */
#define main original_guard_etw_main
#define TTRACE_BEHAVIOR_ETW 1
#include "../guard/etw.c"
#undef main

typedef struct { DWORD pid; ULONGLONG birth; HANDLE process; int retired; } Member;
static Member members[16];static size_t member_count;
static HANDLE finish_event;
static ULONG stop_status=ERROR_INVALID_STATE;
static int property_pid(PEVENT_RECORD record,const wchar_t *name,DWORD *value) {
    PROPERTY_DATA_DESCRIPTOR property={(ULONGLONG)(uintptr_t)name,ULONG_MAX,0};ULONG size=0;
    return TdhGetPropertySize(record,0,NULL,1,&property,&size)==ERROR_SUCCESS&&size==4&&
        TdhGetProperty(record,0,NULL,1,&property,size,(BYTE*)value)==ERROR_SUCCESS;
}
static ULONGLONG property_birth(PEVENT_RECORD record) {
    PROPERTY_DATA_DESCRIPTOR property={(ULONGLONG)(uintptr_t)L"CreateTime",ULONG_MAX,0};ULONG size=0;ULONGLONG birth=0;
    if(TdhGetPropertySize(record,0,NULL,1,&property,&size)==ERROR_SUCCESS&&size==8)
        TdhGetProperty(record,0,NULL,1,&property,size,(BYTE*)&birth);
    return birth;
}
static void WINAPI member_event(PEVENT_RECORD record) {
    DWORD pid=record->EventHeader.ProcessId;GUID *provider=&record->EventHeader.ProviderId;
    int process=!memcmp(provider,&providers[0],sizeof(GUID));
    if(process)property_pid(record,L"ProcessID",&pid);
    else if(!memcmp(provider,&providers[2],sizeof(GUID)))property_pid(record,L"PID",&pid);
    for(size_t i=0;i<member_count;i++)if(members[i].pid==pid&&!members[i].retired) {
        /* Kernel-Process also emits ThreadStart with opcode START (1). Its
         * ProcessID is the enclosing process and there is no process CreateTime.
         * Only this provider's ProcessStart task/event represents a new lifetime.
         * Treating ThreadStart as ProcessStart retired WinHTTP B on its first
         * worker thread and silently discarded all later file/network events. */
        if(process&&record->EventHeader.EventDescriptor.Id==1&&record->EventHeader.EventDescriptor.Task==1&&
           record->EventHeader.EventDescriptor.Opcode==1) {
            ULONGLONG birth=property_birth(record);
            if(!birth||birth!=members[i].birth) {
                event(record);members[i].retired=1;return;
            }
        }
        event(record);return;
    }
}
static DWORD WINAPI timer_stop(void *argument) {
    WaitForSingleObject(finish_event,(DWORD)(uintptr_t)argument*1000);
    stop_status=ControlTraceW(controller,session,properties,EVENT_TRACE_CONTROL_STOP);return 0;
}
static DWORD WINAPI stdin_stop(void *argument) {
    (void)argument;char line[32];
    while(fgets(line,sizeof(line),stdin)) {if(!strcmp(line,"stop\n")||!strcmp(line,"stop\r\n")){SetEvent(finish_event);break;}}
    return 0;
}
static int parse_member(const char *arg,Member *member) {
    char *end=NULL;unsigned long pid=strtoul(arg,&end,10);if(!pid||!end||*end!=':')return 0;
    const char *birth_start=end+1;ULONGLONG birth=strtoull(birth_start,&end,10);
    if(!birth||end==birth_start||*end)return 0;
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);if(!process)return 0;
    FILETIME times[4];ULARGE_INTEGER created;
    if(WaitForSingleObject(process,0)!=WAIT_TIMEOUT||!GetProcessTimes(process,&times[0],&times[1],&times[2],&times[3])){CloseHandle(process);return 0;}
    created.LowPart=times[0].dwLowDateTime;created.HighPart=times[0].dwHighDateTime;
    if(created.QuadPart!=birth){CloseHandle(process);return 0;}
    *member=(Member){pid,birth,process,0};return 1;
}
int main(int argc,char **argv) {
    int duration=argc>=3?atoi(argv[1]):0;ULONG status=ERROR_INVALID_PARAMETER;
    if(duration<1||duration>300||argc>18)return 2;
    for(int i=2;i<argc;i++) {
        if(!parse_member(argv[i],&members[member_count]))goto unavailable;
        for(size_t j=0;j<member_count;j++)if(members[j].pid==members[member_count].pid){CloseHandle(members[member_count].process);goto unavailable;}
        member_count++;
    }
    format_property=(FormatPropertyFn)GetProcAddress(LoadLibraryW(L"tdh.dll"),"TdhFormatProperty");
    if(!format_property){status=ERROR_PROC_NOT_FOUND;goto unavailable;}
    consumer=(TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE;
    swprintf(session,128,L"TranspectFlow-%lu",GetCurrentProcessId());
    size_t n=sizeof(EVENT_TRACE_PROPERTIES)+sizeof(session);properties=calloc(1,n);
    if(!properties){status=ERROR_OUTOFMEMORY;goto unavailable;}
    properties->Wnode.BufferSize=(ULONG)n;properties->Wnode.Flags=WNODE_FLAG_TRACED_GUID;properties->Wnode.ClientContext=1;
    properties->LogFileMode=EVENT_TRACE_REAL_TIME_MODE;properties->LoggerNameOffset=sizeof(EVENT_TRACE_PROPERTIES);
    status=StartTraceW(&controller,session,properties);if(status!=ERROR_SUCCESS)goto unavailable;
    for(int i=0;i<3;i++) {
        status=EnableTraceEx2(controller,&providers[i],EVENT_CONTROL_CODE_ENABLE_PROVIDER,TRACE_LEVEL_VERBOSE,~0ULL,0,0,NULL);
        if(status!=ERROR_SUCCESS)goto unavailable;
    }
    EVENT_TRACE_LOGFILEW log={0};log.LoggerName=session;
    log.ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD|PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback=member_event;consumer=OpenTraceW(&log);
    if(consumer==(TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE){status=GetLastError();goto unavailable;}
    finish_event=CreateEventW(NULL,TRUE,FALSE,NULL);if(!finish_event){status=GetLastError();goto unavailable;}
    HANDLE timer=CreateThread(NULL,0,timer_stop,(void*)(uintptr_t)duration,0,NULL);
    if(!timer){status=GetLastError();goto unavailable;}
    HANDLE input=CreateThread(NULL,0,stdin_stop,NULL,0,NULL);if(input)CloseHandle(input);
    LARGE_INTEGER frequency,tick;FILETIME wall;ULARGE_INTEGER ft;
    QueryPerformanceFrequency(&frequency);QueryPerformanceCounter(&tick);GetSystemTimeAsFileTime(&wall);
    ft.LowPart=wall.dwLowDateTime;ft.HighPart=wall.dwHighDateTime;
    printf("{\"kind\":\"etw.ready\",\"collector_pid\":%lu,\"scope\":\"explicit_members\",\"member_count\":%zu,\"qpc_frequency\":%lld,\"clock_qpc\":%lld,\"clock_filetime\":%llu,\"can_enforce\":false}\n",GetCurrentProcessId(),member_count,frequency.QuadPart,tick.QuadPart,ft.QuadPart);fflush(stdout);
    status=ProcessTrace(&consumer,1,NULL,NULL);WaitForSingleObject(timer,INFINITE);CloseHandle(timer);CloseTrace(consumer);
    printf("{\"kind\":\"etw.stopped\",\"status\":%lu,\"events_lost\":%lu,\"buffers_lost\":%lu,\"decode_errors\":%lu,\"counters_verified\":%s,\"can_enforce\":false}\n",status,properties->EventsLost,properties->RealTimeBuffersLost,decode_errors,stop_status==ERROR_SUCCESS?"true":"false");fflush(stdout);
    for(size_t i=0;i<member_count;i++)CloseHandle(members[i].process);CloseHandle(finish_event);free(properties);
    return status==ERROR_SUCCESS&&stop_status==ERROR_SUCCESS?0:4;
unavailable:
    printf("{\"kind\":\"etw.unavailable\",\"win32_error\":%lu,\"can_enforce\":false}\n",status);fflush(stdout);
    if(controller)ControlTraceW(controller,session,properties,EVENT_TRACE_CONTROL_STOP);
    if(consumer&&consumer!=(TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE)CloseTrace(consumer);
    for(size_t i=0;i<member_count;i++)CloseHandle(members[i].process);free(properties);return 2;
}
