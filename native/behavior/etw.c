/* Reuse the existing metadata-only TDH decoder. The fixed Guard binary is not
 * rebuilt. This separate finite-duration collector verifies STOP counters. */
#define main original_guard_etw_main
#define TTRACE_BEHAVIOR_ETW 1
#include "../guard/etw.c"
#undef main

static ULONG final_stop_status = ERROR_INVALID_STATE;
static DWORD scope_pids[8192], scope_count;
static int scope_enabled;
static int scoped(DWORD pid) {
    for(DWORD i=0;i<scope_count;i++)if(scope_pids[i]==pid)return 1;
    return 0;
}
static int property_pid(PEVENT_RECORD record,const wchar_t *name,DWORD *value) {
    PROPERTY_DATA_DESCRIPTOR property={(ULONGLONG)(uintptr_t)name,ULONG_MAX,0};ULONG size=0;
    return TdhGetPropertySize(record,0,NULL,1,&property,&size)==ERROR_SUCCESS && size==4 &&
           TdhGetProperty(record,0,NULL,1,&property,size,(BYTE *)value)==ERROR_SUCCESS;
}
static void WINAPI scoped_event(PEVENT_RECORD record) {
    /* Optimization only: Python still verifies PID+birth and parent lifetime.
     * Avoid TDH string formatting/JSON for unrelated high-volume file events. */
    if(!scope_enabled){event(record);return;}
    DWORD pid=record->EventHeader.ProcessId;
    GUID *provider=&record->EventHeader.ProviderId;
    if(!memcmp(provider,&providers[0],sizeof(GUID))) {
        property_pid(record,L"ProcessID",&pid);
        DWORD parent=0;
        if(record->EventHeader.EventDescriptor.Opcode==1 && property_pid(record,L"ParentProcessID",&parent)) {
            if(scoped(parent)&&!scoped(pid)) {
                if(scope_count<8192)scope_pids[scope_count++]=pid;
                else decode_errors++;
            } else if(!scoped(parent)&&scoped(pid)) {
                /* Forward the new generation once so the strict consumer retires
                 * the old identity; suppress its subsequent unrelated events. */
                event(record);
                for(DWORD i=0;i<scope_count;i++)if(scope_pids[i]==pid){scope_pids[i]=scope_pids[--scope_count];break;}
                return;
            }
        }
    } else if(!memcmp(provider,&providers[2],sizeof(GUID)))property_pid(record,L"PID",&pid);
    if(scoped(pid))event(record);
}
typedef struct {ULONG count;ULONG reserved;EVENT_DESCRIPTOR events[1];} ManifestEvents;
static int describe_file_schema(void) {
    HMODULE tdh=LoadLibraryW(L"tdh.dll");
    typedef ULONG (WINAPI *EnumFn)(GUID*,ManifestEvents*,ULONG*);
    typedef ULONG (WINAPI *InfoFn)(GUID*,EVENT_DESCRIPTOR*,TRACE_EVENT_INFO*,ULONG*);
    EnumFn enumerate=(EnumFn)GetProcAddress(tdh,"TdhEnumerateManifestProviderEvents");
    InfoFn describe=(InfoFn)GetProcAddress(tdh,"TdhGetManifestEventInformation");
    if(!enumerate||!describe)return 2;
    GUID provider=providers[1];ULONG size=0;
    if(enumerate(&provider,NULL,&size)!=ERROR_INSUFFICIENT_BUFFER)return 2;
    ManifestEvents *events=malloc(size);if(!events)return 2;
    if(enumerate(&provider,events,&size)){free(events);return 2;}
    for(ULONG i=0;i<events->count;i++) {
        size=0;if(describe(&provider,&events->events[i],NULL,&size)!=ERROR_INSUFFICIENT_BUFFER)continue;
        TRACE_EVENT_INFO *info=malloc(size);if(!info)continue;
        if(!describe(&provider,&events->events[i],info,&size)) {
            printf("{\"event_id\":%u,\"task\":",events->events[i].Id);
            quote(info->TaskNameOffset?(wchar_t*)((char*)info+info->TaskNameOffset):L"");
            printf(",\"fields\":[");
            for(ULONG j=0;j<info->TopLevelPropertyCount;j++) {
                if(j)putchar(',');quote((wchar_t*)((char*)info+info->EventPropertyInfoArray[j].NameOffset));
            }
            printf("]}\n");
        }
        free(info);
    }
    free(events);return 0;
}
static DWORD WINAPI timed_stop(void *argument) {
    Sleep((DWORD)(uintptr_t)argument * 1000);
    final_stop_status = ControlTraceW(controller, session, properties, EVENT_TRACE_CONTROL_STOP);
    return 0;
}

int main(int argc, char **argv) {
    if(argc==2&&!strcmp(argv[1],"--schema"))return describe_file_schema();
    int duration = (argc == 2 || argc == 3) ? atoi(argv[1]) : 0;
    if(duration < 1 || duration > 300) return 2;
    if(argc==3){DWORD root=strtoul(argv[2],NULL,10);if(!root)return 2;scope_enabled=1;scope_pids[scope_count++]=root;}
    format_property=(FormatPropertyFn)GetProcAddress(LoadLibraryW(L"tdh.dll"),"TdhFormatProperty");
    if(!format_property) return 2;
    swprintf(session,128,L"TranspectBehavior-%lu",GetCurrentProcessId());
    size_t n=sizeof(EVENT_TRACE_PROPERTIES)+sizeof(session);
    properties=calloc(1,n);properties->Wnode.BufferSize=(ULONG)n;
    properties->Wnode.Flags=WNODE_FLAG_TRACED_GUID;properties->Wnode.ClientContext=1;
    properties->LogFileMode=EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset=sizeof(EVENT_TRACE_PROPERTIES);
    ULONG status=StartTraceW(&controller,session,properties);
    if(status!=ERROR_SUCCESS) goto unavailable;
    for(int i=0;i<3;i++) {
        status=EnableTraceEx2(controller,&providers[i],EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                             TRACE_LEVEL_VERBOSE,~0ULL,0,0,NULL);
        if(status!=ERROR_SUCCESS) goto unavailable;
    }
    EVENT_TRACE_LOGFILEW log={0};log.LoggerName=session;
    log.ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD|PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback=scoped_event;
    consumer=OpenTraceW(&log);
    if(consumer==(TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE){status=GetLastError();goto unavailable;}
    LARGE_INTEGER frequency,tick;FILETIME wall;ULARGE_INTEGER ft;
    QueryPerformanceFrequency(&frequency);QueryPerformanceCounter(&tick);GetSystemTimeAsFileTime(&wall);
    ft.LowPart=wall.dwLowDateTime;ft.HighPart=wall.dwHighDateTime;
    HANDLE timer=CreateThread(NULL,0,timed_stop,(void *)(uintptr_t)duration,0,NULL);
    if(!timer){status=GetLastError();goto unavailable;}
    printf("{\"kind\":\"etw.ready\",\"collector_pid\":%lu,\"qpc_frequency\":%lld,\"clock_qpc\":%lld,\"clock_filetime\":%llu}\n",
           GetCurrentProcessId(),frequency.QuadPart,tick.QuadPart,ft.QuadPart);fflush(stdout);
    status=ProcessTrace(&consumer,1,NULL,NULL);
    WaitForSingleObject(timer,INFINITE);CloseHandle(timer);CloseTrace(consumer);
    printf("{\"kind\":\"etw.stopped\",\"status\":%lu,\"events_lost\":%lu,\"buffers_lost\":%lu,\"decode_errors\":%lu,\"counters_verified\":%s}\n",
           status,properties->EventsLost,properties->RealTimeBuffersLost,decode_errors,
           final_stop_status==ERROR_SUCCESS?"true":"false");
    free(properties);return status==ERROR_SUCCESS && final_stop_status==ERROR_SUCCESS?0:4;
unavailable:
    printf("{\"kind\":\"etw.unavailable\",\"win32_error\":%lu}\n",status);fflush(stdout);
    if(controller)ControlTraceW(controller,session,properties,EVENT_TRACE_CONTROL_STOP);
    free(properties);return 2;
}
