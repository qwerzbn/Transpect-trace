/* Isolated IPv4/TCP loopback validation only. Dynamic APP_ID filtering is NOT
 * PID filtering. Never automatically invoke this as a response to ETW events. */
#define WIN32_LEAN_AND_MEAN
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdarg.h>
#include "wfp_ids.h"

static void record(HANDLE log,const char *format,...) {
    char line[1024];va_list args;va_start(args,format);
    int n=vsnprintf(line,sizeof(line),format,args);va_end(args);
    DWORD written=0;
    if(n>0 && n<(int)sizeof(line)){WriteFile(log,line,n,&written,NULL);FlushFileBuffers(log);}
}
static DWORD query(HANDLE engine,UINT64 id) {
    FWPM_FILTER0 *value=NULL;DWORD code=FwpmFilterGetById0(engine,id,&value);
    if(value)FwpmFreeMemory0((void **)&value);return code;
}

static int hash_file(const wchar_t *path,const wchar_t *expected) {
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(file==INVALID_HANDLE_VALUE)return 0;
    BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;
    BYTE digest[32],buffer[65536];DWORD n=0;int ok=0;
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0))goto done;
    if(BCryptCreateHash(alg,&hash,NULL,0,NULL,0,0))goto done;
    while(1){if(!ReadFile(file,buffer,sizeof(buffer),&n,NULL))goto done;if(!n)break;
        if(BCryptHashData(hash,buffer,n,0))goto done;}
    if(BCryptFinishHash(hash,digest,32,0))goto done;
    wchar_t hex[65];for(int i=0;i<32;i++)swprintf(hex+i*2,3,L"%02x",digest[i]);
    ok=!_wcsicmp(hex,expected);
done:
    if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);CloseHandle(file);return ok;
}

int wmain(int argc,wchar_t **argv) {
    /* Independent read-only BFE verification. Errors are not absence. */
    if(argc==3 && !wcscmp(argv[1],L"--query")) {
        HANDLE e=NULL;DWORD open=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,NULL,&e);
        DWORD found=open?open:query(e,_wcstoui64(argv[2],NULL,10));
        DWORD closed=e?FwpmEngineClose0(e):0;
        printf("{\"open_error\":%lu,\"query_error\":%lu,\"close_error\":%lu}\n",open,found,closed);
        return open||closed?4:0;
    }
    /* pid birth sha256 port lease_seconds report_path */
    if(argc<7)return 2;
    int bad_install=0,bad_remove=0;DWORD owner_pid=0;ULONGLONG owner_birth=0;
    const wchar_t *owner_hash=NULL;
    for(int i=7;i<argc;i++) {
        if(!wcscmp(argv[i],L"--fault-install"))bad_install=1;
        else if(!wcscmp(argv[i],L"--fault-remove"))bad_remove=1;
        else if(!wcscmp(argv[i],L"--owner") && i+3<argc && !owner_pid) {
            owner_pid=wcstoul(argv[++i],NULL,10);owner_birth=_wcstoui64(argv[++i],NULL,10);owner_hash=argv[++i];
            if(!owner_pid||!owner_birth||wcslen(owner_hash)!=64)return 2;
        } else return 2;
    }
    DWORD pid=wcstoul(argv[1],NULL,10);ULONGLONG birth=_wcstoui64(argv[2],NULL,10);
    unsigned port=wcstoul(argv[4],NULL,10),seconds=wcstoul(argv[5],NULL,10);
    if(!pid||!birth||wcslen(argv[3])!=64||!port||port>65535||!seconds||seconds>30)return 2;
    HANDLE target=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);
    if(!target)return 3;
    FILETIME times[4];wchar_t image[32768],own[32768];DWORD length=32768;
    if(!GetProcessTimes(target,&times[0],&times[1],&times[2],&times[3]) ||
       (((ULONGLONG)times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)!=birth ||
       !QueryFullProcessImageNameW(target,0,image,&length)) {CloseHandle(target);return 3;}
    /* Narrow the experiment to the sibling synthetic client; no arbitrary app blocking. */
    if(!GetModuleFileNameW(NULL,own,32768)){CloseHandle(target);return 3;}
    wchar_t *last=wcsrchr(own,L'\\');if(!last){CloseHandle(target);return 3;}
    wcscpy(last+1,L"egress_client.exe");
    if(_wcsicmp(image,own)||!hash_file(image,argv[3])||WaitForSingleObject(target,0)!=WAIT_TIMEOUT){CloseHandle(target);return 3;}
    HANDLE log=CreateFileW(argv[6],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log==INVALID_HANDLE_VALUE){CloseHandle(target);return 3;}
    /* The optional owner bounds lifetime only; it is NEVER a WFP PID condition. */
    HANDLE owner=NULL;
    if(owner_pid) {
        owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,owner_pid);
        FILETIME ot[4];wchar_t owner_image[32768];DWORD owner_length=32768;
        if(!owner || !GetProcessTimes(owner,&ot[0],&ot[1],&ot[2],&ot[3]) ||
           (((ULONGLONG)ot[0].dwHighDateTime<<32)|ot[0].dwLowDateTime)!=owner_birth ||
           !QueryFullProcessImageNameW(owner,0,owner_image,&owner_length) ||
           !hash_file(owner_image,owner_hash) || WaitForSingleObject(owner,0)!=WAIT_TIMEOUT) {
            record(log,"{\"kind\":\"filter.owner_invalid\",\"pid\":%lu}\n",owner_pid);
            if(owner)CloseHandle(owner);CloseHandle(log);CloseHandle(target);return 3;
        }
        record(log,"{\"kind\":\"filter.owner_bound\",\"pid\":%lu,\"creation_filetime\":%llu,\"lifecycle_only\":true}\n",owner_pid,owner_birth);
    }
    HANDLE engine=NULL;FWP_BYTE_BLOB *app=NULL;UINT64 id=0;DWORD code=0,remove_code=0,health_code=0;
    record(log,"{\"kind\":\"filter.preparing\",\"tick_ms\":%llu}\n",GetTickCount64());
    FWPM_SESSION0 session={0};session.flags=FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name=L"Transpect isolated loopback egress validation";
    code=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&session,&engine);if(code)goto done;
    code=FwpmGetAppIdFromFileName0(image,&app);if(code)goto done;
    FWPM_FILTER_CONDITION0 conditions[4]={0};
    conditions[0].fieldKey=FWPM_CONDITION_ALE_APP_ID;conditions[0].matchType=FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type=FWP_BYTE_BLOB_TYPE;conditions[0].conditionValue.byteBlob=app;
    conditions[1].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;conditions[1].matchType=FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type=FWP_UINT32;conditions[1].conditionValue.uint32=0x7f000001;
    conditions[2].fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;conditions[2].matchType=FWP_MATCH_EQUAL;
    conditions[2].conditionValue.type=FWP_UINT16;conditions[2].conditionValue.uint16=(UINT16)port;
    conditions[3].fieldKey=FWPM_CONDITION_IP_PROTOCOL;conditions[3].matchType=FWP_MATCH_EQUAL;
    conditions[3].conditionValue.type=FWP_UINT8;conditions[3].conditionValue.uint8=IPPROTO_TCP;
    FWPM_FILTER0 filter={0};filter.displayData.name=L"Transpect synthetic client loopback only";
    filter.layerKey=FWPM_LAYER_ALE_AUTH_CONNECT_V4;filter.subLayerKey=FWPM_SUBLAYER_UNIVERSAL;
    filter.action.type=FWP_ACTION_BLOCK;filter.weight.type=FWP_EMPTY;
    filter.numFilterConditions=4;filter.filterCondition=conditions;
    /* Explicit local fault injection: a nonexistent layer, never a system filter. */
    if(bad_install)ZeroMemory(&filter.layerKey,sizeof(filter.layerKey));
    code=FwpmFilterAdd0(engine,&filter,NULL,&id);if(code)goto done;
    health_code=query(engine,id);
    if(health_code)goto done;
    record(log,"{\"kind\":\"filter.installed\",\"filter_id\":%llu,\"pid\":%lu,\"creation_filetime\":%llu,\"tick_ms\":%llu,\"readback_error\":0,\"scope\":\"image_path_ipv4_tcp_loopback_port\",\"pid_exact_filter\":false}\n",id,pid,birth,GetTickCount64());
    ULONGLONG deadline=GetTickCount64()+seconds*1000;
    const char *stop_reason="deadline";
    while(GetTickCount64()<deadline) {
        if(WaitForSingleObject(target,0)!=WAIT_TIMEOUT){stop_reason="target_exit";break;}
        if(owner && WaitForSingleObject(owner,0)!=WAIT_TIMEOUT){stop_reason="owner_exit";break;}
        health_code=query(engine,id);
        record(log,"{\"kind\":\"filter.health\",\"filter_id\":%llu,\"tick_ms\":%llu,\"query_error\":%lu}\n",id,GetTickCount64(),health_code);
        if(health_code){stop_reason="health_failed";break;}
        /* Optional harness revoke command. No waiting on target or network threads. */
        DWORD available=0;HANDLE input=GetStdHandle(STD_INPUT_HANDLE);
        if(PeekNamedPipe(input,NULL,0,NULL,&available,NULL)&&available){char cmd[32];DWORD n=0;
            if(ReadFile(input,cmd,sizeof(cmd),&n,NULL)&&n){stop_reason="explicit_revoke";break;}}
        Sleep(200);
    }
    record(log,"{\"kind\":\"filter.stopping\",\"reason\":\"%s\",\"tick_ms\":%llu}\n",stop_reason,GetTickCount64());
    if(bad_remove){
        /* A different session cannot remove this dynamic filter. Real API error,
         * deliberately injected; the owning session still closes below. */
        HANDLE other=NULL;FWPM_SESSION0 other_session={0};other_session.flags=FWPM_SESSION_FLAG_DYNAMIC;
        remove_code=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&other_session,&other);
        if(!remove_code)remove_code=FwpmFilterDeleteById0(other,id);
        if(other)FwpmEngineClose0(other);
    } else remove_code=FwpmFilterDeleteById0(engine,id);
    record(log,"{\"kind\":\"filter.remove\",\"filter_id\":%llu,\"error\":%lu,\"injected_wrong_session\":%s}\n",id,remove_code,bad_remove?"true":"false");
done:
    if(app)FwpmFreeMemory0((void **)&app);
    DWORD close_code=engine?FwpmEngineClose0(engine):0;
    record(log,"{\"kind\":\"filter.closed\",\"install_error\":%lu,\"remove_error\":%lu,\"health_error\":%lu,\"close_error\":%lu,\"filter_id\":%llu,\"tick_ms\":%llu}\n",code,remove_code,health_code,close_code,id,GetTickCount64());
    CloseHandle(log);CloseHandle(target);if(owner)CloseHandle(owner);
    return code||close_code||remove_code||health_code?4:0;
}
