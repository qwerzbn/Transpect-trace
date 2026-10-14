/* Independent C implementation of the guard IPC, for conformance experiments.
 * This ASCII fixture matcher is NOT the general sensitive-data classifier. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "third_party/jsmn/jsmn.h"

static int read_exact(HANDLE pipe, void *data, DWORD n) {
    DWORD offset=0;
    while(offset<n) {
        DWORD got=0;
        if(!ReadFile(pipe,(char*)data+offset,n-offset,&got,NULL)||!got)return 0;
        offset+=got;
    }
    return 1;
}
static int field(const char *json,jsmntok_t *tokens,int count,const char *key,char *out,size_t size) {
    for(int i=1;i+1<count;i++) {
        if(tokens[i].parent!=0||tokens[i].type!=JSMN_STRING)continue;
        int n=tokens[i].end-tokens[i].start;
        if((size_t)n!=strlen(key)||memcmp(json+tokens[i].start,key,n))continue;
        n=tokens[i+1].end-tokens[i+1].start;
        if(tokens[i+1].type!=JSMN_STRING||n<0||(size_t)n>=size)return 0;
        memcpy(out,json+tokens[i+1].start,n);out[n]=0;return 1;
    }
    return 0;
}
int main(int argc,char **argv) {
    if(argc!=4){fprintf(stderr,"Usage: policy-fixture.exe PID ASCII_MARKER ACTION\n");return 2;}
    DWORD pid=(DWORD)strtoul(argv[1],NULL,10);
    const char *action=argv[3];
    if(strcmp(action,"block_request")&&strcmp(action,"block_session")&&strcmp(action,"terminate_process"))return 2;
    HANDLE token;DWORD needed=0;char *user=NULL;LPWSTR sid=NULL;PSECURITY_DESCRIPTOR sd=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return 3;
    GetTokenInformation(token,TokenUser,NULL,0,&needed);user=malloc(needed);
    if(!GetTokenInformation(token,TokenUser,user,needed,&needed)||
       !ConvertSidToStringSidW(((TOKEN_USER*)user)->User.Sid,&sid))return 3;
    wchar_t sddl[512];swprintf(sddl,512,L"D:P(A;;GA;;;SY)(A;;GA;;;%ls)",sid);
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,&sd,NULL))return 3;
    SECURITY_ATTRIBUTES security={sizeof(security),sd,FALSE};
    LocalFree(sid);free(user);CloseHandle(token);
    wchar_t name[128];swprintf(name,128,L"\\\\.\\pipe\\ttrace-guard-%lu",pid);
    int blocked=0;
    printf("{\"kind\":\"engine.listening\",\"engine_language\":\"C\"}\n");fflush(stdout);
    for(;;) {
        HANDLE pipe=CreateNamedPipeW(name,PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,2000,&security);
        if(pipe==INVALID_HANDLE_VALUE)return 4;
        if(!ConnectNamedPipe(pipe,NULL)&&GetLastError()!=ERROR_PIPE_CONNECTED){CloseHandle(pipe);continue;}
        ULONG peer=0;uint32_t n=0;
        if(!GetNamedPipeClientProcessId(pipe,&peer)||peer!=pid||!read_exact(pipe,&n,4)||n==0||n>100*1024*1024){CloseHandle(pipe);continue;}
        char *request=malloc((size_t)n+1);
        if(!request||!read_exact(pipe,request,n)){free(request);CloseHandle(pipe);continue;}
        request[n]=0;jsmn_parser parser;jsmntok_t tokens[128];jsmn_init(&parser);
        int count=jsmn_parse(&parser,request,n,tokens,128);
        char id[65],kind[64];
        if(count<=0||!field(request,tokens,count,"request_id",id,sizeof(id))||!field(request,tokens,count,"kind",kind,sizeof(kind))){free(request);CloseHandle(pipe);continue;}
        int deny=!strcmp(kind,"model.request")&&(blocked||strstr(request,argv[2])!=NULL);
        if(deny&&!strcmp(action,"block_session"))blocked=1;
        char reply[512];int bytes=snprintf(reply,sizeof(reply),
          "{\"schema\":\"transpect.guard.decision/1.0\",\"request_id\":\"%s\",\"decision\":\"%s\",\"action\":\"%s\",\"reason\":\"C_FIXTURE\",\"policy_version\":\"fixture-1\"}",
          id,deny?"deny":"allow",deny?action:"none");
        uint32_t length=(uint32_t)bytes;DWORD wrote;
        WriteFile(pipe,&length,4,&wrote,NULL);WriteFile(pipe,reply,length,&wrote,NULL);FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);CloseHandle(pipe);free(request);
        printf("{\"kind\":\"%s\",\"request_id\":\"%s\",\"decision\":\"%s\",\"engine_language\":\"C\"}\n",kind,id,deny?"deny":"allow");fflush(stdout);
    }
}
