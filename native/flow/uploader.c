/* Controlled participant B. Fixture markers are truth, not collector evidence.
 * Does no source/handoff/network I/O before stdin "release". */
#define WIN32_LEAN_AND_MEAN
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define LIMIT (1024u * 1024u)
static const wchar_t *pipe_prefix=L"\\\\.\\pipe\\TranspectFlowBusiness-";
static int command(const char *expected) {
    char line[32];if(!fgets(line,sizeof(line),stdin))return 0;
    line[strcspn(line,"\r\n")]=0;return !strcmp(line,expected);
}
static void mark(const char *kind) {
    printf("{\"kind\":\"%s\",\"evidence_origin\":\"fixture_truth\"}\n",kind);fflush(stdout);
}
static int fail(const char *stage,DWORD error) {
    printf("{\"kind\":\"error\",\"evidence_origin\":\"fixture_truth\",\"stage\":\"%s\",\"win32_error\":%lu}\n",stage,error);fflush(stdout);return 2;
}
static BYTE *receive(const wchar_t *path,int pipe,DWORD *length) {
    HANDLE h=INVALID_HANDLE_VALUE;BYTE *body=NULL;DWORD used=0;
    if(pipe) {
        size_t prefix=wcslen(pipe_prefix);
        if(wcsncmp(path,pipe_prefix,prefix)||!path[prefix]||wcschr(path+prefix,L'\\')) {SetLastError(ERROR_INVALID_NAME);return NULL;}
        h=CreateNamedPipeW(path,PIPE_ACCESS_INBOUND|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,
            1,65536,65536,10000,NULL);
        if(h==INVALID_HANDLE_VALUE)return NULL;
        mark("pipe_ready");
        if(!ConnectNamedPipe(h,NULL)&&GetLastError()!=ERROR_PIPE_CONNECTED)goto error;
    } else h=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE)return NULL;
    body=malloc(LIMIT+1);if(!body){SetLastError(ERROR_OUTOFMEMORY);goto error;}
    for(;;) {
        DWORD got=0,room=(LIMIT+1-used)>65536?65536:LIMIT+1-used;
        BOOL ok=ReadFile(h,body+used,room,&got,NULL);DWORD error=ok?0:GetLastError();
        if(!ok&&(!pipe||error!=ERROR_MORE_DATA)){SetLastError(error);goto error;}
        used+=got;if(used>LIMIT){SetLastError(ERROR_BUFFER_OVERFLOW);goto error;}
        if(pipe) {if(ok)break;if(!got){SetLastError(ERROR_INVALID_DATA);goto error;}}
        else if(!got)break;
    }
    CloseHandle(h);*length=used;return body;
error: {
    DWORD error=GetLastError();if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);free(body);SetLastError(error);return NULL;
}}
static int upload(const wchar_t *url,const BYTE *body,DWORD length,int json) {
    wchar_t host[256],path[256],extra[256],user[64],pass[64];URL_COMPONENTS parts={0};parts.dwStructSize=sizeof(parts);
    parts.lpszHostName=host;parts.dwHostNameLength=256;parts.lpszUrlPath=path;parts.dwUrlPathLength=256;
    parts.lpszExtraInfo=extra;parts.dwExtraInfoLength=256;parts.lpszUserName=user;parts.dwUserNameLength=64;
    parts.lpszPassword=pass;parts.dwPasswordLength=64;
    if(!WinHttpCrackUrl(url,0,0,&parts))return fail("url",GetLastError());
    if(parts.nScheme!=INTERNET_SCHEME_HTTPS||_wcsicmp(host,L"localhost")||wcscmp(path,L"/upload")||
       parts.dwExtraInfoLength||parts.dwUserNameLength||parts.dwPasswordLength)return fail("url_scope",ERROR_ACCESS_DENIED);
    HINTERNET session=NULL,connect=NULL,request=NULL;DWORD error=0,status=0,size=sizeof(status);
    session=WinHttpOpen(L"TranspectFlowFixture/1",WINHTTP_ACCESS_TYPE_NO_PROXY,NULL,NULL,0);
    if(!session)goto done;
    if(!WinHttpSetTimeouts(session,10000,10000,10000,10000))goto done;
    DWORD protocols=0; /* WinHTTP HTTP/2 and HTTP/3 upgrades are not this fixture. */
    if(!WinHttpSetOption(session,WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,&protocols,sizeof(protocols)))goto done;
    connect=WinHttpConnect(session,host,parts.nPort,0);if(!connect)goto done;
    request=WinHttpOpenRequest(connect,L"POST",L"/upload",L"HTTP/1.1",WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
    if(!request)goto done;
    /* No redirects, implicit credentials, proxy, security-ignore flags or protocol
     * upgrade. Server trust/name/date checks remain WinHTTP defaults. */
    DWORD redirect=WINHTTP_OPTION_REDIRECT_POLICY_NEVER,disable=WINHTTP_DISABLE_COOKIES|WINHTTP_DISABLE_AUTHENTICATION;
    if(!WinHttpSetOption(request,WINHTTP_OPTION_REDIRECT_POLICY,&redirect,sizeof(redirect))||
       !WinHttpSetOption(request,WINHTTP_OPTION_DISABLE_FEATURE,&disable,sizeof(disable)))goto done;
    const wchar_t *headers=json?L"Content-Type: application/json\r\nConnection: close\r\n":L"Content-Type: text/plain; charset=utf-8\r\nConnection: close\r\n";
    if(!WinHttpSendRequest(request,headers,(DWORD)-1,(void*)body,length,length,0)||!WinHttpReceiveResponse(request,NULL)||
       !WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,NULL,&status,&size,NULL))goto done;
    if(status<200||status>=300){SetLastError(ERROR_WINHTTP_INVALID_SERVER_RESPONSE);goto done;}
    /* Complete response before releasing fixture; bounded drain. */
    for(DWORD total=0;;) {
        BYTE buffer[4096];DWORD got=0;if(!WinHttpReadData(request,buffer,sizeof(buffer),&got))goto done;
        total+=got;if(total>LIMIT){SetLastError(ERROR_BUFFER_OVERFLOW);goto done;}if(!got)break;
    }
    printf("{\"kind\":\"sent\",\"evidence_origin\":\"fixture_truth\",\"bytes\":%lu,\"http_status\":%lu}\n",length,status);fflush(stdout);
    error=0;goto cleanup;
done:error=GetLastError();if(!error)error=ERROR_GEN_FAILURE;
cleanup:
    if(request)WinHttpCloseHandle(request);if(connect)WinHttpCloseHandle(connect);if(session)WinHttpCloseHandle(session);
    return error?fail("upload",error):0;
}
int wmain(int argc,wchar_t **argv) {
    const wchar_t *scenario=NULL,*handoff=NULL,*url=NULL;int ordinary=0,json=0;
    for(int i=1;i<argc;i++) {
        if(!wcscmp(argv[i],L"--ordinary-body"))ordinary=1;
        else if(!wcscmp(argv[i],L"--content-type")&&i+1<argc){const wchar_t *value=argv[++i];if(!wcscmp(value,L"json"))json=1;else if(wcscmp(value,L"text"))return 2;}
        else if(!wcscmp(argv[i],L"--scenario")&&i+1<argc)scenario=argv[++i];
        else if(!wcscmp(argv[i],L"--handoff")&&i+1<argc)handoff=argv[++i];
        else if(!wcscmp(argv[i],L"--url")&&i+1<argc)url=argv[++i];else return 2;
    }
    if(!scenario||!handoff||!url||(wcscmp(scenario,L"file")&&wcscmp(scenario,L"pipe")))return 2;
    printf("{\"kind\":\"ready\",\"pid\":%lu,\"evidence_origin\":\"fixture_truth\"}\n",GetCurrentProcessId());fflush(stdout);
    if(!command("release"))return fail("release",ERROR_INVALID_DATA);
    DWORD length=0;BYTE *body=receive(handoff,!wcscmp(scenario,L"pipe"),&length);if(!body)return fail("receive",GetLastError());
    printf("{\"kind\":\"received\",\"evidence_origin\":\"fixture_truth\",\"bytes\":%lu}\n",length);fflush(stdout);
    static const BYTE benign[]="ordinary fixture report";
    int result=upload(url,ordinary?benign:body,ordinary?(DWORD)sizeof(benign)-1:length,json&&!ordinary);
    SecureZeroMemory(body,length);free(body);if(result)return result;
    if(!command("finish"))return fail("finish",ERROR_INVALID_DATA);mark("finished");return 0;
}
