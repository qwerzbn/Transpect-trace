/* Fake-data origin only. Never installs a certificate or forwards traffic. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
int wmain(int argc,wchar_t **argv){
    if(argc!=3)return 2;
    unsigned port=(unsigned)_wtoi(argv[1]);if(!port||port>65535)return 2;
    FILE *file=_wfopen(argv[2],L"rb");if(!file)return 3;
    fseek(file,0,SEEK_END);long bytes=ftell(file);rewind(file);
    if(bytes<0||bytes>1024*1024){fclose(file);return 3;}
    char *body=malloc(bytes?bytes:1);if(!body||fread(body,1,bytes,file)!=(size_t)bytes)return 3;fclose(file);
    HMODULE sspi=LoadLibraryW(L"secur32.dll");if(!sspi)return 4;
    HINTERNET session=WinHttpOpen(L"Transpect synthetic fixture",WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if(!session)return 5;
    printf("ready\n");fflush(stdout);getchar();
    HINTERNET connection=WinHttpConnect(session,L"localhost",(INTERNET_PORT)port,0);
    HINTERNET request=WinHttpOpenRequest(connection,L"POST",L"/responses",NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
    /* Only this standalone localhost fixture accepts its ephemeral test CA. */
    DWORD security=SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    WinHttpSetOption(request,WINHTTP_OPTION_SECURITY_FLAGS,&security,sizeof(security));
    int ok=WinHttpSendRequest(request,L"Content-Type: application/json\r\n",(DWORD)-1,body,(DWORD)bytes,(DWORD)bytes,0)&&WinHttpReceiveResponse(request,NULL);
    if(ok){char data[4096];DWORD got;while(WinHttpReadData(request,data,sizeof(data),&got)&&got);}
    DWORD error=ok?0:GetLastError();printf("sent\n");fflush(stdout);getchar();printf("{\"ok\":%s,\"win32_error\":%lu}\n",ok?"true":"false",error);
    WinHttpCloseHandle(request);WinHttpCloseHandle(connection);WinHttpCloseHandle(session);free(body);return ok?0:6;
}
