/* ECW2 fake-data concurrency fixture, localhost only, no proxy or forwarding. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct {BYTE *data;DWORD bytes;INTERNET_PORT port;unsigned rounds;LONG failures;} Work;
static DWORD WINAPI requests(void *argument){
    Work *work=argument;
    HINTERNET session=WinHttpOpen(L"ECW2 synthetic fixture",WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if(!session){InterlockedIncrement(&work->failures);return 1;}
    WinHttpSetTimeouts(session,5000,5000,5000,5000);
    for(unsigned i=0;i<work->rounds;i++){
        HINTERNET conn=WinHttpConnect(session,L"localhost",work->port,0);
        HINTERNET request=conn?WinHttpOpenRequest(conn,L"POST",L"/responses",NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE):NULL;
        DWORD security=SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        /* This fixture only reaches localhost's ephemeral self-signed origin. */
        int ok=request&&WinHttpSetOption(request,WINHTTP_OPTION_SECURITY_FLAGS,&security,sizeof(security))&&
            WinHttpSendRequest(request,L"Content-Type: application/json\r\n",(DWORD)-1,work->data,work->bytes,work->bytes,0)&&WinHttpReceiveResponse(request,NULL);
        if(ok){BYTE buf[4096];DWORD got;while(WinHttpReadData(request,buf,sizeof(buf),&got)&&got);}
        if(!ok)InterlockedIncrement(&work->failures);
        if(request)WinHttpCloseHandle(request);if(conn)WinHttpCloseHandle(conn);
    }
    WinHttpCloseHandle(session);return 0;
}
int wmain(int argc,wchar_t **argv){
    if(argc!=5)return 2;
    unsigned port=_wtoi(argv[1]),parallel=_wtoi(argv[3]),rounds=_wtoi(argv[4]);
    if(!port||port>65535||!parallel||parallel>8||!rounds||rounds>8)return 2;
    FILE *file=_wfopen(argv[2],L"rb");if(!file)return 3;
    fseek(file,0,SEEK_END);long bytes=ftell(file);rewind(file);
    if(bytes<0||bytes>1024*1024){fclose(file);return 3;}
    Work work={0};work.data=malloc(bytes?bytes:1);work.bytes=(DWORD)bytes;work.port=(INTERNET_PORT)port;work.rounds=rounds;
    if(!work.data||fread(work.data,1,bytes,file)!=(size_t)bytes){fclose(file);return 3;}fclose(file);
    if(!LoadLibraryW(L"secur32.dll"))return 4;
    printf("ready\n");fflush(stdout);getchar();
    HANDLE threads[8]={0};unsigned started=0;
    for(unsigned i=0;i<parallel;i++){threads[i]=CreateThread(NULL,0,requests,&work,0,NULL);if(!threads[i])break;started++;}
    if(started!=parallel)InterlockedIncrement(&work.failures);
    if(started)WaitForMultipleObjects(started,threads,TRUE,INFINITE);
    for(unsigned i=0;i<started;i++)CloseHandle(threads[i]);
    printf("sent\n");fflush(stdout);getchar();
    SecureZeroMemory(work.data,work.bytes);free(work.data);return work.failures?5:0;
}
