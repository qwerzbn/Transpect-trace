/* An isolated, non-forwarding gate test subject. stdin holds the root boundary. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
int wmain(int argc,wchar_t **argv) {
    if (argc>2 && !wcscmp(argv[1],L"root")) {
        getchar(); STARTUPINFOW startup={sizeof(startup)}; PROCESS_INFORMATION child={0};
        if (!CreateProcessW(NULL,argv[2],NULL,NULL,FALSE,0,NULL,NULL,&startup,&child)) { printf("create_failed=%lu\n",GetLastError()); return 50; }
        WaitForSingleObject(child.hProcess,20000); DWORD result=0; GetExitCodeProcess(child.hProcess,&result);
        CloseHandle(child.hThread); CloseHandle(child.hProcess); return (int)result;
    }
    if (argc<4) return 90;
    printf("child_main_started\n"); fflush(stdout);
    if (argc>5) Sleep((DWORD)_wtoi(argv[5]));
    WSADATA data; if (WSAStartup(MAKEWORD(2,2),&data)) return 91;
    int family=!wcscmp(argv[1],L"6")?AF_INET6:AF_INET;
    SOCKET socket=WSASocketW(family,SOCK_STREAM,IPPROTO_TCP,NULL,0,WSA_FLAG_OVERLAPPED);
    if (family==AF_INET6) { DWORD only=0; setsockopt(socket,IPPROTO_IPV6,IPV6_V6ONLY,(char*)&only,sizeof(only)); }
    struct sockaddr_storage storage={0}; int length;
    if (family==AF_INET) { struct sockaddr_in *a=(void*)&storage; a->sin_family=AF_INET; a->sin_port=htons((unsigned short)_wtoi(argv[3])); InetPtonW(AF_INET,argv[2],&a->sin_addr); length=sizeof(*a); }
    else { struct sockaddr_in6 *a=(void*)&storage; a->sin6_family=AF_INET6; a->sin6_port=htons((unsigned short)_wtoi(argv[3])); InetPtonW(AF_INET6,argv[2],&a->sin6_addr); length=sizeof(*a); }
    int result;
    if (argc>4 && !wcscmp(argv[4],L"wsaconnect")) result=WSAConnect(socket,(void*)&storage,length,NULL,NULL,NULL,NULL);
    else if (argc>4 && !wcscmp(argv[4],L"connectex")) {
        GUID guid=WSAID_CONNECTEX; LPFN_CONNECTEX connectex=NULL; DWORD bytes=0;
        if (WSAIoctl(socket,SIO_GET_EXTENSION_FUNCTION_POINTER,&guid,sizeof(guid),&connectex,sizeof(connectex),&bytes,NULL,NULL)) return 92;
        struct sockaddr_storage local={0}; ((struct sockaddr*)&local)->sa_family=(ADDRESS_FAMILY)family;
        if (bind(socket,(void*)&local,length)) return 93;
        OVERLAPPED ov={0}; ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
        BOOL ok=connectex(socket,(void*)&storage,length,NULL,0,&bytes,&ov);
        if (!ok && WSAGetLastError()==ERROR_IO_PENDING) { WaitForSingleObject(ov.hEvent,5000); DWORD flags=0; ok=WSAGetOverlappedResult(socket,&ov,&bytes,FALSE,&flags); }
        result=ok?0:SOCKET_ERROR; CloseHandle(ov.hEvent);
    } else result=connect(socket,(void*)&storage,length);
    int error=result?WSAGetLastError():0;
    if (!result) send(socket,"synthetic-egress",16,0);
    printf("connect_result=%d error=%d\n",result,error); closesocket(socket); WSACleanup();
    return result? (error==WSAEACCES?13:14):0;
}
