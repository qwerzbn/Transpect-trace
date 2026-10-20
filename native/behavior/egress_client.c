/* Synthetic local-only source oracle client. Never used as a production hook. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int once=argc==3&&!strcmp(argv[2],"--once");
    int ipv6=argc==3&&!strcmp(argv[2],"--ipv6");
    int udp=argc==3&&!strcmp(argv[2],"--udp");
    int persistent=argc==3&&!strcmp(argv[2],"--persistent");
    int port=(argc==2||once||ipv6||udp||persistent)?atoi(argv[1]):0;
    if(port<1||port>65535)return 2;
    WSADATA wsa;if(WSAStartup(MAKEWORD(2,2),&wsa))return 2;
    char line[32];
    SOCKET retained=INVALID_SOCKET;
    while(once||fgets(line,sizeof(line),stdin)) {
        if(!once&&!strncmp(line,"quit",4))break;
        SOCKET s=retained!=INVALID_SOCKET?retained:socket(ipv6?AF_INET6:AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,udp?IPPROTO_UDP:IPPROTO_TCP);
        DWORD timeout=2000;setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(timeout));
        struct sockaddr_in address={0};address.sin_family=AF_INET;
        address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons((u_short)port);
        struct sockaddr_in6 address6={0};address6.sin6_family=AF_INET6;
        address6.sin6_addr.u.Byte[15]=1;address6.sin6_port=htons((u_short)port);
        int result=retained!=INVALID_SOCKET?0:connect(s,ipv6?(struct sockaddr *)&address6:(struct sockaddr *)&address,ipv6?sizeof(address6):sizeof(address));
        int error=result==SOCKET_ERROR?WSAGetLastError():0;
        const char *stage=error?"connect":"none";
        const char payload[]="synthetic-egress-fixture";
        int bytes=error?0:send(s,payload,sizeof(payload)-1,0);
        if(bytes<0){error=WSAGetLastError();bytes=0;stage="send";}
        if(persistent&&!error)retained=s;else{closesocket(s);retained=INVALID_SOCKET;}
        printf("{\"connect_error\":%d,\"sent_bytes\":%d,\"failure_stage\":\"%s\",\"tick_ms\":%llu}\n",error,bytes,stage,GetTickCount64());fflush(stdout);
        if(once){Sleep(2000);break;} /* Keep the synthetic child alive for identity evidence. */
    }
    if(retained!=INVALID_SOCKET)closesocket(retained);
    WSACleanup();return 0;
}
