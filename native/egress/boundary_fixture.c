/* Synthetic loopback boundary probe. Never a protection component. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static const char before[]="boundary-existing-before-ready";
static const char after[]="boundary-existing-after-ready";
static const char datagram[]="boundary-unconnected-udp";

static struct sockaddr_in destination(unsigned short port) {
    struct sockaddr_in value={0};value.sin_family=AF_INET;
    value.sin_addr.s_addr=htonl(INADDR_LOOPBACK);value.sin_port=htons(port);return value;
}
static int failure(const char *stage,int error) {
    printf("{\"kind\":\"fixture.failure\",\"stage\":\"%s\",\"error\":%d}\n",stage,error);fflush(stdout);return 80;
}
int wmain(int argc,wchar_t **argv) {
    if(argc<4)return 90;
    unsigned tcp=(unsigned)_wtoi(argv[2]),udp=(unsigned)_wtoi(argv[3]);
    if(!tcp||tcp>65535||!udp||udp>65535)return 91;
    WSADATA data;if(WSAStartup(MAKEWORD(2,2),&data))return 92;
    struct sockaddr_in tcp_address=destination((unsigned short)tcp),udp_address=destination((unsigned short)udp);
    if(!wcscmp(argv[1],L"root")) {
        SOCKET existing=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,WSA_FLAG_OVERLAPPED);
        if(existing==INVALID_SOCKET)return failure("root_socket",WSAGetLastError());
        if(!SetHandleInformation((HANDLE)existing,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT))return failure("socket_inheritance",(int)GetLastError());
        if(connect(existing,(void*)&tcp_address,sizeof(tcp_address)))return failure("pre_ready_connect",WSAGetLastError());
        int count=send(existing,before,(int)sizeof(before)-1,0);
        if(count!=(int)sizeof(before)-1)return failure("pre_ready_send",WSAGetLastError());
        printf("{\"kind\":\"fixture.preexisting_ready\",\"pid\":%lu,\"sent_bytes\":%d,\"socket_inheritable\":true}\n",GetCurrentProcessId(),count);fflush(stdout);
        if(getchar()==EOF)return failure("root_input_not_released",0);
        wchar_t image[32768],command[65536];
        if(!GetModuleFileNameW(NULL,image,32768))return failure("root_image",(int)GetLastError());
        int n=swprintf(command,65536,L"\"%ls\" child %u %u %llu",image,tcp,udp,(unsigned long long)existing);
        if(n<0)return failure("child_command_bound",0);
        STARTUPINFOW startup={sizeof(startup)};PROCESS_INFORMATION child={0};
        startup.dwFlags=STARTF_USESTDHANDLES;startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);startup.hStdError=GetStdHandle(STD_ERROR_HANDLE);
        if(!CreateProcessW(image,command,NULL,NULL,TRUE,0,NULL,NULL,&startup,&child))return failure("child_create",(int)GetLastError());
        DWORD wait=WaitForSingleObject(child.hProcess,20000),result=99;
        BOOL exit_ok=wait==WAIT_OBJECT_0&&GetExitCodeProcess(child.hProcess,&result);
        FILETIME times[4];
        if(exit_ok&&GetProcessTimes(child.hProcess,&times[0],&times[1],&times[2],&times[3])) {
            unsigned long long birth=((unsigned long long)times[0].dwHighDateTime<<32)|times[0].dwLowDateTime;
            /* The owned process handle supplies both lifetime and exit proof;
               reopening a rapidly exited PID can fail or find a reused PID. */
            printf("{\"kind\":\"fixture.child_exited\",\"pid\":%lu,\"creation_filetime\":%llu,\"exit_code\":%lu,\"handle_wait_confirmed\":true,\"identity_from_process_handle\":true}\n",child.dwProcessId,birth,result);fflush(stdout);
        }
        CloseHandle(child.hThread);CloseHandle(child.hProcess);closesocket(existing);WSACleanup();
        return (int)result;
    }
    if(wcscmp(argv[1],L"child")||argc!=5)return 93;
    SOCKET existing=(SOCKET)_wcstoui64(argv[4],NULL,10);
    printf("{\"kind\":\"fixture.child_main_started\",\"pid\":%lu}\n",GetCurrentProcessId());fflush(stdout);
    SOCKET fresh=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,WSA_FLAG_OVERLAPPED);
    int result=connect(fresh,(void*)&tcp_address,sizeof(tcp_address));int error=result==SOCKET_ERROR?WSAGetLastError():0;
    printf("{\"kind\":\"boundary.new_tcp\",\"result\":%d,\"error\":%d}\n",result,error);closesocket(fresh);
    struct sockaddr_in peer={0};int peer_size=sizeof(peer);
    int peer_ok=getpeername(existing,(void*)&peer,&peer_size)==0&&peer.sin_family==AF_INET&&peer.sin_port==tcp_address.sin_port;
    int sent=send(existing,after,(int)sizeof(after)-1,0);error=sent==SOCKET_ERROR?WSAGetLastError():0;
    printf("{\"kind\":\"boundary.existing_tcp\",\"peer_matches\":%s,\"sent_bytes\":%d,\"error\":%d}\n",peer_ok?"true":"false",sent,error);
    closesocket(existing);
    SOCKET connected=WSASocketW(AF_INET,SOCK_DGRAM,IPPROTO_UDP,NULL,0,WSA_FLAG_OVERLAPPED);
    result=connect(connected,(void*)&udp_address,sizeof(udp_address));error=result==SOCKET_ERROR?WSAGetLastError():0;
    printf("{\"kind\":\"boundary.udp_connect\",\"result\":%d,\"error\":%d}\n",result,error);closesocket(connected);
    SOCKET unconnected=WSASocketW(AF_INET,SOCK_DGRAM,IPPROTO_UDP,NULL,0,WSA_FLAG_OVERLAPPED);
    sent=sendto(unconnected,datagram,(int)sizeof(datagram)-1,0,(void*)&udp_address,sizeof(udp_address));error=sent==SOCKET_ERROR?WSAGetLastError():0;
    printf("{\"kind\":\"boundary.udp_sendto\",\"sent_bytes\":%d,\"error\":%d}\n",sent,error);fflush(stdout);
    closesocket(unconnected);WSACleanup();return 0;
}
