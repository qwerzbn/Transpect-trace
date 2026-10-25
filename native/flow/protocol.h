#ifndef TTRACE_FLOW_PROTOCOL_H
#define TTRACE_FLOW_PROTOCOL_H
#include <stdint.h>
#include <wchar.h>
#define FLOW_LIMIT (1024u*1024u)
#define FLOW_QUEUE_LIMIT (16u*1024u*1024u)
#define FLOW_MAX_SCOPES 4
enum { F_INIT=1,F_READY,F_OPEN,F_READ,F_WRITE,F_CLOSE,F_CONNECT,F_DISCONNECT,F_GAP,F_TERMINAL };
enum { F_SUCCESS=1,F_MORE=2,F_UNSUPPORTED=4,F_FILE=8,F_PIPE=16,F_OVERLAPPED=32,F_MESSAGE=64,F_ID=128,F_OFFSET=256,F_DATA_GAP=512,F_SERVER=1024 };
enum { R_NONE=0,R_SIZE=1,R_ASYNC=2,R_CONCURRENT=3,R_MEMORY=4,R_HANDLE_CAP=5,R_PIPE_MODE=6,R_SNAPSHOT=7,R_STOP_BUSY=8 };
#pragma pack(push,1)
typedef struct {
    char magic[4]; uint32_t kind;
    uint64_t pid,tid,birth,sequence,qpc,handle,open_generation,connection_generation;
    uint64_t volume,file_id,offset,requested,completed,error,flags,peer_pid,peer_birth;
    uint64_t length,dropped,scope,reason,completed_qpc;
} FlowHeader;
typedef struct {
    char magic[4]; uint32_t count; uint64_t birth;
    wchar_t paths[FLOW_MAX_SCOPES][1024];
} FlowConfig;
#pragma pack(pop)
_Static_assert(sizeof(FlowHeader)==184,"FIO1 frame size");
_Static_assert(sizeof(FlowConfig)==8208,"FIC1 config size");
#endif
