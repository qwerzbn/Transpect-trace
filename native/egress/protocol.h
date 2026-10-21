#ifndef TTRACE_EGRESS_PROTOCOL_H
#define TTRACE_EGRESS_PROTOCOL_H
#include <stdint.h>
#include <wchar.h>
#define EGRESS_MAGIC 0x31474554u
#define EGRESS_VERSION 1u
#define EGRESS_REGISTER 1u
#define EGRESS_READY 2u
#define EGRESS_CHILD 3u
#define EGRESS_CONNECT 4u
#define EGRESS_RESULT 5u
#define EGRESS_HELD 6u
#define EGRESS_HEARTBEAT 7u
#pragma pack(push, 1)
typedef struct {
    uint32_t magic, version, kind, pid;
    uint64_t creation;
    unsigned char token[32];
    uint32_t child_pid, reserved;
    uint64_t child_creation;
    uint32_t family, port;
    unsigned char address[16];
    int32_t result;
    uint32_t error;
    uint64_t sequence;
} EgressRequest;
typedef struct {
    uint32_t magic, version, allow, reason;
    uint64_t sequence;
} EgressResponse;
typedef struct {
    uint32_t magic, version, root, controller_pid;
    uint64_t creation;
    unsigned char token[32];
    wchar_t pipe_name[128];
    wchar_t dll_path[1024];
    uint64_t create_rva;
    unsigned char create_prologue[16];
} EgressConfig;
#pragma pack(pop)
#endif
