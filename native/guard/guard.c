/* Fixed-build runtime instrumentation. No network forwarding or TLS replacement. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "third_party/minhook/include/MinHook.h"
#define JSMN_STRICT
#include "third_party/jsmn/jsmn.h"

#define HTTP_RVA 0x09d96b10
#define WSS_RVA 0x03d6daa0
#define DROP_HEADERS_RVA 0x000eeb20
#define LIMIT (16u * 1024u * 1024u)
#define DEADLINE_MS 2000
static const char EXPECTED_HASH[] = "d13914ced6c7af174d8d638db938284231227312104b06a25e9608c632a7daec";
typedef void *(*HttpFn)(void *, void *, void *, void *);
typedef void *(*WssFn)(void *, void *);
typedef void (*DropFn)(void *);
static HttpFn original_http;
static WssFn original_wss;
static DropFn drop_headers;
static volatile LONG sequence;
static volatile LONG session_blocked;
static char session_id[96];
static wchar_t pipe_name[128];
static HANDLE ready_event;
static _Thread_local char last_request_id[64];
static _Thread_local char outcome_parent[64];
static _Thread_local const char *outcome_action;
static _Thread_local long long last_request_qpc;
static _Thread_local long long outcome_qpc;

static int readable(const void *pointer, size_t bytes) {
    uintptr_t p = (uintptr_t)pointer, end = p + bytes;
    if (p < 0x10000 || end < p || bytes > LIMIT) return 0;
    while (p < end) {
        MEMORY_BASIC_INFORMATION m;
        if (!VirtualQuery((void *)p, &m, sizeof(m)) || m.State != MEM_COMMIT ||
            (m.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return 0;
        uintptr_t next = (uintptr_t)m.BaseAddress + m.RegionSize;
        if (next <= p) return 0;
        p = next < end ? next : end;
    }
    return 1;
}

static int same_binary(void) {
    wchar_t path[32768];
    if (!GetModuleFileNameW(NULL, path, 32768)) return 0;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    BCRYPT_ALG_HANDLE algorithm = NULL; BCRYPT_HASH_HANDLE hash = NULL;
    DWORD size = 0, written = 0; unsigned char digest[32], block[65536];
    int ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0;
    if (ok) ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&size, sizeof(size), &written, 0) == 0;
    unsigned char *object = ok ? HeapAlloc(GetProcessHeap(), 0, size) : NULL;
    if (ok) ok = object && BCryptCreateHash(algorithm, &hash, object, size, NULL, 0, 0) == 0;
    DWORD count;
    while (ok) {
        if (!ReadFile(file, block, sizeof(block), &count, NULL)) { ok = 0; break; }
        if (!count) break;
        if (BCryptHashData(hash, block, count, 0) != 0) ok = 0;
    }
    if (ok) ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
    char hex[65];
    if (ok) {
        for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", digest[i]);
        ok = strcmp(hex, EXPECTED_HASH) == 0;
    }
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (object) HeapFree(GetProcessHeap(), 0, object);
    CloseHandle(file);
    return ok;
}

static int io(HANDLE pipe, void *buffer, DWORD bytes, int writing, ULONGLONG deadline) {
    DWORD offset = 0;
    while (offset < bytes) {
        if (GetTickCount64() >= deadline) return 0;
        OVERLAPPED ov = {0}; ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) return 0;
        DWORD transferred = 0;
        BOOL ok = writing ? WriteFile(pipe, (char *)buffer + offset, bytes - offset, &transferred, &ov)
                          : ReadFile(pipe, (char *)buffer + offset, bytes - offset, &transferred, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            ULONGLONG now = GetTickCount64();
            DWORD remaining = now < deadline ? (DWORD)(deadline - now) : 0;
            if (WaitForSingleObject(ov.hEvent, remaining) == WAIT_OBJECT_0)
                ok = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
            else {
                CancelIoEx(pipe, &ov);
                GetOverlappedResult(pipe, &ov, &transferred, TRUE);
                ok = FALSE;
            }
        }
        CloseHandle(ov.hEvent);
        if (!ok || !transferred) return 0;
        offset += transferred;
    }
    return 1;
}

static int json_field(const char *json, const jsmntok_t *t, int n,
                      const char *key, char *out, size_t capacity) {
    if (n < 1 || t[0].type != JSMN_OBJECT) return 0;
    int found = 0;
    for (int i = 1; i + 1 < n; i++) {
        if (t[i].parent != 0 || t[i].type != JSMN_STRING) continue;
        int len = t[i].end - t[i].start;
        if ((size_t)len != strlen(key) || memcmp(json + t[i].start, key, len)) continue;
        if (found++) return 0;
        if (t[i + 1].type != JSMN_STRING) return 0;
        len = t[i + 1].end - t[i + 1].start;
        if (len < 0 || (size_t)len >= capacity) return 0;
        memcpy(out, json + t[i + 1].start, len); out[len] = 0;
    }
    return found == 1;
}

static int whitespace(char c) { return c==' ' || c=='\t' || c=='\r' || c=='\n'; }
/* The decision contract is exactly six string fields. jsmn tokenization alone
 * does not reject missing commas, multiple roots or duplicate object keys. */
static int decision_shape(const char *json, size_t bytes, const jsmntok_t *t, int n) {
    if (n != 13 || t[0].type != JSMN_OBJECT) return 0;
    size_t p=0;
    while(p<bytes && whitespace(json[p]))p++;
    if(p!=(size_t)t[0].start || json[p++]!='{')return 0;
    for(int i=1;i<n;i+=2) {
        if(t[i].type!=JSMN_STRING || t[i].parent!=0 ||
           t[i+1].type!=JSMN_STRING || t[i+1].parent!=i)return 0;
        while(p<bytes && whitespace(json[p]))p++;
        if(p!=(size_t)t[i].start-1 || json[p]!='"')return 0;
        p=(size_t)t[i].end+1;
        while(p<bytes && whitespace(json[p]))p++;
        if(p>=bytes || json[p++]!=':')return 0;
        while(p<bytes && whitespace(json[p]))p++;
        if(p!=(size_t)t[i+1].start-1 || json[p]!='"')return 0;
        p=(size_t)t[i+1].end+1;
        while(p<bytes && whitespace(json[p]))p++;
        if(i+2<n && (p>=bytes || json[p++]!=','))return 0;
    }
    if(p>=bytes || json[p++]!='}' || p!=(size_t)t[0].end)return 0;
    while(p<bytes && whitespace(json[p]))p++;
    return p==bytes;
}

static size_t quote(char *out, const unsigned char *data, size_t bytes) {
    static const char hex[] = "0123456789abcdef";
    size_t n = 0; out[n++] = '"';
    for (size_t i = 0; i < bytes; i++) {
        unsigned char c = data[i];
        if (c == '"' || c == '\\') { out[n++] = '\\'; out[n++] = c; }
        else if (c < 32) {
            out[n++] = '\\'; out[n++] = 'u'; out[n++] = '0'; out[n++] = '0';
            out[n++] = hex[c >> 4]; out[n++] = hex[c & 15];
        } else out[n++] = c;
    }
    out[n++] = '"'; out[n] = 0; return n;
}

/* Returns 0 allow, 1 block_request, 2 block_session, 3 terminate_process.
 * Transport/protocol failures always return block_request, never terminate. */
static int policy(const char *kind, const char *protocol, const void *data, size_t bytes) {
    DWORD id = (DWORD)InterlockedIncrement(&sequence);
    char request_id[64]; snprintf(request_id, sizeof(request_id), "%lu-%lu", GetCurrentProcessId(), id);
    if(!strcmp(kind,"model.request")) {
        strcpy(last_request_id,request_id);outcome_parent[0]=0;outcome_action=NULL;
        LARGE_INTEGER observed;QueryPerformanceCounter(&observed);last_request_qpc=observed.QuadPart;
    }
    if (!strcmp(protocol,"control") ? 0 : InterlockedCompareExchange(&session_blocked, 0, 0)) return 2;
    if (bytes > LIMIT || (bytes && !readable(data, bytes))) return 1;
    char *request = HeapAlloc(GetProcessHeap(), 0, bytes * 6 + 1024);
    if (!request) return 1;
    LARGE_INTEGER tick,frequency;QueryPerformanceCounter(&tick);QueryPerformanceFrequency(&frequency);
    int n = snprintf(request, 1024,
        "{\"schema\":\"transpect.guard.request/1.0\",\"request_id\":\"%s\","
        "\"guard_session_id\":\"%s\",\"pid\":%lu,\"tid\":%lu,\"kind\":\"%s\","
        "\"protocol\":\"%s\",\"destination\":null,\"completeness\":\"complete\","
        "\"captured_qpc\":%lld,\"qpc_frequency\":%lld,\"outcome_for_request_id\":\"%s\",\"outcome_action\":\"%s\",\"outcome_captured_qpc\":%lld,\"payload_utf8\":",
        request_id, session_id, GetCurrentProcessId(), GetCurrentThreadId(), kind, protocol,
        !strcmp(kind,"model.request")?last_request_qpc:tick.QuadPart,
        frequency.QuadPart,outcome_parent,outcome_action?outcome_action:"none",outcome_qpc);
    n += (int)quote(request + n, data ? data : "", bytes); request[n++] = '}'; request[n] = 0;
    ULONGLONG deadline = GetTickCount64() + DEADLINE_MS;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    do {
        pipe = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (pipe != INVALID_HANDLE_VALUE || GetLastError() != ERROR_PIPE_BUSY) break;
        ULONGLONG now = GetTickCount64();
        if (now >= deadline || !WaitNamedPipeW(pipe_name, (DWORD)(deadline - now))) break;
    } while (GetTickCount64() < deadline);
    int action = 1;
    if (pipe != INVALID_HANDLE_VALUE) {
        uint32_t length = (uint32_t)n, reply_length = 0; char reply[8193];
        if (io(pipe, &length, 4, 1, deadline) && io(pipe, request, length, 1, deadline) &&
            io(pipe, &reply_length, 4, 0, deadline) && reply_length && reply_length <= 8192 &&
            io(pipe, reply, reply_length, 0, deadline)) {
            reply[reply_length] = 0;
            jsmn_parser parser; jsmntok_t tokens[128]; jsmn_init(&parser);
            int count = jsmn_parse(&parser, reply, reply_length, tokens, 128);
            char schema[80], matched_id[64], decision[32], requested_action[32], reason[1024], version[128];
            if (GetTickCount64() < deadline && decision_shape(reply, reply_length, tokens, count) &&
                json_field(reply, tokens, count, "reason", reason, sizeof(reason)) &&
                json_field(reply, tokens, count, "policy_version", version, sizeof(version)) &&
                json_field(reply, tokens, count, "schema", schema, sizeof(schema)) &&
                !strcmp(schema, "transpect.guard.decision/1.0") &&
                json_field(reply, tokens, count, "request_id", matched_id, sizeof(matched_id)) && !strcmp(matched_id, request_id) &&
                json_field(reply, tokens, count, "decision", decision, sizeof(decision)) &&
                json_field(reply, tokens, count, "action", requested_action, sizeof(requested_action))) {
                if (!strcmp(decision, "allow") && !strcmp(requested_action, "none")) action = 0;
                else if (!strcmp(decision, "deny")) {
                    if (!strcmp(requested_action, "block_request")) action = 1;
                    else if (!strcmp(requested_action, "block_session")) action = 2;
                    else if (!strcmp(requested_action, "terminate_process")) action = 3;
                }
            }
        }
        CloseHandle(pipe);
    }
    HeapFree(GetProcessHeap(), 0, request);
    if (action == 2) InterlockedExchange(&session_blocked, 1);
    return action;
}

typedef struct { char parent[64]; int action; long long qpc; } Outcome;
static DWORD WINAPI send_outcome(void *parameter) {
    Outcome *result=parameter;strcpy(outcome_parent,result->parent);
    outcome_qpc=result->qpc;
    outcome_action=result->action==2?"block_session":"block_request";
    policy("native.outcome","control",NULL,0);
    outcome_parent[0]=0;outcome_action=NULL;outcome_qpc=0;
    HeapFree(GetProcessHeap(),0,result);return 0;
}
static void report_outcome(int action) {
    Outcome *result=HeapAlloc(GetProcessHeap(),0,sizeof(Outcome));
    if(!result)return;
    strcpy(result->parent,last_request_id);result->action=action;
    result->qpc=last_request_qpc;
    if(!QueueUserWorkItem(send_outcome,result,WT_EXECUTEDEFAULT))HeapFree(GetProcessHeap(),0,result);
}

static void *http_gate(void *result, void *request, void *headers, void *body) {
    uintptr_t *b = body;
    int action = 1;
    if (readable(body, 65)) action = policy("model.request", "http", (void *)b[1], b[2]);
    if (!action) return original_http(result, request, headers, body);
    if(action==3){TerminateProcess(GetCurrentProcess(),76);return result;}
    const char *reason = "Transpect: request denied by local policy";
    size_t length = strlen(reason);
    char *error = HeapAlloc(GetProcessHeap(), 0, length + 1);
    if (!error) { /* Valid empty String, avoiding an unverified allocation failure return. */
        length = 0; error = (char *)1;
    } else memcpy(error, reason, length + 1);
    drop_headers(headers);
    uintptr_t *out = result;
    out[0] = 3; out[1] = length ? length + 1 : 0; out[2] = (uintptr_t)error; out[3] = length;
    report_outcome(action);
    return result;
}

static void *wss_gate(void *result, void *request) {
    void *returned = original_wss(result, request);
    uintptr_t *out = result;
    if (out[0] != 0x1c) return returned;
    int action = policy("model.request", "wss", (void *)out[2], out[3]);
    if (!action) return returned;
    if(action==3){TerminateProcess(GetCurrentProcess(),76);return returned;}
    const char *reason = "Transpect: request denied by local policy";
    size_t length = strlen(reason);
    if (out[1] <= length || !readable((void *)out[2], length + 1)) {
        /* Keep the owned buffer/capacity, represent a valid empty String. */
        out[3] = 0;
    } else {
        memcpy((void *)out[2], reason, length + 1); out[3] = length;
    }
    out[0] = 0x0d; /* ApiError::Stream(String), fixed-build layout. */
    report_outcome(action);
    return returned;
}

static DWORD WINAPI initialize(LPVOID unused) {
    (void)unused;
    FILETIME created, exited, kernel, user;
    if (!same_binary() || !GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 1;
    ULARGE_INTEGER creation; creation.LowPart = created.dwLowDateTime; creation.HighPart = created.dwHighDateTime;
    snprintf(session_id, sizeof(session_id), "%lu-%llu", GetCurrentProcessId(), (unsigned long long)creation.QuadPart);
    swprintf(pipe_name, 128, L"\\\\.\\pipe\\ttrace-guard-%lu", GetCurrentProcessId());
    /* No hooks become active before a compatible local engine responds. */
    if (policy("native.initialize", "control", NULL, 0) != 0) return 2;
    unsigned char *base = (unsigned char *)GetModuleHandleW(NULL);
    const unsigned char http_prefix[] = {0x55,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x53};
    const unsigned char wss_prefix[] = {0x55,0x56,0x57,0x53,0x48,0x83,0xec,0x68};
    if (memcmp(base + HTTP_RVA, http_prefix, sizeof(http_prefix)) ||
        memcmp(base + WSS_RVA, wss_prefix, sizeof(wss_prefix))) return 3;
    drop_headers = (DropFn)(base + DROP_HEADERS_RVA);
    if (MH_Initialize() != MH_OK) return 4;
    if (MH_CreateHook(base + HTTP_RVA, http_gate, (LPVOID *)&original_http) != MH_OK ||
        MH_CreateHook(base + WSS_RVA, wss_gate, (LPVOID *)&original_wss) != MH_OK) {
        MH_Uninitialize(); return 5;
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) { MH_Uninitialize(); return 6; }
    wchar_t ready_name[160];swprintf(ready_name,160,L"Local\\ttrace-guard-ready-%hs",session_id);
    ready_event=CreateEventW(NULL,TRUE,TRUE,ready_name);
    policy("native.ready", "control", NULL, 0);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        HANDLE thread = CreateThread(NULL, 0, initialize, NULL, 0, NULL);
        if (thread) CloseHandle(thread);
    }
    /* Resident hooks: policy-service loss cannot revert to unguarded sending. */
    return TRUE;
}
