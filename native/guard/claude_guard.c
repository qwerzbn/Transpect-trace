/* Fixed Claude Code 2.1.317 in-process request gate (Windows x64).
 *
 * The pinned Bun writer receives plaintext HTTP bytes before BoringSSL. Its
 * first /v1/messages call contains the headers and the start of the JSON body;
 * the incoming R9 register points inside a separate, contiguous copy of that
 * complete body. A later call on the same thread writes the remainder. This
 * lab gate derives the full body, gets a local decision before the first HTTP
 * byte, and makes every body chunk consume approved snapshot bytes.
 *
 * The controller lease has three states: active asks the local DLP, controlled
 * stop passes through, and lost controller fails closed. An unrecognized
 * writer call, malformed request or DLP denial still terminates the Claude
 * process with code 76; a session-preserving nonretry error ABI has not been
 * validated. CreateProcessW is also gated before tool processes launch.
 * This is intentionally not a general Claude version or provider implementation. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "third_party/minhook/include/MinHook.h"
#define JSMN_STRICT
#include "third_party/jsmn/jsmn.h"
#include "third_party/miniz/miniz.h"

#ifndef REQUEST_RVA
#error "A validated Claude request RVA is required"
#endif
#ifndef REQUEST_PREFIX_BYTES
#error "Validated Claude request entry bytes are required"
#endif
#ifndef READ_RVA
#error "A validated Claude read RVA is required"
#endif
#ifndef READ_PREFIX_BYTES
#error "Validated Claude read entry bytes are required"
#endif
#ifndef TTRACE_EXPECTED_HASH
#error "The exact Claude executable SHA-256 is required"
#endif

#define BODY_LIMIT (16u * 1024u * 1024u)
#define HEADER_LIMIT (64u * 1024u)
#define FRAME_LIMIT (100u * 1024u * 1024u)
#define DECISION_MS 2000u
#define CURSOR_PROBE 24u

/* R9 is an observed, volatile value at this entry. The original function
 * overwrites it immediately. Windows x64's first four register slots let the
 * detour capture it without altering the original three-argument operation. */
typedef uintptr_t (*RequestFn)(void *, const unsigned char *, size_t,
                               const unsigned char *);
static RequestFn original_request;
static const char EXPECTED_HASH[] = TTRACE_EXPECTED_HASH;
static char session_id[96];
static wchar_t pipe_name[128];
static HANDLE lease_mutex;
static HANDLE lease_stop_event;
static HANDLE ready_event;
static volatile LONG sequence;

typedef BOOL (WINAPI *CreateProcessWFn)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                       LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                       LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
static CreateProcessWFn original_create_process;
static _Thread_local int inside_exec_gate;

/* Soft-denial continuation state: after a policy denial that did not stop the
 * process, further writer calls on the same thread carry the remaining body
 * chunks. They are swallowed with the same synthetic result until a fresh
 * request line starts normal gating again. */
static _Thread_local int denying;
static _Thread_local int deny_return;

/* Historical synthetic-403 experiment, disabled at runtime. Frida showed
 * READ_RVA is poll_cb and its third argument is an event bitmask (1 or 2),
 * not a uv_buf_t pointer. No read hook is installed. */
volatile LONG synthetic_pending;
unsigned char synthetic_response[1024];
size_t synthetic_length;

typedef struct {
    unsigned char *body;
    unsigned char *first_chunk;
    const unsigned char *original_body;
    size_t length;
    size_t sent;
    size_t first_length;
    /* Buffering fallback (no R9 snapshot): accumulate wire bytes across
     * writer calls, decide when the complete body has arrived, then flush
     * or deny. Used when the interactive TUI writer ABI differs from the
     * validated print-mode snapshot ABI. */
    int buffering;
    int gzip_encoding;
    unsigned char *wire;
    size_t wire_length;
    size_t wire_capacity;
} Pending;
static _Thread_local Pending pending;

/* Termination records carry a reason code and no request content: the file
 * lives under %LOCALAPPDATA%\TranspectTrace\claude-guard\terminations and is
 * the diagnosis anchor for any hard stop this fixed-version gate performs. */
static void record_termination(const char *reason, size_t detail_length,
                               int detail_prefix_ok) {
    wchar_t root[32768];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", root, 32768);
    if (!n || n >= 32768) return;
    wchar_t dir[32800], path[32900];
    swprintf(dir, 32800, L"%ls\\TranspectTrace\\claude-guard\\terminations", root);
    CreateDirectoryW(root, NULL);
    CreateDirectoryW(dir, NULL);
    swprintf(path, 32900, L"%ls\\terminations.jsonl", dir);
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return;
    char line[512];
    int wrote = snprintf(line, sizeof(line),
        "{\"reason\":\"%s\",\"pid\":%lu,\"tick\":%llu,\"length\":%llu,"
        "\"prefix_ok\":%s}\n",
        reason, GetCurrentProcessId(), (unsigned long long)GetTickCount64(),
        (unsigned long long)detail_length, detail_prefix_ok ? "true" : "false");
    if (wrote > 0 && wrote < (int)sizeof(line)) {
        DWORD done = 0;
        WriteFile(file, line, (DWORD)wrote, &done, NULL);
    }
    CloseHandle(file);
}

__declspec(noreturn) static void fail_stop(const char *reason) {
    record_termination(reason, 0, 0);
    TerminateProcess(GetCurrentProcess(), 76);
    ExitProcess(76);
    for (;;) {}
}

/* Same hard stop, with the observed request length and whether the buffer
 * started with a request line (no content is ever recorded). */
__declspec(noreturn) static void fail_stop_len(const char *reason, size_t length,
                                               int prefix_ok) {
    record_termination(reason, length, prefix_ok);
    TerminateProcess(GetCurrentProcess(), 76);
    ExitProcess(76);
    for (;;) {}
}

/* Non-fatal diagnostic for pass-through decisions: records the request line
 * (first CR/LF, at most 64 bytes, never the body) so unexpected first-chunk
 * shapes on the pinned writer can be classified. */
static size_t quote(char *output, const unsigned char *data, size_t length);
static void record_diag(const char *tag, const unsigned char *data, size_t length) {
    wchar_t root[32768];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", root, 32768);
    if (!n || n >= 32768) return;
    wchar_t dir[32800], path[32900];
    swprintf(dir, 32800, L"%ls\\TranspectTrace\\claude-guard", root);
    CreateDirectoryW(root, NULL);
    CreateDirectoryW(dir, NULL);
    swprintf(path, 32900, L"%ls\\diagnostics.jsonl", dir);
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return;
    size_t cut = 0;
    while (cut < length && cut < 64 && data[cut] != '\r' && data[cut] != '\n') ++cut;
    char line[256];
    int wrote = snprintf(line, sizeof(line), "{\"tag\":\"%s\",\"pid\":%lu,\"tick\":%llu,\"line\":",
                         tag, GetCurrentProcessId(), (unsigned long long)GetTickCount64());
    if (wrote > 0 && wrote < (int)sizeof(line)) {
        DWORD done = 0;
        WriteFile(file, line, (DWORD)wrote, &done, NULL);
    }
    char buffer[160];
    int quoted = quote(buffer, data, cut);
    if (quoted > 0 && quoted < (int)sizeof(buffer)) {
        DWORD done = 0;
        WriteFile(file, buffer, (DWORD)quoted, &done, NULL);
    }
    static const char tail[] = "}\n";
    DWORD done = 0;
    WriteFile(file, tail, sizeof(tail) - 1, &done, NULL);
    CloseHandle(file);
}

/* Length-only diagnostic for wire rebuilds: never records body bytes. */
static void record_diag_sizes(const char *tag, size_t original, size_t rebuilt,
                              size_t body_start) {
    char line[256];
    int wrote = snprintf(line, sizeof(line),
                         "{\"tag\":\"%s\",\"pid\":%lu,\"tick\":%llu,"
                         "\"original\":%llu,\"rebuilt\":%llu,\"body_start\":%llu}\n",
                         tag, GetCurrentProcessId(), (unsigned long long)GetTickCount64(),
                         (unsigned long long)original, (unsigned long long)rebuilt,
                         (unsigned long long)body_start);
    if (wrote <= 0 || wrote >= (int)sizeof(line)) return;
    /* 固定路径双写：实验室子进程的环境变量被 Bun 重写，固定路径不受影响。 */
    HANDLE fixed = CreateFileW(L"D:\\rea-tools\\guard-diag.jsonl", FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fixed != INVALID_HANDLE_VALUE) {
        DWORD done = 0;
        WriteFile(fixed, line, (DWORD)wrote, &done, NULL);
        CloseHandle(fixed);
    }
    wchar_t root[32768];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", root, 32768);
    if (!n || n >= 32768) return;
    wchar_t dir[32800], path[32900];
    swprintf(dir, 32800, L"%ls\\TranspectTrace\\claude-guard", root);
    CreateDirectoryW(root, NULL);
    CreateDirectoryW(dir, NULL);
    swprintf(path, 32900, L"%ls\\diagnostics.jsonl", dir);
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(file, line, (DWORD)wrote, &written, NULL);
    CloseHandle(file);
}

static int read_bytes(const void *source, void *target, size_t length) {
    SIZE_T copied = 0;
    return source && target && length <= BODY_LIMIT + HEADER_LIMIT &&
           ReadProcessMemory(GetCurrentProcess(), source, target, length,
                             &copied) && copied == length;
}

static int same_binary(void) {
    wchar_t path[32768];
    if (!GetModuleFileNameW(NULL, path, 32768)) return 0;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    BCRYPT_ALG_HANDLE algorithm = NULL; BCRYPT_HASH_HANDLE hash = NULL;
    DWORD size = 0, written = 0, count;
    unsigned char digest[32], block[65536];
    int ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                         NULL, 0) == 0;
    if (ok) ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&size,
                                  sizeof(size), &written, 0) == 0;
    unsigned char *object = ok ? HeapAlloc(GetProcessHeap(), 0, size) : NULL;
    if (ok) ok = object && BCryptCreateHash(algorithm, &hash, object, size,
                                           NULL, 0, 0) == 0;
    while (ok) {
        if (!ReadFile(file, block, sizeof(block), &count, NULL)) { ok = 0; break; }
        if (!count) break;
        if (BCryptHashData(hash, block, count, 0) != 0) ok = 0;
    }
    if (ok) ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
    char hex[65];
    if (ok) {
        for (int i = 0; i < 32; ++i) sprintf(hex + 2 * i, "%02x", digest[i]);
        hex[64] = 0;
        ok = strcmp(hex, EXPECTED_HASH) == 0;
    }
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (object) HeapFree(GetProcessHeap(), 0, object);
    CloseHandle(file);
    return ok;
}

static int io(HANDLE pipe, void *buffer, DWORD bytes, int writing,
              ULONGLONG deadline) {
    DWORD offset = 0;
    while (offset < bytes) {
        if (GetTickCount64() >= deadline) return 0;
        OVERLAPPED ov = {0};
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) return 0;
        DWORD moved = 0;
        BOOL ok = writing
            ? WriteFile(pipe, (char *)buffer + offset, bytes - offset, &moved, &ov)
            : ReadFile(pipe, (char *)buffer + offset, bytes - offset, &moved, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            ULONGLONG now = GetTickCount64();
            DWORD remaining = now < deadline ? (DWORD)(deadline - now) : 0;
            if (WaitForSingleObject(ov.hEvent, remaining) == WAIT_OBJECT_0)
                ok = GetOverlappedResult(pipe, &ov, &moved, FALSE);
            else {
                CancelIoEx(pipe, &ov);
                GetOverlappedResult(pipe, &ov, &moved, TRUE);
                ok = FALSE;
            }
        }
        CloseHandle(ov.hEvent);
        if (!ok || !moved) return 0;
        offset += moved;
    }
    return 1;
}

static int json_field(const char *json, const jsmntok_t *tokens, int count,
                      const char *key, char *output, size_t capacity) {
    if (count < 1 || tokens[0].type != JSMN_OBJECT) return 0;
    int found = 0;
    for (int i = 1; i + 1 < count; ++i) {
        if (tokens[i].parent != 0 || tokens[i].type != JSMN_STRING) continue;
        int length = tokens[i].end - tokens[i].start;
        if ((size_t)length != strlen(key) ||
            memcmp(json + tokens[i].start, key, length)) continue;
        if (found++ || tokens[i + 1].type != JSMN_STRING) return 0;
        length = tokens[i + 1].end - tokens[i + 1].start;
        if (length < 0 || (size_t)length >= capacity) return 0;
        memcpy(output, json + tokens[i + 1].start, length);
        output[length] = 0;
    }
    return found == 1;
}

/* The redacted body is a JSON string inside the pipe reply. Copying its raw
 * token would forward JSON escape bytes instead of the approved wire body. */
static int json_body_field(const char *json, const jsmntok_t *tokens, int count,
                           const char *key, char *output, size_t capacity,
                           size_t *decoded_length) {
    int found = 0;
    for (int t = 1; t + 1 < count; t += 2) {
        int key_len = tokens[t].end - tokens[t].start;
        if (key_len != (int)strlen(key) ||
            memcmp(json + tokens[t].start, key, (size_t)key_len)) continue;
        if (found++ || tokens[t + 1].type != JSMN_STRING) return 0;
        size_t n = 0;
        for (int p = tokens[t + 1].start; p < tokens[t + 1].end; ++p) {
            unsigned char value = (unsigned char)json[p];
            if (value == '\\') {
                if (++p >= tokens[t + 1].end) return 0;
                value = (unsigned char)json[p];
                if (value == 'n') value = '\n';
                else if (value == 'r') value = '\r';
                else if (value == 't') value = '\t';
                else if (value == 'b') value = '\b';
                else if (value == 'f') value = '\f';
                else if (value == 'u') {
                    if (p + 4 >= tokens[t + 1].end) return 0;
                    unsigned int codepoint = 0;
                    for (int k = 0; k < 4; ++k) {
                        unsigned char digit = (unsigned char)json[++p];
                        if (digit >= '0' && digit <= '9') digit -= '0';
                        else if (digit >= 'a' && digit <= 'f') digit = digit - 'a' + 10;
                        else if (digit >= 'A' && digit <= 'F') digit = digit - 'A' + 10;
                        else return 0;
                        codepoint = (codepoint << 4) | digit;
                    }
                    /* json.dumps(ensure_ascii=False) emits Unicode directly;
                     * only ASCII control escapes should reach this branch. */
                    if (!codepoint || codepoint > 0x7f) return 0;
                    value = (unsigned char)codepoint;
                } else if (value != '"' && value != '\\' && value != '/') return 0;
            }
            if (n + 1 >= capacity) return 0;
            output[n++] = (char)value;
        }
        output[n] = 0;
        *decoded_length = n;
    }
    return found == 1;
}

static int whitespace(char value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

/* Exactly six unique string fields (13 tokens), or seven when an optional
 * redacted_payload is present (15 tokens), with no trailing JSON. */
static int decision_shape(const char *json, size_t bytes,
                          const jsmntok_t *tokens, int count) {
    if ((count != 13 && count != 15) || tokens[0].type != JSMN_OBJECT) return 0;
    size_t p = 0;
    while (p < bytes && whitespace(json[p])) ++p;
    if (p != (size_t)tokens[0].start || json[p++] != '{') return 0;
    for (int i = 1; i < count; i += 2) {
        if (tokens[i].type != JSMN_STRING || tokens[i].parent != 0 ||
            tokens[i + 1].type != JSMN_STRING ||
            tokens[i + 1].parent != i) return 0;
        while (p < bytes && whitespace(json[p])) ++p;
        if (p != (size_t)tokens[i].start - 1 || json[p] != '"') return 0;
        p = (size_t)tokens[i].end + 1;
        while (p < bytes && whitespace(json[p])) ++p;
        if (p >= bytes || json[p++] != ':') return 0;
        while (p < bytes && whitespace(json[p])) ++p;
        if (p != (size_t)tokens[i + 1].start - 1 || json[p] != '"') return 0;
        p = (size_t)tokens[i + 1].end + 1;
        while (p < bytes && whitespace(json[p])) ++p;
        if (i + 2 < count && (p >= bytes || json[p++] != ',')) return 0;
    }
    if (p >= bytes || json[p++] != '}' || p != (size_t)tokens[0].end) return 0;
    while (p < bytes && whitespace(json[p])) ++p;
    return p == bytes;
}

static size_t quote(char *output, const unsigned char *data, size_t length) {
    static const char hex[] = "0123456789abcdef";
    size_t n = 0;
    output[n++] = '"';
    for (size_t i = 0; i < length; ++i) {
        unsigned char value = data[i];
        if (value == '"' || value == '\\') {
            output[n++] = '\\'; output[n++] = value;
        } else if (value < 32) {
            output[n++] = '\\'; output[n++] = 'u';
            output[n++] = '0'; output[n++] = '0';
            output[n++] = hex[value >> 4]; output[n++] = hex[value & 15];
        } else output[n++] = value;
    }
    output[n++] = '"';
    output[n] = 0;
    return n;
}

/* The controller owns the lease while it answers requests. A controlled stop
 * sets the event before releasing it; an abandoned lease without that event
 * means the controller disappeared and must not turn into direct sending. */
enum { LEASE_ACTIVE, LEASE_STOPPED, LEASE_LOST };

static int lease_state(void) {
    if (!lease_mutex) return LEASE_LOST;
    DWORD state = WaitForSingleObject(lease_mutex, 0);
    if (state == WAIT_TIMEOUT) return LEASE_ACTIVE;
    if (state != WAIT_OBJECT_0 && state != WAIT_ABANDONED_0)
        return LEASE_LOST;
    ReleaseMutex(lease_mutex);
    if (lease_stop_event &&
        WaitForSingleObject(lease_stop_event, 0) == WAIT_OBJECT_0)
        return LEASE_STOPPED;
    return LEASE_LOST;
}

static int controller_active(void) {
    return lease_state() == LEASE_ACTIVE;
}

#define REDACTED_LIMIT (18u * 1024u * 1024u)

static int policy(const char *kind, const unsigned char *body, size_t body_length,
                  ULONGLONG deadline, char **redacted_out, size_t *redacted_len_out) {
    if (redacted_out) *redacted_out = NULL;
    if (redacted_len_out) *redacted_len_out = 0;
    if (!controller_active() || body_length > BODY_LIMIT) return 0;
    DWORD id = (DWORD)InterlockedIncrement(&sequence);
    char request_id[64];
    snprintf(request_id, sizeof(request_id), "%lu-%lu", GetCurrentProcessId(), id);
    size_t capacity = body_length * 6 + 4096;
    if (capacity > FRAME_LIMIT) return 0;
    char *frame = HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!frame) return 0;
    LARGE_INTEGER tick, frequency;
    QueryPerformanceCounter(&tick);
    QueryPerformanceFrequency(&frequency);
    int prefix = snprintf(frame, 2048,
        "{\"schema\":\"transpect.guard.request/1.0\",\"request_id\":\"%s\","
        "\"guard_session_id\":\"%s\",\"pid\":%lu,\"tid\":%lu,"
        "\"kind\":\"%s\",\"protocol\":\"%s\",\"destination\":null,"
        "\"completeness\":\"complete\",\"captured_qpc\":%lld,"
        "\"qpc_frequency\":%lld,\"payload_utf8\":",
        request_id, session_id, GetCurrentProcessId(), GetCurrentThreadId(),
        kind, !strcmp(kind, "tool.exec") ? "process" : body ? "http" : "control",
        tick.QuadPart, frequency.QuadPart);
    if (prefix <= 0 || prefix >= 2048) {
        HeapFree(GetProcessHeap(), 0, frame); return 0;
    }
    size_t length = (size_t)prefix;
    length += quote(frame + length, body ? body : (const unsigned char *)"",
                    body_length);
    frame[length++] = '}';
    if (length > FRAME_LIMIT || GetTickCount64() >= deadline) {
        SecureZeroMemory(frame, capacity);
        HeapFree(GetProcessHeap(), 0, frame); return 0;
    }
    HANDLE pipe = INVALID_HANDLE_VALUE;
    do {
        pipe = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (pipe != INVALID_HANDLE_VALUE || GetLastError() != ERROR_PIPE_BUSY) break;
        ULONGLONG now = GetTickCount64();
        if (now >= deadline ||
            !WaitNamedPipeW(pipe_name, (DWORD)(deadline - now))) break;
    } while (GetTickCount64() < deadline);
    int allowed = 0;
    if (pipe != INVALID_HANDLE_VALUE) {
        uint32_t size = (uint32_t)length, reply_length = 0;
        char *reply = HeapAlloc(GetProcessHeap(), 0, REDACTED_LIMIT + 65536);
        if (reply &&
            io(pipe, &size, 4, 1, deadline) &&
            io(pipe, frame, size, 1, deadline) &&
            io(pipe, &reply_length, 4, 0, deadline) &&
            reply_length && reply_length <= REDACTED_LIMIT + 65536 &&
            io(pipe, reply, reply_length, 0, deadline)) {
            reply[reply_length] = 0;
            jsmn_parser parser; jsmntok_t tokens[128];
            jsmn_init(&parser);
            int count = jsmn_parse(&parser, reply, reply_length, tokens, 128);
            char schema[80], matched_id[64], decision[32], action[32];
            char reason[1024], version[128];
            allowed = GetTickCount64() < deadline &&
                controller_active() &&
                decision_shape(reply, reply_length, tokens, count) &&
                json_field(reply, tokens, count, "reason", reason,
                           sizeof(reason)) &&
                json_field(reply, tokens, count, "policy_version", version,
                           sizeof(version)) &&
                json_field(reply, tokens, count, "schema", schema,
                           sizeof(schema)) &&
                !strcmp(schema, "transpect.guard.decision/1.0") &&
                json_field(reply, tokens, count, "request_id", matched_id,
                           sizeof(matched_id)) && !strcmp(matched_id, request_id) &&
                json_field(reply, tokens, count, "decision", decision,
                           sizeof(decision)) &&
                json_field(reply, tokens, count, "action", action,
                           sizeof(action)) &&
                !strcmp(decision, "allow") && !strcmp(action, "none");
            if (allowed && count == 15) {
                char *redacted = HeapAlloc(GetProcessHeap(), 0, REDACTED_LIMIT);
                size_t decoded_length = 0;
                if (redacted_out && redacted &&
                    json_body_field(reply, tokens, count, "redacted_payload", redacted,
                                    REDACTED_LIMIT, &decoded_length) && decoded_length) {
                    *redacted_out = redacted;
                    if (redacted_len_out) *redacted_len_out = decoded_length;
                } else if (redacted) {
                    allowed = 0; /* never send the original on a bad payload */
                    HeapFree(GetProcessHeap(), 0, redacted);
                } else {
                    allowed = 0;
                }
            }
        }
        if (reply) { SecureZeroMemory(reply, REDACTED_LIMIT + 65536);
                     HeapFree(GetProcessHeap(), 0, reply); }
        CloseHandle(pipe);
    }
    SecureZeroMemory(frame, capacity);
    HeapFree(GetProcessHeap(), 0, frame);
    return allowed;
}

static int header_key(const unsigned char *line, size_t length, const char *key) {
    size_t n = strlen(key);
    if (length <= n || line[n] != ':') return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char a = line[i], b = (unsigned char)key[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (a != b) return 0;
    }
    return 1;
}

static int header_value(const unsigned char *line, size_t length,
                        const char *expected) {
    size_t n = strlen(expected);
    while (length && (*line == ' ' || *line == '\t')) { ++line; --length; }
    if (length < n) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char a = line[i], b = (unsigned char)expected[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (a != b) return 0;
    }
    return length == n || line[n] == ';';
}

/* Inflate a gzip-wrapped body (the client compresses model requests by
 * default). miniz 3.x has no gzip wrapper support, so RFC 1952 is parsed
 * here and the inner raw deflate stream is inflated. Fail closed: anything
 * that is not a complete gzip stream is rejected rather than forwarded
 * uninspected. */
static int gzip_decompress(const unsigned char *src, size_t src_len,
                           unsigned char **out, size_t *out_len) {
    if (src_len < 18) return 0;
    size_t p = 0;
    if (src[p] != 0x1f || src[p + 1] != 0x8b || src[p + 2] != 8) return 0;
    unsigned int flg = src[3];
    if (flg & 0xe0) return 0; /* reserved flag bits set */
    p += 10; /* magic, CM, FLG, MTIME(4), XFL, OS */
    if (flg & 4) { /* FEXTRA */
        if (p + 2 > src_len) return 0;
        size_t xlen = src[p] | ((size_t)src[p + 1] << 8);
        p += 2 + xlen;
        if (p > src_len) return 0;
    }
    if (flg & 8) { /* FNAME */
        while (p < src_len && src[p]) ++p;
        if (++p > src_len) return 0;
    }
    if (flg & 16) { /* FCOMMENT */
        while (p < src_len && src[p]) ++p;
        if (++p > src_len) return 0;
    }
    if (flg & 2) { /* FHCRC */
        if (p + 2 > src_len) return 0;
        p += 2;
    }
    if (p + 8 > src_len) return 0; /* raw deflate + CRC32 + ISIZE */
    size_t deflate_len = src_len - p - 8;
    if (!deflate_len) return 0;
    mz_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (mz_inflateInit2(&stream, -MZ_DEFAULT_WINDOW_BITS) != MZ_OK) return 0;
    size_t capacity = deflate_len * 16 + 65536;
    if (capacity > 96u * 1024u * 1024u) capacity = 96u * 1024u * 1024u;
    unsigned char *buffer = HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!buffer) { mz_inflateEnd(&stream); return 0; }
    stream.next_in = src + p;
    stream.avail_in = (mz_uint32)deflate_len;
    stream.next_out = buffer;
    stream.avail_out = (mz_uint32)capacity;
    int status = mz_inflate(&stream, MZ_FINISH);
    int ok = (status == MZ_STREAM_END);
    size_t produced = stream.total_out;
    mz_inflateEnd(&stream);
    if (!ok || !produced) {
        SecureZeroMemory(buffer, capacity);
        HeapFree(GetProcessHeap(), 0, buffer);
        return 0;
    }
    *out = buffer;
    *out_len = produced;
    return 1;
}

/* gzip-compress a redacted payload so the wire keeps the client's declared
 * Content-Encoding. miniz 3.x has no gzip wrapper support, so RFC 1952 is
 * written here around a raw deflate stream. */
static int gzip_compress_exact(const unsigned char *src, size_t src_len,
                               size_t target_len, unsigned char **out) {
    if (!src_len || src_len > REDACTED_LIMIT) return 0;
    mz_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (mz_deflateInit2(&stream, 6, MZ_DEFLATED, -MZ_DEFAULT_WINDOW_BITS,
                        8, MZ_DEFAULT_STRATEGY) != MZ_OK) return 0;
    size_t capacity = src_len + src_len / 2 + 128;
    unsigned char *buffer = HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!buffer) { mz_deflateEnd(&stream); return 0; }
    stream.next_in = (const unsigned char *)src;
    stream.avail_in = (mz_uint32)src_len;
    stream.next_out = buffer;
    stream.avail_out = (mz_uint32)capacity;
    int status = mz_deflate(&stream, MZ_FINISH);
    size_t raw_len = stream.total_out;
    mz_deflateEnd(&stream);
    if (status != MZ_STREAM_END) {
        SecureZeroMemory(buffer, capacity);
        HeapFree(GetProcessHeap(), 0, buffer);
        return 0;
    }
    size_t total = 10 + raw_len + 8;
    if (total > target_len) {
        SecureZeroMemory(buffer, capacity);
        HeapFree(GetProcessHeap(), 0, buffer);
        return 0;
    }
    size_t padding = target_len - total;
    unsigned char *gz = HeapAlloc(GetProcessHeap(), 0, target_len);
    if (!gz) {
        SecureZeroMemory(buffer, capacity);
        HeapFree(GetProcessHeap(), 0, buffer);
        return 0;
    }
    gz[0] = 0x1f; gz[1] = 0x8b; gz[2] = 8;
    gz[3] = padding ? 8 : 0; /* FNAME safely pads to the exact wire length. */
    gz[4] = gz[5] = gz[6] = gz[7] = 0; gz[8] = 0; gz[9] = 3;
    if (padding) {
        memset(gz + 10, 'X', padding - 1);
        gz[10 + padding - 1] = 0;
    }
    memcpy(gz + 10 + padding, buffer, raw_len);
    SecureZeroMemory(buffer, capacity);
    HeapFree(GetProcessHeap(), 0, buffer);
    uint32_t crc = mz_crc32(0, src, src_len);
    gz[10 + padding + raw_len] = (unsigned char)(crc & 0xff);
    gz[11 + padding + raw_len] = (unsigned char)((crc >> 8) & 0xff);
    gz[12 + padding + raw_len] = (unsigned char)((crc >> 16) & 0xff);
    gz[13 + padding + raw_len] = (unsigned char)((crc >> 24) & 0xff);
    uint32_t isize = (uint32_t)src_len;
    gz[14 + padding + raw_len] = (unsigned char)(isize & 0xff);
    gz[15 + padding + raw_len] = (unsigned char)((isize >> 8) & 0xff);
    gz[16 + padding + raw_len] = (unsigned char)((isize >> 16) & 0xff);
    gz[17 + padding + raw_len] = (unsigned char)((isize >> 24) & 0xff);
    *out = gz;
    return 1;
}

/* Rebuild only when the entire wire stays exactly the same length. */
static int rebuild_redacted_wire(const unsigned char *wire, size_t wire_length,
                                 size_t body_start, int gzip,
                                 const unsigned char *redacted, size_t redacted_len,
                                 unsigned char **out, size_t *out_len) {
    if (body_start > wire_length) return 0;
    size_t original_body_len = wire_length - body_start;
    unsigned char *body = NULL;
    if (gzip) {
        if (!gzip_compress_exact(redacted, redacted_len,
                                 original_body_len, &body)) return 0;
    } else {
        if (redacted_len != original_body_len) return 0;
        body = HeapAlloc(GetProcessHeap(), 0, original_body_len);
        if (!body) return 0;
        memcpy(body, redacted, redacted_len);
    }
    unsigned char *new_wire = HeapAlloc(GetProcessHeap(), 0, wire_length);
    if (!new_wire) {
        SecureZeroMemory(body, original_body_len);
        HeapFree(GetProcessHeap(), 0, body);
        return 0;
    }
    memcpy(new_wire, wire, body_start);
    memcpy(new_wire + body_start, body, original_body_len);
    SecureZeroMemory(body, original_body_len);
    HeapFree(GetProcessHeap(), 0, body);
    *out = new_wire;
    *out_len = wire_length;
    return 1;
}

/* Model requests this gate inspects: any POST whose path ends with
 * /v1/messages or /v1/messages/count_tokens. Relay/session path prefixes
 * drift across builds (observed: /v1/messages, /anthropic/v1/messages,
 * /apps/anthropic/v1/messages), so suffix matching is the durable shape.
 * Everything else on the writer is outside the model hook's scope and passes
 * through unchanged. */
static int model_request_line(const unsigned char *data, size_t length) {
    if (length < 18 || memcmp(data, "POST ", 5)) return 0;
    size_t start = 5, end = 5;
    while (end < length && data[end] != ' ' && data[end] != '?') {
        if (data[end] == '\r' || data[end] == '\n') return 0;
        ++end;
    }
    size_t path_len = end - start;
    if (path_len < 12) return 0;
    const unsigned char *path = data + start;
    if (!memcmp(path + path_len - 12, "/v1/messages", 12)) return 1;
    if (path_len >= 25 &&
        !memcmp(path + path_len - 25, "/v1/messages/count_tokens", 25)) return 1;
    return 0;
}

static int parse_headers(const unsigned char *buffer, size_t length,
                         size_t *body_offset, size_t *body_length,
                         int *gzip_encoding) {
    if (length < 28 || length > BODY_LIMIT + HEADER_LIMIT ||
        !model_request_line(buffer, length)) return 0;
    size_t p = 5;
    while (p < length && buffer[p] != ' ') {
        if (buffer[p] == '\r' || buffer[p] == '\n') return 0;
        ++p;
    }
    if (p + 11 >= length || memcmp(buffer + p, " HTTP/1.1\r\n", 11)) return 0;
    p += 11;
    int seen_length = 0, seen_type = 0, seen_encoding = 0;
    while (p + 1 < length && p < HEADER_LIMIT) {
        if (buffer[p] == '\r' && buffer[p + 1] == '\n') {
            *body_offset = p + 2;
            return seen_length && seen_type && *body_offset <= length;
        }
        size_t start = p;
        while (p + 1 < length && p < HEADER_LIMIT &&
               !(buffer[p] == '\r' && buffer[p + 1] == '\n')) ++p;
        if (p + 1 >= length || p >= HEADER_LIMIT) return 0;
        size_t size = p - start;
        const unsigned char *line = buffer + start;
        if (header_key(line, size, "content-length")) {
            if (seen_length++) return 0;
            size_t q = strlen("content-length") + 1;
            while (q < size && (line[q] == ' ' || line[q] == '\t')) ++q;
            size_t number = 0, digits = 0;
            while (q < size && line[q] >= '0' && line[q] <= '9') {
                number = number * 10 + (line[q] - '0');
                if (number > BODY_LIMIT) return 0;
                ++q; ++digits;
            }
            while (q < size && (line[q] == ' ' || line[q] == '\t')) ++q;
            if (!digits || q != size || !number) return 0;
            *body_length = number;
        } else if (header_key(line, size, "content-type")) {
            if (seen_type++) return 0;
            size_t q = strlen("content-type") + 1;
            if (!header_value(line + q, size - q, "application/json")) return 0;
        } else if (header_key(line, size, "content-encoding")) {
            /* The client compresses request bodies by default. Only gzip is
             * understood; the decoded form is inspected while the wire keeps
             * the compressed bytes. Anything else fails closed. */
            if (seen_encoding++) return 0;
            size_t q = strlen("content-encoding") + 1;
            if (!header_value(line + q, size - q, "gzip")) return 0;
            if (gzip_encoding) *gzip_encoding = 1;
        } else if (header_key(line, size, "transfer-encoding")) {
            return 0; /* Fixed-length bodies only. */
        }
        p += 2;
    }
    return 0;
}

static unsigned char *capture_body(const unsigned char *first, size_t first_len,
                                   size_t body_offset, size_t body_len,
                                   const unsigned char *cursor,
                                   const unsigned char **original_body) {
    size_t prefix_len = first_len - body_offset;
    if (prefix_len > body_len) return NULL;
    unsigned char *body = HeapAlloc(GetProcessHeap(), 0, body_len);
    if (!body) return NULL;
    if (prefix_len == body_len) {
        memcpy(body, first + body_offset, body_len);
        *original_body = NULL;
        return body;
    }
    unsigned char probe[CURSOR_PROBE];
    if (!read_bytes(cursor, probe, sizeof(probe))) goto invalid;
    /* Repeated prompt padding can make the bytes at R9 appear hundreds of
     * times in the first chunk. Disambiguate using the JSON body's beginning,
     * rather than requiring this interior probe itself to be unique. */
    size_t matches = 0;
    const unsigned char *start = NULL;
    size_t compare_length = prefix_len < 128 ? prefix_len : 128;
    unsigned char beginning[128];
    for (size_t p = body_offset; p + sizeof(probe) <= first_len; ++p) {
        if (!memcmp(first + p, probe, sizeof(probe))) {
            size_t displacement = p - body_offset;
            if ((uintptr_t)cursor < displacement) continue;
            const unsigned char *candidate = cursor - displacement;
            if (!read_bytes(candidate, beginning, compare_length) ||
                memcmp(beginning, first + body_offset, compare_length)) continue;
            start = candidate;
            if (++matches > 1) goto invalid;
        }
    }
    SecureZeroMemory(beginning, sizeof(beginning));
    SecureZeroMemory(probe, sizeof(probe));
    if (matches != 1) goto invalid;
    if (!read_bytes(start, body, body_len) ||
        memcmp(body, first + body_offset, prefix_len)) goto invalid;
    *original_body = start;
    return body;
invalid:
    SecureZeroMemory(probe, sizeof(probe));
    SecureZeroMemory(beginning, sizeof(beginning));
    SecureZeroMemory(body, body_len);
    HeapFree(GetProcessHeap(), 0, body);
    return NULL;
}

static char *utf8_of(LPCWSTR value, int *length) {
    *length = 0;
    if (!value) return NULL;
    int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    if (required <= 0) return NULL;
    char *result = HeapAlloc(GetProcessHeap(), 0, (size_t)required);
    if (!result) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, value, -1, result, required,
                            NULL, NULL) != required) {
        HeapFree(GetProcessHeap(), 0, result);
        return NULL;
    }
    *length = required - 1;
    return result;
}

/* Command inspection supplements the VM's actual network boundary. It does
 * not claim to see the payload a launched program will send later. */
static int tool_exec_policy(LPCWSTR application, LPCWSTR command,
                            LPCWSTR directory) {
    int app_length, cmd_length, dir_length;
    char *app = utf8_of(application, &app_length);
    char *cmd = utf8_of(command, &cmd_length);
    char *dir = utf8_of(directory, &dir_length);
    int allowed = 0;
    size_t capacity = ((size_t)app_length + cmd_length + dir_length) * 6 + 128;
    char *payload = HeapAlloc(GetProcessHeap(), 0, capacity);
    if (payload && (!application || app) && (!command || cmd) &&
        (!directory || dir)) {
        static const char a[] = "{\"application\":";
        static const char c[] = ",\"command_line\":";
        static const char d[] = ",\"cwd\":";
        size_t n = 0;
        memcpy(payload + n, a, sizeof(a) - 1); n += sizeof(a) - 1;
        n += quote(payload + n, (const unsigned char *)(app ? app : ""),
                   (size_t)app_length);
        memcpy(payload + n, c, sizeof(c) - 1); n += sizeof(c) - 1;
        n += quote(payload + n, (const unsigned char *)(cmd ? cmd : ""),
                   (size_t)cmd_length);
        memcpy(payload + n, d, sizeof(d) - 1); n += sizeof(d) - 1;
        n += quote(payload + n, (const unsigned char *)(dir ? dir : ""),
                   (size_t)dir_length);
        payload[n++] = '}'; payload[n] = 0;
        allowed = policy("tool.exec", (const unsigned char *)payload, n,
                         GetTickCount64() + DECISION_MS, NULL, NULL);
    }
    if (payload) { SecureZeroMemory(payload, capacity); HeapFree(GetProcessHeap(), 0, payload); }
    if (app) { SecureZeroMemory(app, (size_t)app_length); HeapFree(GetProcessHeap(), 0, app); }
    if (cmd) { SecureZeroMemory(cmd, (size_t)cmd_length); HeapFree(GetProcessHeap(), 0, cmd); }
    if (dir) { SecureZeroMemory(dir, (size_t)dir_length); HeapFree(GetProcessHeap(), 0, dir); }
    return allowed;
}

static BOOL WINAPI create_process_gate(LPCWSTR application, LPWSTR command,
                                       LPSECURITY_ATTRIBUTES process_attributes,
                                       LPSECURITY_ATTRIBUTES thread_attributes,
                                       BOOL inherit, DWORD flags, LPVOID environment,
                                       LPCWSTR directory, LPSTARTUPINFOW startup,
                                       LPPROCESS_INFORMATION information) {
    if (inside_exec_gate) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    int lease = lease_state();
    if (lease == LEASE_STOPPED)
        return original_create_process(application, command, process_attributes,
                                       thread_attributes, inherit, flags, environment,
                                       directory, startup, information);
    int allowed = 0;
    if (lease == LEASE_ACTIVE) {
        inside_exec_gate = 1;
        allowed = tool_exec_policy(application, command, directory);
        inside_exec_gate = 0;
    }
    if (allowed)
        return original_create_process(application, command, process_attributes,
                                       thread_attributes, inherit, flags, environment,
                                       directory, startup, information);
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
}

/* Policy denial of a model request. The default is session-preserving soft
 * denial: nothing reaches the writer and a synthetic write failure tells the
 * Bun caller the request failed immediately (ECONNRESET surfaces in seconds,
 * no wait for the provider watchdog), so the terminal stays alive.
 * TTRACE_DENY_MODE overrides the action:
 *   returnfail  - default; return (uintptr_t)-1 (immediate local write failure)
 *   return0     - claim zero bytes were written
 *   returnlen   - claim the full length was written (client waits for a
 *                 response that never comes; provider watchdog then errors)
 *   kill        - TerminateProcess(76) (legacy fail-stop) */
enum { DENY_KILL, DENY_RETURN0, DENY_RETURNFAIL, DENY_RETURNLEN };

static int deny_mode(void) {
    char mode[32] = {0};
    DWORD got = GetEnvironmentVariableA("TTRACE_DENY_MODE", mode, sizeof(mode));
    if (got == 0 || got >= sizeof(mode)) return DENY_RETURNFAIL;
    if (!strcmp(mode, "kill")) return DENY_KILL;
    if (!strcmp(mode, "return0")) return DENY_RETURN0;
    if (!strcmp(mode, "returnfail")) return DENY_RETURNFAIL;
    if (!strcmp(mode, "returnlen")) return DENY_RETURNLEN;
    /* The pinned read RVA is poll_cb(uv_poll_t *, int status, int events).
     * Its third argument is an event bitmask, not a response buffer. Keep
     * synthetic 403 disabled until a plaintext delivery ABI is proven. */
    if (!strcmp(mode, "synthesize")) return DENY_RETURNFAIL;
    return DENY_RETURNFAIL;
}

/* 合成 403 响应模板：完整 HTTP 响应 + Anthropic SSE error 事件。
 * 文案来自 TTRACE_DENY_MESSAGE（默认英文，规则名之外的正文由部署方提供）。 */
static void prepare_synthetic(void) {
    char message[256] = "DLP blocked: sensitive content matched; the request was not sent.";
    DWORD got = GetEnvironmentVariableA("TTRACE_DENY_MESSAGE", message, sizeof(message));
    if (got == 0 || got >= sizeof(message))
        strcpy(message, "DLP blocked: sensitive content matched; the request was not sent.");
    char escaped[512];
    size_t n = 0;
    for (size_t i = 0; message[i] && n + 2 < sizeof(escaped); ++i) {
        if (message[i] == '"' || message[i] == '\\') escaped[n++] = '\\';
        escaped[n++] = message[i];
    }
    escaped[n] = 0;
    int written = snprintf((char *)synthetic_response, sizeof(synthetic_response),
        "HTTP/1.1 403 Forbidden\r\n"
        "content-type: text/event-stream\r\n"
        "cache-control: no-cache, no-transform\r\n"
        "\r\n"
        "event: error\r\n"
        "data: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"%s\"}}\r\n"
        "\r\n", escaped);
    synthetic_length = (written > 0 && (size_t)written < sizeof(synthetic_response))
        ? (size_t)written : 0;
}

/* Inactive historical hypothesis. The actual poll_cb ABI differs. Do not
 * install this hook without a newly proven plaintext delivery ABI. */
typedef uintptr_t (*ReadCbFn)(void *, int32_t, void *);
static ReadCbFn original_readcb;

static uintptr_t read_cb_gate(void *stream, int32_t nread, void *buf) {
    if (nread <= 0 && InterlockedCompareExchange(&synthetic_pending, 0, 1) == 1) {
        record_diag_sizes("read_synth_hit", synthetic_length, 0, 0);
        /* 读驱动（0x3654cd0）同款结构关系：
         * inner = *stream；while ([inner+0x1a] & 0x40) inner = [inner+0x38]；
         * consumer = [inner+0x18]，调用 (inner, &uv_buf_t, len)。
         * read_cb 也服务 TTY 等非 socket 流：消费者必须落在主模块映像内，
         * 否则放弃本次注入（置回标志），绝不放行原文。 */
        unsigned char *image = (unsigned char *)GetModuleHandleW(NULL);
        void *inner = stream ? *(void **)stream : NULL;
        int guard = 0;
        while (inner && (*(unsigned char *)((unsigned char *)inner + 0x1a) & 0x40)
               && guard++ < 16)
            inner = *(void **)((unsigned char *)inner + 0x38);
        void (*consumer)(void *, void *, uint32_t) = NULL;
        if (inner)
            consumer = *(void (**)(void *, void *, uint32_t))((unsigned char *)inner + 0x18);
        MEMORY_BASIC_INFORMATION info = {0};
        if (consumer && VirtualQuery(consumer, &info, sizeof(info)) == sizeof(info)
            && info.State == MEM_COMMIT
            && (unsigned char *)consumer >= image
            && (unsigned char *)consumer < image + 0x6000000) {
            struct { void *base; size_t len; } synth_buf =
                { synthetic_response, synthetic_length };
            consumer(inner, &synth_buf, (uint32_t)synthetic_length);
            record_diag_sizes("read_synth_done", synthetic_length, 0, 0);
            return 0;
        }
        record_diag_sizes("read_synth_noc", (size_t)consumer, (size_t)inner,
                          (size_t)stream);
        /* 消费链不可解析：置回标志，留待下一次机会；绝不放行原文。 */
        InterlockedExchange(&synthetic_pending, 1);
    }
    return original_readcb(stream, nread, buf);
}

/* Complete-buffer decision: run the local DLP on the assembled body, then
 * flush the (possibly redacted) wire once, or apply the soft-deny ABI.
 * Consumes and clears `pending`; returns the synthetic writer result for the
 * chunk that completed the request. */
static uintptr_t buffered_decide(void *context, const unsigned char *cursor,
                                 size_t chunk_length) {
    ULONGLONG deadline = GetTickCount64() + DECISION_MS;
    unsigned char *decoded = NULL;
    size_t decoded_length = 0;
    size_t body_start = pending.wire_length - pending.length;
    if (pending.gzip_encoding &&
        !gzip_decompress(pending.wire + body_start, pending.length,
                         &decoded, &decoded_length))
        fail_stop_len("gzip_decode", pending.length, 1);
    const unsigned char *policy_body = decoded ? decoded : pending.wire + body_start;
    size_t policy_length = decoded ? decoded_length : pending.length;
    char *redacted = NULL;
    size_t redacted_len = 0;
    int allowed = policy("model.request", policy_body, policy_length, deadline,
                         &redacted, &redacted_len);
    if (decoded) {
        SecureZeroMemory(decoded, decoded_length);
        HeapFree(GetProcessHeap(), 0, decoded);
    }
    unsigned char *wire = pending.wire;
    size_t wire_length = pending.wire_length;
    int wire_gzip = pending.gzip_encoding;
    memset(&pending, 0, sizeof(pending));
    if (allowed || lease_state() == LEASE_STOPPED) {
        unsigned char *send = wire;
        size_t send_len = wire_length;
        if (allowed && redacted && redacted_len) {
            record_diag_sizes("redact_lens", policy_length, redacted_len, wire_gzip);
            if (!wire_gzip && redacted_len == policy_length) {
                /* 长度保持型红action：原地替换正文，线材字节数不变，
                 * 客户端 TLS 写计数不会失配。 */
                memcpy(wire + body_start, redacted, redacted_len);
                record_diag_sizes("redact_inplace", wire_length, wire_length,
                                  body_start);
            } else {
                if (redacted_len != policy_length ||
                    !rebuild_redacted_wire(wire, wire_length, body_start, wire_gzip,
                                           (const unsigned char *)redacted,
                                           redacted_len, &send, &send_len))
                    goto redaction_denied;
                /* 长度对照诊断（不记录正文字节），供真实链路排障。 */
                record_diag_sizes("redact_sizes", wire_length, send_len, body_start);
                SecureZeroMemory(wire, wire_length);
                HeapFree(GetProcessHeap(), 0, wire);
            }
        }
        original_request(context, send, send_len, cursor);
        SecureZeroMemory(send, send_len);
        HeapFree(GetProcessHeap(), 0, send);
        if (redacted) {
            SecureZeroMemory(redacted, redacted_len);
            HeapFree(GetProcessHeap(), 0, redacted);
        }
        return (uintptr_t)chunk_length;
    }
redaction_denied:
    if (redacted) {
        SecureZeroMemory(redacted, redacted_len);
        HeapFree(GetProcessHeap(), 0, redacted);
    }
    SecureZeroMemory(wire, wire_length);
    HeapFree(GetProcessHeap(), 0, wire);
    int mode = deny_mode();
    if (mode != DENY_KILL) {
        denying = 1;
        deny_return = mode;
        return mode == DENY_RETURN0 ? 0
             : mode == DENY_RETURNFAIL ? (uintptr_t)-1
             : (uintptr_t)chunk_length;
    }
    fail_stop_len("policy_denied", policy_length, 1);
}

static int request_prefix_ok(const unsigned char *data, size_t length) {
    return length >= 5 && (!memcmp(data, "POST ", 5) ||
                           !memcmp(data, "HEAD ", 5) ||
                           !memcmp(data, "GET /", 5));
}

static uintptr_t request_gate(void *context, const unsigned char *data,
                              size_t length, const unsigned char *cursor) {
    int lease = lease_state();
    if (lease == LEASE_STOPPED && !pending.body && !pending.buffering)
        return original_request(context, data, length, cursor);
    if (lease == LEASE_LOST)
        fail_stop_len("lease_lost", length, request_prefix_ok(data, length));
    if (denying) {
        /* Continuation chunks of a soft-denied request carry no request line.
         * A fresh request on this thread restarts normal gating. */
        if (request_prefix_ok(data, length)) {
            denying = 0;
        } else {
            return deny_return == DENY_RETURN0 ? 0
                 : deny_return == DENY_RETURNFAIL ? (uintptr_t)-1
                 : (uintptr_t)length;
        }
    }
    if (!length || length > BODY_LIMIT + HEADER_LIMIT)
        fail_stop_len("bad_length", length, request_prefix_ok(data, length));
    if (pending.buffering) {
        /* Wire-byte accumulation for a request whose body was not available
         * as one snapshot. Nothing is forwarded until the complete body has
         * been buffered and the local decision has been made. */
        if (request_prefix_ok(data, length))
            fail_stop_len("buffering_new_request", length, 1);
        size_t remaining = pending.length - pending.sent;
        if (!length || length > remaining)
            fail_stop_len("buffering_overflow", length, 0);
        unsigned char *actual = HeapAlloc(GetProcessHeap(), 0, length);
        if (!actual || !read_bytes(data, actual, length)) {
            if (actual) {
                SecureZeroMemory(actual, length);
                HeapFree(GetProcessHeap(), 0, actual);
            }
            fail_stop_len("buffering_read", length, 0);
        }
        if (pending.wire_length + length > pending.wire_capacity) {
            SecureZeroMemory(actual, length);
            HeapFree(GetProcessHeap(), 0, actual);
            fail_stop_len("buffering_capacity", length, 0);
        }
        memcpy(pending.wire + pending.wire_length, actual, length);
        pending.wire_length += length;
        pending.sent += length;
        SecureZeroMemory(actual, length);
        HeapFree(GetProcessHeap(), 0, actual);
        if (pending.sent < pending.length)
            return (uintptr_t)length;  /* keep buffering; nothing forwarded yet */
        return buffered_decide(context, cursor, length);
    }
    if (pending.body) {
        if (length > pending.length - pending.sent ||
            data != pending.original_body + pending.sent)
            fail_stop_len("continuation_bounds", length, 0);
        unsigned char *actual = HeapAlloc(GetProcessHeap(), 0, length);
        if (!actual || !read_bytes(data, actual, length) ||
            memcmp(actual, pending.body + pending.sent, length)) {
            if (actual) {
                SecureZeroMemory(actual, length);
                HeapFree(GetProcessHeap(), 0, actual);
            }
            fail_stop_len("continuation_bytes", length, 0);
        }
        SecureZeroMemory(actual, length);
        HeapFree(GetProcessHeap(), 0, actual);
        const unsigned char *approved = pending.body + pending.sent;
        pending.sent += length;
        uintptr_t result = original_request(context, approved, length, cursor);
        if (pending.sent == pending.length) {
            SecureZeroMemory(pending.first_chunk, pending.first_length);
            HeapFree(GetProcessHeap(), 0, pending.first_chunk);
            SecureZeroMemory(pending.body, pending.length);
            HeapFree(GetProcessHeap(), 0, pending.body);
            memset(&pending, 0, sizeof(pending));
        }
        return result;
    }
    ULONGLONG deadline = GetTickCount64() + DECISION_MS;
    unsigned char *first = HeapAlloc(GetProcessHeap(), 0, length);
    if (!first || !read_bytes(data, first, length))
        fail_stop_len("first_read", length, request_prefix_ok(data, length));
    if (!model_request_line(first, length)) {
        /* The pinned writer also carries provider-specific POST paths. Until
         * their body shape has an accepted parser, forwarding one would be a
         * silent model-data bypass. Unknown POSTs fail closed. */
        if (length >= 5 && !memcmp(first, "POST ", 5))
            fail_stop_len("unsupported_post_route", length, 1);
        /* Feature-flag fetches, token refresh and other non-model traffic
         * are outside this hook's scope; forward them unchanged. A record
         * classifies unexpected first-chunk shapes for the TUI path. */
        record_diag("pass_through", first, length);
        SecureZeroMemory(first, length);
        HeapFree(GetProcessHeap(), 0, first);
        return original_request(context, data, length, cursor);
    }
    size_t offset = 0, body_length = 0;
    int gzip_encoding = 0;
    if (!parse_headers(first, length, &offset, &body_length, &gzip_encoding))
        fail_stop_len("parse_headers", length, request_prefix_ok(first, length));
    /* Every model request is buffered: the body accumulates across writer
     * calls and is forwarded only after the local decision, so both the
     * print-mode and interactive writer ABIs share one validated path and
     * redaction can replace the body before anything leaves. */
    if (!body_length || length - offset > body_length)
        fail_stop_len("capture_body", body_length, 1);
    size_t wire_capacity = length + body_length + 4096;
    unsigned char *wire = HeapAlloc(GetProcessHeap(), 0, wire_capacity);
    if (!wire) fail_stop_len("capture_body_alloc", body_length, 1);
    memcpy(wire, first, length);
    pending.buffering = 1;
    pending.gzip_encoding = gzip_encoding;
    pending.length = body_length;
    pending.sent = length - offset;
    pending.wire = wire;
    pending.wire_length = length;
    pending.wire_capacity = wire_capacity;
    SecureZeroMemory(first, length);
    HeapFree(GetProcessHeap(), 0, first);
    if (pending.sent < pending.length)
        return (uintptr_t)length;  /* wait for the remaining body chunks */
    return buffered_decide(context, cursor, length);
}

static DWORD WINAPI initialize(void *ignored) {
    (void)ignored;
    FILETIME created, exited, kernel, user;
    if (!same_binary() ||
        !GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        return 1;
    ULARGE_INTEGER birth;
    birth.LowPart = created.dwLowDateTime;
    birth.HighPart = created.dwHighDateTime;
    snprintf(session_id, sizeof(session_id), "%lu-%llu", GetCurrentProcessId(),
             (unsigned long long)birth.QuadPart);
    swprintf(pipe_name, 128, L"\\\\.\\pipe\\ttrace-guard-%lu", GetCurrentProcessId());
    /* A denied request must not be re-sent by the client's retry budget: each
     * retry is re-denied locally, so retries only delay the surfaced error.
     * The guard pins the budget to zero inside the protected process, whatever
     * environment launched it. */
    SetEnvironmentVariableA("CLAUDE_CODE_MAX_RETRIES", "0");
    wchar_t lease_name[160], stop_name[160], ready_name[160];
    swprintf(lease_name, 160, L"Local\\ttrace-guard-lease-%hs", session_id);
    swprintf(stop_name, 160, L"Local\\ttrace-guard-stop-%hs", session_id);
    swprintf(ready_name, 160, L"Local\\ttrace-guard-ready-%hs", session_id);
    lease_mutex = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, lease_name);
    if (!lease_mutex || lease_state() != LEASE_ACTIVE) return 2;
    lease_stop_event = CreateEventW(NULL, TRUE, FALSE, stop_name);
    if (!lease_stop_event || GetLastError() == ERROR_ALREADY_EXISTS) return 10;
    if (!policy("native.initialize", NULL, 0, GetTickCount64() + DECISION_MS, NULL, NULL))
        return 3;
    unsigned char *base = (unsigned char *)GetModuleHandleW(NULL);
    const unsigned char prefix[] = REQUEST_PREFIX_BYTES;
    const unsigned char read_prefix[] = READ_PREFIX_BYTES;
    if (!base || memcmp(base + REQUEST_RVA, prefix, sizeof(prefix))) return 4;
    if (memcmp(base + READ_RVA, read_prefix, sizeof(read_prefix))) return 4;
    prepare_synthetic();
    record_diag_sizes("read_gate_disabled", (size_t)deny_mode(), 0, 0);
    if (MH_Initialize() != MH_OK) return 5;
    if (MH_CreateHook(base + REQUEST_RVA, request_gate,
                      (LPVOID *)&original_request) != MH_OK ||
        MH_CreateHookApi(L"kernelbase", "CreateProcessW", create_process_gate,
                         (LPVOID *)&original_create_process) != MH_OK) {
        MH_Uninitialize(); return 6;
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MH_Uninitialize(); return 7;
    }
    if (!policy("native.ready", NULL, 0, GetTickCount64() + DECISION_MS, NULL, NULL))
        return 8;
    ready_event = CreateEventW(NULL, TRUE, TRUE, ready_name);
    return ready_event ? 0 : 9;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(NULL, 0, initialize, NULL, 0, NULL);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}

#ifdef TTRACE_GZIP_PROBE
/* Standalone test entry; the production DLL is built without this define. */
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned long long target = 0;
    if (sscanf(argv[1], "%llu", &target) != 1) return 2;
    const unsigned char *source = (const unsigned char *)argv[2];
    size_t source_len = strlen(argv[2]);
    unsigned char *wire = NULL, *decoded = NULL;
    size_t decoded_len = 0;
    if (!gzip_compress_exact(source, source_len, (size_t)target, &wire)) return 3;
    int ok = gzip_decompress(wire, (size_t)target, &decoded, &decoded_len)
             && decoded_len == source_len
             && !memcmp(decoded, source, source_len);
    if (decoded) {
        SecureZeroMemory(decoded, decoded_len);
        HeapFree(GetProcessHeap(), 0, decoded);
    }
    SecureZeroMemory(wire, (size_t)target);
    HeapFree(GetProcessHeap(), 0, wire);
    puts(ok ? "{\"result\":\"PASS\"}" : "{\"result\":\"FAIL\"}");
    return ok ? 0 : 1;
}
#endif
