/* Version-independent tool execution gate (Windows x64).
 *
 * This DLL hooks the documented CreateProcess family of kernel32 and of
 * kernelbase, so it carries no image hash, no RVA and no entry-byte pin, and
 * keeps working across client releases. A denial returns ERROR_ACCESS_DENIED
 * from the API; no path in this file terminates the host process, so the agent
 * receives an ordinary tool error and its session continues.
 *
 * Installation is verified, not assumed: the ready frame names each export and
 * records whether a call through it actually reached the gate.
 *
 * The controller lease has three states: active asks the local DLP, controlled
 * stop passes creations through, and a lost controller denies them. Hooks are
 * installed only while a controller already owns this process generation's
 * lease, so an unexpected load leaves the host untouched.
 *
 * Command inspection is an execution-intent check. It cannot see the payload a
 * launched program sends later; a network boundary remains the only cover for
 * that. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "third_party/minhook/include/MinHook.h"
#define JSMN_STRICT
#include "third_party/jsmn/jsmn.h"

#define PAYLOAD_LIMIT (16u * 1024u * 1024u)
#define FRAME_LIMIT (100u * 1024u * 1024u)
#define DECISION_MS 2000u

static char session_id[96];
static wchar_t pipe_name[128];
static HANDLE lease_mutex;
static HANDLE lease_stop_event;
static HANDLE ready_event;
static volatile LONG sequence;

typedef BOOL (WINAPI *CreateProcessWFn)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                       LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                       LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
/* kernel32's CreateProcessW reaches kernelbase's, so one creation passes two
 * hooks. The layer that decided marks the thread approved and the inner layer
 * executes without asking again; the decision path itself stays refused. */
enum { GATE_IDLE, GATE_DECIDING, GATE_APPROVED };
static _Thread_local int gate_state;

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

static int whitespace(char value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

/* Exactly six, unique string fields, with no trailing JSON. */
static int decision_shape(const char *json, size_t bytes,
                          const jsmntok_t *tokens, int count) {
    if (count != 13 || tokens[0].type != JSMN_OBJECT) return 0;
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
 * means the controller disappeared and must not turn into direct execution. */
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

static int policy(const char *kind, const char *installed,
                  const unsigned char *body, size_t body_length,
                  ULONGLONG deadline) {
    if (!controller_active() || body_length > PAYLOAD_LIMIT) return 0;
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
        "\"completeness\":\"complete\",\"installed\":\"%s\","
        "\"captured_qpc\":%lld,"
        "\"qpc_frequency\":%lld,\"payload_utf8\":",
        request_id, session_id, GetCurrentProcessId(), GetCurrentThreadId(),
        kind, !strcmp(kind, "tool.exec") ? "process" : "control",
        installed ? installed : "", tick.QuadPart, frequency.QuadPart);
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
        char reply[8193];
        if (io(pipe, &size, 4, 1, deadline) &&
            io(pipe, frame, size, 1, deadline) &&
            io(pipe, &reply_length, 4, 0, deadline) &&
            reply_length && reply_length <= 8192 &&
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
        }
        CloseHandle(pipe);
    }
    SecureZeroMemory(frame, capacity);
    HeapFree(GetProcessHeap(), 0, frame);
    return allowed;
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
        allowed = policy("tool.exec", NULL, (const unsigned char *)payload, n,
                         GetTickCount64() + DECISION_MS);
    }
    if (payload) { SecureZeroMemory(payload, capacity); HeapFree(GetProcessHeap(), 0, payload); }
    if (app) { SecureZeroMemory(app, (size_t)app_length); HeapFree(GetProcessHeap(), 0, app); }
    if (cmd) { SecureZeroMemory(cmd, (size_t)cmd_length); HeapFree(GetProcessHeap(), 0, cmd); }
    if (dir) { SecureZeroMemory(dir, (size_t)dir_length); HeapFree(GetProcessHeap(), 0, dir); }
    return allowed;
}

static volatile LONG gate_entered;

/* 1 when the creation may proceed. The outer layer owns the approval and must
 * return the thread to idle once the original API has returned. */
static int approve(LPCWSTR application, LPCWSTR command, LPCWSTR directory) {
    InterlockedIncrement(&gate_entered);
    /* The decision path itself must never create a process through a gate. */
    if (gate_state == GATE_DECIDING) return 0;
    if (gate_state == GATE_APPROVED) return 1;
    int lease = lease_state();
    if (lease != LEASE_STOPPED) {
        int allowed = 0;
        if (lease == LEASE_ACTIVE) {
            gate_state = GATE_DECIDING;
            allowed = tool_exec_policy(application, command, directory);
            gate_state = GATE_IDLE;
        }
        if (!allowed) return 0;
    }
    gate_state = GATE_APPROVED;
    return 1;
}

/* An ANSI caller is inspected on the converted text. A command line that does
 * not convert is malformed rather than merely unclassifiable, so it is refused;
 * content the engine simply cannot judge is allowed by the policy above. */
static wchar_t *wide_of(LPCSTR value) {
    if (!value) return NULL;
    int required = MultiByteToWideChar(CP_ACP, 0, value, -1, NULL, 0);
    if (required <= 0) return NULL;
    wchar_t *result = HeapAlloc(GetProcessHeap(), 0,
                                (size_t)required * sizeof(wchar_t));
    if (!result) return NULL;
    if (MultiByteToWideChar(CP_ACP, 0, value, -1, result, required) != required) {
        HeapFree(GetProcessHeap(), 0, result);
        return NULL;
    }
    return result;
}

/* Every documented entry of the CreateProcess family needs its own trampoline:
 * the ANSI and AsUser exports do not pass through CreateProcessW, so hooking
 * the wide form alone leaves them as working bypasses. Each gate decides once
 * per creation; nested layers execute on the approval already granted. */
#define CREATE_PROCESS_GATE(tag, call_original)                               \
    static BOOL WINAPI tag##_gate call_original##_PARAMETERS {                \
        int outer = gate_state == GATE_IDLE;                                  \
        BOOL created = FALSE;                                                 \
        if (call_original##_APPROVE) {                                        \
            created = call_original##_CALL(original_##tag);                   \
        } else {                                                              \
            SetLastError(ERROR_ACCESS_DENIED);                                \
        }                                                                     \
        DWORD error = GetLastError();                                         \
        if (outer) gate_state = GATE_IDLE;                                    \
        SetLastError(error);                                                  \
        return created;                                                       \
    }

#define WIDE_PARAMETERS                                                       \
    (LPCWSTR application, LPWSTR command,                                     \
     LPSECURITY_ATTRIBUTES process_attributes,                                \
     LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags,      \
     LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,           \
     LPPROCESS_INFORMATION information)
#define WIDE_APPROVE approve(application, command, directory)
#define WIDE_CALL(original)                                                   \
    original(application, command, process_attributes, thread_attributes,     \
             inherit, flags, environment, directory, startup, information)

#define TOKEN_WIDE_PARAMETERS                                                 \
    (HANDLE token, LPCWSTR application, LPWSTR command,                       \
     LPSECURITY_ATTRIBUTES process_attributes,                                \
     LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags,      \
     LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,           \
     LPPROCESS_INFORMATION information)
#define TOKEN_WIDE_APPROVE approve(application, command, directory)
#define TOKEN_WIDE_CALL(original)                                             \
    original(token, application, command, process_attributes,                 \
             thread_attributes, inherit, flags, environment, directory,       \
             startup, information)

#define ANSI_PARAMETERS                                                       \
    (LPCSTR application, LPSTR command,                                       \
     LPSECURITY_ATTRIBUTES process_attributes,                                \
     LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags,      \
     LPVOID environment, LPCSTR directory, LPSTARTUPINFOA startup,            \
     LPPROCESS_INFORMATION information)
#define ANSI_APPROVE approve_ansi(application, command, directory)
#define ANSI_CALL(original)                                                   \
    original(application, command, process_attributes, thread_attributes,     \
             inherit, flags, environment, directory, startup, information)

#define TOKEN_ANSI_PARAMETERS                                                 \
    (HANDLE token, LPCSTR application, LPSTR command,                         \
     LPSECURITY_ATTRIBUTES process_attributes,                                \
     LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags,      \
     LPVOID environment, LPCSTR directory, LPSTARTUPINFOA startup,            \
     LPPROCESS_INFORMATION information)
#define TOKEN_ANSI_APPROVE approve_ansi(application, command, directory)
#define TOKEN_ANSI_CALL(original)                                             \
    original(token, application, command, process_attributes,                 \
             thread_attributes, inherit, flags, environment, directory,       \
             startup, information)

static int approve_ansi(LPCSTR application, LPCSTR command, LPCSTR directory) {
    /* A nested layer inherits the decision, so it converts nothing. */
    if (gate_state != GATE_IDLE) return approve(NULL, NULL, NULL);
    wchar_t *wide_application = wide_of(application);
    wchar_t *wide_command = wide_of(command);
    wchar_t *wide_directory = wide_of(directory);
    int allowed = (application && !wide_application) ||
                  (command && !wide_command) || (directory && !wide_directory)
        ? 0 : approve(wide_application, wide_command, wide_directory);
    if (wide_application) HeapFree(GetProcessHeap(), 0, wide_application);
    if (wide_command) HeapFree(GetProcessHeap(), 0, wide_command);
    if (wide_directory) HeapFree(GetProcessHeap(), 0, wide_directory);
    return allowed;
}

typedef BOOL (WINAPI *CreateProcessAFn) ANSI_PARAMETERS;
typedef BOOL (WINAPI *CreateProcessAsUserWFn) TOKEN_WIDE_PARAMETERS;
typedef BOOL (WINAPI *CreateProcessAsUserAFn) TOKEN_ANSI_PARAMETERS;

static CreateProcessWFn original_kernel32_w, original_kernelbase_w;
static CreateProcessAFn original_kernel32_a, original_kernelbase_a;
static CreateProcessAsUserWFn original_kernel32_user_w, original_kernelbase_user_w;
static CreateProcessAsUserAFn original_kernel32_user_a, original_kernelbase_user_a;

CREATE_PROCESS_GATE(kernel32_w, WIDE)
CREATE_PROCESS_GATE(kernelbase_w, WIDE)
CREATE_PROCESS_GATE(kernel32_a, ANSI)
CREATE_PROCESS_GATE(kernelbase_a, ANSI)
CREATE_PROCESS_GATE(kernel32_user_w, TOKEN_WIDE)
CREATE_PROCESS_GATE(kernelbase_user_w, TOKEN_WIDE)
CREATE_PROCESS_GATE(kernel32_user_a, TOKEN_ANSI)
CREATE_PROCESS_GATE(kernelbase_user_a, TOKEN_ANSI)

enum { SHAPE_WIDE, SHAPE_ANSI, SHAPE_TOKEN_WIDE, SHAPE_TOKEN_ANSI };

/* Reporting that a hook library returned success is not evidence that calls
 * arrive. Call the export the way any caller resolves it and confirm the gate
 * ran. The deciding state makes the gate refuse before it reaches the pipe, so
 * the probe creates nothing and sends no decision request. */
static int reaches_gate(LPCWSTR module, const char *symbol, int shape) {
    HMODULE handle = GetModuleHandleW(module);
    void *entry = handle ? (void *)GetProcAddress(handle, symbol) : NULL;
    if (!entry) return 0;
    static const wchar_t wide_name[] = L"\\\\?\\ttrace-guard-selftest";
    static const char ansi_name[] = "\\\\?\\ttrace-guard-selftest";
    STARTUPINFOW wide = {0};
    STARTUPINFOA ansi = {0};
    PROCESS_INFORMATION information = {0};
    wide.cb = sizeof(wide);
    ansi.cb = sizeof(ansi);
    LONG before = gate_entered;
    gate_state = GATE_DECIDING;
    switch (shape) {
    case SHAPE_ANSI:
        ((CreateProcessAFn)entry)(ansi_name, NULL, NULL, NULL, FALSE, 0, NULL,
                                  NULL, &ansi, &information);
        break;
    case SHAPE_TOKEN_WIDE:
        ((CreateProcessAsUserWFn)entry)(NULL, wide_name, NULL, NULL, NULL, FALSE,
                                        0, NULL, NULL, &wide, &information);
        break;
    case SHAPE_TOKEN_ANSI:
        ((CreateProcessAsUserAFn)entry)(NULL, ansi_name, NULL, NULL, NULL, FALSE,
                                        0, NULL, NULL, &ansi, &information);
        break;
    default:
        ((CreateProcessWFn)entry)(wide_name, NULL, NULL, NULL, FALSE, 0, NULL,
                                  NULL, &wide, &information);
        break;
    }
    gate_state = GATE_IDLE;
    return gate_entered != before;
}

static const struct {
    LPCWSTR module;
    const char *symbol;
    const char *label;
    int shape;
    LPVOID detour;
    LPVOID *original;
} gates[] = {
    {L"kernel32", "CreateProcessW", "k32.W", SHAPE_WIDE,
     kernel32_w_gate, (LPVOID *)&original_kernel32_w},
    {L"kernelbase", "CreateProcessW", "kb.W", SHAPE_WIDE,
     kernelbase_w_gate, (LPVOID *)&original_kernelbase_w},
    {L"kernel32", "CreateProcessA", "k32.A", SHAPE_ANSI,
     kernel32_a_gate, (LPVOID *)&original_kernel32_a},
    {L"kernelbase", "CreateProcessA", "kb.A", SHAPE_ANSI,
     kernelbase_a_gate, (LPVOID *)&original_kernelbase_a},
    {L"kernel32", "CreateProcessAsUserW", "k32.userW", SHAPE_TOKEN_WIDE,
     kernel32_user_w_gate, (LPVOID *)&original_kernel32_user_w},
    {L"kernelbase", "CreateProcessAsUserW", "kb.userW", SHAPE_TOKEN_WIDE,
     kernelbase_user_w_gate, (LPVOID *)&original_kernelbase_user_w},
    {L"kernel32", "CreateProcessAsUserA", "k32.userA", SHAPE_TOKEN_ANSI,
     kernel32_user_a_gate, (LPVOID *)&original_kernel32_user_a},
    {L"kernelbase", "CreateProcessAsUserA", "kb.userA", SHAPE_TOKEN_ANSI,
     kernelbase_user_a_gate, (LPVOID *)&original_kernelbase_user_a},
};
#define GATE_COUNT (sizeof(gates) / sizeof(gates[0]))

static DWORD WINAPI initialize(void *ignored) {
    (void)ignored;
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        return 1;
    ULARGE_INTEGER birth;
    birth.LowPart = created.dwLowDateTime;
    birth.HighPart = created.dwHighDateTime;
    snprintf(session_id, sizeof(session_id), "%lu-%llu", GetCurrentProcessId(),
             (unsigned long long)birth.QuadPart);
    swprintf(pipe_name, 128, L"\\\\.\\pipe\\ttrace-guard-%lu", GetCurrentProcessId());
    wchar_t lease_name[160], stop_name[160], ready_name[160];
    swprintf(lease_name, 160, L"Local\\ttrace-guard-lease-%hs", session_id);
    swprintf(stop_name, 160, L"Local\\ttrace-guard-stop-%hs", session_id);
    swprintf(ready_name, 160, L"Local\\ttrace-guard-ready-%hs", session_id);
    /* No controller for this generation means no hooks at all, so an
     * unexpected load cannot start denying the host's process creations. */
    lease_mutex = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, lease_name);
    if (!lease_mutex || lease_state() != LEASE_ACTIVE) return 2;
    lease_stop_event = CreateEventW(NULL, TRUE, FALSE, stop_name);
    if (!lease_stop_event || GetLastError() == ERROR_ALREADY_EXISTS) return 10;
    if (!policy("native.initialize", NULL, NULL, 0,
                GetTickCount64() + DECISION_MS))
        return 3;
    if (MH_Initialize() != MH_OK) return 5;
    MH_STATUS status[GATE_COUNT];
    int created_hooks = 0;
    for (size_t i = 0; i < GATE_COUNT; i++) {
        status[i] = MH_CreateHookApi(gates[i].module, gates[i].symbol,
                                     gates[i].detour, gates[i].original);
        created_hooks += status[i] == MH_OK;
    }
    if (!created_hooks) { MH_Uninitialize(); return 6; }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) { MH_Uninitialize(); return 7; }
    /* The ready frame names every export that was hooked and whether a call
     * through it reached the gate, so the controller knows the real coverage
     * instead of trusting that the hook library reported success. */
    char installed[512];
    int described = 0;
    for (size_t i = 0; i < GATE_COUNT && described >= 0 &&
                       described < (int)sizeof(installed); i++)
        described += snprintf(installed + described,
                              sizeof(installed) - (size_t)described,
                              "%s%s=%d/%d", i ? " " : "", gates[i].label,
                              (int)status[i],
                              status[i] == MH_OK
                                  ? reaches_gate(gates[i].module,
                                                 gates[i].symbol, gates[i].shape)
                                  : 0);
    if (described <= 0 || described >= (int)sizeof(installed) ||
        !policy("native.ready", installed, NULL, 0,
                GetTickCount64() + DECISION_MS))
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
