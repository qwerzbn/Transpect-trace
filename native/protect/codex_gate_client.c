/*
 * Codex hook command: forward one hook event to the resident gate service.
 *
 *   codex_gate_client.exe <pipe-name> <python.exe> <codex_hook_gate.py> <gate-config.json>
 *
 * Codex splits the hook command on whitespace and never quotes, so every
 * argument is a single token and no path may contain a space.
 *
 * Order of attempts, each strictly fail-closed:
 *   1. the resident service over the named pipe (fast path);
 *   2. the per-event Python gate, fed the same bytes (slow path, same policy);
 *   3. a built-in denial for an enforceable event name (last resort).
 *
 * The process always exits 0. A non-zero exit or a crash makes Codex report
 * the hook as `Failed` and send anyway, so every error path must end in a
 * reply this program writes itself.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EVENT (8u * 1024u * 1024u)
#define MAX_REPLY (1u * 1024u * 1024u)
#define PIPE_WAIT_MS 300
#define SERVICE_DEADLINE_MS 8000
#define FALLBACK_DEADLINE_MS 30000

/* Must stay identical to codex_hook_gate._deny_response(..., "GATE_UNAVAILABLE");
 * the contract test runs this binary and validates the output. UTF-8. */
static const char DENY_PROMPT[] =
    "{\"decision\": \"block\", \"reason\": \"\xe6\x9c\xac\xe5\x9c\xb0 DLP \xe6\x8b\x92\xe7\xbb\x9d"
    "\xe5\x8f\x91\xe9\x80\x81\xe8\xaf\xa5\xe8\xbe\x93\xe5\x85\xa5\xef\xbc\x88GATE_UNAVAILABLE\xef\xbc\x89\"}\n";
static const char DENY_POST[] =
    "{\"decision\": \"block\", \"reason\": \"\xe6\x9c\xac\xe5\x9c\xb0 DLP \xe5\xb7\xb2\xe6\x8b\xa6"
    "\xe6\x88\xaa\xe8\xaf\xa5\xe5\xb7\xa5\xe5\x85\xb7\xe8\xbe\x93\xe5\x87\xba\xef\xbc\x8c\xe6\x9c\xaa"
    "\xe5\x8f\x91\xe9\x80\x81\xe7\xbb\x99\xe6\xa8\xa1\xe5\x9e\x8b\xef\xbc\x88GATE_UNAVAILABLE\xef\xbc\x89\"}\n";
static const char DENY_PRE[] =
    "{\"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"permissionDecision\": \"deny\", "
    "\"permissionDecisionReason\": \"\xe6\x9c\xac\xe5\x9c\xb0 DLP \xe6\x8b\x92\xe7\xbb\x9d\xe8\xaf\xa5"
    "\xe5\xb7\xa5\xe5\x85\xb7\xe8\xb0\x83\xe7\x94\xa8\xef\xbc\x88GATE_UNAVAILABLE\xef\xbc\x89\"}}\n";

typedef struct { char *data; DWORD size; } Buffer;

static void write_out(const char *data, DWORD size) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD done = 0, n;
    while (done < size && WriteFile(out, data + done, size - done, &n, NULL) && n) done += n;
    FlushFileBuffers(out);
}

/* Find `"hook_event_name"` then the next quoted value, within the first 64 KiB. */
static const char *deny_for(const Buffer *event) {
    static const char key[] = "\"hook_event_name\"";
    DWORD limit = event->size < 65536 ? event->size : 65536;
    for (DWORD i = 0; i + sizeof(key) - 1 <= limit; i++) {
        if (memcmp(event->data + i, key, sizeof(key) - 1) != 0) continue;
        DWORD j = i + (DWORD)sizeof(key) - 1;
        while (j < limit && (event->data[j] == ' ' || event->data[j] == '\t' ||
                             event->data[j] == '\r' || event->data[j] == '\n')) j++;
        if (j >= limit || event->data[j] != ':') continue;
        j++;
        while (j < limit && (event->data[j] == ' ' || event->data[j] == '\t')) j++;
        if (j >= limit || event->data[j] != '"') continue;
        const char *name = event->data + j + 1;
        DWORD room = limit - j - 1;
#define IS(lit) (room > sizeof(lit) - 1 && memcmp(name, lit "\"", sizeof(lit)) == 0)
        if (IS("UserPromptSubmit")) return DENY_PROMPT;
        if (IS("PreToolUse")) return DENY_PRE;
        if (IS("PostToolUse")) return DENY_POST;
#undef IS
        return NULL;
    }
    return NULL;
}

static void deny_or_allow(const Buffer *event) {
    const char *reply = deny_for(event);
    if (reply) write_out(reply, (DWORD)strlen(reply));
}

static int read_all(HANDLE h, Buffer *b, DWORD cap) {
    DWORD size = 0, alloc = 65536, n;
    char *data = (char *)malloc(alloc);
    if (!data) return 0;
    for (;;) {
        if (size == alloc) {
            if (alloc > cap) break;
            alloc *= 2;
            char *grown = (char *)realloc(data, alloc);
            if (!grown) { free(data); return 0; }
            data = grown;
        }
        if (!ReadFile(h, data + size, alloc - size, &n, NULL) || n == 0) break;
        size += n;
        if (size > cap) break;
    }
    b->data = data; b->size = size;
    return 1;
}

static int pipe_io(HANDLE pipe, void *buf, DWORD size, int writing, DWORD deadline) {
    DWORD done = 0;
    while (done < size) {
        OVERLAPPED ov; memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) return 0;
        DWORD n = 0;
        BOOL ok = writing ? WriteFile(pipe, (char *)buf + done, size - done, NULL, &ov)
                          : ReadFile(pipe, (char *)buf + done, size - done, NULL, &ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING) { CloseHandle(ov.hEvent); return 0; }
        DWORD now = GetTickCount();
        DWORD wait = (int)(deadline - now) > 0 ? deadline - now : 0;
        if (WaitForSingleObject(ov.hEvent, wait) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            GetOverlappedResult(pipe, &ov, &n, TRUE);
            CloseHandle(ov.hEvent);
            return 0;
        }
        if (!GetOverlappedResult(pipe, &ov, &n, FALSE) || n == 0) { CloseHandle(ov.hEvent); return 0; }
        CloseHandle(ov.hEvent);
        done += n;
    }
    return 1;
}

/* 1 = a reply (possibly empty) was obtained and written. */
static int via_service(const wchar_t *name, const Buffer *event) {
    DWORD deadline = GetTickCount() + SERVICE_DEADLINE_MS;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 3 && pipe == INVALID_HANDLE_VALUE; attempt++) {
        pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED, NULL);
        if (pipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY || !WaitNamedPipeW(name, PIPE_WAIT_MS)) return 0;
    }
    if (pipe == INVALID_HANDLE_VALUE) return 0;
    int ok = 0;
    UINT32 size = event->size, reply_size = 0;
    char *reply = NULL;
    if (pipe_io(pipe, &size, 4, 1, deadline) && pipe_io(pipe, event->data, size, 1, deadline) &&
        pipe_io(pipe, &reply_size, 4, 0, deadline) && reply_size <= MAX_REPLY) {
        reply = (char *)malloc(reply_size ? reply_size : 1);
        if (reply && pipe_io(pipe, reply, reply_size, 0, deadline)) {
            if (reply_size) write_out(reply, reply_size);
            ok = 1;
        }
    }
    free(reply);
    CloseHandle(pipe);
    return ok;
}

/* Run the per-event Python gate with the same stdin bytes; pass its stdout through. */
static int via_python(const wchar_t *python, const wchar_t *entry, const wchar_t *config,
                      const Buffer *event) {
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE in_r, in_w, out_r, out_w;
    if (!CreatePipe(&in_r, &in_w, &sa, 0)) return 0;
    if (!CreatePipe(&out_r, &out_w, &sa, 0)) { CloseHandle(in_r); CloseHandle(in_w); return 0; }
    SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    wchar_t cmd[4 * MAX_PATH + 16];
    if (_snwprintf(cmd, sizeof cmd / sizeof cmd[0], L"\"%ls\" \"%ls\" \"%ls\"", python, entry, config) < 0) {
        CloseHandle(in_r); CloseHandle(in_w); CloseHandle(out_r); CloseHandle(out_w);
        return 0;
    }
    STARTUPINFOW si; memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_r; si.hStdOutput = out_w; si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi;
    BOOL started = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(in_r); CloseHandle(out_w);
    if (!started) { CloseHandle(in_w); CloseHandle(out_r); return 0; }
    DWORD done = 0, n;
    while (done < event->size && WriteFile(in_w, event->data + done, event->size - done, &n, NULL) && n)
        done += n;
    CloseHandle(in_w);
    Buffer reply = { NULL, 0 };
    int read_ok = read_all(out_r, &reply, MAX_REPLY);
    CloseHandle(out_r);
    DWORD waited = WaitForSingleObject(pi.hProcess, FALLBACK_DEADLINE_MS);
    DWORD code = 1;
    if (waited == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
    else TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    int ok = read_ok && waited == WAIT_OBJECT_0 && code == 0 && reply.size <= MAX_REPLY;
    if (ok && reply.size) write_out(reply.data, reply.size);
    free(reply.data);
    return ok;
}

int wmain(int argc, wchar_t **argv) {
    Buffer event = { NULL, 0 };
    if (!read_all(GetStdHandle(STD_INPUT_HANDLE), &event, MAX_EVENT)) return 0;
    if (argc == 5 && event.size <= MAX_EVENT) {
        if (via_service(argv[1], &event)) return 0;
        if (via_python(argv[2], argv[3], argv[4], &event)) return 0;
    }
    deny_or_allow(&event);
    return 0;
}
