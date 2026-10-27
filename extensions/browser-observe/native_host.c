/* Per-experiment stdio launcher. Compiled paths, no shell, no arbitrary args. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#include "launcher_config.h"

int wmain(int argc, wchar_t **argv) {
    if (argc < 2 || wcscmp(argv[1], TT_ORIGIN) != 0) return 2;
    wchar_t command[32768];
    int n = _snwprintf(command, 32768, L"\"%ls\" -I -m transpect_trace.flow.browser.host --config \"%ls\" \"%ls\"", TT_PYTHON, TT_CONFIG, TT_ORIGIN);
    if (n < 0 || n >= 32767) return 2;
    STARTUPINFOW startup = {0}; PROCESS_INFORMATION child = {0};
    startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, TRUE};
    HANDLE errors = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, &attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (errors == INVALID_HANDLE_VALUE) return 2;
    startup.hStdError = errors;
    BOOL created = CreateProcessW(TT_PYTHON, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup, &child);
    CloseHandle(errors);
    if (!created) return 2;
    CloseHandle(child.hThread);
    WaitForSingleObject(child.hProcess, INFINITE);
    DWORD code = 2; GetExitCodeProcess(child.hProcess, &code); CloseHandle(child.hProcess);
    return (int)code;
}
