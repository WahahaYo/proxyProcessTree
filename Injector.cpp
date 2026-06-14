#include "Injector.h"
#include <cstdio>

// Diagnostic logging (compile-time gated; OFF by default). Define
// PROXY_DEBUG_LOG=1 to append injection results to proxyProcessTree_inject.log
// next to the host exe. When disabled, InjLog(...) compiles to nothing.
#ifndef PROXY_DEBUG_LOG
#define PROXY_DEBUG_LOG 0
#endif

#if PROXY_DEBUG_LOG
static void InjLog(const char* fmt, ...) {
    wchar_t logPath[MAX_PATH] = {};
    if (!GetModuleFileNameW(NULL, logPath, MAX_PATH)) return;
    wchar_t* slash = wcsrchr(logPath, L'\\');
    if (!slash) return;
    wcscpy_s(slash + 1, MAX_PATH - (size_t)(slash + 1 - logPath), L"proxyProcessTree_inject.log");

    char body[512];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, args);
    va_end(args);

    char line[600];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "%s\r\n", body);

    HANDLE h = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, line, (DWORD)strlen(line), &written, NULL);
    CloseHandle(h);
}
#else
#define InjLog(...) ((void)0)
#endif

bool Injector::EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = false;
    if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
        ok = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(token);
    return ok;
}

bool Injector::Inject(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        InjLog("inject pid=%lu: OpenProcess FAILED err=%lu", pid, GetLastError());
        return false;
    }

    // An x64 DLL cannot be loaded into a 32-bit (WOW64) process. Skip those
    // rather than corrupting the target.
    BOOL targetIsWow64 = FALSE;
    if (IsWow64Process(hProc, &targetIsWow64) && targetIsWow64) {
        InjLog("inject pid=%lu: skipped (WOW64/x86 target)", pid);
        CloseHandle(hProc);
        return false;
    }

    SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        InjLog("inject pid=%lu: VirtualAllocEx FAILED err=%lu", pid, GetLastError());
        CloseHandle(hProc);
        return false;
    }

    bool success = false;
    if (WriteProcessMemory(hProc, remote, dllPath.c_str(), bytes, NULL)) {
        // LoadLibraryW lives at the same address in every process (kernel32 is
        // mapped at a per-boot but process-shared base), so the host's pointer
        // is valid in the target.
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        LPTHREAD_START_ROUTINE loadLib =
            (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
        if (loadLib) {
            HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, loadLib, remote, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, 10000);
                DWORD exitCode = 0;
                // Truncated HMODULE on x64, but 0 reliably means LoadLibrary failed.
                GetExitCodeThread(hThread, &exitCode);
                success = (exitCode != 0);
                InjLog("inject pid=%lu: %s (LoadLibrary ret=0x%lx)",
                       pid, success ? "OK" : "FAILED", exitCode);
                CloseHandle(hThread);
            } else {
                InjLog("inject pid=%lu: CreateRemoteThread FAILED err=%lu", pid, GetLastError());
            }
        }
    } else {
        InjLog("inject pid=%lu: WriteProcessMemory FAILED err=%lu", pid, GetLastError());
    }

    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return success;
}
