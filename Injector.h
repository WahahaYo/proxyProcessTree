#pragma once
#include <windows.h>
#include <string>

// Injects proxyHook.dll into proxy-domain processes via the classic
// CreateRemoteThread + LoadLibraryW technique. Requires the host to run
// elevated (SeDebugPrivilege) for reliable cross-process access.
class Injector {
public:
    // Enable SeDebugPrivilege for the current process (call once at startup).
    static bool EnableDebugPrivilege();

    // Inject `dllPath` into the process identified by `pid`.
    // Returns true if the DLL was loaded in the target. Same-architecture only
    // (an x64 host cannot inject an x64 DLL into a WOW64/x86 target).
    static bool Inject(DWORD pid, const std::wstring& dllPath);
};
