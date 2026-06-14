#pragma once
#include <windows.h>
#include <set>
#include <string>
#include <mutex>

class ProcessController {
public:
    ProcessController();
    ~ProcessController();

    bool StartProcess(const std::wstring& exePath);
    void StopAll();
    bool IsInProxyDomain(DWORD pid);
    const std::set<DWORD>& GetProxyPids() const { return m_proxyPids; }

private:
    void TrackChildProcesses();
    static DWORD WINAPI TrackThread(LPVOID lpParam);
    void AddToProxyDomain(DWORD pid);

    std::set<DWORD> m_proxyPids;
    std::mutex m_mutex;
    bool m_tracking;
    HANDLE m_trackThread;
    HANDLE m_mainProcess;
};
