#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <set>
#include <mutex>

class WFPInterceptor {
public:
    WFPInterceptor() : m_running(false), m_pProxyPids(nullptr), m_proxyPort(10808) {}
    ~WFPInterceptor() { Stop(); }

    bool Start() { m_running = true; return true; }
    void Stop() { m_running = false; }
    void SetProxyPids(const std::set<DWORD>* pids) { std::lock_guard<std::mutex> lock(m_mutex); m_pProxyPids = pids; }
    void SetProxyPort(WORD port) { m_proxyPort = port; }

private:
    bool m_running;
    const std::set<DWORD>* m_pProxyPids;
    WORD m_proxyPort;
    std::mutex m_mutex;
};
