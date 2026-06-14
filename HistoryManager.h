#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>

class HistoryManager {
public:
    HistoryManager();
    ~HistoryManager();

    void AddProgram(const std::wstring& path);
    void AddUpstreamProxy(const std::wstring& proxy);
    
    const std::vector<std::wstring>& GetPrograms() const { return m_programs; }
    const std::vector<std::wstring>& GetUpstreamProxies() const { return m_proxies; }
    
    void Load();
    void Save();

private:
    std::wstring GetHistoryFilePath() const;
    
    std::vector<std::wstring> m_programs;
    std::vector<std::wstring> m_proxies;
    std::mutex m_mutex;
    static const size_t MAX_HISTORY = 10;
};
