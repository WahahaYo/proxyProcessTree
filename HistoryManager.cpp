#include "HistoryManager.h"
#include <fstream>
#include <algorithm>

HistoryManager::HistoryManager() {
    Load();
}

HistoryManager::~HistoryManager() {
    Save();
}

std::wstring HistoryManager::GetHistoryFilePath() const {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L'\\');
    return fullPath.substr(0, pos + 1) + L"history.txt";
}

void HistoryManager::AddProgram(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = std::find(m_programs.begin(), m_programs.end(), path);
    if (it != m_programs.end()) {
        m_programs.erase(it);
    }
    
    m_programs.insert(m_programs.begin(), path);
    
    if (m_programs.size() > MAX_HISTORY) {
        m_programs.pop_back();
    }
    
    Save();
}

void HistoryManager::AddUpstreamProxy(const std::wstring& proxy) {
    if (proxy.empty()) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = std::find(m_proxies.begin(), m_proxies.end(), proxy);
    if (it != m_proxies.end()) {
        m_proxies.erase(it);
    }
    
    m_proxies.insert(m_proxies.begin(), proxy);
    
    if (m_proxies.size() > MAX_HISTORY) {
        m_proxies.pop_back();
    }
    
    Save();
}

void HistoryManager::Load() {
    std::wstring filePath = GetHistoryFilePath();
    std::wifstream file(filePath);
    
    if (!file.is_open()) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_programs.clear();
    m_proxies.clear();
    
    std::wstring line;
    bool readingPrograms = true;
    
    while (std::getline(file, line)) {
        if (line == L"[UPSTREAM]") {
            readingPrograms = false;
            continue;
        }
        
        if (readingPrograms) {
            if (!line.empty()) {
                m_programs.push_back(line);
            }
        } else {
            if (!line.empty()) {
                m_proxies.push_back(line);
            }
        }
    }
    
    file.close();
}

void HistoryManager::Save() {
    std::wstring filePath = GetHistoryFilePath();
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::wofstream file(filePath);
    if (!file.is_open()) {
        return;
    }
    
    for (const auto& program : m_programs) {
        file << program << std::endl;
    }
    
    file << L"[UPSTREAM]" << std::endl;
    
    for (const auto& proxy : m_proxies) {
        file << proxy << std::endl;
    }
    
    file.flush();
    file.close();
}
