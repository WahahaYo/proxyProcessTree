#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <vector>
#include <string>

class UI {
public:
    UI();
    ~UI();

    bool CreateMainWindow(HINSTANCE hInstance, int nCmdShow);
    HWND GetHWND() const { return m_hwnd; }
    
    void SetStartCallback(void (*callback)(const wchar_t*, const wchar_t*)) { m_startCallback = callback; }
    void SetStopCallback(void (*callback)()) { m_stopCallback = callback; }
    
    void SetProgramHistory(const std::vector<std::wstring>& history);
    void SetProxyHistory(const std::vector<std::wstring>& history);

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMsg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    void UpdateProgramCombo();
    void UpdateProxyCombo();

    HWND m_hwnd;
    HWND m_hComboPath;
    HWND m_hBtnBrowse;
    HWND m_hBtnStart;
    HWND m_hBtnStop;
    HWND m_hBtnSelectProcess;
    HWND m_hComboUpstream;
    HWND m_hLabelUpstream;

    void (*m_startCallback)(const wchar_t*, const wchar_t*);
    void (*m_stopCallback)();
    
    std::vector<std::wstring> m_programHistory;
    std::vector<std::wstring> m_proxyHistory;
};
