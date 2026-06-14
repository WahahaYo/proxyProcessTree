#include "UI.h"

UI::UI()
    : m_hwnd(nullptr)
    , m_hComboPath(nullptr)
    , m_hBtnBrowse(nullptr)
    , m_hBtnStart(nullptr)
    , m_hBtnStop(nullptr)
    , m_hBtnSelectProcess(nullptr)
    , m_hComboUpstream(nullptr)
    , m_hLabelUpstream(nullptr)
    , m_startCallback(nullptr)
    , m_stopCallback(nullptr)
{
}

UI::~UI() {
}

void UI::SetProgramHistory(const std::vector<std::wstring>& history) {
    m_programHistory = history;
    UpdateProgramCombo();
}

void UI::SetProxyHistory(const std::vector<std::wstring>& history) {
    m_proxyHistory = history;
    UpdateProxyCombo();
}

void UI::UpdateProgramCombo() {
    if (!m_hComboPath) return;
    
    SendMessageW(m_hComboPath, CB_RESETCONTENT, 0, 0);
    
    for (const auto& program : m_programHistory) {
        SendMessageW(m_hComboPath, CB_ADDSTRING, 0, (LPARAM)program.c_str());
    }
}

void UI::UpdateProxyCombo() {
    if (!m_hComboUpstream) return;
    
    SendMessageW(m_hComboUpstream, CB_RESETCONTENT, 0, 0);
    
    SendMessageW(m_hComboUpstream, CB_ADDSTRING, 0, (LPARAM)L"");
    
    for (const auto& proxy : m_proxyHistory) {
        SendMessageW(m_hComboUpstream, CB_ADDSTRING, 0, (LPARAM)proxy.c_str());
    }
}

bool UI::CreateMainWindow(HINSTANCE hInstance, int nCmdShow) {
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"ProxyProcessTree";
    RegisterClassExW(&wc);

    m_hwnd = ::CreateWindowExW(0, L"ProxyProcessTree", L"ProxyProcessTree",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 250,
        NULL, NULL, hInstance, this);

    if (!m_hwnd) return false;

    int y = 15;
    
    m_hComboPath = ::CreateWindowExW(0, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWN,
        20, y, 350, 200, m_hwnd, NULL, hInstance, NULL);

    m_hBtnBrowse = ::CreateWindowExW(0, L"BUTTON", L"Browse",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        380, y, 80, 25, m_hwnd, (HMENU)1, hInstance, NULL);

    y += 35;
    m_hLabelUpstream = ::CreateWindowExW(0, L"STATIC", L"Upstream Proxy (host:port):",
        WS_CHILD | WS_VISIBLE,
        20, y, 180, 20, m_hwnd, NULL, hInstance, NULL);

    m_hComboUpstream = ::CreateWindowExW(0, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWN,
        200, y, 260, 200, m_hwnd, NULL, hInstance, NULL);

    y += 35;
    m_hBtnSelectProcess = ::CreateWindowExW(0, L"BUTTON", L"Select Process",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, y, 120, 25, m_hwnd, (HMENU)2, hInstance, NULL);

    y += 40;
    m_hBtnStart = ::CreateWindowExW(0, L"BUTTON", L"Start",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        120, y, 80, 30, m_hwnd, (HMENU)3, hInstance, NULL);

    m_hBtnStop = ::CreateWindowExW(0, L"BUTTON", L"Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        220, y, 80, 30, m_hwnd, (HMENU)4, hInstance, NULL);

    EnableWindow(m_hBtnStop, FALSE);

    UpdateProgramCombo();
    UpdateProxyCombo();

    ShowWindow(m_hwnd, nCmdShow);
    UpdateWindow(m_hwnd);

    return true;
}

LRESULT CALLBACK UI::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    UI* pThis = nullptr;
    if (msg == WM_NCCREATE) {
        pThis = (UI*)((CREATESTRUCTW*)lParam)->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
    }
    else {
        pThis = (UI*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    }

    if (pThis) {
        return pThis->HandleMsg(hwnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT UI::HandleMsg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            OPENFILENAMEW ofn = { sizeof(OPENFILENAMEW) };
            wchar_t path[MAX_PATH] = {};
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"Executable\0*.exe\0All Files\0*.*\0";
            ofn.lpstrFile = path;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST;

            if (GetOpenFileNameW(&ofn)) {
                int idx = SendMessageW(m_hComboPath, CB_ADDSTRING, 0, (LPARAM)path);
                SendMessageW(m_hComboPath, CB_SETCURSEL, (WPARAM)idx, 0);
            }
        }
        else if (LOWORD(wParam) == 2) {
            OPENFILENAMEW ofn = { sizeof(OPENFILENAMEW) };
            wchar_t path[MAX_PATH] = {};
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"Executable\0*.exe\0All Files\0*.*\0";
            ofn.lpstrFile = path;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST;

            if (GetOpenFileNameW(&ofn)) {
                int idx = SendMessageW(m_hComboPath, CB_ADDSTRING, 0, (LPARAM)path);
                SendMessageW(m_hComboPath, CB_SETCURSEL, (WPARAM)idx, 0);
            }
        }
        else if (LOWORD(wParam) == 3) {
            wchar_t path[MAX_PATH] = {};
            wchar_t upstream[256] = {};
            
            int len = SendMessageW(m_hComboPath, CB_GETLBTEXT, 
                SendMessageW(m_hComboPath, CB_GETCURSEL, 0, 0), (LPARAM)path);
            if (len == CB_ERR) {
                GetWindowTextW(m_hComboPath, path, MAX_PATH);
            }
            
            len = SendMessageW(m_hComboUpstream, CB_GETLBTEXT, 
                SendMessageW(m_hComboUpstream, CB_GETCURSEL, 0, 0), (LPARAM)upstream);
            if (len == CB_ERR) {
                GetWindowTextW(m_hComboUpstream, upstream, 256);
            }
            
            if (wcslen(path) > 0 && m_startCallback) {
                m_startCallback(path, upstream);
                EnableWindow(m_hBtnStart, FALSE);
                EnableWindow(m_hBtnStop, TRUE);
                EnableWindow(m_hBtnBrowse, FALSE);
                EnableWindow(m_hComboPath, FALSE);
                EnableWindow(m_hComboUpstream, FALSE);
            }
        }
        else if (LOWORD(wParam) == 4) {
            if (m_stopCallback) {
                m_stopCallback();
            }
            EnableWindow(m_hBtnStart, TRUE);
            EnableWindow(m_hBtnStop, FALSE);
            EnableWindow(m_hBtnBrowse, TRUE);
            EnableWindow(m_hComboPath, TRUE);
            EnableWindow(m_hComboUpstream, TRUE);
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}
