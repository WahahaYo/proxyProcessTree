#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <string>
#include "ProcessController.h"
#include "UI.h"
#include "HistoryManager.h"

#pragma comment(lib, "comctl32.lib")

ProcessController g_processController;
UI g_ui;
HistoryManager g_historyManager;

void OnStart(const wchar_t* exePath, const wchar_t* upstreamProxy) {
    g_historyManager.AddProgram(exePath);
    if (wcslen(upstreamProxy) > 0) {
        g_historyManager.AddUpstreamProxy(upstreamProxy);
    }
    
    g_processController.StartProcess(exePath);
}

void OnStop() {
    g_processController.StopAll();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_STANDARD_CLASSES | ICC_COOL_CLASSES;
    InitCommonControlsEx(&icex);

    g_ui.SetStartCallback(OnStart);
    g_ui.SetStopCallback(OnStop);

    if (!g_ui.CreateMainWindow(hInstance, nCmdShow)) {
        return 1;
    }

    g_ui.SetProgramHistory(g_historyManager.GetPrograms());
    g_ui.SetProxyHistory(g_historyManager.GetUpstreamProxies());

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    OnStop();

    return 0;
}
