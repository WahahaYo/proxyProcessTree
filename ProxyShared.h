#pragma once
#include <windows.h>

// Contract shared between the host (proxyProcessTree.exe) and the injected
// hook DLL (proxyHook.dll). The host publishes the live local SOCKS5 port into
// a session-local file mapping; the hook DLL reads it on load so it knows where
// to redirect intercepted connections.
//
// "Local\\" keeps the object in the current logon session — the proxy-domain
// child processes are launched by the host and run in the same session, so the
// hook can open it without needing the global namespace privilege.
#define PROXY_SHARED_MAPPING_NAME L"Local\\ProxyProcessTree_Endpoint"

#pragma pack(push, 8)
struct ProxySharedData {
    DWORD proxyPort;   // loopback SOCKS5 port the hook redirects connections to
};
#pragma pack(pop)
