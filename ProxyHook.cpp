// proxyHook.dll - injected into every proxy-domain process.
//
// Strategy: IAT (Import Address Table) hooking. We patch the import tables of
// every loaded module so that Winsock connection/resolution calls land in our
// replacements. To stay robust against late binding we also hook
// kernel32!GetProcAddress (so dynamically resolved pointers get swapped too)
// and kernel32!LoadLibrary* (so modules loaded later also get patched).
//
// Connection coverage: connect, WSAConnect, ConnectEx (obtained at runtime via
// WSAIoctl/SIO_GET_EXTENSION_FUNCTION_POINTER), and WSAConnectByName. Each TCP
// connect is pointed at the local SOCKS5 proxy and tunnelled transparently.
//
// DNS leak prevention (fake-IP): getaddrinfo / GetAddrInfoW are hooked to return
// a synthetic IP from 198.18.0.0/15 instead of doing real resolution, recording
// fakeIP -> hostname. When the app later connects to that fake IP, we recover the
// hostname and send it to the proxy as a SOCKS5 domain request (ATYP=3), so the
// actual DNS resolution happens at the proxy, not on the local machine.
//
// Fail-closed: if the proxy cannot be reached or refuses, we return a connect
// failure rather than silently falling back to a direct connection, so traffic
// never leaks around the proxy.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <string>
#include <map>
#include <set>
#include "ProxyShared.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

// ---- Debug logging (compile-time gated; OFF by default) --------------------
// Rebuild proxyHook with PROXY_DEBUG_LOG=1 defined to trace every injected
// process and connection to proxyhook.log next to proxyHook.dll. When disabled,
// HookLog(...) compiles to nothing (no runtime cost, no disk I/O).
#ifndef PROXY_DEBUG_LOG
#define PROXY_DEBUG_LOG 0
#endif

#if PROXY_DEBUG_LOG
static HMODULE g_selfForLog = nullptr;
static void HookLog(const char* fmt, ...) {
    wchar_t logPath[MAX_PATH] = {};
    if (!GetModuleFileNameW(g_selfForLog, logPath, MAX_PATH)) return;
    wchar_t* slash = wcsrchr(logPath, L'\\');
    if (!slash) return;
    wcscpy_s(slash + 1, MAX_PATH - (size_t)(slash + 1 - logPath), L"proxyhook.log");

    char body[512];
    va_list args;
    va_start(args, fmt);
    int n = _vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, args);
    va_end(args);
    if (n < 0) n = (int)strlen(body);

    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    const wchar_t* exeName = wcsrchr(exe, L'\\');
    exeName = exeName ? exeName + 1 : exe;

    char line[800];
    int m = _snprintf_s(line, sizeof(line), _TRUNCATE,
                        "[%lu %ls] %s\r\n", GetCurrentProcessId(), exeName, body);
    if (m < 0) return;

    HANDLE h = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, line, (DWORD)strlen(line), &written, NULL);
    CloseHandle(h);
}
#else
#define HookLog(...) ((void)0)
#endif

// ---- Real function pointers (captured before any hook is installed) --------
typedef int (WSAAPI *PFN_connect)(SOCKET, const sockaddr*, int);
typedef int (WSAAPI *PFN_WSAConnect)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef int (WSAAPI *PFN_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI *PFN_WSAConnectByNameW)(SOCKET, LPWSTR, LPWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const timeval*, LPWSAOVERLAPPED);
typedef BOOL (WSAAPI *PFN_WSAConnectByNameA)(SOCKET, LPCSTR, LPCSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const timeval*, LPWSAOVERLAPPED);
typedef int (WSAAPI *PFN_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef void (WSAAPI *PFN_FreeAddrInfoW)(PADDRINFOW);
typedef int (WSAAPI *PFN_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef void (WSAAPI *PFN_freeaddrinfo)(PADDRINFOA);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                          BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                          BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static PFN_connect        g_realConnect       = nullptr;
static PFN_WSAConnect     g_realWSAConnect    = nullptr;
static PFN_GetProcAddress g_realGetProcAddress = nullptr;
static PFN_LoadLibraryW   g_realLoadLibraryW  = nullptr;
static PFN_LoadLibraryA   g_realLoadLibraryA  = nullptr;
static PFN_LoadLibraryExW g_realLoadLibraryExW = nullptr;
static PFN_LoadLibraryExA g_realLoadLibraryExA = nullptr;
static PFN_WSAIoctl       g_realWSAIoctl      = nullptr;
static PFN_WSAConnectByNameW g_realWSAConnectByNameW = nullptr;
static PFN_WSAConnectByNameA g_realWSAConnectByNameA = nullptr;
static PFN_GetAddrInfoW   g_realGetAddrInfoW  = nullptr;
static PFN_FreeAddrInfoW  g_realFreeAddrInfoW = nullptr;
static PFN_getaddrinfo    g_realGetaddrinfo   = nullptr;
static PFN_freeaddrinfo   g_realFreeaddrinfo  = nullptr;
static LPFN_CONNECTEX     g_realConnectEx     = nullptr;
static PFN_CreateProcessW g_realCreateProcessW = nullptr;
static PFN_CreateProcessA g_realCreateProcessA = nullptr;

static WORD     g_proxyPort = 0;          // 0 => not configured, hooks pass through
static HMODULE  g_selfModule = nullptr;   // our own module, excluded from patching
static volatile LONG g_installed = 0;

// Forward declarations of the hook entry points.
static int WSAAPI MyConnect(SOCKET s, const sockaddr* name, int namelen);
static int WSAAPI MyWSAConnect(SOCKET s, const sockaddr* name, int namelen,
                               LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                               LPQOS lpSQOS, LPQOS lpGQOS);
static FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
static HMODULE WINAPI MyLoadLibraryW(LPCWSTR lpLibFileName);
static HMODULE WINAPI MyLoadLibraryA(LPCSTR lpLibFileName);
static HMODULE WINAPI MyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
static HMODULE WINAPI MyLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
static int WSAAPI MyWSAIoctl(SOCKET s, DWORD code, LPVOID inBuf, DWORD inLen, LPVOID outBuf,
                             DWORD outLen, LPDWORD bytesRet, LPWSAOVERLAPPED ov,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE cr);
static BOOL PASCAL MyConnectEx(SOCKET s, const sockaddr* name, int namelen, PVOID lpSendBuffer,
                               DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);
static BOOL WSAAPI MyWSAConnectByNameW(SOCKET s, LPWSTR node, LPWSTR svc, LPDWORD localLen,
                                       LPSOCKADDR local, LPDWORD remoteLen, LPSOCKADDR remote,
                                       const timeval* tv, LPWSAOVERLAPPED reserved);
static BOOL WSAAPI MyWSAConnectByNameA(SOCKET s, LPCSTR node, LPCSTR svc, LPDWORD localLen,
                                       LPSOCKADDR local, LPDWORD remoteLen, LPSOCKADDR remote,
                                       const timeval* tv, LPWSAOVERLAPPED reserved);
static int WSAAPI MyGetAddrInfoW(PCWSTR node, PCWSTR svc, const ADDRINFOW* hints, PADDRINFOW* result);
static void WSAAPI MyFreeAddrInfoW(PADDRINFOW p);
static int WSAAPI MyGetaddrinfo(PCSTR node, PCSTR svc, const ADDRINFOA* hints, PADDRINFOA* result);
static void WSAAPI MyFreeaddrinfo(PADDRINFOA p);
static USHORT ResolvePortA(PCSTR svc);
static BOOL WINAPI MyCreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                    BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
                                    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi);
static BOOL WINAPI MyCreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                    BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir,
                                    LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi);

static void PatchAllModules();

// ---------------------------------------------------------------------------
// Socket helpers that tolerate both blocking and non-blocking sockets by
// driving the I/O with select(). The application may have put its socket into
// non-blocking mode before calling connect(); we must not assume blocking.
// ---------------------------------------------------------------------------

static const int HANDSHAKE_TIMEOUT_SEC = 10;

static bool WaitReady(SOCKET s, bool forWrite) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeval tv = { HANDSHAKE_TIMEOUT_SEC, 0 };
    int ret = forWrite ? select(0, NULL, &set, NULL, &tv)
                       : select(0, &set, NULL, NULL, &tv);
    return ret > 0 && FD_ISSET(s, &set);
}

static bool SendAll(SOCKET s, const unsigned char* buf, int len) {
    int total = 0;
    while (total < len) {
        int n = send(s, (const char*)buf + total, len - total, 0);
        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK && WaitReady(s, true)) continue;
            return false;
        }
        if (n == 0) return false;
        total += n;
    }
    return true;
}

static bool RecvAll(SOCKET s, unsigned char* buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(s, (char*)buf + total, len - total, 0);
        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK && WaitReady(s, false)) continue;
            return false;
        }
        if (n == 0) return false;  // peer closed mid-handshake
        total += n;
    }
    return true;
}

// Connect the socket to the local proxy, tolerating non-blocking sockets.
static bool ConnectToProxy(SOCKET s, ADDRESS_FAMILY family) {
    sockaddr_storage ss = {};
    int sslen = 0;
    if (family == AF_INET6) {
        sockaddr_in6* a = (sockaddr_in6*)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(g_proxyPort);
        a->sin6_addr = in6addr_loopback;
        sslen = sizeof(sockaddr_in6);
    } else {
        sockaddr_in* a = (sockaddr_in*)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(g_proxyPort);
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sslen = sizeof(sockaddr_in);
    }

    int ret = g_realConnect(s, (sockaddr*)&ss, sslen);
    if (ret == 0) return true;

    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY) {
        if (!WaitReady(s, true)) return false;
        int soErr = 0;
        int optLen = sizeof(soErr);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soErr, &optLen) == 0 && soErr == 0) {
            return true;
        }
        return false;
    }
    return false;
}

// ---- Fake-IP DNS table -----------------------------------------------------
// getaddrinfo/GetAddrInfoW hand out synthetic IPs from 198.18.0.0/15 instead of
// resolving for real. The connect hook maps them back to the hostname so the
// proxy does the resolution (no DNS leaks to the local resolver).
static const ULONG FAKE_LOW  = 0xC6120000UL;  // 198.18.0.0
static const ULONG FAKE_HIGH = 0xC613FFFFUL;  // 198.19.255.255

static CRITICAL_SECTION g_dnsLock;
static std::map<ULONG, std::string> g_fakeToHost;  // host-order fake IP -> name
static std::map<std::string, ULONG> g_hostToFake;
static ULONG g_nextFake = FAKE_LOW + 1;
static std::set<void*> g_ourAddrinfo;              // addrinfo blocks we allocated

static bool IsFakeIp(ULONG hostOrderIp) {
    return hostOrderIp >= FAKE_LOW && hostOrderIp <= FAKE_HIGH;
}

static ULONG AllocFakeIp(const std::string& host) {
    EnterCriticalSection(&g_dnsLock);
    ULONG ip;
    auto it = g_hostToFake.find(host);
    if (it != g_hostToFake.end()) {
        ip = it->second;
    } else {
        if (g_nextFake <= FAKE_LOW || g_nextFake >= FAKE_HIGH) g_nextFake = FAKE_LOW + 1;
        ip = g_nextFake++;
        g_hostToFake[host] = ip;
        g_fakeToHost[ip] = host;
    }
    LeaveCriticalSection(&g_dnsLock);
    return ip;
}

static bool LookupFakeIp(ULONG ip, std::string& host) {
    EnterCriticalSection(&g_dnsLock);
    auto it = g_fakeToHost.find(ip);
    bool ok = (it != g_fakeToHost.end());
    if (ok) host = it->second;
    LeaveCriticalSection(&g_dnsLock);
    return ok;
}

static std::string NarrowW(PCWSTR w) {
    if (!w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 1) return std::string();
    std::string s((size_t)(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, NULL, NULL);
    return s;
}

// ---- SOCKS5 CONNECT target -------------------------------------------------
// A resolved destination to ask the proxy for: an IPv4/IPv6 literal or a domain.
struct Target {
    int atyp;                 // 1 = IPv4, 4 = IPv6, 3 = domain name
    unsigned char addr[16];   // for atyp 1/4
    std::string domain;       // for atyp 3
    USHORT portNet;           // network byte order
};

// Build a Target from the sockaddr the app asked to connect to. A fake IP is
// translated back into the original hostname (sent as a domain to the proxy).
static bool ResolveTarget(const sockaddr* name, Target& t) {
    if (name->sa_family == AF_INET) {
        const sockaddr_in* a = (const sockaddr_in*)name;
        ULONG iph = ntohl(a->sin_addr.s_addr);
        std::string host;
        if (IsFakeIp(iph) && LookupFakeIp(iph, host)) {
            t.atyp = 3; t.domain = host; t.portNet = a->sin_port;
            return true;
        }
        t.atyp = 1; memcpy(t.addr, &a->sin_addr, 4); t.portNet = a->sin_port;
        return true;
    }
    if (name->sa_family == AF_INET6) {
        const sockaddr_in6* a = (const sockaddr_in6*)name;
        t.atyp = 4; memcpy(t.addr, &a->sin6_addr, 16); t.portNet = a->sin6_port;
        return true;
    }
    return false;
}

// Perform the SOCKS5 client handshake on an already-proxy-connected socket.
static bool Socks5HandshakeTarget(SOCKET s, const Target& t) {
    unsigned char greeting[3] = { 0x05, 0x01, 0x00 };  // VER, 1 method, NO-AUTH
    if (!SendAll(s, greeting, sizeof(greeting))) return false;

    unsigned char methodReply[2] = {};
    if (!RecvAll(s, methodReply, 2)) return false;
    if (methodReply[0] != 0x05 || methodReply[1] != 0x00) return false;

    unsigned char req[262] = { 0x05, 0x01, 0x00 };
    req[3] = (unsigned char)t.atyp;
    int reqLen = 0;
    if (t.atyp == 1) {
        memcpy(&req[4], t.addr, 4);
        memcpy(&req[8], &t.portNet, 2);
        reqLen = 10;
    } else if (t.atyp == 4) {
        memcpy(&req[4], t.addr, 16);
        memcpy(&req[20], &t.portNet, 2);
        reqLen = 22;
    } else if (t.atyp == 3) {
        size_t L = t.domain.size();
        if (L == 0 || L > 255) return false;
        req[4] = (unsigned char)L;
        memcpy(&req[5], t.domain.data(), L);
        memcpy(&req[5 + L], &t.portNet, 2);
        reqLen = (int)(7 + L);
    } else {
        return false;
    }
    if (!SendAll(s, req, reqLen)) return false;

    unsigned char head[4] = {};
    if (!RecvAll(s, head, 4)) return false;
    if (head[1] != 0x00) return false;  // REP != success

    int drain = 0;
    switch (head[3]) {
        case 0x01: drain = 4 + 2; break;
        case 0x04: drain = 16 + 2; break;
        case 0x03: {
            unsigned char dlen = 0;
            if (!RecvAll(s, &dlen, 1)) return false;
            drain = dlen + 2;
            break;
        }
        default: return false;
    }
    unsigned char scratch[64];
    while (drain > 0) {
        int chunk = drain < (int)sizeof(scratch) ? drain : (int)sizeof(scratch);
        if (!RecvAll(s, scratch, chunk)) return false;
        drain -= chunk;
    }
    return true;
}

// Returns true if `name` points at a loopback address (must not be redirected:
// it is either local IPC or our own proxy connection).
static bool IsLoopback(const sockaddr* name) {
    if (name->sa_family == AF_INET) {
        const sockaddr_in* a = (const sockaddr_in*)name;
        return (ntohl(a->sin_addr.s_addr) >> 24) == 127;  // 127.0.0.0/8
    }
    if (name->sa_family == AF_INET6) {
        const sockaddr_in6* a = (const sockaddr_in6*)name;
        return IN6_IS_ADDR_LOOPBACK(&a->sin6_addr) != 0;
    }
    return false;
}

// Decide whether a connect() on this socket to this address should be proxied.
static bool ShouldRedirect(SOCKET s, const sockaddr* name, int namelen) {
    if (g_proxyPort == 0 || name == nullptr || namelen < (int)sizeof(sockaddr_in)) return false;
    if (name->sa_family != AF_INET && name->sa_family != AF_INET6) return false;
    if (IsLoopback(name)) return false;

    int type = 0;
    int optLen = sizeof(type);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &optLen) != 0) return false;
    return type == SOCK_STREAM;  // only TCP
}

// Address family of a (possibly unconnected) socket.
static ADDRESS_FAMILY SocketFamily(SOCKET s) {
    WSAPROTOCOL_INFOW info = {};
    int len = sizeof(info);
    if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*)&info, &len) == 0) {
        return (ADDRESS_FAMILY)info.iAddressFamily;
    }
    return AF_INET;
}

// Tunnel socket `s` to `t` through the local proxy. connectFamily is the family
// of the application's socket (how we reach the loopback proxy).
// Returns 0 on success, SOCKET_ERROR (with WSAECONNREFUSED) on any failure.
static int RedirectToTarget(SOCKET s, ADDRESS_FAMILY connectFamily, const Target& t) {
    if (!ConnectToProxy(s, connectFamily)) {
        HookLog("redirect: ConnectToProxy(127.0.0.1:%u) FAILED err=%d", g_proxyPort, WSAGetLastError());
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    if (!Socks5HandshakeTarget(s, t)) {
        HookLog("redirect: SOCKS5 handshake FAILED err=%d", WSAGetLastError());
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    HookLog("redirect: OK via 127.0.0.1:%u (atyp=%d)", g_proxyPort, t.atyp);
    return 0;
}

// Shared redirect path for connect()/WSAConnect()/ConnectEx() (sockaddr-based).
static int RedirectConnect(SOCKET s, const sockaddr* name) {
    Target t;
    if (!ResolveTarget(name, t)) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    return RedirectToTarget(s, name->sa_family, t);
}

// ---- Hook entry points -----------------------------------------------------

static int WSAAPI MyConnect(SOCKET s, const sockaddr* name, int namelen) {
    if (ShouldRedirect(s, name, namelen)) {
        return RedirectConnect(s, name);
    }
    return g_realConnect(s, name, namelen);
}

static int WSAAPI MyWSAConnect(SOCKET s, const sockaddr* name, int namelen,
                               LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                               LPQOS lpSQOS, LPQOS lpGQOS) {
    if (ShouldRedirect(s, name, namelen)) {
        return RedirectConnect(s, name);
    }
    return g_realWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

// ConnectEx (async/overlapped). We perform a synchronous proxy connect + SOCKS5
// handshake (the loopback proxy responds instantly), send any initial data, and
// signal completion. Event-based overlapped is fully supported; IOCP-only
// overlapped (no hEvent) can't be completed by us, so we fail closed rather than
// leak or hang.
static BOOL PASCAL MyConnectEx(SOCKET s, const sockaddr* name, int namelen, PVOID lpSendBuffer,
                               DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped) {
    if (!ShouldRedirect(s, name, namelen)) {
        return g_realConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }

    if (RedirectConnect(s, name) != 0) {
        if (lpOverlapped) lpOverlapped->Internal = (ULONG_PTR)WSAECONNREFUSED;
        return FALSE;  // WSAECONNREFUSED already set by RedirectConnect
    }

    DWORD sent = 0;
    if (lpSendBuffer && dwSendDataLength > 0) {
        if (!SendAll(s, (const unsigned char*)lpSendBuffer, (int)dwSendDataLength)) {
            WSASetLastError(WSAECONNRESET);
            if (lpOverlapped) lpOverlapped->Internal = (ULONG_PTR)WSAECONNRESET;
            return FALSE;
        }
        sent = dwSendDataLength;
    }
    if (lpdwBytesSent) *lpdwBytesSent = sent;

    if (lpOverlapped) {
        lpOverlapped->Internal = 0;             // STATUS_SUCCESS
        lpOverlapped->InternalHigh = sent;
        if (lpOverlapped->hEvent) {
            SetEvent(lpOverlapped->hEvent);
            return TRUE;                         // event-based: completed synchronously
        }
        // IOCP-only: we cannot post a completion packet, so fail closed.
        HookLog("ConnectEx: IOCP overlapped without event - failing closed");
        WSASetLastError(WSAECONNREFUSED);
        return FALSE;
    }
    return TRUE;
}

static int WSAAPI MyWSAIoctl(SOCKET s, DWORD code, LPVOID inBuf, DWORD inLen, LPVOID outBuf,
                             DWORD outLen, LPDWORD bytesRet, LPWSAOVERLAPPED ov,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = g_realWSAIoctl(s, code, inBuf, inLen, outBuf, outLen, bytesRet, ov, cr);
    if (r == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        inBuf && inLen >= sizeof(GUID) && outBuf && outLen >= sizeof(void*)) {
        GUID connectExId = WSAID_CONNECTEX;
        if (memcmp(inBuf, &connectExId, sizeof(GUID)) == 0) {
            LPFN_CONNECTEX real = *(LPFN_CONNECTEX*)outBuf;
            if (real && real != MyConnectEx) {
                g_realConnectEx = real;
                *(LPFN_CONNECTEX*)outBuf = MyConnectEx;
                HookLog("WSAIoctl: ConnectEx pointer hooked");
            }
        }
    }
    return r;
}

static BOOL WSAAPI MyWSAConnectByNameW(SOCKET s, LPWSTR node, LPWSTR svc, LPDWORD localLen,
                                       LPSOCKADDR local, LPDWORD remoteLen, LPSOCKADDR remote,
                                       const timeval* tv, LPWSAOVERLAPPED reserved) {
    if (g_proxyPort != 0 && node) {
        Target t;
        t.atyp = 3;
        t.domain = NarrowW(node);
        std::string svcA = NarrowW(svc);
        t.portNet = htons(ResolvePortA(svcA.empty() ? nullptr : svcA.c_str()));
        if (!t.domain.empty()) {
            if (RedirectToTarget(s, SocketFamily(s), t) == 0) {
                if (localLen) *localLen = 0;
                if (remoteLen) *remoteLen = 0;
                return TRUE;
            }
            return FALSE;  // fail closed (WSAECONNREFUSED set)
        }
    }
    return g_realWSAConnectByNameW(s, node, svc, localLen, local, remoteLen, remote, tv, reserved);
}

static BOOL WSAAPI MyWSAConnectByNameA(SOCKET s, LPCSTR node, LPCSTR svc, LPDWORD localLen,
                                       LPSOCKADDR local, LPDWORD remoteLen, LPSOCKADDR remote,
                                       const timeval* tv, LPWSAOVERLAPPED reserved) {
    if (g_proxyPort != 0 && node) {
        Target t;
        t.atyp = 3;
        t.domain = node;
        t.portNet = htons(ResolvePortA(svc));
        if (!t.domain.empty()) {
            if (RedirectToTarget(s, SocketFamily(s), t) == 0) {
                if (localLen) *localLen = 0;
                if (remoteLen) *remoteLen = 0;
                return TRUE;
            }
            return FALSE;
        }
    }
    return g_realWSAConnectByNameA(s, node, svc, localLen, local, remoteLen, remote, tv, reserved);
}

// ---- DNS hooks (fake-IP) ---------------------------------------------------

// True if this resolution should NOT be faked (let the real resolver handle it):
// numeric host, UDP, IPv6-only, or a null host (passive lookup).
static bool DnsPassthrough(const void* node, bool wide, const ADDRINFOW* hintsW, const ADDRINFOA* hintsA) {
    if (!node) return true;
    int flags = wide ? (hintsW ? hintsW->ai_flags : 0) : (hintsA ? hintsA->ai_flags : 0);
    int family = wide ? (hintsW ? hintsW->ai_family : AF_UNSPEC) : (hintsA ? hintsA->ai_family : AF_UNSPEC);
    int stype = wide ? (hintsW ? hintsW->ai_socktype : 0) : (hintsA ? hintsA->ai_socktype : 0);
    int proto = wide ? (hintsW ? hintsW->ai_protocol : 0) : (hintsA ? hintsA->ai_protocol : 0);
    if (flags & AI_NUMERICHOST) return true;
    if (family == AF_INET6) return true;       // we only synthesise IPv4 fakes
    if (stype == SOCK_DGRAM || proto == IPPROTO_UDP) return true;  // TCP proxy only

    // Numeric literal? Let it through unchanged.
    in_addr a4; in6_addr a6;
    if (wide) {
        if (InetPtonW(AF_INET, (PCWSTR)node, &a4) == 1) return true;
        if (InetPtonW(AF_INET6, (PCWSTR)node, &a6) == 1) return true;
    } else {
        if (InetPtonA(AF_INET, (PCSTR)node, &a4) == 1) return true;
        if (InetPtonA(AF_INET6, (PCSTR)node, &a6) == 1) return true;
    }
    return false;
}

static USHORT ResolvePortA(PCSTR svc) {
    if (!svc || !*svc) return 0;
    char* end = nullptr;
    long v = strtol(svc, &end, 10);
    if (end && *end == '\0' && v > 0 && v < 65536) return (USHORT)v;
    servent* se = getservbyname(svc, "tcp");
    return se ? ntohs(se->s_port) : 0;
}

static int WSAAPI MyGetAddrInfoW(PCWSTR node, PCWSTR svc, const ADDRINFOW* hints, PADDRINFOW* result) {
    if (g_proxyPort == 0 || !result || DnsPassthrough(node, true, hints, nullptr)) {
        return g_realGetAddrInfoW(node, svc, hints, result);
    }

    std::string host = NarrowW(node);
    if (host.empty()) return g_realGetAddrInfoW(node, svc, hints, result);

    std::string svcA = NarrowW(svc);
    USHORT port = ResolvePortA(svcA.empty() ? nullptr : svcA.c_str());
    ULONG fake = AllocFakeIp(host);

    PADDRINFOW ai = (PADDRINFOW)calloc(1, sizeof(ADDRINFOW));
    sockaddr_in* sa = (sockaddr_in*)calloc(1, sizeof(sockaddr_in));
    if (!ai || !sa) { free(ai); free(sa); return EAI_MEMORY; }
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(fake);
    sa->sin_port = htons(port);
    ai->ai_family = AF_INET;
    ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
    ai->ai_protocol = hints ? hints->ai_protocol : IPPROTO_TCP;
    ai->ai_addrlen = sizeof(sockaddr_in);
    ai->ai_addr = (sockaddr*)sa;

    EnterCriticalSection(&g_dnsLock);
    g_ourAddrinfo.insert(ai);
    LeaveCriticalSection(&g_dnsLock);

    *result = ai;
    HookLog("GetAddrInfoW(%ls) -> fake 198.18", node);
    return 0;
}

static void WSAAPI MyFreeAddrInfoW(PADDRINFOW p) {
    if (p) {
        EnterCriticalSection(&g_dnsLock);
        auto it = g_ourAddrinfo.find(p);
        bool ours = (it != g_ourAddrinfo.end());
        if (ours) g_ourAddrinfo.erase(it);
        LeaveCriticalSection(&g_dnsLock);
        if (ours) { free(p->ai_addr); free(p); return; }
    }
    g_realFreeAddrInfoW(p);
}

static int WSAAPI MyGetaddrinfo(PCSTR node, PCSTR svc, const ADDRINFOA* hints, PADDRINFOA* result) {
    if (g_proxyPort == 0 || !result || DnsPassthrough(node, false, nullptr, hints)) {
        return g_realGetaddrinfo(node, svc, hints, result);
    }

    std::string host = node;
    USHORT port = ResolvePortA(svc);
    ULONG fake = AllocFakeIp(host);

    PADDRINFOA ai = (PADDRINFOA)calloc(1, sizeof(ADDRINFOA));
    sockaddr_in* sa = (sockaddr_in*)calloc(1, sizeof(sockaddr_in));
    if (!ai || !sa) { free(ai); free(sa); return EAI_MEMORY; }
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(fake);
    sa->sin_port = htons(port);
    ai->ai_family = AF_INET;
    ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
    ai->ai_protocol = hints ? hints->ai_protocol : IPPROTO_TCP;
    ai->ai_addrlen = sizeof(sockaddr_in);
    ai->ai_addr = (sockaddr*)sa;

    EnterCriticalSection(&g_dnsLock);
    g_ourAddrinfo.insert(ai);
    LeaveCriticalSection(&g_dnsLock);

    *result = ai;
    HookLog("getaddrinfo(%s) -> fake 198.18", node);
    return 0;
}

static void WSAAPI MyFreeaddrinfo(PADDRINFOA p) {
    if (p) {
        EnterCriticalSection(&g_dnsLock);
        auto it = g_ourAddrinfo.find(p);
        bool ours = (it != g_ourAddrinfo.end());
        if (ours) g_ourAddrinfo.erase(it);
        LeaveCriticalSection(&g_dnsLock);
        if (ours) { free(p->ai_addr); free(p); return; }
    }
    g_realFreeaddrinfo(p);
}

static FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    FARPROC real = g_realGetProcAddress(hModule, lpProcName);
    if (real == (FARPROC)g_realConnect)            return (FARPROC)MyConnect;
    if (real == (FARPROC)g_realWSAConnect)         return (FARPROC)MyWSAConnect;
    if (real == (FARPROC)g_realWSAIoctl)           return (FARPROC)MyWSAIoctl;
    if (real == (FARPROC)g_realWSAConnectByNameW)  return (FARPROC)MyWSAConnectByNameW;
    if (real == (FARPROC)g_realWSAConnectByNameA)  return (FARPROC)MyWSAConnectByNameA;
    if (real == (FARPROC)g_realGetAddrInfoW)       return (FARPROC)MyGetAddrInfoW;
    if (real == (FARPROC)g_realFreeAddrInfoW)      return (FARPROC)MyFreeAddrInfoW;
    if (real == (FARPROC)g_realGetaddrinfo)        return (FARPROC)MyGetaddrinfo;
    if (real == (FARPROC)g_realFreeaddrinfo)       return (FARPROC)MyFreeaddrinfo;
    if (real == (FARPROC)g_realCreateProcessW)     return (FARPROC)MyCreateProcessW;
    if (real == (FARPROC)g_realCreateProcessA)     return (FARPROC)MyCreateProcessA;
    return real;
}

static HMODULE WINAPI MyLoadLibraryW(LPCWSTR n) {
    HMODULE h = g_realLoadLibraryW(n);
    if (h) PatchAllModules();
    return h;
}
static HMODULE WINAPI MyLoadLibraryA(LPCSTR n) {
    HMODULE h = g_realLoadLibraryA(n);
    if (h) PatchAllModules();
    return h;
}
static HMODULE WINAPI MyLoadLibraryExW(LPCWSTR n, HANDLE f, DWORD fl) {
    HMODULE h = g_realLoadLibraryExW(n, f, fl);
    if (h) PatchAllModules();
    return h;
}
static HMODULE WINAPI MyLoadLibraryExA(LPCSTR n, HANDLE f, DWORD fl) {
    HMODULE h = g_realLoadLibraryExA(n, f, fl);
    if (h) PatchAllModules();
    return h;
}

// Inject this DLL into a freshly-created child using the handle we already own
// (no OpenProcess / SeDebugPrivilege needed). Synchronous: the remote LoadLibrary
// runs while the child's main thread is still suspended, so hooks are installed
// before the child executes any code — closing the early-traffic / DNS race.
static void InjectIntoChild(HANDLE hProcess) {
    BOOL wow64 = FALSE;
    if (IsWow64Process(hProcess, &wow64) && wow64) {
        HookLog("CreateProcess: child is WOW64/x86, cannot inject x64 DLL");
        return;  // x64 DLL can't load into a 32-bit child
    }

    wchar_t dllPath[MAX_PATH] = {};
    if (!GetModuleFileNameW(g_selfModule, dllPath, MAX_PATH)) return;
    SIZE_T bytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    LPVOID remote = VirtualAllocEx(hProcess, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return;
    if (WriteProcessMemory(hProcess, remote, dllPath, bytes, NULL)) {
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)g_realLoadLibraryW, remote, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
            HookLog("CreateProcess: injected hook into child");
        }
    }
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
}

static BOOL WINAPI MyCreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                    BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
                                    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    bool callerSuspended = (flags & CREATE_SUSPENDED) != 0;
    BOOL ok = g_realCreateProcessW(app, cmd, pa, ta, inherit, flags | CREATE_SUSPENDED, env, dir, si, pi);
    if (ok && pi) {
        InjectIntoChild(pi->hProcess);
        if (!callerSuspended) ResumeThread(pi->hThread);
    }
    return ok;
}

static BOOL WINAPI MyCreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                    BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir,
                                    LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi) {
    bool callerSuspended = (flags & CREATE_SUSPENDED) != 0;
    BOOL ok = g_realCreateProcessA(app, cmd, pa, ta, inherit, flags | CREATE_SUSPENDED, env, dir, si, pi);
    if (ok && pi) {
        InjectIntoChild(pi->hProcess);
        if (!callerSuspended) ResumeThread(pi->hThread);
    }
    return ok;
}

// ---- IAT patching ----------------------------------------------------------

// Swap a single IAT slot's value if it currently points at a function we hook.
static void PatchSlot(void** slot) {
    void* cur = *slot;
    void* repl = nullptr;
    if      (cur == (void*)g_realConnect)            repl = (void*)MyConnect;
    else if (cur == (void*)g_realWSAConnect)         repl = (void*)MyWSAConnect;
    else if (cur == (void*)g_realWSAIoctl)           repl = (void*)MyWSAIoctl;
    else if (cur == (void*)g_realWSAConnectByNameW)  repl = (void*)MyWSAConnectByNameW;
    else if (cur == (void*)g_realWSAConnectByNameA)  repl = (void*)MyWSAConnectByNameA;
    else if (cur == (void*)g_realGetAddrInfoW)       repl = (void*)MyGetAddrInfoW;
    else if (cur == (void*)g_realFreeAddrInfoW)      repl = (void*)MyFreeAddrInfoW;
    else if (cur == (void*)g_realGetaddrinfo)        repl = (void*)MyGetaddrinfo;
    else if (cur == (void*)g_realFreeaddrinfo)       repl = (void*)MyFreeaddrinfo;
    else if (cur == (void*)g_realCreateProcessW)     repl = (void*)MyCreateProcessW;
    else if (cur == (void*)g_realCreateProcessA)     repl = (void*)MyCreateProcessA;
    else if (cur == (void*)g_realGetProcAddress)     repl = (void*)MyGetProcAddress;
    else if (cur == (void*)g_realLoadLibraryW)       repl = (void*)MyLoadLibraryW;
    else if (cur == (void*)g_realLoadLibraryA)       repl = (void*)MyLoadLibraryA;
    else if (cur == (void*)g_realLoadLibraryExW)     repl = (void*)MyLoadLibraryExW;
    else if (cur == (void*)g_realLoadLibraryExA)     repl = (void*)MyLoadLibraryExA;
    if (!repl || repl == cur) return;

    DWORD oldProtect = 0;
    if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        *slot = repl;
        VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
    }
}

// Walk one module's import table and patch every slot pointing at a hooked fn.
// Pointer-comparison handles both import-by-name and import-by-ordinal.
static void PatchModule(HMODULE module) {
    if (module == nullptr || module == g_selfModule) return;

    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp.VirtualAddress == 0 || imp.Size == 0) return;

    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp.VirtualAddress);
    for (; desc->Name != 0; ++desc) {
        if (desc->FirstThunk == 0) continue;
        void** thunk = (void**)(base + desc->FirstThunk);
        for (; *thunk != nullptr; ++thunk) {
            PatchSlot(thunk);
        }
    }
}

static void PatchAllModules() {
    HMODULE modules[512];
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, modules, sizeof(modules), &needed)) return;
    DWORD count = needed / sizeof(HMODULE);
    if (count > 512) count = 512;
    for (DWORD i = 0; i < count; ++i) {
        PatchModule(modules[i]);
    }
}

// ---- Setup / teardown ------------------------------------------------------

static bool LoadProxyPort() {
    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, PROXY_SHARED_MAPPING_NAME);
    if (!map) return false;
    ProxySharedData* data = (ProxySharedData*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, sizeof(ProxySharedData));
    bool ok = false;
    if (data) {
        if (data->proxyPort != 0 && data->proxyPort <= 0xFFFF) {
            g_proxyPort = (WORD)data->proxyPort;
            ok = true;
        }
        UnmapViewOfFile(data);
    }
    CloseHandle(map);
    return ok;
}

static void Install() {
    if (InterlockedCompareExchange(&g_installed, 1, 0) != 0) return;

    HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
    if (!ws2) ws2 = GetModuleHandleW(L"wsock32.dll");
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!ws2 || !k32) return;

    // Capture the genuine entry points BEFORE installing any hook.
    g_realConnect        = (PFN_connect)GetProcAddress(ws2, "connect");
    g_realWSAConnect     = (PFN_WSAConnect)GetProcAddress(ws2, "WSAConnect");
    g_realWSAIoctl       = (PFN_WSAIoctl)GetProcAddress(ws2, "WSAIoctl");
    g_realWSAConnectByNameW = (PFN_WSAConnectByNameW)GetProcAddress(ws2, "WSAConnectByNameW");
    g_realWSAConnectByNameA = (PFN_WSAConnectByNameA)GetProcAddress(ws2, "WSAConnectByNameA");
    g_realGetAddrInfoW   = (PFN_GetAddrInfoW)GetProcAddress(ws2, "GetAddrInfoW");
    g_realFreeAddrInfoW  = (PFN_FreeAddrInfoW)GetProcAddress(ws2, "FreeAddrInfoW");
    g_realGetaddrinfo    = (PFN_getaddrinfo)GetProcAddress(ws2, "getaddrinfo");
    g_realFreeaddrinfo   = (PFN_freeaddrinfo)GetProcAddress(ws2, "freeaddrinfo");
    g_realGetProcAddress = (PFN_GetProcAddress)GetProcAddress(k32, "GetProcAddress");
    g_realLoadLibraryW   = (PFN_LoadLibraryW)GetProcAddress(k32, "LoadLibraryW");
    g_realLoadLibraryA   = (PFN_LoadLibraryA)GetProcAddress(k32, "LoadLibraryA");
    g_realLoadLibraryExW = (PFN_LoadLibraryExW)GetProcAddress(k32, "LoadLibraryExW");
    g_realLoadLibraryExA = (PFN_LoadLibraryExA)GetProcAddress(k32, "LoadLibraryExA");
    g_realCreateProcessW = (PFN_CreateProcessW)GetProcAddress(k32, "CreateProcessW");
    g_realCreateProcessA = (PFN_CreateProcessA)GetProcAddress(k32, "CreateProcessA");

    if (!g_realConnect || !g_realGetProcAddress) {
        HookLog("Install: FAILED to resolve real connect/GetProcAddress");
        return;
    }

    // No proxy endpoint published => do not hook; let the process run normally
    // rather than bricking it with fail-closed behaviour it can't satisfy.
    if (!LoadProxyPort()) {
        HookLog("Install: no proxy port published; hooks NOT installed (pass-through)");
        return;
    }

    PatchAllModules();
    HookLog("Install: hooks installed, proxyPort=%u", g_proxyPort);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_selfModule = hModule;
#if PROXY_DEBUG_LOG
        g_selfForLog = hModule;
#endif
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_dnsLock);
        HookLog("DLL_PROCESS_ATTACH");
        Install();
        break;
    case DLL_PROCESS_DETACH:
        // Process is going away; leave patches in place.
        break;
    }
    return TRUE;
}
