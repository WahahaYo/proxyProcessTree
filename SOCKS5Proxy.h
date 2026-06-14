#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

class SOCKS5Proxy {
public:
    SOCKS5Proxy();
    ~SOCKS5Proxy();

    bool Start(WORD port = 10808);
    void Stop();
    WORD GetPort() const { return m_port; }
    
    void SetUpstreamProxy(const std::string& host, USHORT port) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_upstreamHost = host;
        m_upstreamPort = port;
        m_useUpstream = !host.empty();
    }
    
    void ClearUpstreamProxy() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_upstreamHost.clear();
        m_upstreamPort = 0;
        m_useUpstream = false;
    }

private:
    static DWORD WINAPI AcceptThread(LPVOID lpParam);
    void AcceptConnections();
    static DWORD WINAPI HandleClientThread(LPVOID lpParam);
    void HandleClient(SOCKET clientSocket);

    bool HandleSOCKS5Handshake(SOCKET clientSocket);
    bool HandleConnectRequest(SOCKET clientSocket, std::string& targetHost, USHORT& targetPort);
    bool ForwardData(SOCKET clientSocket, SOCKET targetSocket);
    SOCKET ConnectToTarget(const std::string& host, USHORT port);
    
    bool IsPortInUse(WORD port);

    SOCKET m_listenSocket;
    HANDLE m_acceptThread;
    bool m_running;
    WORD m_port;
    std::mutex m_mutex;
    
    std::string m_upstreamHost;
    USHORT m_upstreamPort;
    bool m_useUpstream;
};
