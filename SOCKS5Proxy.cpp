#include "SOCKS5Proxy.h"

struct ClientData {
    SOCKS5Proxy* proxy;
    SOCKET socket;
};

SOCKS5Proxy::SOCKS5Proxy()
    : m_listenSocket(INVALID_SOCKET)
    , m_acceptThread(nullptr)
    , m_running(false)
    , m_port(10808)
    , m_upstreamPort(0)
    , m_useUpstream(false)
{
}

SOCKS5Proxy::~SOCKS5Proxy() {
    Stop();
}

bool SOCKS5Proxy::IsPortInUse(WORD port) {
    SOCKET testSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (testSocket == INVALID_SOCKET) {
        return true;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    bool inUse = (bind(testSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR);
    closesocket(testSocket);
    return inUse;
}

bool SOCKS5Proxy::Start(WORD port) {
    m_port = port;

    if (IsPortInUse(m_port)) {
        for (WORD p = 10809; p < 10900; p++) {
            if (!IsPortInUse(p)) {
                m_port = p;
                break;
            }
        }
    }

    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) {
        return false;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(m_port);

    if (bind(m_listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        return false;
    }

    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        return false;
    }

    m_running = true;
    m_acceptThread = CreateThread(NULL, 0, AcceptThread, this, 0, NULL);
    return m_acceptThread != nullptr;
}

void SOCKS5Proxy::Stop() {
    m_running = false;

    if (m_acceptThread) {
        if (m_listenSocket != INVALID_SOCKET) {
            closesocket(m_listenSocket);
            m_listenSocket = INVALID_SOCKET;
        }
        WaitForSingleObject(m_acceptThread, INFINITE);
        CloseHandle(m_acceptThread);
        m_acceptThread = nullptr;
    }
}

DWORD WINAPI SOCKS5Proxy::AcceptThread(LPVOID lpParam) {
    SOCKS5Proxy* pThis = (SOCKS5Proxy*)lpParam;
    pThis->AcceptConnections();
    return 0;
}

void SOCKS5Proxy::AcceptConnections() {
    while (m_running) {
        SOCKET clientSocket = accept(m_listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            if (m_running) Sleep(10);
            continue;
        }

        ClientData* data = new ClientData{ this, clientSocket };
        HANDLE hThread = CreateThread(NULL, 0, HandleClientThread, data, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
}

DWORD WINAPI SOCKS5Proxy::HandleClientThread(LPVOID lpParam) {
    ClientData* data = (ClientData*)lpParam;
    data->proxy->HandleClient(data->socket);
    delete data;
    return 0;
}

void SOCKS5Proxy::HandleClient(SOCKET clientSocket) {
    std::string targetHost;
    USHORT targetPort = 0;

    if (!HandleSOCKS5Handshake(clientSocket)) {
        closesocket(clientSocket);
        return;
    }

    if (!HandleConnectRequest(clientSocket, targetHost, targetPort)) {
        closesocket(clientSocket);
        return;
    }

    SOCKET targetSocket = ConnectToTarget(targetHost, targetPort);
    if (targetSocket == INVALID_SOCKET) {
        unsigned char reply[10] = {
            0x05, 0x04, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        };
        send(clientSocket, (char*)reply, 10, 0);
        closesocket(clientSocket);
        return;
    }

    unsigned char reply[10] = {
        0x05, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    send(clientSocket, (char*)reply, 10, 0);

    ForwardData(clientSocket, targetSocket);

    closesocket(targetSocket);
    closesocket(clientSocket);
}

SOCKET SOCKS5Proxy::ConnectToTarget(const std::string& host, USHORT port) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::string connectHost = host;
    USHORT connectPort = port;
    bool useUpstream = m_useUpstream;
    std::string upstreamHost = m_upstreamHost;
    USHORT upstreamPort = m_upstreamPort;

    SOCKET socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketFd == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;

    if (useUpstream) {
        addr.sin_port = htons(upstreamPort);
        inet_pton(AF_INET, upstreamHost.c_str(), &addr.sin_addr);
        
        if (connect(socketFd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(socketFd);
            return INVALID_SOCKET;
        }

        unsigned char socksRequest[512] = { 0x05, 0x01, 0x00, 0x03 };
        size_t hostLen = host.length();
        socksRequest[4] = (BYTE)hostLen;
        memcpy(&socksRequest[5], host.c_str(), hostLen);
        *(USHORT*)&socksRequest[5 + hostLen] = htons(port);
        
        send(socketFd, (char*)socksRequest, 6 + hostLen, 0);
        
        char reply[10] = {};
        recv(socketFd, reply, 10, 0);
        if (reply[1] != 0x00) {
            closesocket(socketFd);
            return INVALID_SOCKET;
        }
    } else {
        addr.sin_port = htons(connectPort);
        inet_pton(AF_INET, connectHost.c_str(), &addr.sin_addr);
        
        if (connect(socketFd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(socketFd);
            return INVALID_SOCKET;
        }
    }

    return socketFd;
}

bool SOCKS5Proxy::HandleSOCKS5Handshake(SOCKET clientSocket) {
    char buffer[256] = {};
    int len = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (len < 2) return false;

    if (buffer[0] != 0x05) return false;

    unsigned char reply[2] = { 0x05, 0x00 };
    send(clientSocket, (char*)reply, 2, 0);
    return true;
}

bool SOCKS5Proxy::HandleConnectRequest(SOCKET clientSocket, std::string& targetHost, USHORT& targetPort) {
    char buffer[256] = {};
    int len = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (len < 7) return false;

    if (buffer[0] != 0x05 || buffer[1] != 0x01) return false;

    BYTE addrType = buffer[3];

    if (addrType == 0x01) {
        char ip[16] = {};
        memcpy(ip, &buffer[4], 4);
        targetHost = std::to_string((unsigned char)ip[0]) + "." +
                     std::to_string((unsigned char)ip[1]) + "." +
                     std::to_string((unsigned char)ip[2]) + "." +
                     std::to_string((unsigned char)ip[3]);
        targetPort = *(USHORT*)&buffer[8];
        targetPort = ntohs(targetPort);
    }
    else if (addrType == 0x03) {
        BYTE addrLen = buffer[4];
        targetHost = std::string(&buffer[5], addrLen);
        targetPort = *(USHORT*)&buffer[5 + addrLen];
        targetPort = ntohs(targetPort);
    }
    else {
        return false;
    }

    return true;
}

bool SOCKS5Proxy::ForwardData(SOCKET clientSocket, SOCKET targetSocket) {
    char buffer[8192];
    fd_set readfds;
    bool running = true;

    while (running) {
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        FD_SET(targetSocket, &readfds);

        timeval tv = { 1, 0 };
        int ret = select(0, &readfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        if (FD_ISSET(clientSocket, &readfds)) {
            int len = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (len <= 0) break;
            int sent = send(targetSocket, buffer, len, 0);
            if (sent != len) break;
        }

        if (FD_ISSET(targetSocket, &readfds)) {
            int len = recv(targetSocket, buffer, sizeof(buffer), 0);
            if (len <= 0) break;
            int sent = send(clientSocket, buffer, len, 0);
            if (sent != len) break;
        }
    }

    return true;
}
