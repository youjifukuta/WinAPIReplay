#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include "sample/log_helper.h"
#include "sample/scenarios.h"

// エコーサーバースレッド（ログ対象外）
static HANDLE g_serverReadyEvent = nullptr;

static DWORD WINAPI EchoServerThread(LPVOID) {
    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        SetEvent(g_serverReadyEvent);
        return 1;
    }

    sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(13000);

    if (bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR ||
        listen(srv, 1) == SOCKET_ERROR) {
        closesocket(srv);
        SetEvent(g_serverReadyEvent);
        return 1;
    }

    SetEvent(g_serverReadyEvent);

    SOCKET cli = accept(srv, nullptr, nullptr);
    closesocket(srv);
    if (cli == INVALID_SOCKET) return 1;

    char buf[256];
    int n = recv(cli, buf, sizeof(buf), 0);
    if (n > 0) send(cli, buf, n, 0);
    closesocket(cli);
    return 0;
}

int RunNetworkScenario() {
    printf("\n[SCENARIO] network\n");
    int failures = 0;

    // seq 1: WSAStartup（② はフックしない。JSON ログには含まれない）
    WSADATA wsaData = {};
    int wsaRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaRet != 0) {
        LogCallErr("WSAStartup", "MAKEWORD(2,2)", (DWORD)wsaRet);
        return ++failures;
    }
    LogCallOk("WSAStartup", "MAKEWORD(2,2)");

    // エコーサーバーを起動して準備完了を待つ
    g_serverReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE hThread = CreateThread(nullptr, 0, EchoServerThread, nullptr, 0, nullptr);
    WaitForSingleObject(g_serverReadyEvent, 3000);
    CloseHandle(g_serverReadyEvent);
    g_serverReadyEvent = nullptr;

    // seq 2: socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        LogCallErr("socket", "AF_INET SOCK_STREAM IPPROTO_TCP", (DWORD)WSAGetLastError());
        ++failures;
        WSACleanup();
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        return failures;
    }
    LogCallOk("socket", "AF_INET SOCK_STREAM IPPROTO_TCP");

    // seq 3: GetAddrInfoW
    ADDRINFOW hints = {};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    ADDRINFOW* pAddr = nullptr;
    int gai = GetAddrInfoW(L"127.0.0.1", L"13000", &hints, &pAddr);
    if (gai != 0) {
        LogCallErr("GetAddrInfoW", "127.0.0.1:13000", (DWORD)gai);
        ++failures;
        closesocket(sock);
        WSACleanup();
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        return failures;
    }
    LogCallOk("GetAddrInfoW", "127.0.0.1:13000");

    // seq 4: WSAConnect
    int cr = WSAConnect(sock, pAddr->ai_addr, (int)pAddr->ai_addrlen,
                         nullptr, nullptr, nullptr, nullptr);
    FreeAddrInfoW(pAddr);
    if (cr == SOCKET_ERROR) {
        LogCallErr("WSAConnect", "127.0.0.1:13000", (DWORD)WSAGetLastError());
        ++failures;
        closesocket(sock);
        WSACleanup();
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        return failures;
    }
    LogCallOk("WSAConnect", "127.0.0.1:13000");

    // seq 5: send（"WinAPIReplaySample" 18バイト）
    static const char* kMsg    = "WinAPIReplaySample";
    static const int   kMsgLen = 18;
    int sent = send(sock, kMsg, kMsgLen, 0);
    if (sent == SOCKET_ERROR) {
        LogCallErr("send", "WinAPIReplaySample", (DWORD)WSAGetLastError());
        ++failures;
    } else {
        char detail[64];
        sprintf_s(detail, "sent=%d", sent);
        LogCallOk("send", detail);
    }

    // seq 6: recv
    char recvBuf[64] = {};
    int recvd = recv(sock, recvBuf, sizeof(recvBuf) - 1, 0);
    if (recvd == SOCKET_ERROR) {
        LogCallErr("recv", "echo response", (DWORD)WSAGetLastError());
        ++failures;
    } else {
        char detail[64];
        sprintf_s(detail, "recv=%d", recvd);
        LogCallOk("recv", detail);
    }

    // seq 7: closesocket
    if (closesocket(sock) == SOCKET_ERROR) {
        LogCallErr("closesocket", "", (DWORD)WSAGetLastError());
        ++failures;
    } else {
        LogCallOk("closesocket", "");
    }

    // seq 8: WSACleanup
    if (WSACleanup() == SOCKET_ERROR) {
        LogCallErr("WSACleanup", "", (DWORD)WSAGetLastError());
        ++failures;
    } else {
        LogCallOk("WSACleanup", "");
    }

    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);

    printf("[RESULT] network: %d/8 calls succeeded\n", 8 - failures);
    return failures;
}
