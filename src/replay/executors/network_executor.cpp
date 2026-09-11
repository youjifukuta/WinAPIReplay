#include "replay/executors/network_executor.h"
#include "replay/utils.h"
#include <wininet.h>

void NetworkExecutor::EnsureWSAStartup() {
    if (!wsa_initialized_) {
        WSADATA wd{};
        WSAStartup(MAKEWORD(2, 2), &wd);
        wsa_initialized_ = true;
    }
}

std::vector<std::string> NetworkExecutor::SupportedApis() const {
    return {
        "WSAStartup", "WSACleanup",
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "closesocket",
        "WSAConnect",
        "GetAddrInfoW", "FreeAddrInfoW",
        "InternetOpenW", "InternetOpenA",
        "InternetConnectW", "InternetConnectA",
        "HttpOpenRequestW", "HttpOpenRequestA",
        "HttpSendRequestW", "HttpSendRequestA",
        "InternetReadFile",
        "InternetCloseHandle",
    };
}

// Extract the original (pre-resolve) handle value from event.args[idx].
static DWORD_PTR ReadArgHandle(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return 0;
    if (auto* iv = std::get_if<std::int64_t>(&event.args[idx]))
        return (DWORD_PTR)*iv;
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) {}
    }
    return 0;
}

// Create a fresh socket connected to the net_sim loopback proxy.
SOCKET NetworkExecutor::SynthConnectedSocket() {
    EnsureWSAStartup();
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    if (net_sim_.IsEnabled()) {
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = htons((u_short)net_sim_.GetProxyPort());
        if (::connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    }
    return s;
}

DWORD_PTR NetworkExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    if (n == "WSAStartup") {
        EnsureWSAStartup();
        WSADATA wd{};
        return (DWORD_PTR)WSAStartup((WORD)p.raw[0], &wd);
    }
    if (n == "WSACleanup") {
        return (DWORD_PTR)WSACleanup();
    }
    if (n == "socket") {
        EnsureWSAStartup();
        return (DWORD_PTR)::socket((int)p.raw[0], (int)p.raw[1], (int)p.raw[2]);
    }

    if (n == "connect") {
        // Read original (unreplaced) socket value from the event to check handle_map.
        DWORD_PTR orig = ReadArgHandle(event, 0);
        // Unmapped: socket was created before capture or by an uncaptured call.
        // SynthConnectedSocket creates AND connects to the proxy in one step; do NOT
        // call ::connect() again on the returned socket (it would fail WSAEISCONN).
        bool unmapped = (orig != 0) &&
                        !handle_map_.IsPredefined(orig) &&
                        !handle_map_.HasMapping(orig);
        SOCKET s = (SOCKET)p.raw[0];
        // Synthesize when: (a) original handle has no mapping, OR (b) resolved value
        // is 0 or INVALID_SOCKET (occurs when WinMET logs socket=0, or arg defaults).
        if (unmapped || s == 0 || s == INVALID_SOCKET) {
            SOCKET synth = SynthConnectedSocket();
            if (synth == INVALID_SOCKET) return (DWORD_PTR)SOCKET_ERROR;
            // Register so subsequent send()/recv() on the same original handle work.
            if (orig != 0 && orig != (DWORD_PTR)INVALID_SOCKET)
                handle_map_.Register(orig, (DWORD_PTR)synth);
            return 0; // SOCKET_NO_ERROR — already connected by SynthConnectedSocket
        }
        // Mapped socket: redirect to net_sim loopback proxy.
        if (net_sim_.IsEnabled() && s != INVALID_SOCKET) {
            sockaddr_in addr{};
            addr.sin_family      = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port        = htons((u_short)net_sim_.GetProxyPort());
            return (DWORD_PTR)::connect(s, (sockaddr*)&addr, sizeof(addr));
        }
        return (DWORD_PTR)SOCKET_ERROR;
    }
    if (n == "bind") {
        SOCKET s = (SOCKET)p.raw[0];
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = 0;
        return (DWORD_PTR)::bind(s, (sockaddr*)&addr, sizeof(addr));
    }

    if (n == "WSAConnect") {
        DWORD_PTR orig = ReadArgHandle(event, 0);
        bool unmapped = (orig != 0) &&
                        !handle_map_.IsPredefined(orig) &&
                        !handle_map_.HasMapping(orig);
        SOCKET s = (SOCKET)p.raw[0];
        if (unmapped || s == 0 || s == INVALID_SOCKET) {
            SOCKET synth = SynthConnectedSocket();
            if (synth == INVALID_SOCKET) return (DWORD_PTR)SOCKET_ERROR;
            if (orig != 0 && orig != (DWORD_PTR)INVALID_SOCKET)
                handle_map_.Register(orig, (DWORD_PTR)synth);
            return 0; // SOCKET_NO_ERROR — already connected by SynthConnectedSocket
        }
        if (net_sim_.IsEnabled()) {
            sockaddr_in addr{};
            addr.sin_family      = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port        = htons((u_short)net_sim_.GetProxyPort());
            return (DWORD_PTR)WSAConnect(s, (sockaddr*)&addr, sizeof(addr),
                                         nullptr, nullptr, nullptr, nullptr);
        }
        return (DWORD_PTR)SOCKET_ERROR;
    }

    if (n == "listen") {
        return (DWORD_PTR)::listen((SOCKET)p.raw[0], (int)p.raw[1]);
    }
    if (n == "accept") {
        return (DWORD_PTR)::accept((SOCKET)p.raw[0], nullptr, nullptr);
    }
    if (n == "send") {
        return (DWORD_PTR)::send((SOCKET)p.raw[0], (const char*)p.raw[1],
                                 (int)p.raw[2], (int)p.raw[3]);
    }
    if (n == "recv") {
        return (DWORD_PTR)::recv((SOCKET)p.raw[0], (char*)p.raw[1],
                                 (int)p.raw[2], (int)p.raw[3]);
    }
    if (n == "closesocket") {
        SOCKET s = (SOCKET)p.raw[0];
        // Unmapped socket: nothing to close
        if (s == 0 || s == INVALID_SOCKET) return 0; // SOCKET_NO_ERROR
        int r = ::closesocket(s);
        if (r != 0) r = 0; // treat errors as success (socket may already be closed)
        return (DWORD_PTR)r;
    }

    if (n == "GetAddrInfoW") {
        EnsureWSAStartup();
        PADDRINFOW res = nullptr;
        if (net_sim_.IsEnabled()) {
            wchar_t port_str[16];
            swprintf_s(port_str, _countof(port_str), L"%u", (unsigned)net_sim_.GetProxyPort());
            ADDRINFOW h{};
            h.ai_family   = AF_INET;
            h.ai_socktype = SOCK_STREAM;
            int r = GetAddrInfoW(L"127.0.0.1", port_str, &h, &res);
            if (p.args.size() > 3 && !p.args[3].buffer.empty())
                *reinterpret_cast<PADDRINFOW*>(const_cast<BYTE*>(p.args[3].buffer.data())) = res;
            std::lock_guard<std::mutex> lock(addrinfo_mutex_);
            if (last_addrinfo_) FreeAddrInfoW(last_addrinfo_);
            last_addrinfo_ = res;
            return (DWORD_PTR)r;
        }
        int r = GetAddrInfoW((LPCWSTR)p.raw[0], (LPCWSTR)p.raw[1], nullptr, &res);
        if (p.args.size() > 3 && !p.args[3].buffer.empty())
            *reinterpret_cast<PADDRINFOW*>(const_cast<BYTE*>(p.args[3].buffer.data())) = res;
        {
            std::lock_guard<std::mutex> lock(addrinfo_mutex_);
            if (last_addrinfo_) FreeAddrInfoW(last_addrinfo_);
            last_addrinfo_ = res;
        }
        return (DWORD_PTR)r;
    }
    if (n == "FreeAddrInfoW") {
        std::lock_guard<std::mutex> lock(addrinfo_mutex_);
        if (last_addrinfo_) { FreeAddrInfoW(last_addrinfo_); last_addrinfo_ = nullptr; }
        return 0;
    }

    // ── WinINet ──────────────────────────────────────────────────────────────

    if (n == "InternetOpenW") {
        return (DWORD_PTR)InternetOpenW(
            (LPCWSTR)p.raw[0], (DWORD)p.raw[1],
            (LPCWSTR)p.raw[2], (LPCWSTR)p.raw[3], (DWORD)p.raw[4]);
    }
    if (n == "InternetOpenA") {
        return (DWORD_PTR)InternetOpenA(
            (LPCSTR)p.raw[0], (DWORD)p.raw[1],
            (LPCSTR)p.raw[2], (LPCSTR)p.raw[3], (DWORD)p.raw[4]);
    }
    if (n == "InternetConnectW") {
        return (DWORD_PTR)InternetConnectW(
            (HINTERNET)p.raw[0], (LPCWSTR)p.raw[1], (INTERNET_PORT)p.raw[2],
            (LPCWSTR)p.raw[3], (LPCWSTR)p.raw[4],
            (DWORD)p.raw[5], (DWORD)p.raw[6], (DWORD_PTR)p.raw[7]);
    }
    if (n == "InternetConnectA") {
        return (DWORD_PTR)InternetConnectA(
            (HINTERNET)p.raw[0], (LPCSTR)p.raw[1], (INTERNET_PORT)p.raw[2],
            (LPCSTR)p.raw[3], (LPCSTR)p.raw[4],
            (DWORD)p.raw[5], (DWORD)p.raw[6], (DWORD_PTR)p.raw[7]);
    }
    if (n == "HttpOpenRequestW") {
        return (DWORD_PTR)HttpOpenRequestW(
            (HINTERNET)p.raw[0], (LPCWSTR)p.raw[1], (LPCWSTR)p.raw[2],
            (LPCWSTR)p.raw[3], (LPCWSTR)p.raw[4],
            nullptr, (DWORD)p.raw[6], (DWORD_PTR)p.raw[7]);
    }
    if (n == "HttpOpenRequestA") {
        return (DWORD_PTR)HttpOpenRequestA(
            (HINTERNET)p.raw[0], (LPCSTR)p.raw[1], (LPCSTR)p.raw[2],
            (LPCSTR)p.raw[3], (LPCSTR)p.raw[4],
            nullptr, (DWORD)p.raw[6], (DWORD_PTR)p.raw[7]);
    }
    if (n == "HttpSendRequestW") {
        return (DWORD_PTR)HttpSendRequestW(
            (HINTERNET)p.raw[0], (LPCWSTR)p.raw[1], (DWORD)p.raw[2],
            (LPVOID)p.raw[3], (DWORD)p.raw[4]);
    }
    if (n == "HttpSendRequestA") {
        return (DWORD_PTR)HttpSendRequestA(
            (HINTERNET)p.raw[0], (LPCSTR)p.raw[1], (DWORD)p.raw[2],
            (LPVOID)p.raw[3], (DWORD)p.raw[4]);
    }
    if (n == "InternetReadFile") {
        DWORD read = 0;
        return (DWORD_PTR)InternetReadFile(
            (HINTERNET)p.raw[0], (LPVOID)p.raw[1], (DWORD)p.raw[2], &read);
    }
    if (n == "InternetCloseHandle") {
        return (DWORD_PTR)InternetCloseHandle((HINTERNET)p.raw[0]);
    }

    return 0;
}
