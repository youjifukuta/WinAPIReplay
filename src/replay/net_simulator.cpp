#include "replay/net_simulator.h"
#include <stdexcept>
#include <vector>

void NetSimulator::Start() {
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);

    server_sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock_ == INVALID_SOCKET)
        throw std::runtime_error("NetSimulator: socket() failed");

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(0);  // OS が空きポートを割り当て

    if (bind(server_sock_, (sockaddr*)&addr, sizeof(addr)) != 0)
        throw std::runtime_error("NetSimulator: bind() failed");

    int addrlen = sizeof(addr);
    getsockname(server_sock_, (sockaddr*)&addr, &addrlen);
    proxy_port_ = ntohs(addr.sin_port);

    listen(server_sock_, SOMAXCONN);

    enabled_ = true;
    running_ = true;
    server_thread_ = std::thread(&NetSimulator::ServerLoop, this);
}

void NetSimulator::Stop() {
    if (!enabled_) return;
    running_ = false;
    if (server_sock_ != INVALID_SOCKET) {
        closesocket(server_sock_);
        server_sock_ = INVALID_SOCKET;
    }
    if (server_thread_.joinable())
        server_thread_.join();
    enabled_ = false;
}

std::pair<std::string, std::string> NetSimulator::ResolveEndpoint(
    const std::string&, const std::string&) const
{
    return { proxy_host_, std::to_string(proxy_port_) };
}

void NetSimulator::ServerLoop() {
    while (running_) {
        sockaddr_in client_addr{};
        int addrlen = sizeof(client_addr);
        SOCKET client = accept(server_sock_, (sockaddr*)&client_addr, &addrlen);
        if (client == INVALID_SOCKET) break;

        std::thread([client]() {
            // 接続直後に初期ダミーデータを送信
            std::vector<char> init(NetSimulator::kInitialPayload, 0);
            send(client, init.data(), (int)init.size(), 0);
            // クライアントからのデータを echo で返し続ける
            char buf[4096];
            int n;
            while ((n = recv(client, buf, sizeof(buf), 0)) > 0)
                send(client, buf, n, 0);
            closesocket(client);
        }).detach();
    }
}
