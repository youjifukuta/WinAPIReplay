#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <utility>

class NetSimulator {
public:
    NetSimulator() = default;
    ~NetSimulator() { Stop(); }

    void Start();
    void Stop();

    std::pair<std::string, std::string> ResolveEndpoint(
        const std::string& host, const std::string& port) const;

    bool IsEnabled() const { return enabled_; }
    int  GetProxyPort() const { return proxy_port_; }

private:
    bool             enabled_     = false;
    SOCKET           server_sock_ = INVALID_SOCKET;
    std::thread      server_thread_;
    std::atomic<bool> running_    = false;
    int              proxy_port_  = 0;
    std::string      proxy_host_  = "127.0.0.1";

    static constexpr size_t kInitialPayload = 65536;

    void ServerLoop();
};
