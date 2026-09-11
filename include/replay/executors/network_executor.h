#pragma once
#include "replay/api_executor.h"
#include "replay/net_simulator.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mutex>

class NetworkExecutor : public ExecutorBase {
public:
    NetworkExecutor(HandleMap& hmap, PointerMap& pmap, NetSimulator& net_sim)
        : ExecutorBase(hmap, pmap), net_sim_(net_sim) {}

    ~NetworkExecutor() {
        std::lock_guard<std::mutex> lock(addrinfo_mutex_);
        if (last_addrinfo_) { FreeAddrInfoW(last_addrinfo_); last_addrinfo_ = nullptr; }
    }

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

    void EnsureWSAStartup();
    SOCKET SynthConnectedSocket();

private:
    NetSimulator&     net_sim_;
    bool              wsa_initialized_ = false;
    ADDRINFOW*        last_addrinfo_   = nullptr;
    mutable std::mutex addrinfo_mutex_;
};
