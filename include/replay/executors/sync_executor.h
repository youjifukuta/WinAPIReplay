#pragma once
#include "replay/api_executor.h"

class SyncExecutor : public ExecutorBase {
public:
    SyncExecutor(HandleMap& hmap, PointerMap& pmap, DWORD timeout_ms)
        : ExecutorBase(hmap, pmap), timeout_ms_(timeout_ms) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    DWORD timeout_ms_;
};
