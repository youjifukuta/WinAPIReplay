#pragma once
#include "replay/api_executor.h"

class ShellExecutor : public ExecutorBase {
public:
    ShellExecutor(HandleMap& hmap, PointerMap& pmap, bool no_spawn)
        : ExecutorBase(hmap, pmap), no_spawn_(no_spawn) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    bool no_spawn_;
};
