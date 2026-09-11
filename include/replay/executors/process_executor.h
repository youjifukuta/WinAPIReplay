#pragma once
#include "replay/api_executor.h"
#include "replay/pid_map.h"

class ProcessExecutor : public ExecutorBase {
public:
    ProcessExecutor(HandleMap& hmap, PointerMap& pmap, PidMap& pid_map, bool no_spawn)
        : ExecutorBase(hmap, pmap), pid_map_(pid_map), no_spawn_(no_spawn) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    PidMap& pid_map_;
    bool    no_spawn_;
};
