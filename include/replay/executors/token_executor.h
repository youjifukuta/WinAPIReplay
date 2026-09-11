#pragma once
#include "replay/api_executor.h"

class TokenExecutor : public ExecutorBase {
public:
    using ExecutorBase::ExecutorBase;
    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;
};
