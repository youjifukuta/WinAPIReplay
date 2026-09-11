#pragma once
#include "replay/api_executor.h"

class NtMemoryExecutor : public ExecutorBase {
public:
    using ExecutorBase::ExecutorBase;
    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    static DWORD_PTR ReadHexArg(const LogEvent& event, int idx);
    static SIZE_T ReadSizeArg(const LogEvent& event, int idx);
};
