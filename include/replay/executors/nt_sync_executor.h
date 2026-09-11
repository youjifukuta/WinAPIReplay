#pragma once
#include "replay/api_executor.h"

class NtSyncExecutor : public ExecutorBase {
public:
    NtSyncExecutor(HandleMap& hmap, PointerMap& pmap, DWORD wait_timeout_ms = 100)
        : ExecutorBase(hmap, pmap), wait_timeout_ms_(wait_timeout_ms) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    DWORD wait_timeout_ms_;

    static DWORD_PTR ReadHexArg(const LogEvent& event, int idx);
    static std::wstring ReadStrArg(const LogEvent& event, int idx);
    static SIZE_T ReadSizeArg(const LogEvent& event, int idx);
};
