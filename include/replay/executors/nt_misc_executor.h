#pragma once
#include "replay/api_executor.h"
#include "replay/path_sandbox.h"

class NtMiscExecutor : public ExecutorBase {
public:
    NtMiscExecutor(HandleMap& hmap, PointerMap& pmap, PathSandbox& path_sandbox)
        : ExecutorBase(hmap, pmap), path_sandbox_(path_sandbox) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    PathSandbox& path_sandbox_;

    static DWORD_PTR ReadHexArg(const LogEvent& event, int idx);
    static std::wstring ReadStrArg(const LogEvent& event, int idx);
    static SIZE_T ReadSizeArg(const LogEvent& event, int idx);
};
