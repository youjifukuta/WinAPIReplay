#pragma once
#include "replay/api_executor.h"
#include "replay/path_sandbox.h"

class FileExecutor : public ExecutorBase {
public:
    FileExecutor(HandleMap& hmap, PointerMap& pmap, PathSandbox& sb)
        : ExecutorBase(hmap, pmap), path_sandbox_(sb) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    PathSandbox& path_sandbox_;
};
