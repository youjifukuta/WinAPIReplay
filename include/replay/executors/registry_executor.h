#pragma once
#include "replay/api_executor.h"
#include "replay/registry_sandbox.h"

class RegistryExecutor : public ExecutorBase {
public:
    RegistryExecutor(HandleMap& hmap, PointerMap& pmap, RegistrySandbox& sb)
        : ExecutorBase(hmap, pmap), reg_sandbox_(sb) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    RegistrySandbox& reg_sandbox_;
};
