#pragma once
#include "replay/api_executor.h"

// Handles system-information APIs that require pre-initialised structs or
// caller-allocated output buffers.  GenericDispatcher cannot handle these
// because it passes 0 for all integer arguments, leaving output-buffer
// pointers as NULL and causing AVs inside user32/kernel32.
class SystemExecutor : public ExecutorBase {
public:
    SystemExecutor(HandleMap& hmap, PointerMap& pmap)
        : ExecutorBase(hmap, pmap) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;
};
