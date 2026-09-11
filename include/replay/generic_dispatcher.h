#pragma once
#include "log_types.h"
#include "handle_map.h"
#include <string>
#include <vector>

class GenericDispatcher {
public:
    explicit GenericDispatcher(HandleMap& handle_map)
        : handle_map_(handle_map) {}

    // Returns true if dispatched; false if no export found
    bool Dispatch(const LogEvent& event, DWORD_PTR& out_result);

private:
    HandleMap& handle_map_;
};
