#include "replay/executors/hook_executor.h"

std::vector<std::string> HookExecutor::SupportedApis() const {
    return { "SetWindowsHookExW", "SetWindowsHookExA" };
}

DWORD_PTR HookExecutor::Execute(const LogEvent& event, const PreparedArgs&) {
    const auto& n = event.api_name;
    // Stub: do NOT install real Windows hooks.
    // A malware log typically records dwThreadId=0 (system-wide), which would
    // attach to every desktop thread for the lifetime of this process and
    // degrade VM responsiveness across samples.  Return a non-NULL sentinel so
    // downstream UnhookWindowsHookEx calls receive a defined (non-null) value.
    if (n == "SetWindowsHookExW" || n == "SetWindowsHookExA")
        return 1;  // non-NULL sentinel; no real hook installed
    return 0;
}
