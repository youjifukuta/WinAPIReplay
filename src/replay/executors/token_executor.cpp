#include "replay/executors/token_executor.h"

std::vector<std::string> TokenExecutor::SupportedApis() const {
    return { "OpenProcessToken", "AdjustTokenPrivileges" };
}

DWORD_PTR TokenExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    if (n == "OpenProcessToken") {
        // arg[2] is DATA_OUT(8) for *TokenHandle — pass buffer ptr directly
        return (DWORD_PTR)OpenProcessToken(
            (HANDLE)p.raw[0], (DWORD)p.raw[1], (PHANDLE)p.raw[2]);
    }
    if (n == "AdjustTokenPrivileges") {
        // Stub: do NOT adjust token privileges.
        // DisableAllPrivileges=TRUE would strip all privileges from the replay
        // process's own token (the only token we can open), breaking subsequent
        // sandboxed file/registry operations within the same sample.
        return (DWORD_PTR)TRUE;
    }

    return 0;
}
