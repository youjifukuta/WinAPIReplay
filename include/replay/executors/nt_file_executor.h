#pragma once
#include "replay/api_executor.h"
#include "replay/path_sandbox.h"

// Handles NT-native file I/O APIs.
// Calls the EXACT NT API named in the log (NtCreateFile, NtReadFile, etc.)
// via ntdll.dll function pointers loaded by PreInit.
// No extra OS calls are made during event replay.
class NtFileExecutor : public ExecutorBase {
public:
    NtFileExecutor(HandleMap& hmap, PointerMap& pmap, PathSandbox& sb)
        : ExecutorBase(hmap, pmap), path_sandbox_(sb) {}

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    PathSandbox& path_sandbox_;

    static DWORD_PTR ReadHexArg(const LogEvent& event, int idx);
    static std::wstring ReadStrArg(const LogEvent& event, int idx);
};
