#pragma once
#include "replay/api_executor.h"
#include "replay/registry_sandbox.h"
#include "replay/nt_native.h"
#include <utility>
#include <string>

class NtRegistryExecutor : public ExecutorBase {
public:
    NtRegistryExecutor(HandleMap& hmap, PointerMap& pmap,
                       RegistrySandbox& reg_sandbox)
        : ExecutorBase(hmap, pmap), reg_sandbox_(reg_sandbox) {}

    ~NtRegistryExecutor() override {
        if (hSandboxRoot_) RegCloseKey(hSandboxRoot_);
    }

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

    // Called by ApiExecutor::PreInit before the event loop.
    // Opens the sandbox root key once (Win32 call, outside event loop).
    void Initialize() override;

private:
    RegistrySandbox& reg_sandbox_;
    HKEY hSandboxRoot_ = nullptr;  // HKCU\Software\WinAPIReplaySandbox

    static DWORD_PTR ReadHexArg(const LogEvent& event, int idx);
    static std::wstring ReadStrArg(const LogEvent& event, int idx);
    HANDLE ResolveHKEY(const LogEvent& event, int idx);
    std::pair<HKEY, std::wstring> ParseRegPath(const LogEvent& event);

    // Build OBJECT_ATTRIBUTES pointing into the sandbox, relative to hSandboxRoot_.
    // Returns {oa_valid=true, oa} if successful.
    bool BuildSandboxOA(HKEY root_key, const std::wstring& subkey,
                        std::wstring& rel_path_out,
                        UNICODE_STRING& us_out, OBJECT_ATTRIBUTES& oa_out) const;
};
