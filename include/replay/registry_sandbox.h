#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <utility>

class RegistrySandbox {
public:
    static constexpr wchar_t kSandboxRoot[] = L"Software\\WinAPIReplaySandbox";

    bool IsEnabled() const { return enabled_; }
    void Enable()          { enabled_ = true; }

    std::pair<HKEY, std::wstring> Redirect(HKEY root, const std::wstring& subkey) const;
    void Cleanup() const;

private:
    bool enabled_ = false;

    static std::wstring RootKeyName(HKEY root);
};
